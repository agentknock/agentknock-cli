use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    io,
    pin::Pin,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    config::{ConfigurationError, Pairing, clear_rotation_key, read_pairing},
    crypto::{self, Session},
    pairing::{RotationError, maybe_rotate_psk},
    profiles::{ProfileContentsMessage, ProfileMessage, SecretValueMessage},
    protocol::Method,
    websocket::{self, RelayExchange},
};

pub struct CredentialRequest<'a> {
    pub profiles: &'a [String],
    pub operation: RequestOperation<'a>,
    pub reason: Option<&'a str>,
    pub launcher_chain: &'a [String],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    Terminal,
    NullDevice,
    Pipe,
    Socket,
    RegularFile,
    Unknown,
}

pub enum RequestOperation<'a> {
    Exec {
        command: &'a str,
        arguments: &'a [String],
        working_directory: &'a str,
        executable_path: &'a str,
        executable_hash: Option<&'a [u8; 32]>,
        executable_mode: ExecutableMode,
        stdin: StreamKind,
        stdout: StreamKind,
        stderr: StreamKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutableMode {
    Binary,
    Script,
}

pub struct Credentials {
    environment: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRequestProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

impl Credentials {
    pub fn environment_variable_names(&self) -> impl Iterator<Item = &str> {
        self.environment.keys().map(String::as_str)
    }

    pub fn into_environment(self) -> BTreeMap<String, String> {
        self.environment
    }
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error("relay remained unavailable after {failures} consecutive failures")]
    RelayUnavailable { failures: usize },

    #[error("received unauthenticated error {code}: {message:?}")]
    Unauthenticated { code: String, message: String },

    #[error("paired client is inactive: {message}")]
    ClientInactive { message: String },

    #[error(transparent)]
    Other(#[from] io::Error),

    #[error("request denied ({reason}): {message}")]
    Denied {
        reason: DenialReason,
        message: String,
    },

    #[error("pairing was rejected")]
    PairingRejected,

    #[error("profile access request was interrupted")]
    Interrupted,

    #[error("AGENTKNOCK_TEST_RELAY_URL isn't valid UTF-8")]
    InvalidTestRelayUrl,
}

impl RequestError {
    pub(crate) fn other<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Other(io::Error::other(error))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialReason {
    UserDenied,
    PolicyDenied,
    InvalidRequest,
    Other,
}

impl fmt::Display for DenialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UserDenied => "USER_DENIED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::Other => "OTHER",
        })
    }
}

pub async fn request_credentials<C, P>(
    request: CredentialRequest<'_>,
    cancellation: C,
    mut progress: P,
) -> Result<Credentials, RequestError>
where
    C: Future<Output = ()>,
    P: FnMut(CredentialRequestProgress),
{
    tokio::pin!(cancellation);
    progress(CredentialRequestProgress::Preparing);
    maybe_rotate_psk().map_err(|error| match error {
        RotationError::Configuration(error) => RequestError::Configuration(error),
        RotationError::Other(error) => RequestError::Other(error),
    })?;
    let pairing = read_pairing()?;
    let operation = match request.operation {
        RequestOperation::Exec {
            command,
            arguments,
            working_directory,
            executable_path,
            executable_hash,
            executable_mode,
            stdin,
            stdout,
            stderr,
        } => OperationMessage::Exec {
            command,
            arguments,
            working_directory,
            executable_path,
            executable_hash: executable_hash.map(|hash| BASE64_STANDARD.encode(hash)),
            executable_mode,
            stdin: stdin.into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
        },
    };
    let request_payload = CredentialRequestPayload {
        method: Method::CredentialRequest,
        profiles: request.profiles,
        reason: request.reason,
        operation,
        launcher_chain: request.launcher_chain,
    };

    message_exchange(
        &pairing,
        &request_payload,
        cancellation.as_mut(),
        &mut progress,
    )
    .await
}

async fn message_exchange<C, P>(
    pairing: &Pairing,
    request_payload: &CredentialRequestPayload<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<Credentials, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(CredentialRequestProgress),
{
    let request_id = Ulid::generate();
    let plaintext = crate::protocol::encode(request_payload).map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(pairing, &request_id.to_string())?;

    progress(CredentialRequestProgress::WaitingForDelivery);
    let response = match tokio::select! {
        biased;
        _ = cancellation.as_mut() => {
            if relay.request_was_sent() {
                complete_cancelled(&mut session, &mut relay).await;
            }
            return Err(RequestError::Interrupted);
        }
        response = relay.request(&request, || {
            progress(CredentialRequestProgress::WaitingForResponse);
        }) => response,
    } {
        Ok(response) => response,
        Err(error) => {
            let abort_reason = abort_reason(&error);
            let error = RequestError::from(error);
            let completion = seal_aborted(&mut session, abort_reason, error.to_string());
            if let Some(completion) = completion {
                tokio::select! {
                    biased;
                    _ = cancellation.as_mut() => {
                        let _ = relay.complete_briefly(&completion).await;
                        return Err(RequestError::Interrupted);
                    }
                    _ = relay.complete(&completion) => {}
                }
            }
            return Err(error);
        }
    };
    progress(CredentialRequestProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(RequestError::other)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(rotation_key)?;
    }
    let result: RequestResult = serde_json::from_slice(&plaintext).map_err(RequestError::other)?;
    let (completion_result, exchange_result) = match result {
        RequestResult::Approved {
            profiles: Some(profiles),
        } => match credentials_from_profiles(profiles, request_payload.profiles) {
            Ok(credentials) => (RequestResult::Approved { profiles: None }, Ok(credentials)),
            Err(error) => (
                RequestResult::Aborted {
                    reason: AbortReason::InvalidResponse,
                    message: error.to_string(),
                },
                Err(error.into()),
            ),
        },
        RequestResult::Approved { profiles: None } => (
            RequestResult::Aborted {
                reason: AbortReason::InvalidResponse,
                message: "approved response doesn't contain profiles".into(),
            },
            Err(RequestError::other(
                "approved response doesn't contain profiles",
            )),
        ),
        RequestResult::Denied { reason, message } => (
            RequestResult::Denied {
                reason,
                message: message.clone(),
            },
            Err(RequestError::Denied { reason, message }),
        ),
        RequestResult::Aborted { .. } => (
            RequestResult::Aborted {
                reason: AbortReason::InvalidResponse,
                message: "received an ABORTED result in a response".into(),
            },
            Err(RequestError::other(
                "received an ABORTED result in a response",
            )),
        ),
    };

    let plaintext = crate::protocol::encode(&completion_result).map_err(RequestError::other)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(RequestError::other)?;
    let interrupted = tokio::select! {
        biased;
        _ = cancellation.as_mut() => true,
        result = relay.complete(&completion) => {
            result?;
            progress(CredentialRequestProgress::Completed);
            false
        }
    };
    if interrupted {
        let _ = relay.complete_briefly(&completion).await;
        return Err(RequestError::Interrupted);
    }

    exchange_result
}

fn credentials_from_profiles(
    profiles: BTreeMap<String, ProfileMessage<BTreeMap<String, SecretValueMessage>>>,
    requested_profiles: &[String],
) -> io::Result<Credentials> {
    let mut environment = BTreeMap::new();
    let received_profiles = profiles.keys().cloned().collect::<BTreeSet<_>>();
    for profile in profiles.into_values() {
        match profile.contents {
            ProfileContentsMessage::Environment { variables } => {
                for (name, variable) in variables {
                    if let Some(previous) = environment.get(&name)
                        && previous != &variable.value
                    {
                        return Err(io::Error::other(format!(
                            "approved profiles contain different values for environment variable {name:?}"
                        )));
                    }
                    environment.insert(name, variable.value);
                }
            }
        }
    }
    let expected_profiles = requested_profiles.iter().cloned().collect::<BTreeSet<_>>();
    if received_profiles != expected_profiles {
        return Err(io::Error::other(format!(
            "approved response contains profiles {:?}, expected {:?}",
            received_profiles.into_iter().collect::<Vec<_>>(),
            expected_profiles.into_iter().collect::<Vec<_>>()
        )));
    }
    Ok(Credentials { environment })
}

fn abort_reason(error: &websocket::Error) -> AbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => AbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            AbortReason::ClientError
        }
        _ => AbortReason::InvalidResponse,
    }
}

fn seal_aborted(
    session: &mut Session,
    reason: AbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let Ok(plaintext) = crate::protocol::encode(&RequestResult::Aborted { reason, message }) else {
        return None;
    };
    session.seal_completion(&plaintext).ok()
}

async fn complete_cancelled(session: &mut Session, relay: &mut RelayExchange) {
    let Some(completion) = seal_aborted(
        session,
        AbortReason::Cancelled,
        RequestError::Interrupted.to_string(),
    ) else {
        return;
    };
    let _ = relay.complete_briefly(&completion).await;
}

impl From<websocket::Error> for RequestError {
    fn from(error: websocket::Error) -> Self {
        match error {
            websocket::Error::RetriesExhausted { failures, .. } => {
                Self::RelayUnavailable { failures }
            }
            websocket::Error::Unauthenticated { code, message } => {
                Self::Unauthenticated { code, message }
            }
            websocket::Error::RelayRejected { code, message } if code == "CLIENT_INACTIVE" => {
                Self::ClientInactive { message }
            }
            websocket::Error::ClientInactive { reason, .. } => {
                Self::ClientInactive { message: reason }
            }
            websocket::Error::InvalidTestRelayUrl => Self::InvalidTestRelayUrl,
            error => Self::other(error),
        }
    }
}

#[derive(Serialize)]
struct CredentialRequestPayload<'a> {
    method: Method,
    profiles: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    operation: OperationMessage<'a>,
    launcher_chain: &'a [String],
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum OperationMessage<'a> {
    Exec {
        command: &'a str,
        arguments: &'a [String],
        working_directory: &'a str,
        executable_path: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        executable_hash: Option<String>,
        executable_mode: ExecutableMode,
        stdin: StreamKindMessage,
        stdout: StreamKindMessage,
        stderr: StreamKindMessage,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum StreamKindMessage {
    Terminal,
    NullDevice,
    Pipe,
    Socket,
    RegularFile,
    Unknown,
}

impl From<StreamKind> for StreamKindMessage {
    fn from(kind: StreamKind) -> Self {
        match kind {
            StreamKind::Terminal => Self::Terminal,
            StreamKind::NullDevice => Self::NullDevice,
            StreamKind::Pipe => Self::Pipe,
            StreamKind::Socket => Self::Socket,
            StreamKind::RegularFile => Self::RegularFile,
            StreamKind::Unknown => Self::Unknown,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum RequestResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        profiles: Option<BTreeMap<String, ProfileMessage<BTreeMap<String, SecretValueMessage>>>>,
    },
    Denied {
        reason: DenialReason,
        message: String,
    },
    Aborted {
        reason: AbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AbortReason {
    Cancelled,
    TimedOut,
    InvalidResponse,
    ClientError,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_equal_environment_values_from_different_profiles() {
        let profiles = BTreeMap::from([
            ("first".into(), environment_profile([("TOKEN", "same")])),
            (
                "second".into(),
                environment_profile([("TOKEN", "same"), ("OTHER", "value")]),
            ),
        ]);
        let requested = vec!["first".into(), "second".into()];

        let credentials = credentials_from_profiles(profiles, &requested).unwrap();

        assert_eq!(
            credentials.environment,
            BTreeMap::from([
                ("OTHER".into(), "value".into()),
                ("TOKEN".into(), "same".into()),
            ])
        );
    }

    #[test]
    fn rejects_conflicting_environment_values() {
        let profiles = BTreeMap::from([
            ("first".into(), environment_profile([("TOKEN", "one")])),
            ("second".into(), environment_profile([("TOKEN", "two")])),
        ]);
        let requested = vec!["first".into(), "second".into()];

        let error = credentials_from_profiles(profiles, &requested)
            .err()
            .expect("conflicting values should fail");
        assert_eq!(
            error.to_string(),
            "approved profiles contain different values for environment variable \"TOKEN\""
        );
    }

    #[test]
    fn rejects_a_different_profile_set() {
        let profiles =
            BTreeMap::from([("other".into(), environment_profile([("TOKEN", "value")]))]);
        let requested = vec!["requested".into()];

        let error = credentials_from_profiles(profiles, &requested)
            .err()
            .expect("a different profile set should fail");
        assert_eq!(
            error.to_string(),
            "approved response contains profiles [\"other\"], expected [\"requested\"]"
        );
    }

    fn environment_profile<const N: usize>(
        variables: [(&str, &str); N],
    ) -> ProfileMessage<BTreeMap<String, SecretValueMessage>> {
        ProfileMessage {
            description: None,
            contents: ProfileContentsMessage::Environment {
                variables: variables
                    .into_iter()
                    .map(|(name, value)| {
                        (
                            name.into(),
                            SecretValueMessage {
                                value: value.into(),
                            },
                        )
                    })
                    .collect(),
            },
        }
    }
}
