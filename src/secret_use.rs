use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    io,
    path::Path,
    pin::Pin,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    Client,
    config::{ConfigurationError, Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    pairing::RotationError,
    protocol::Method,
    secrets::{EnvironmentVariableMessage, SecretContentsMessage, SecretMessage},
    websocket::{self, RelayExchange},
};

pub struct SecretUseRequest<'a> {
    pub secrets: &'a BTreeSet<String>,
    pub operation: SecretUseOperation<'a>,
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

#[non_exhaustive]
pub enum SecretUseOperation<'a> {
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

pub struct SecretUseOutput {
    environment: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretUseProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

impl SecretUseOutput {
    pub fn environment_variable_names(&self) -> impl Iterator<Item = &str> {
        self.environment.keys().map(String::as_str)
    }

    pub fn into_environment(self) -> BTreeMap<String, String> {
        self.environment
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
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
        reason: SecretUseDenialReason,
        message: String,
    },

    #[error("pairing was rejected")]
    PairingRejected,

    #[error("secret use request was interrupted")]
    Interrupted,
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
pub enum SecretUseDenialReason {
    UserDenied,
    PolicyDenied,
    InvalidRequest,
    Other,
}

impl fmt::Display for SecretUseDenialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UserDenied => "USER_DENIED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::Other => "OTHER",
        })
    }
}

impl Client {
    pub async fn request_secret_use<C, P>(
        &self,
        request: SecretUseRequest<'_>,
        cancellation: C,
        mut progress: P,
    ) -> Result<SecretUseOutput, RequestError>
    where
        C: Future<Output = ()>,
        P: FnMut(SecretUseProgress),
    {
        tokio::pin!(cancellation);
        progress(SecretUseProgress::Preparing);
        self.maybe_rotate_psk().map_err(|error| match error {
            RotationError::Configuration(error) => RequestError::Configuration(error),
            RotationError::Other(error) => RequestError::Other(error),
        })?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let operation = match request.operation {
            SecretUseOperation::Exec {
                command,
                arguments,
                working_directory,
                executable_path,
                executable_hash,
                executable_mode,
                stdin,
                stdout,
                stderr,
            } => SecretUseOperationMessage::Exec {
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
        let request_payload = SecretUseRequestPayload {
            method: Method::SecretUse,
            secrets: request.secrets,
            reason: request.reason,
            operation,
            launcher_chain: request.launcher_chain,
        };

        message_exchange(
            &pairing_path,
            &pairing,
            &request_payload,
            cancellation.as_mut(),
            &mut progress,
        )
        .await
    }
}

async fn message_exchange<C, P>(
    pairing_path: &Path,
    pairing: &Pairing,
    request_payload: &SecretUseRequestPayload<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<SecretUseOutput, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(SecretUseProgress),
{
    let request_id = Ulid::generate();
    let plaintext = crate::protocol::encode(request_payload).map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(pairing, &request_id.to_string())?;

    progress(SecretUseProgress::WaitingForDelivery);
    let response = match tokio::select! {
        biased;
        _ = cancellation.as_mut() => {
            if relay.request_was_sent() {
                complete_cancelled(&mut session, &mut relay).await;
            }
            return Err(RequestError::Interrupted);
        }
        response = relay.request(&request, || {
            progress(SecretUseProgress::WaitingForResponse);
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
    progress(SecretUseProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(RequestError::other)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(pairing_path, rotation_key)?;
    }
    let result: SecretUseResult =
        serde_json::from_slice(&plaintext).map_err(RequestError::other)?;
    let (completion_result, exchange_result) = match result {
        SecretUseResult::Approved {
            secrets: Some(secrets),
        } => match secret_use_output_from_secrets(secrets, request_payload.secrets) {
            Ok(secret_use_output) => (
                SecretUseResult::Approved { secrets: None },
                Ok(secret_use_output),
            ),
            Err(error) => (
                SecretUseResult::Aborted {
                    reason: SecretUseAbortReason::InvalidResponse,
                    message: error.to_string(),
                },
                Err(error.into()),
            ),
        },
        SecretUseResult::Approved { secrets: None } => (
            SecretUseResult::Aborted {
                reason: SecretUseAbortReason::InvalidResponse,
                message: "approved response doesn't contain secrets".into(),
            },
            Err(RequestError::other(
                "approved response doesn't contain secrets",
            )),
        ),
        SecretUseResult::Denied { reason, message } => (
            SecretUseResult::Denied {
                reason,
                message: message.clone(),
            },
            Err(RequestError::Denied { reason, message }),
        ),
        SecretUseResult::Aborted { .. } => (
            SecretUseResult::Aborted {
                reason: SecretUseAbortReason::InvalidResponse,
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
            progress(SecretUseProgress::Completed);
            false
        }
    };
    if interrupted {
        let _ = relay.complete_briefly(&completion).await;
        return Err(RequestError::Interrupted);
    }

    exchange_result
}

fn secret_use_output_from_secrets(
    secrets: BTreeMap<String, SecretMessage<BTreeMap<String, EnvironmentVariableMessage>>>,
    requested_secrets: &BTreeSet<String>,
) -> io::Result<SecretUseOutput> {
    let mut environment = BTreeMap::new();
    let received_secrets = secrets.keys().cloned().collect::<BTreeSet<_>>();
    for secret in secrets.into_values() {
        match secret.contents {
            SecretContentsMessage::Environment { variables } => {
                for (name, variable) in variables {
                    if let Some(previous) = environment.get(&name)
                        && previous != &variable.value
                    {
                        return Err(io::Error::other(format!(
                            "approved secrets contain different values for environment variable {name:?}"
                        )));
                    }
                    environment.insert(name, variable.value);
                }
            }
        }
    }
    if &received_secrets != requested_secrets {
        return Err(io::Error::other(format!(
            "approved response contains secrets {:?}, expected {:?}",
            received_secrets.into_iter().collect::<Vec<_>>(),
            requested_secrets.iter().collect::<Vec<_>>()
        )));
    }
    Ok(SecretUseOutput { environment })
}

fn abort_reason(error: &websocket::Error) -> SecretUseAbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => SecretUseAbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            SecretUseAbortReason::ClientError
        }
        _ => SecretUseAbortReason::InvalidResponse,
    }
}

fn seal_aborted(
    session: &mut Session,
    reason: SecretUseAbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let Ok(plaintext) = crate::protocol::encode(&SecretUseResult::Aborted { reason, message })
    else {
        return None;
    };
    session.seal_completion(&plaintext).ok()
}

async fn complete_cancelled(session: &mut Session, relay: &mut RelayExchange) {
    let Some(completion) = seal_aborted(
        session,
        SecretUseAbortReason::Cancelled,
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
            error => Self::other(error),
        }
    }
}

#[derive(Serialize)]
struct SecretUseRequestPayload<'a> {
    method: Method,
    secrets: &'a BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    operation: SecretUseOperationMessage<'a>,
    launcher_chain: &'a [String],
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum SecretUseOperationMessage<'a> {
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
enum SecretUseResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        secrets:
            Option<BTreeMap<String, SecretMessage<BTreeMap<String, EnvironmentVariableMessage>>>>,
    },
    Denied {
        reason: SecretUseDenialReason,
        message: String,
    },
    Aborted {
        reason: SecretUseAbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SecretUseAbortReason {
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
    fn coalesces_equal_environment_values_from_different_secrets() {
        let secrets = BTreeMap::from([
            ("first".into(), environment_secret([("TOKEN", "same")])),
            (
                "second".into(),
                environment_secret([("TOKEN", "same"), ("OTHER", "value")]),
            ),
        ]);
        let requested = BTreeSet::from(["first".into(), "second".into()]);

        let secret_use_output = secret_use_output_from_secrets(secrets, &requested).unwrap();

        assert_eq!(
            secret_use_output.environment,
            BTreeMap::from([
                ("OTHER".into(), "value".into()),
                ("TOKEN".into(), "same".into()),
            ])
        );
    }

    #[test]
    fn rejects_conflicting_environment_values() {
        let secrets = BTreeMap::from([
            ("first".into(), environment_secret([("TOKEN", "one")])),
            ("second".into(), environment_secret([("TOKEN", "two")])),
        ]);
        let requested = BTreeSet::from(["first".into(), "second".into()]);

        let error = secret_use_output_from_secrets(secrets, &requested)
            .err()
            .expect("conflicting values should fail");
        assert_eq!(
            error.to_string(),
            "approved secrets contain different values for environment variable \"TOKEN\""
        );
    }

    #[test]
    fn rejects_a_different_secret_set() {
        let secrets = BTreeMap::from([("other".into(), environment_secret([("TOKEN", "value")]))]);
        let requested = BTreeSet::from(["requested".into()]);

        let error = secret_use_output_from_secrets(secrets, &requested)
            .err()
            .expect("a different secret set should fail");
        assert_eq!(
            error.to_string(),
            "approved response contains secrets [\"other\"], expected [\"requested\"]"
        );
    }

    fn environment_secret<const N: usize>(
        variables: [(&str, &str); N],
    ) -> SecretMessage<BTreeMap<String, EnvironmentVariableMessage>> {
        SecretMessage {
            description: None,
            contents: SecretContentsMessage::Environment {
                variables: variables
                    .into_iter()
                    .map(|(name, value)| {
                        (
                            name.into(),
                            EnvironmentVariableMessage {
                                value: value.into(),
                            },
                        )
                    })
                    .collect(),
            },
        }
    }
}
