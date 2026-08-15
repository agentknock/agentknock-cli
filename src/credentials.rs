use std::{collections::BTreeMap, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    config::{ConfigurationError, Pairing, clear_rotation_key, read_pairing},
    crypto::{self, Session},
    pairing::{RotationError, maybe_rotate_psk},
    websocket::{self, Relay},
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
        resolved_path: Option<&'a str>,
        stdin: StreamKind,
        stdout: StreamKind,
        stderr: StreamKind,
    },
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

    #[error("relay request failed: {0}")]
    Relay(String),

    #[error("relay returned unexpected HTTP status {0}")]
    UnexpectedRelayStatus(u16),

    #[error("relay remained unavailable after {failures} consecutive failures")]
    RelayUnavailable { failures: usize },

    #[error("received unauthenticated error {code}: {message:?}")]
    Unauthenticated { code: String, message: String },

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("request denied ({reason}): {message}")]
    Denied {
        reason: DenialReason,
        message: String,
    },

    #[error("pairing was rejected")]
    PairingRejected,

    #[error("credential request interrupted")]
    Interrupted,

    #[error("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8")]
    InvalidTestRelayUrl,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid protocol JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("cannot {operation} while cryptographic session is {state}")]
    MessageOrder {
        operation: &'static str,
        state: &'static str,
    },

    #[error("invalid base64 in encrypted response: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("HPKE operation failed: {0}")]
    Hpke(#[from] hpke::HpkeError),

    #[error("random generation failed: {0}")]
    Random(#[from] getrandom::Error),

    #[error("key derivation failed: {0}")]
    KeyDerivation(#[from] hkdf::InvalidLength),

    #[error("response decryption failed")]
    Decryption(#[from] chacha20poly1305::aead::Error),

    #[error("relay response state did not include a response message")]
    MissingResponse,

    #[error("approved response did not contain an environment mapping")]
    MissingEnvironment,

    #[error("received an ABORTED result in a response")]
    AbortedResponse,

    #[error("device random has length {actual}, expected {expected} bytes")]
    InvalidDeviceRandomLength { actual: usize, expected: usize },
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

pub async fn request_credentials(
    request: CredentialRequest<'_>,
) -> Result<Credentials, RequestError> {
    request_credentials_with_progress(request, std::future::pending(), |_| {}).await
}

pub async fn request_credentials_until_cancelled<C>(
    request: CredentialRequest<'_>,
    cancellation: C,
) -> Result<Credentials, RequestError>
where
    C: Future<Output = ()>,
{
    request_credentials_with_progress(request, cancellation, |_| {}).await
}

pub async fn request_credentials_with_progress<C, P>(
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
        RotationError::Protocol(error) => RequestError::Protocol(error),
    })?;
    let pairing = read_pairing()?;
    let operation = match request.operation {
        RequestOperation::Exec {
            command,
            arguments,
            working_directory,
            resolved_path,
            stdin,
            stdout,
            stderr,
        } => OperationMessage::Exec {
            command,
            arguments,
            working_directory,
            resolved_path,
            stdin: stdin.into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
        },
    };
    let request_contents = RequestContents {
        method: "CredentialRequest",
        profiles: request.profiles,
        reason: request.reason,
        operation,
        launcher_chain: request.launcher_chain,
    };

    message_exchange(
        &pairing,
        &request_contents,
        cancellation.as_mut(),
        &mut progress,
    )
    .await
}

async fn message_exchange<C, P>(
    pairing: &Pairing,
    request_contents: &RequestContents<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<Credentials, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(CredentialRequestProgress),
{
    let request_id = Ulid::generate();
    let plaintext = crate::protocol::encode(request_contents).map_err(ProtocolError::from)?;
    let mut session = Session::new(pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let mut relay = Relay::authenticated(pairing, &request_id.to_string())?;

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
        .map_err(ProtocolError::from)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(rotation_key)?;
    }
    let result: RequestResult = serde_json::from_slice(&plaintext).map_err(ProtocolError::from)?;
    let (completion_result, exchange_result) = match result {
        RequestResult::Approved {
            environment: Some(environment),
        } => (
            RequestResult::Approved { environment: None },
            Ok(Credentials { environment }),
        ),
        RequestResult::Approved { environment: None } => (
            RequestResult::Aborted {
                reason: AbortReason::InvalidResponse,
                message: ProtocolError::MissingEnvironment.to_string(),
            },
            Err(ProtocolError::MissingEnvironment.into()),
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
                message: ProtocolError::AbortedResponse.to_string(),
            },
            Err(ProtocolError::AbortedResponse.into()),
        ),
    };

    let plaintext = crate::protocol::encode(&completion_result).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;
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

async fn complete_cancelled(session: &mut Session, relay: &mut Relay) {
    let Some(completion) = seal_aborted(
        session,
        AbortReason::Cancelled,
        RequestError::Interrupted.to_string(),
    ) else {
        return;
    };
    let _ = relay.complete_briefly(&completion).await;
}

impl From<crypto::Error> for ProtocolError {
    fn from(error: crypto::Error) -> Self {
        match error {
            crypto::Error::MessageOrder { operation, state } => {
                Self::MessageOrder { operation, state }
            }
            crypto::Error::Base64(error) => Self::Base64(error),
            crypto::Error::Hpke(error) => Self::Hpke(error),
            crypto::Error::Random(error) => Self::Random(error),
            crypto::Error::KeyDerivation(error) => Self::KeyDerivation(error),
            crypto::Error::Decryption(error) => Self::Decryption(error),
            crypto::Error::InvalidDeviceRandomLength { actual, expected } => {
                Self::InvalidDeviceRandomLength { actual, expected }
            }
        }
    }
}

impl From<websocket::Error> for RequestError {
    fn from(error: websocket::Error) -> Self {
        match error {
            websocket::Error::InvalidJson(error) => Self::Protocol(ProtocolError::Json(error)),
            websocket::Error::UnexpectedStatus(status) => Self::UnexpectedRelayStatus(status),
            websocket::Error::RetriesExhausted { failures, .. } => {
                Self::RelayUnavailable { failures }
            }
            websocket::Error::Unauthenticated { code, message } => {
                Self::Unauthenticated { code, message }
            }
            websocket::Error::MissingResponse => Self::Protocol(ProtocolError::MissingResponse),
            websocket::Error::InvalidTestRelayUrl => Self::InvalidTestRelayUrl,
            error => Self::Relay(error.to_string()),
        }
    }
}

#[derive(Serialize)]
struct RequestContents<'a> {
    method: &'static str,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved_path: Option<&'a str>,
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
        environment: Option<BTreeMap<String, String>>,
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
