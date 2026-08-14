use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    config::{ConfigurationError, Pairing, clear_rotation_key, read_pairing},
    crypto::{self, Session},
    pairing::{RotationError, maybe_rotate_psk},
    rest::{self, Relay},
};

pub struct CredentialRequest<'a> {
    pub profiles: &'a [String],
    pub operation: RequestOperation<'a>,
    pub reason: Option<&'a str>,
}

pub enum RequestOperation<'a> {
    Exec {
        command: &'a str,
        arguments: &'a [String],
    },
}

pub struct Credentials {
    environment: BTreeMap<String, String>,
}

impl Credentials {
    pub fn into_environment(self) -> BTreeMap<String, String> {
        self.environment
    }
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error("relay request failed: {0}")]
    Relay(#[from] reqwest::Error),

    #[error("relay returned unexpected HTTP status {0}")]
    UnexpectedRelayStatus(u16),

    #[error("relay remained unavailable after {failures} consecutive failures")]
    RelayUnavailable { failures: usize },

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("request denied ({reason}): {message}")]
    Denied {
        reason: DenialReason,
        message: String,
    },

    #[error("pairing was rejected")]
    PairingRejected,

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

    #[error("relay returned {state} for {operation}")]
    UnexpectedMessageState {
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
    maybe_rotate_psk().map_err(|error| match error {
        RotationError::Configuration(error) => RequestError::Configuration(error),
        RotationError::Protocol(error) => RequestError::Protocol(error),
    })?;
    let pairing = read_pairing()?;
    let request_contents = match request.operation {
        RequestOperation::Exec { command, arguments } => RequestContents {
            method: "CredentialRequest",
            profiles: request.profiles,
            operation: "exec",
            command,
            arguments,
            reason: request.reason,
        },
    };

    message_exchange(&pairing, &request_contents).await
}

async fn message_exchange(
    pairing: &Pairing,
    request_contents: &RequestContents<'_>,
) -> Result<Credentials, RequestError> {
    let request_id = Ulid::generate();
    let plaintext = serde_json::to_vec(request_contents).map_err(ProtocolError::from)?;
    let mut session = Session::new(pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let relay = Relay::new(&pairing.route_id(), &request_id.to_string())?;

    let response = match relay.request(&request).await {
        Ok(response) => response,
        Err(error) => {
            let abort_reason = abort_reason(&error);
            let error = RequestError::from(error);
            try_complete_aborted(
                &mut session,
                &relay,
                &request,
                abort_reason,
                error.to_string(),
            )
            .await;
            return Err(error);
        }
    };
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

    let plaintext = serde_json::to_vec(&completion_result).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;
    relay.complete(&request, &completion).await?;

    exchange_result
}

fn abort_reason(error: &rest::Error) -> AbortReason {
    match error {
        rest::Error::RetriesExhausted { .. } => AbortReason::TimedOut,
        rest::Error::Relay(error)
            if error
                .status()
                .is_some_and(|status| status.is_client_error()) =>
        {
            AbortReason::ClientError
        }
        _ => AbortReason::InvalidResponse,
    }
}

async fn try_complete_aborted(
    session: &mut Session,
    relay: &Relay,
    request: &crypto::Request,
    reason: AbortReason,
    message: String,
) {
    let Ok(plaintext) = serde_json::to_vec(&RequestResult::Aborted { reason, message }) else {
        return;
    };
    let Ok(completion) = session.seal_completion(&plaintext) else {
        return;
    };
    let _ = relay.complete(request, &completion).await;
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
        }
    }
}

impl From<rest::Error> for RequestError {
    fn from(error: rest::Error) -> Self {
        match error {
            rest::Error::Relay(error) => Self::Relay(error),
            rest::Error::InvalidJson(error) => Self::Protocol(ProtocolError::Json(error)),
            rest::Error::UnexpectedStatus(status) => Self::UnexpectedRelayStatus(status),
            rest::Error::RetriesExhausted { failures } => Self::RelayUnavailable { failures },
            rest::Error::UnexpectedState { operation, state } => {
                Self::Protocol(ProtocolError::UnexpectedMessageState { operation, state })
            }
            rest::Error::MissingResponse => Self::Protocol(ProtocolError::MissingResponse),
            rest::Error::InvalidTestRelayUrl => Self::InvalidTestRelayUrl,
        }
    }
}

#[derive(Serialize)]
struct RequestContents<'a> {
    method: &'static str,
    profiles: &'a [String],
    operation: &'static str,
    command: &'a str,
    arguments: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
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
