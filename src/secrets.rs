use std::{collections::BTreeMap, future::Future, io};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    Client, RequestError,
    config::{ConfigurationError, clear_rotation_key, read_pairing_from},
    crypto::Session,
    protocol::{self, Method, Response},
    websocket::RelayExchange,
};

/// Metadata for a secret available from the paired device.
///
/// This type never contains secret values.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Secret {
    /// A secret that provides environment variables.
    #[non_exhaustive]
    Environment {
        /// An optional human-readable description.
        description: Option<String>,
        /// The environment variable names provided by the secret.
        ///
        /// Names are sorted and contain no duplicates.
        variables: Vec<String>,
    },

    /// A secret that provides SSH operations without exposing its private key.
    #[non_exhaustive]
    Ssh {
        /// An optional human-readable description.
        description: Option<String>,
        /// The public key in OpenSSH format.
        public_key: String,
    },

    /// A secret type that this library version doesn't recognize.
    #[non_exhaustive]
    Unknown {
        /// An optional human-readable description.
        description: Option<String>,
        /// The type name reported by the device.
        secret_type: String,
    },
}

/// Secret metadata keyed by secret name.
///
/// Iteration yields secret names in lexicographic order.
pub type Secrets = BTreeMap<String, Secret>;

/// A secret to upload to the device.
#[derive(Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretUpload {
    /// An environment-variable secret.
    Environment {
        /// The name of the new or existing secret.
        name: String,
        /// The proposed description.
        description: Option<String>,
        /// Environment variable values keyed by variable name.
        variables: BTreeMap<String, String>,
    },

    /// An SSH private-key secret.
    Ssh {
        /// The name of the new or existing secret.
        name: String,
        /// The proposed description.
        description: Option<String>,
        /// A passphrase-free private key in OpenSSH format.
        ///
        /// The client-device protocol encrypts the upload. A passphrase used to decrypt the source
        /// key is not sent to the device.
        private_key: String,
    },
}

impl SecretUpload {
    /// Returns the proposed or existing secret name.
    pub fn name(&self) -> &str {
        match self {
            Self::Environment { name, .. } | Self::Ssh { name, .. } => name,
        }
    }
}

/// How an uploaded secret changes device state after user acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretUploadMode {
    /// Proposes a new secret whose final name the user can choose on the device.
    Create,

    /// Replaces an existing secret and removes content that isn't supplied.
    Replace,

    /// Updates supplied fields while retaining content that isn't supplied.
    Update,
}

/// A stage reported while a secret-list request is running.
///
/// A successful operation reports `Preparing`, `WaitingForDelivery`,
/// optionally one or more `WaitingForResponse` updates, `Completing`, and
/// `Completed`, in that order. An operation that fails stops without reporting
/// `Completed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretListProgress {
    /// Agentknock is reading local state and preparing the protected request.
    Preparing,

    /// The request is waiting to be delivered to the device.
    WaitingForDelivery,

    /// The device has received the request but hasn't returned a response.
    WaitingForResponse,

    /// Agentknock is validating the response and handing off the completion.
    Completing,

    /// The operation has finished successfully.
    Completed,
}

/// A stage reported while a secret upload is running.
///
/// A completed exchange reports `Preparing`, `WaitingForDelivery`, optionally
/// one or more `WaitingForResponse` updates, `Completing`, and `Completed`, in
/// that order. A rejected upload can return an error after reporting
/// `Completed`; other failures stop without reporting `Completed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretUploadProgress {
    /// Agentknock is reading local state and preparing the protected upload.
    Preparing,

    /// The upload is waiting to be delivered to the device.
    WaitingForDelivery,

    /// The device has received the upload but hasn't confirmed receipt.
    WaitingForResponse,

    /// Agentknock is validating the response and handing off the completion.
    Completing,

    /// The device confirmed receipt and the operation has finished.
    Completed,
}

/// An error uploading a secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretUploadError {
    /// The authenticated exchange failed.
    #[error(transparent)]
    Request(#[from] RequestError),

    /// The device rejected the upload instead of storing it for user review.
    #[error("the device rejected the secret upload: {message}")]
    Rejected {
        /// Human-readable context supplied by the device.
        message: String,
    },
}

impl From<ConfigurationError> for SecretUploadError {
    fn from(error: ConfigurationError) -> Self {
        Self::Request(error.into())
    }
}

impl From<crate::websocket::Error> for SecretUploadError {
    fn from(error: crate::websocket::Error) -> Self {
        Self::Request(error.into())
    }
}

impl Client {
    /// Lists metadata for secrets available from the paired device.
    ///
    /// The returned [`Secrets`] includes names, types, descriptions, and the
    /// names of values each secret provides. It never includes secret values.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. Cancellation before an authenticated response
    /// returns [`RequestError::Interrupted`]. After a response is
    /// authenticated, cancellation only shortens the best-effort completion
    /// handoff and the method still returns the decoded list. Pass
    /// [`std::future::pending()`] when the operation doesn't need cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] if local pairing state isn't active, the relay
    /// exchange fails, the response is invalid, or the operation is canceled
    /// before a response is authenticated.
    pub async fn list_secrets<P>(
        &self,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<Secrets, RequestError>
    where
        P: FnMut(SecretListProgress),
    {
        tokio::pin!(cancellation);
        progress(SecretListProgress::Preparing);
        self.maybe_rotate_psk()?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let request_id = Ulid::generate();
        let plaintext = self
            .encode(&ListRequest {
                method: Method::SecretList,
            })
            .map_err(RequestError::other)?;
        let mut session = Session::new(&pairing, &request_id).map_err(RequestError::other)?;
        let request = session
            .seal_request(&plaintext)
            .map_err(RequestError::other)?;
        let mut relay = RelayExchange::authenticated(self, &pairing, &request_id.to_string())?;

        progress(SecretListProgress::WaitingForDelivery);
        let response = tokio::select! {
            biased;
            _ = cancellation.as_mut() => return Err(RequestError::Interrupted),
            response = relay.request(&request, || {
                progress(SecretListProgress::WaitingForResponse);
            }) => response?,
        };
        progress(SecretListProgress::Completing);
        let plaintext = session
            .open_response(response)
            .map_err(RequestError::other)?;
        if let Some(rotation_key) = pairing.rotation_key() {
            clear_rotation_key(&pairing_path, rotation_key)?;
        }
        let response: ListResponse =
            match protocol::decode_response(&plaintext).map_err(RequestError::other)? {
                Response::Message(response) => response,
                Response::Error(error) => {
                    if let Some(completion) =
                        protocol::seal_error_completion(self, &mut session, &error)
                    {
                        let _ = relay.complete_briefly(&completion).await;
                    }
                    return Err(RequestError::DeviceRejected {
                        code: error.code,
                        message: error.message,
                    });
                }
            };
        let plaintext = self.encode(&EmptyMessage {}).map_err(RequestError::other)?;
        let completion = session
            .seal_completion(&plaintext)
            .map_err(RequestError::other)?;
        let interrupted = tokio::select! {
            biased;
            _ = cancellation.as_mut() => true,
            result = relay.complete(&completion) => {
                result?;
                false
            }
        };
        if interrupted {
            let _ = relay.complete_briefly(&completion).await;
        }
        progress(SecretListProgress::Completed);

        response
            .secrets
            .into_iter()
            .map(|(name, secret)| Ok((name, secret.try_into()?)))
            .collect::<io::Result<_>>()
            .map_err(RequestError::other)
    }

    /// Uploads a secret for review on the device.
    ///
    /// Success means that the device received and stored the upload proposal.
    /// It doesn't mean that the user accepted the proposal or that the secret
    /// is available for use. Upload mode controls how a later acceptance would
    /// change device state.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. Cancellation before an authenticated response
    /// returns [`RequestError::Interrupted`] through [`SecretUploadError`].
    /// After a response is authenticated, cancellation only shortens the
    /// best-effort completion handoff and the method still returns the device's
    /// result. Pass [`std::future::pending()`] when the operation doesn't need
    /// cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`SecretUploadError`] if local pairing state isn't active, the
    /// relay exchange fails, the device rejects the proposal, the response is
    /// invalid, or the operation is canceled before a response is
    /// authenticated.
    pub async fn upload_secret<P>(
        &self,
        secret: &SecretUpload,
        mode: SecretUploadMode,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<(), SecretUploadError>
    where
        P: FnMut(SecretUploadProgress),
    {
        tokio::pin!(cancellation);
        progress(SecretUploadProgress::Preparing);
        self.maybe_rotate_psk()?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let request_id = Ulid::generate();
        let request_payload = UploadRequest {
            method: Method::SecretUpload,
            mode: mode.into(),
            secret: UploadSecretMessage::from(secret),
        };
        let plaintext = self.encode(&request_payload).map_err(RequestError::other)?;
        let mut session = Session::new(&pairing, &request_id).map_err(RequestError::other)?;
        let request = session
            .seal_request(&plaintext)
            .map_err(RequestError::other)?;
        let mut relay = RelayExchange::authenticated(self, &pairing, &request_id.to_string())?;

        progress(SecretUploadProgress::WaitingForDelivery);
        let response = tokio::select! {
            biased;
            _ = cancellation.as_mut() => {
                return Err(RequestError::Interrupted.into());
            }
            response = relay.request(&request, || {
                progress(SecretUploadProgress::WaitingForResponse);
            }) => response?,
        };
        progress(SecretUploadProgress::Completing);
        let plaintext = session
            .open_response(response)
            .map_err(RequestError::other)?;
        if let Some(rotation_key) = pairing.rotation_key() {
            clear_rotation_key(&pairing_path, rotation_key)?;
        }
        let response: UploadResult =
            match protocol::decode_response(&plaintext).map_err(RequestError::other)? {
                Response::Message(response) => response,
                Response::Error(error) => {
                    if let Some(completion) =
                        protocol::seal_error_completion(self, &mut session, &error)
                    {
                        let _ = relay.complete_briefly(&completion).await;
                    }
                    return Err(RequestError::DeviceRejected {
                        code: error.code,
                        message: error.message,
                    }
                    .into());
                }
            };
        let completion = self.encode(&response).map_err(RequestError::other)?;
        let completion = session
            .seal_completion(&completion)
            .map_err(RequestError::other)?;
        tokio::select! {
            biased;
            _ = cancellation.as_mut() => {},
            _ = relay.complete_briefly(&completion) => {},
        }
        progress(SecretUploadProgress::Completed);

        match response {
            UploadResult::Received => Ok(()),
            UploadResult::Rejected { message } => Err(SecretUploadError::Rejected { message }),
        }
    }
}

#[derive(Serialize)]
struct ListRequest {
    method: Method,
}

#[derive(Serialize)]
struct EmptyMessage {}

#[derive(Deserialize)]
struct ListResponse {
    secrets: BTreeMap<String, ListedSecretMessage>,
}

#[derive(Serialize)]
struct UploadRequest<'a> {
    method: Method,
    mode: SecretUploadModeMessage,
    secret: UploadSecretMessage<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SecretUploadModeMessage {
    Create,
    Replace,
    Update,
}

impl From<SecretUploadMode> for SecretUploadModeMessage {
    fn from(mode: SecretUploadMode) -> Self {
        match mode {
            SecretUploadMode::Create => Self::Create,
            SecretUploadMode::Replace => Self::Replace,
            SecretUploadMode::Update => Self::Update,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum UploadResult {
    Received,
    Rejected { message: String },
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SecretMessage<T> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(flatten)]
    pub(crate) contents: SecretContentsMessage<T>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum SecretContentsMessage<T> {
    Environment { variables: T },
    Ssh { public_key: String },
}

#[derive(Deserialize, Serialize)]
pub(crate) struct EnvironmentVariableMessage {
    pub(crate) value: String,
}

#[derive(Deserialize)]
struct ListedSecretMessage {
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "type")]
    secret_type: String,
    #[serde(flatten)]
    metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UploadSecretMessage<'a> {
    Environment {
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<&'a str>,
        variables: BTreeMap<&'a str, UploadEnvironmentVariableMessage<'a>>,
    },
    Ssh {
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<&'a str>,
        private_key: &'a str,
    },
}

#[derive(Serialize)]
struct UploadEnvironmentVariableMessage<'a> {
    value: &'a str,
}

impl<'a> From<&'a SecretUpload> for UploadSecretMessage<'a> {
    fn from(secret: &'a SecretUpload) -> Self {
        match secret {
            SecretUpload::Environment {
                name,
                description,
                variables,
            } => Self::Environment {
                name,
                description: description.as_deref(),
                variables: variables
                    .iter()
                    .map(|(name, value)| {
                        (name.as_str(), UploadEnvironmentVariableMessage { value })
                    })
                    .collect(),
            },
            SecretUpload::Ssh {
                name,
                description,
                private_key,
            } => Self::Ssh {
                name,
                description: description.as_deref(),
                private_key,
            },
        }
    }
}

impl TryFrom<ListedSecretMessage> for Secret {
    type Error = io::Error;

    fn try_from(mut secret: ListedSecretMessage) -> Result<Self, Self::Error> {
        match secret.secret_type.as_str() {
            "environment" => {
                let variables = secret.metadata.remove("variables").ok_or_else(|| {
                    io::Error::other("environment secret metadata has no variables")
                })?;
                let mut variables: Vec<String> =
                    serde_json::from_value(variables).map_err(io::Error::other)?;
                variables.sort();
                variables.dedup();
                Ok(Self::Environment {
                    description: secret.description,
                    variables,
                })
            }
            "ssh" => Ok(Self::Ssh {
                description: secret.description,
                public_key: serde_json::from_value(
                    secret
                        .metadata
                        .remove("public_key")
                        .ok_or_else(|| io::Error::other("SSH secret metadata has no public key"))?,
                )
                .map_err(io::Error::other)?,
            }),
            _ => Ok(Self::Unknown {
                description: secret.description,
                secret_type: secret.secret_type,
            }),
        }
    }
}
