use std::{collections::BTreeMap, future::Future};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    Client, RequestError,
    config::{ConfigurationError, clear_rotation_key, read_pairing_from},
    crypto::Session,
    pairing::RotationError,
    protocol::Method,
    websocket::RelayExchange,
};

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Secret {
    #[non_exhaustive]
    Environment {
        description: Option<String>,
        variables: Vec<String>,
    },
}

pub type Secrets = BTreeMap<String, Secret>;

#[derive(Debug, Eq, PartialEq)]
pub struct EnvironmentSecret {
    pub name: String,
    pub description: Option<String>,
    pub variables: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretUploadMode {
    Create,
    Replace,
    Update,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretListProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretUploadProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretUploadError {
    #[error(transparent)]
    Request(#[from] RequestError),

    #[error("the device rejected the secret upload: {message}")]
    Rejected { message: String },
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
        self.prepare_request()?;
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
        let mut relay = RelayExchange::authenticated(&pairing, &request_id.to_string())?;

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
            serde_json::from_slice(&plaintext).map_err(RequestError::other)?;
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

        Ok(response
            .secrets
            .into_iter()
            .map(|(name, secret)| (name, secret.into()))
            .collect())
    }

    pub async fn upload_secret<P>(
        &self,
        secret: &EnvironmentSecret,
        mode: SecretUploadMode,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<(), SecretUploadError>
    where
        P: FnMut(SecretUploadProgress),
    {
        tokio::pin!(cancellation);
        progress(SecretUploadProgress::Preparing);
        self.prepare_request()?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let request_id = Ulid::generate();
        let request_payload = UploadRequest {
            method: Method::SecretUpload,
            mode: mode.into(),
            secret: NamedSecretMessage::from(secret),
        };
        let plaintext = self.encode(&request_payload).map_err(RequestError::other)?;
        let mut session = Session::new(&pairing, &request_id).map_err(RequestError::other)?;
        let request = session
            .seal_request(&plaintext)
            .map_err(RequestError::other)?;
        let mut relay = RelayExchange::authenticated(&pairing, &request_id.to_string())?;

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
            serde_json::from_slice(&plaintext).map_err(RequestError::other)?;
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

    fn prepare_request(&self) -> Result<(), RequestError> {
        self.maybe_rotate_psk().map_err(|error| match error {
            RotationError::Configuration(error) => RequestError::Configuration(error),
            RotationError::Other(error) => RequestError::Other(error),
        })?;
        Ok(())
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
    secrets: BTreeMap<String, SecretMessage<Vec<String>>>,
}

#[derive(Serialize)]
struct UploadRequest {
    method: Method,
    mode: SecretUploadModeMessage,
    secret: NamedSecretMessage<BTreeMap<String, EnvironmentVariableMessage>>,
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
}

#[derive(Deserialize, Serialize)]
pub(crate) struct EnvironmentVariableMessage {
    pub(crate) value: String,
}

#[derive(Serialize)]
struct NamedSecretMessage<T> {
    name: String,
    #[serde(flatten)]
    secret: SecretMessage<T>,
}

impl From<&EnvironmentSecret> for NamedSecretMessage<BTreeMap<String, EnvironmentVariableMessage>> {
    fn from(secret: &EnvironmentSecret) -> Self {
        Self {
            name: secret.name.clone(),
            secret: SecretMessage {
                description: secret.description.clone(),
                contents: SecretContentsMessage::Environment {
                    variables: secret
                        .variables
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.clone(),
                                EnvironmentVariableMessage {
                                    value: value.clone(),
                                },
                            )
                        })
                        .collect(),
                },
            },
        }
    }
}

impl From<SecretMessage<Vec<String>>> for Secret {
    fn from(secret: SecretMessage<Vec<String>>) -> Self {
        match secret.contents {
            SecretContentsMessage::Environment { mut variables } => {
                variables.sort();
                variables.dedup();
                Self::Environment {
                    description: secret.description,
                    variables,
                }
            }
        }
    }
}
