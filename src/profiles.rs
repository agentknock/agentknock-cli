use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    ProtocolError, RequestError,
    config::{ConfigurationError, clear_rotation_key, read_pairing},
    crypto::Session,
    pairing::{RotationError, maybe_rotate_psk},
    protocol::Method,
    websocket::RelayExchange,
};

#[derive(Debug, Eq, PartialEq)]
pub enum Profile {
    Environment {
        description: Option<String>,
        variables: Vec<String>,
    },
}

pub type Profiles = BTreeMap<String, Profile>;

#[derive(Debug, Eq, PartialEq)]
pub struct EnvironmentProfile {
    pub name: String,
    pub description: Option<String>,
    pub variables: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileUploadMode {
    Create,
    Replace,
    Update,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileListProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileUploadProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

#[derive(Debug, Error)]
pub enum ProfileUploadError {
    #[error(transparent)]
    Request(#[from] RequestError),

    #[error("the device rejected the profile proposal: {message}")]
    Rejected { message: String },
}

impl From<ConfigurationError> for ProfileUploadError {
    fn from(error: ConfigurationError) -> Self {
        Self::Request(error.into())
    }
}

impl From<ProtocolError> for ProfileUploadError {
    fn from(error: ProtocolError) -> Self {
        Self::Request(error.into())
    }
}

impl From<crate::websocket::Error> for ProfileUploadError {
    fn from(error: crate::websocket::Error) -> Self {
        Self::Request(error.into())
    }
}

pub async fn list_profiles<P>(mut progress: P) -> Result<Profiles, RequestError>
where
    P: FnMut(ProfileListProgress),
{
    progress(ProfileListProgress::Preparing);
    prepare_request()?;
    let pairing = read_pairing()?;
    let request_id = Ulid::generate();
    let plaintext = crate::protocol::encode(&ListRequest {
        method: Method::ProfileList,
    })
    .map_err(ProtocolError::from)?;
    let mut session = Session::new(&pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let mut relay = RelayExchange::authenticated(&pairing, &request_id.to_string())?;

    progress(ProfileListProgress::WaitingForDelivery);
    let response = relay
        .request(&request, || {
            progress(ProfileListProgress::WaitingForResponse);
        })
        .await?;
    progress(ProfileListProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(ProtocolError::from)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(rotation_key)?;
    }
    let response: ListResponse = serde_json::from_slice(&plaintext).map_err(ProtocolError::from)?;
    let plaintext = crate::protocol::encode(&EmptyMessage {}).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;
    relay.complete(&completion).await?;
    progress(ProfileListProgress::Completed);

    Ok(response
        .profiles
        .into_iter()
        .map(|(name, profile)| (name, profile.into()))
        .collect())
}

pub async fn upload_profile<P>(
    profile: &EnvironmentProfile,
    mode: ProfileUploadMode,
    mut progress: P,
) -> Result<(), ProfileUploadError>
where
    P: FnMut(ProfileUploadProgress),
{
    progress(ProfileUploadProgress::Preparing);
    prepare_request()?;
    let pairing = read_pairing()?;
    let request_id = Ulid::generate();
    let request_payload = UploadRequest {
        method: Method::ProfileUpload,
        mode: mode.into(),
        profile: NamedProfileMessage::from(profile),
    };
    let plaintext = crate::protocol::encode(&request_payload).map_err(ProtocolError::from)?;
    let mut session = Session::new(&pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let mut relay = RelayExchange::authenticated(&pairing, &request_id.to_string())?;

    progress(ProfileUploadProgress::WaitingForDelivery);
    let response = relay
        .request(&request, || {
            progress(ProfileUploadProgress::WaitingForResponse);
        })
        .await?;
    progress(ProfileUploadProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(ProtocolError::from)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(rotation_key)?;
    }
    let response: UploadResult = serde_json::from_slice(&plaintext).map_err(ProtocolError::from)?;
    let completion = crate::protocol::encode(&response).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&completion)
        .map_err(ProtocolError::from)?;
    let _ = relay.complete_briefly(&completion).await;
    progress(ProfileUploadProgress::Completed);

    match response {
        UploadResult::Received => Ok(()),
        UploadResult::Rejected { message } => Err(ProfileUploadError::Rejected { message }),
    }
}

fn prepare_request() -> Result<(), RequestError> {
    maybe_rotate_psk().map_err(|error| match error {
        RotationError::Configuration(error) => RequestError::Configuration(error),
        RotationError::Protocol(error) => RequestError::Protocol(error),
    })?;
    Ok(())
}

#[derive(Serialize)]
struct ListRequest {
    method: Method,
}

#[derive(Serialize)]
struct EmptyMessage {}

#[derive(Deserialize)]
struct ListResponse {
    profiles: BTreeMap<String, ProfileMessage<Vec<String>>>,
}

#[derive(Serialize)]
struct UploadRequest {
    method: Method,
    mode: ProfileUploadModeMessage,
    profile: NamedProfileMessage<BTreeMap<String, SecretValueMessage>>,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ProfileUploadModeMessage {
    Create,
    Replace,
    Update,
}

impl From<ProfileUploadMode> for ProfileUploadModeMessage {
    fn from(mode: ProfileUploadMode) -> Self {
        match mode {
            ProfileUploadMode::Create => Self::Create,
            ProfileUploadMode::Replace => Self::Replace,
            ProfileUploadMode::Update => Self::Update,
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
pub(crate) struct ProfileMessage<T> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(flatten)]
    pub(crate) contents: ProfileContentsMessage<T>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ProfileContentsMessage<T> {
    Environment { variables: T },
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SecretValueMessage {
    pub(crate) value: String,
}

#[derive(Serialize)]
struct NamedProfileMessage<T> {
    name: String,
    #[serde(flatten)]
    profile: ProfileMessage<T>,
}

impl From<&EnvironmentProfile> for NamedProfileMessage<BTreeMap<String, SecretValueMessage>> {
    fn from(profile: &EnvironmentProfile) -> Self {
        Self {
            name: profile.name.clone(),
            profile: ProfileMessage {
                description: profile.description.clone(),
                contents: ProfileContentsMessage::Environment {
                    variables: profile
                        .variables
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.clone(),
                                SecretValueMessage {
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

impl From<ProfileMessage<Vec<String>>> for Profile {
    fn from(profile: ProfileMessage<Vec<String>>) -> Self {
        match profile.contents {
            ProfileContentsMessage::Environment { mut variables } => {
                variables.sort();
                variables.dedup();
                Self::Environment {
                    description: profile.description,
                    variables,
                }
            }
        }
    }
}
