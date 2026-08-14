use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    ProtocolError, RequestError,
    config::{clear_rotation_key, read_pairing},
    crypto::Session,
    pairing::{RotationError, maybe_rotate_psk},
    rest::{Relay, RequestState},
};

#[derive(Debug, Eq, PartialEq)]
pub struct Profile {
    pub description: String,
    pub environment: BTreeMap<String, ValueSource>,
}

pub type Profiles = BTreeMap<String, Profile>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueSource {
    Stored,
    Issued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileListProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

pub async fn list_profiles() -> Result<Profiles, RequestError> {
    list_profiles_with_progress(|_| {}).await
}

pub async fn list_profiles_with_progress<P>(mut progress: P) -> Result<Profiles, RequestError>
where
    P: FnMut(ProfileListProgress),
{
    progress(ProfileListProgress::Preparing);
    maybe_rotate_psk().map_err(|error| match error {
        RotationError::Configuration(error) => RequestError::Configuration(error),
        RotationError::Protocol(error) => RequestError::Protocol(error),
    })?;
    let pairing = read_pairing()?;
    let request_id = Ulid::generate();
    let plaintext =
        crate::protocol::encode(&ListRequest { method: "List" }).map_err(ProtocolError::from)?;
    let mut session = Session::new(&pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let relay = Relay::new(&pairing.route_id(), &request_id.to_string())?;

    progress(ProfileListProgress::WaitingForDelivery);
    let response = relay
        .request_with_state(&request, |state| {
            progress(match state {
                RequestState::Pending => ProfileListProgress::WaitingForDelivery,
                RequestState::Delivered => ProfileListProgress::WaitingForResponse,
            });
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
    relay.complete(&request, &completion).await?;
    progress(ProfileListProgress::Completed);

    Ok(response
        .profiles
        .into_iter()
        .map(|(name, profile)| (name, profile.into()))
        .collect())
}

impl fmt::Display for ValueSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stored => "stored",
            Self::Issued => "issued on request",
        })
    }
}

#[derive(Serialize)]
struct ListRequest {
    method: &'static str,
}

#[derive(Serialize)]
struct EmptyMessage {}

#[derive(Deserialize)]
struct ListResponse {
    profiles: BTreeMap<String, ProfileMessage>,
}

#[derive(Deserialize)]
struct ProfileMessage {
    description: String,
    environment: BTreeMap<String, ValueSourceMessage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ValueSourceMessage {
    Stored,
    Issued,
}

impl From<ProfileMessage> for Profile {
    fn from(profile: ProfileMessage) -> Self {
        Self {
            description: profile.description,
            environment: profile
                .environment
                .into_iter()
                .map(|(name, source)| (name, source.into()))
                .collect(),
        }
    }
}

impl From<ValueSourceMessage> for ValueSource {
    fn from(source: ValueSourceMessage) -> Self {
        match source {
            ValueSourceMessage::Stored => Self::Stored,
            ValueSourceMessage::Issued => Self::Issued,
        }
    }
}
