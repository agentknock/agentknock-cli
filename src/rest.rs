use std::env;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::crypto::{Completion, Request, Response};

const RELAY_URL: &str = "https://relay.agentknock.dev/";
const TEST_RELAY_URL_ENV: &str = "AGENTKNOCK_TEST_RELAY_URL";

pub(crate) struct Relay {
    client: reqwest::Client,
    message_url: String,
}

impl Relay {
    pub(crate) fn new(route_id: &str, request_id: &str) -> Result<Self, Error> {
        let relay_url = match env::var(TEST_RELAY_URL_ENV) {
            Ok(relay_url) => relay_url,
            Err(env::VarError::NotPresent) => RELAY_URL.to_owned(),
            Err(env::VarError::NotUnicode(_)) => return Err(Error::InvalidTestRelayUrl),
        };
        let message_url = format!(
            "{}/v1/route/{route_id}/msg/{request_id}",
            relay_url.trim_end_matches('/'),
        );

        Ok(Self {
            client: reqwest::Client::new(),
            message_url,
        })
    }

    pub(crate) async fn request(&self, request: &Request) -> Result<Option<Response>, Error> {
        let response: RequestResponse = self
            .post(
                &format!("{}/request", self.message_url),
                &RequestMessage { request },
            )
            .await?;
        let _state = response.state;

        Ok(response.response)
    }

    pub(crate) async fn complete(
        &self,
        request: &Request,
        completion: Completion,
    ) -> Result<(), Error> {
        let response: CompletionResponse = self
            .post(
                &format!("{}/complete", self.message_url),
                &CompletionMessage {
                    request,
                    completion,
                },
            )
            .await?;
        let _state = response.state;

        Ok(())
    }

    async fn post<B, R>(&self, url: &str, body: &B) -> Result<R, reqwest::Error>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        self.client
            .post(url)
            .json(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
}

#[derive(Serialize)]
struct RequestMessage<'a> {
    request: &'a Request,
}

#[derive(Deserialize)]
struct RequestResponse {
    state: MessageState,
    response: Option<Response>,
}

#[derive(Serialize)]
struct CompletionMessage<'a> {
    request: &'a Request,
    completion: Completion,
}

#[derive(Deserialize)]
struct CompletionResponse {
    state: MessageState,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MessageState {
    RequestPending,
    RequestDelivered,
    ResponsePending,
    ResponseDelivered,
    CompletionPending,
    CompletionDelivered,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("relay request failed: {0}")]
    Relay(#[from] reqwest::Error),

    #[error("{TEST_RELAY_URL_ENV} is not valid UTF-8")]
    InvalidTestRelayUrl,
}
