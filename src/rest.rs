use std::{env, time::Duration};

use reqwest::{StatusCode, header::RETRY_AFTER};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::time::{Instant, sleep};

const RELAY_URL: &str = "https://relay.agentknock.dev/";
const TEST_RELAY_URL_ENV: &str = "AGENTKNOCK_TEST_RELAY_URL";
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
const RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_CONSECUTIVE_FAILURE_DURATION: Duration = Duration::from_secs(2 * 60);
const MAX_CONSECUTIVE_FAILURES: usize = 10;

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
            client: reqwest::Client::builder()
                .timeout(HTTP_REQUEST_TIMEOUT)
                .build()?,
            message_url,
        })
    }

    pub(crate) async fn request<B, R>(&self, request: &B) -> Result<R, Error>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = format!("{}/request", self.message_url);
        let body = RequestMessage { request };

        loop {
            let response: RequestResponse<R> = self.post(&url, &body).await?;
            match response.state {
                MessageState::RequestPending | MessageState::RequestDelivered => {}
                MessageState::ResponsePending | MessageState::ResponseDelivered => {
                    return response.response.ok_or(Error::MissingResponse);
                }
                state => {
                    return Err(Error::UnexpectedState {
                        operation: "request",
                        state: state.name(),
                    });
                }
            }
        }
    }

    pub(crate) async fn complete<B, C>(&self, request: &B, completion: &C) -> Result<(), Error>
    where
        B: Serialize + ?Sized,
        C: Serialize + ?Sized,
    {
        let response: CompletionResponse = self
            .post(
                &format!("{}/complete", self.message_url),
                &CompletionMessage {
                    request,
                    completion,
                },
            )
            .await?;

        match response.state {
            MessageState::CompletionPending | MessageState::CompletionDelivered => Ok(()),
            state => Err(Error::UnexpectedState {
                operation: "completion",
                state: state.name(),
            }),
        }
    }

    async fn post<B, R>(&self, url: &str, body: &B) -> Result<R, Error>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let mut failures = 0;
        let failure_deadline = Instant::now() + MAX_CONSECUTIVE_FAILURE_DURATION;
        loop {
            let timeout = HTTP_REQUEST_TIMEOUT
                .min(failure_deadline.saturating_duration_since(Instant::now()));
            if timeout.is_zero() {
                return Err(retries_exhausted(failures));
            }
            let response = match self
                .client
                .post(url)
                .timeout(timeout)
                .json(body)
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    retry_failure(&mut failures, failure_deadline, RETRY_DELAY).await?;
                    continue;
                }
            };
            let status = response.status();

            if status.is_server_error() {
                let delay = retry_after(&response).unwrap_or(RETRY_DELAY);
                retry_failure(&mut failures, failure_deadline, delay).await?;
                continue;
            }
            if status.is_client_error() {
                return Err(Error::Relay(
                    response
                        .error_for_status()
                        .expect_err("client error status must produce an error"),
                ));
            }
            if status != StatusCode::OK {
                return Err(Error::UnexpectedStatus(status.as_u16()));
            }

            let bytes = match response.bytes().await {
                Ok(bytes) => bytes,
                Err(_) => {
                    retry_failure(&mut failures, failure_deadline, RETRY_DELAY).await?;
                    continue;
                }
            };
            return serde_json::from_slice(&bytes).map_err(Error::InvalidJson);
        }
    }
}

async fn retry_failure(
    failures: &mut usize,
    deadline: Instant,
    delay: Duration,
) -> Result<(), Error> {
    *failures += 1;
    if *failures >= MAX_CONSECUTIVE_FAILURES {
        return Err(retries_exhausted(*failures));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(retries_exhausted(*failures));
    }
    sleep(delay.min(remaining)).await;
    if Instant::now() >= deadline {
        return Err(retries_exhausted(*failures));
    }
    Ok(())
}

fn retries_exhausted(failures: usize) -> Error {
    Error::RetriesExhausted { failures }
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after(value)
}

fn parse_retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.parse() {
        return Some(Duration::from_secs(seconds));
    }

    Some(
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(std::time::SystemTime::now())
            .unwrap_or_default(),
    )
}

#[derive(Serialize)]
struct RequestMessage<'a, B: ?Sized> {
    request: &'a B,
}

#[derive(Deserialize)]
struct RequestResponse<R> {
    state: MessageState,
    response: Option<R>,
}

#[derive(Serialize)]
struct CompletionMessage<'a, B: ?Sized, C: ?Sized> {
    request: &'a B,
    completion: &'a C,
}

#[derive(Deserialize)]
struct CompletionResponse {
    state: MessageState,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MessageState {
    RequestPending,
    RequestDelivered,
    ResponsePending,
    ResponseDelivered,
    CompletionPending,
    CompletionDelivered,
}

impl MessageState {
    fn name(self) -> &'static str {
        match self {
            Self::RequestPending => "REQUEST_PENDING",
            Self::RequestDelivered => "REQUEST_DELIVERED",
            Self::ResponsePending => "RESPONSE_PENDING",
            Self::ResponseDelivered => "RESPONSE_DELIVERED",
            Self::CompletionPending => "COMPLETION_PENDING",
            Self::CompletionDelivered => "COMPLETION_DELIVERED",
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("relay request failed: {0}")]
    Relay(#[from] reqwest::Error),

    #[error("relay returned invalid JSON: {0}")]
    InvalidJson(serde_json::Error),

    #[error("relay returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),

    #[error("relay returned {state} for {operation}")]
    UnexpectedState {
        operation: &'static str,
        state: &'static str,
    },

    #[error("relay response state did not include a response message")]
    MissingResponse,

    #[error("relay remained unavailable after {failures} consecutive failures")]
    RetriesExhausted { failures: usize },

    #[error("{TEST_RELAY_URL_ENV} is not valid UTF-8")]
    InvalidTestRelayUrl,
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn parses_retry_after_seconds() {
        assert_eq!(parse_retry_after("42"), Some(Duration::from_secs(42)));
    }

    #[test]
    fn treats_past_retry_after_date_as_immediate() {
        assert_eq!(
            parse_retry_after(&httpdate::fmt_http_date(UNIX_EPOCH)),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn ignores_invalid_retry_after() {
        assert_eq!(parse_retry_after("eventually"), None);
    }
}
