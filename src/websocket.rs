use std::time::Duration;

#[cfg(all(feature = "integration-tests", debug_assertions))]
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use futures_util::{SinkExt as _, StreamExt as _};
use http::{
    HeaderValue, Uri,
    header::{AUTHORIZATION, USER_AGENT},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;
use tokio::time::Instant;
use tokio_websockets::{
    ClientBuilder, Connector, Limits, MaybeTlsStream, Message, WebSocketStream, upgrade,
};

use crate::{ApplicationInfo, Client, config::Pairing, proxy};

const RELAY_URL: &str = "wss://relay.agentknock.dev";
const LIBRARY_PRODUCT_NAME: &str = env!("CARGO_PKG_NAME");
const LIBRARY_PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(all(feature = "integration-tests", debug_assertions))]
const TEST_RELAY_URL_ENV: &str = "AGENTKNOCK_TEST_RELAY_URL";
const MAXIMUM_FRAME_SIZE: usize = 256 * 1024;
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PONG_TIMEOUT: Duration = Duration::from_secs(10);
const BRIEF_COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);
const NORMAL_RETRY_POLICY: RetryPolicy = RetryPolicy {
    connection_timeout: Duration::from_secs(15),
    retry_delay: Duration::from_secs(1),
    failure_timeout: Duration::from_secs(2 * 60),
    maximum_failures: 10,
};
const BRIEF_RETRY_POLICY: RetryPolicy = RetryPolicy {
    connection_timeout: Duration::from_secs(2),
    retry_delay: Duration::from_millis(250),
    failure_timeout: BRIEF_COMPLETION_TIMEOUT,
    maximum_failures: 2,
};

type Socket = WebSocketStream<MaybeTlsStream<proxy::Stream>>;

#[derive(Clone, Copy)]
struct RetryPolicy {
    connection_timeout: Duration,
    retry_delay: Duration,
    failure_timeout: Duration,
    maximum_failures: usize,
}

pub(crate) struct RelayExchange {
    uri: Uri,
    proxy: proxy::Config,
    connection_kind: ConnectionKind,
    authorization: HeaderValue,
    user_agent: HeaderValue,
    client_id: String,
    request_id: String,
    socket: Option<Socket>,
    request: Option<OutgoingMessage>,
    response: Option<Value>,
    completion: Option<OutgoingMessage>,
}

#[derive(Clone, Copy)]
enum ConnectionKind {
    Pairing,
    Client,
}

fn user_agent(application: &ApplicationInfo) -> HeaderValue {
    let library = product(LIBRARY_PRODUCT_NAME, LIBRARY_PRODUCT_VERSION)
        .expect("the Cargo package name and version are valid HTTP product tokens");
    let value = match product(application.name(), application.version()) {
        Some(application) if application != library => format!("{application} {library}"),
        _ => library,
    };
    HeaderValue::from_str(&value).expect("validated HTTP product tokens form a header value")
}

fn product(name: &str, version: &str) -> Option<String> {
    (is_product_token(name) && is_product_token(version)).then(|| format!("{name}/{version}"))
}

fn is_product_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

struct OutgoingMessage {
    encoded: String,
    sent: bool,
    acknowledged: bool,
}

impl RelayExchange {
    pub(crate) fn pairing(
        client: &Client,
        address_id: &str,
        client_id: &str,
        client_token: &str,
    ) -> Result<Self, Error> {
        let path = format!("/v1/address/{address_id}/request/{client_id}");
        Self::new(
            client,
            path,
            ConnectionKind::Pairing,
            client_id,
            client_id,
            client_token,
        )
    }

    pub(crate) fn authenticated(
        client: &Client,
        pairing: &Pairing,
        request_id: &str,
    ) -> Result<Self, Error> {
        let path = format!(
            "/v1/device/{}/client/{}",
            pairing.device_id(),
            pairing.client_id(),
        );
        Self::new(
            client,
            path,
            ConnectionKind::Client,
            &pairing.client_id(),
            request_id,
            pairing.client_token(),
        )
    }

    fn new(
        client: &Client,
        path: String,
        connection_kind: ConnectionKind,
        client_id: &str,
        request_id: &str,
        client_token: &str,
    ) -> Result<Self, Error> {
        let relay_url = relay_url()?;
        let authorization = HeaderValue::from_str(&format!("Bearer {client_token}"))
            .map_err(|_| Error::InvalidClientToken)?;
        let user_agent = user_agent(client.application_info());

        let url = format!("{}{path}", relay_url.trim_end_matches('/'));
        let uri = url
            .parse::<Uri>()
            .map_err(|error| Error::InvalidRelayUrl(error.to_string()))?;
        let proxy = proxy::Config::from_env(&uri)?;

        Ok(Self {
            uri,
            proxy,
            connection_kind,
            authorization,
            user_agent,
            client_id: client_id.to_owned(),
            request_id: request_id.to_owned(),
            socket: None,
            request: None,
            response: None,
            completion: None,
        })
    }

    pub(crate) fn request_was_sent(&self) -> bool {
        self.request.as_ref().is_some_and(|request| request.sent)
    }

    pub(crate) async fn request<B, R, F>(
        &mut self,
        request: &B,
        mut delivered: F,
    ) -> Result<R, Error>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
        F: FnMut(),
    {
        if self.request.is_some() {
            return Err(Error::Protocol("request was already started".into()));
        }
        self.request = Some(OutgoingMessage::new(
            self.message(MessageKind::Request, request)?,
        )?);

        let mut retry = RetryState::new(NORMAL_RETRY_POLICY);
        loop {
            let reconnected = self.ensure_connected(&mut retry).await?;
            if reconnected {
                if self.request_message().acknowledged {
                    if !self.send_resume(&mut retry).await? {
                        continue;
                    }
                } else if !self.send_request(&mut retry).await? {
                    continue;
                }
            }

            let incoming = match self.receive(&mut retry).await? {
                Some(incoming) => incoming,
                None => continue,
            };
            match incoming {
                IncomingFrame::Ack {
                    kind: MessageKind::Request,
                    ..
                } => {
                    self.request_mut().acknowledged = true;
                }
                IncomingFrame::Receipt {
                    kind: MessageKind::Request,
                    ..
                } => {
                    self.request_mut().acknowledged = true;
                    delivered();
                }
                IncomingFrame::Message {
                    kind: MessageKind::Response,
                    payload,
                    ..
                } => {
                    self.request_mut().acknowledged = true;
                    delivered();
                    if self.response.is_none() {
                        self.response = Some(payload);
                    }
                    if self.send_ack(MessageKind::Response, &mut retry).await? {
                        return self.decode_response();
                    }
                }
                IncomingFrame::State {
                    exchange,
                    request,
                    response,
                    ..
                } => {
                    self.apply_request_state(request, &mut delivered);
                    if response == MessageState::Delivered {
                        return self.decode_response();
                    }
                    if matches!(exchange, ExchangeState::Settled | ExchangeState::Expired) {
                        return Err(Error::MissingResponse);
                    }
                }
                _ => {}
            }
        }
    }

    pub(crate) async fn complete<C>(&mut self, completion: &C) -> Result<(), Error>
    where
        C: Serialize + ?Sized,
    {
        self.complete_with_policy(completion, NORMAL_RETRY_POLICY)
            .await
    }

    pub(crate) async fn complete_briefly<C>(&mut self, completion: &C) -> Result<(), Error>
    where
        C: Serialize + ?Sized,
    {
        tokio::time::timeout(
            BRIEF_COMPLETION_TIMEOUT,
            self.complete_with_policy(completion, BRIEF_RETRY_POLICY),
        )
        .await
        .map_err(|_| Error::CompletionTimedOut)?
    }

    async fn complete_with_policy<C>(
        &mut self,
        completion: &C,
        policy: RetryPolicy,
    ) -> Result<(), Error>
    where
        C: Serialize + ?Sized,
    {
        if self.request.is_none() {
            return Err(Error::Protocol(
                "completion can't be sent before a request".into(),
            ));
        }
        if self.completion.is_none() {
            self.completion = Some(OutgoingMessage::new(
                self.message(MessageKind::Completion, completion)?,
            )?);
        }

        let mut retry = RetryState::new(policy);
        loop {
            let reconnected = self.ensure_connected(&mut retry).await?;
            if reconnected {
                if self.request_message().acknowledged {
                    if !self.send_resume(&mut retry).await? {
                        continue;
                    }
                } else if !self.send_request(&mut retry).await? {
                    continue;
                }
            }

            if !self.request_message().acknowledged {
                let Some(incoming) = self.receive(&mut retry).await? else {
                    continue;
                };
                match incoming {
                    IncomingFrame::Ack {
                        kind: MessageKind::Request,
                        ..
                    } => {
                        self.request_mut().acknowledged = true;
                    }
                    IncomingFrame::Receipt {
                        kind: MessageKind::Request,
                        ..
                    } => {
                        self.request_mut().acknowledged = true;
                    }
                    IncomingFrame::Message {
                        kind: MessageKind::Response,
                        payload,
                        ..
                    } => {
                        self.request_mut().acknowledged = true;
                        self.response.get_or_insert(payload);
                        if !self.send_ack(MessageKind::Response, &mut retry).await? {
                            continue;
                        }
                    }
                    _ => {}
                }
                continue;
            }

            if (reconnected || !self.completion().sent) && !self.send_completion(&mut retry).await?
            {
                continue;
            }

            let Some(incoming) = self.receive(&mut retry).await? else {
                continue;
            };
            match incoming {
                IncomingFrame::Ack {
                    kind: MessageKind::Completion,
                    ..
                } => {
                    return Ok(());
                }
                IncomingFrame::Message {
                    kind: MessageKind::Response,
                    payload,
                    ..
                } => {
                    self.response.get_or_insert(payload);
                    if !self.send_ack(MessageKind::Response, &mut retry).await? {
                        continue;
                    }
                }
                IncomingFrame::State {
                    completion:
                        MessageState::Accepted | MessageState::Delivered | MessageState::Discarded,
                    ..
                } => {
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    fn message<B>(&self, kind: MessageKind, payload: &B) -> Result<String, Error>
    where
        B: Serialize + ?Sized,
    {
        serde_json::to_string(&OutgoingFrame::Message {
            client_id: &self.client_id,
            request_id: &self.request_id,
            kind,
            payload,
        })
        .map_err(Error::InvalidJson)
    }

    async fn ensure_connected(&mut self, retry: &mut RetryState) -> Result<bool, Error> {
        if self.socket.is_some() {
            return Ok(false);
        }
        ensure_rustls_provider();
        loop {
            let builder = ClientBuilder::from_uri(self.uri.clone())
                .limits(Limits::default().max_payload_len(Some(MAXIMUM_FRAME_SIZE)))
                .add_header(AUTHORIZATION, self.authorization.clone())?
                .add_header(USER_AGENT, self.user_agent.clone())?;
            let connect = async {
                let stream = self.proxy.connect(&self.uri).await?;
                let host = self.uri.host().ok_or(proxy::ConnectionError::MissingHost)?;
                let connector = match self.uri.scheme_str() {
                    Some("wss") => Connector::new()?,
                    Some("ws") => Connector::Plain,
                    _ => return Err(proxy::ConnectionError::UnsupportedDestination),
                };
                let stream = connector.wrap(host, stream).await?;
                builder
                    .connect_on(stream)
                    .await
                    .map_err(proxy::ConnectionError::from)
            };
            match tokio::time::timeout(retry.policy.connection_timeout, connect).await {
                Ok(Ok((socket, _))) => {
                    self.socket = Some(socket);
                    return Ok(true);
                }
                Ok(Err(proxy::ConnectionError::WebSocket(tokio_websockets::Error::Upgrade(
                    upgrade::Error::DidNotSwitchProtocols(status),
                )))) if status == 403 && matches!(self.connection_kind, ConnectionKind::Client) => {
                    return Err(Error::ClientInactive {
                        code: status,
                        reason: "WebSocket setup returned HTTP status 403".into(),
                    });
                }
                Ok(Err(proxy::ConnectionError::WebSocket(tokio_websockets::Error::Upgrade(
                    upgrade::Error::DidNotSwitchProtocols(status),
                )))) if status < 500 => return Err(Error::UnexpectedStatus(status)),
                Ok(Err(error @ proxy::ConnectionError::Rejected(status)))
                    if (500..600).contains(&status) =>
                {
                    retry.failed_with(error.to_string()).await?;
                }
                Ok(Err(proxy::ConnectionError::Rejected(status))) => {
                    return Err(Error::ProxyRejected(status));
                }
                Ok(Err(error)) => retry.failed_with(error.to_string()).await?,
                Err(_) => retry.failed_with("connection timed out".into()).await?,
            }
        }
    }

    async fn send_request(&mut self, retry: &mut RetryState) -> Result<bool, Error> {
        let encoded = self.request_message().encoded.clone();
        let sent = self.send_text(encoded, retry).await?;
        self.request_mut().sent |= sent;
        Ok(sent)
    }

    async fn send_completion(&mut self, retry: &mut RetryState) -> Result<bool, Error> {
        let encoded = self.completion().encoded.clone();
        let sent = self.send_text(encoded, retry).await?;
        self.completion_mut().sent |= sent;
        Ok(sent)
    }

    async fn send_resume(&mut self, retry: &mut RetryState) -> Result<bool, Error> {
        let frame: OutgoingFrame<'_, ()> = OutgoingFrame::Resume {
            client_id: &self.client_id,
            request_id: &self.request_id,
        };
        let encoded = serde_json::to_string(&frame).map_err(Error::InvalidJson)?;
        self.send_text(encoded, retry).await
    }

    async fn send_ack(&mut self, kind: MessageKind, retry: &mut RetryState) -> Result<bool, Error> {
        let frame: OutgoingFrame<'_, ()> = OutgoingFrame::Ack {
            client_id: &self.client_id,
            request_id: &self.request_id,
            kind,
        };
        let encoded = serde_json::to_string(&frame).map_err(Error::InvalidJson)?;
        self.send_text(encoded, retry).await
    }

    async fn send_text(&mut self, encoded: String, retry: &mut RetryState) -> Result<bool, Error> {
        if encoded.len() > MAXIMUM_FRAME_SIZE {
            return Err(Error::FrameTooLarge(encoded.len()));
        }
        let result = self
            .socket
            .as_mut()
            .expect("socket is connected")
            .send(Message::text(encoded))
            .await;
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                self.socket = None;
                retry.failed_with(error.to_string()).await?;
                Ok(false)
            }
        }
    }

    async fn receive(&mut self, retry: &mut RetryState) -> Result<Option<IncomingFrame>, Error> {
        loop {
            let message = match tokio::time::timeout(
                PING_INTERVAL,
                self.socket.as_mut().expect("socket is connected").next(),
            )
            .await
            {
                Ok(message) => message,
                Err(_) => {
                    if let Err(error) = self
                        .socket
                        .as_mut()
                        .expect("socket is connected")
                        .send(Message::ping(Vec::new()))
                        .await
                    {
                        self.socket = None;
                        retry.failed_with(error.to_string()).await?;
                        return Ok(None);
                    }
                    match tokio::time::timeout(
                        PONG_TIMEOUT,
                        self.socket.as_mut().expect("socket is connected").next(),
                    )
                    .await
                    {
                        Ok(message) => message,
                        Err(_) => {
                            self.socket = None;
                            retry
                                .failed_with("relay didn't answer a WebSocket ping".into())
                                .await?;
                            return Ok(None);
                        }
                    }
                }
            };

            let Some(message) = message else {
                self.socket = None;
                retry
                    .failed_with("relay closed the WebSocket".into())
                    .await?;
                return Ok(None);
            };
            let message = match message {
                Ok(message) => message,
                Err(error) => {
                    self.socket = None;
                    retry.failed_with(error.to_string()).await?;
                    return Ok(None);
                }
            };
            if let Some((code, reason)) = message.as_close() {
                let code = u16::from(code);
                self.socket = None;
                if matches!(code, 4002 | 4003) {
                    return Err(Error::ClientInactive {
                        code,
                        reason: reason.to_owned(),
                    });
                }
                retry
                    .failed_with(format!("relay closed the WebSocket ({code} {reason})"))
                    .await?;
                return Ok(None);
            }
            if message.is_ping() {
                let payload = message.into_payload();
                if let Err(error) = self
                    .socket
                    .as_mut()
                    .expect("socket is connected")
                    .send(Message::pong(payload))
                    .await
                {
                    self.socket = None;
                    retry.failed_with(error.to_string()).await?;
                    return Ok(None);
                }
                retry.succeeded();
                continue;
            }
            if message.is_pong() {
                retry.succeeded();
                continue;
            }
            let Some(text) = message.as_text() else {
                return Err(Error::Protocol(
                    "relay sent a binary WebSocket frame".into(),
                ));
            };
            let incoming: IncomingFrame = serde_json::from_str(text).map_err(Error::InvalidJson)?;
            let incoming = self.validate(incoming)?;
            match incoming {
                IncomingFrame::Error {
                    error,
                    message,
                    retryable,
                    retry_after_ms,
                    ..
                } => {
                    if !retryable {
                        return Err(Error::RelayRejected {
                            code: error,
                            message,
                        });
                    }
                    self.socket = None;
                    retry.last_error = format!("relay requested retry: {error}: {message}");
                    retry
                        .failed(Duration::from_millis(retry_after_ms.unwrap_or(1000)))
                        .await?;
                    return Ok(None);
                }
                IncomingFrame::Inactive { kind, .. } => return Err(Error::Inactive { kind }),
                incoming => {
                    retry.succeeded();
                    return Ok(Some(incoming));
                }
            }
        }
    }

    fn validate(&self, incoming: IncomingFrame) -> Result<IncomingFrame, Error> {
        if let Some(client_id) = incoming.client_id()
            && client_id != self.client_id
        {
            return Err(Error::Protocol(
                "relay frame has the wrong client_id".into(),
            ));
        }
        if let Some(request_id) = incoming.request_id()
            && request_id != self.request_id
        {
            return Err(Error::Protocol(
                "relay frame has the wrong request_id".into(),
            ));
        }
        Ok(incoming)
    }

    fn apply_request_state<F>(&mut self, state: MessageState, delivered: &mut F)
    where
        F: FnMut(),
    {
        match state {
            MessageState::Accepted => self.request_mut().acknowledged = true,
            MessageState::Delivered => {
                self.request_mut().acknowledged = true;
                delivered();
            }
            MessageState::Absent | MessageState::Discarded => {}
        }
    }

    fn decode_response<R: DeserializeOwned>(&self) -> Result<R, Error> {
        let response = self.response.clone().ok_or(Error::MissingResponse)?;
        match serde_json::from_value(response).map_err(Error::InvalidJson)? {
            ApplicationResponse::Message(response) => Ok(response),
            ApplicationResponse::Error(error) => Err(Error::Unauthenticated {
                code: error.error,
                message: error.message,
            }),
        }
    }

    fn request_message(&self) -> &OutgoingMessage {
        self.request.as_ref().expect("request exists")
    }

    fn request_mut(&mut self) -> &mut OutgoingMessage {
        self.request.as_mut().expect("request exists")
    }

    fn completion(&self) -> &OutgoingMessage {
        self.completion.as_ref().expect("completion exists")
    }

    fn completion_mut(&mut self) -> &mut OutgoingMessage {
        self.completion.as_mut().expect("completion exists")
    }
}

fn relay_url() -> Result<String, Error> {
    #[cfg(all(feature = "integration-tests", debug_assertions))]
    {
        match env::var(TEST_RELAY_URL_ENV) {
            Ok(url) => return validate_test_relay_url(url),
            Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(Error::InvalidRelayUrl(
                    "integration-test relay URL isn't valid UTF-8".into(),
                ));
            }
        }
    }

    Ok(RELAY_URL.to_owned())
}

#[cfg(all(feature = "integration-tests", debug_assertions))]
fn validate_test_relay_url(url: String) -> Result<String, Error> {
    let uri = url
        .parse::<http::Uri>()
        .map_err(|_| Error::InvalidRelayUrl(url.clone()))?;
    let address = uri
        .authority()
        .and_then(|authority| authority.as_str().parse::<SocketAddr>().ok());
    let path_is_empty = uri.path_and_query().is_none_or(|path| path.as_str() == "/");

    if uri.scheme_str() == Some("ws")
        && address.is_some_and(|address| address.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        && path_is_empty
    {
        Ok(url)
    } else {
        Err(Error::InvalidRelayUrl(url))
    }
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

impl OutgoingMessage {
    fn new(encoded: String) -> Result<Self, Error> {
        if encoded.len() > MAXIMUM_FRAME_SIZE {
            return Err(Error::FrameTooLarge(encoded.len()));
        }
        Ok(Self {
            encoded,
            sent: false,
            acknowledged: false,
        })
    }
}

struct RetryState {
    policy: RetryPolicy,
    first_failure: Option<Instant>,
    failures: usize,
    last_error: String,
}

impl RetryState {
    fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            first_failure: None,
            failures: 0,
            last_error: String::new(),
        }
    }

    fn succeeded(&mut self) {
        self.first_failure = None;
        self.failures = 0;
        self.last_error.clear();
    }

    async fn failed_with(&mut self, error: String) -> Result<(), Error> {
        self.last_error = error;
        self.failed(self.policy.retry_delay).await
    }

    async fn failed(&mut self, delay: Duration) -> Result<(), Error> {
        let first_failure = *self.first_failure.get_or_insert_with(Instant::now);
        self.failures += 1;
        let deadline = first_failure + self.policy.failure_timeout;
        if self.failures >= self.policy.maximum_failures || Instant::now() >= deadline {
            return Err(Error::RetriesExhausted {
                failures: self.failures,
                last_error: self.last_error.clone(),
            });
        }
        tokio::time::sleep(delay.min(deadline.saturating_duration_since(Instant::now()))).await;
        if Instant::now() >= deadline {
            return Err(Error::RetriesExhausted {
                failures: self.failures,
                last_error: self.last_error.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum MessageKind {
    Request,
    Response,
    Completion,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutgoingFrame<'a, B: ?Sized> {
    Message {
        client_id: &'a str,
        request_id: &'a str,
        kind: MessageKind,
        payload: &'a B,
    },
    Ack {
        client_id: &'a str,
        request_id: &'a str,
        kind: MessageKind,
    },
    Resume {
        client_id: &'a str,
        request_id: &'a str,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IncomingFrame {
    Ack {
        client_id: String,
        request_id: String,
        kind: MessageKind,
    },
    Receipt {
        client_id: String,
        request_id: String,
        kind: MessageKind,
    },
    Message {
        client_id: String,
        request_id: String,
        kind: MessageKind,
        payload: Value,
    },
    State {
        client_id: String,
        request_id: String,
        exchange: ExchangeState,
        request: MessageState,
        response: MessageState,
        completion: MessageState,
    },
    Inactive {
        client_id: String,
        request_id: String,
        #[serde(default)]
        kind: Option<MessageKind>,
    },
    Error {
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        request_id: Option<String>,
        error: String,
        message: String,
        retryable: bool,
        #[serde(default)]
        retry_after_ms: Option<u64>,
    },
}

impl IncomingFrame {
    fn client_id(&self) -> Option<&str> {
        match self {
            Self::Ack { client_id, .. }
            | Self::Receipt { client_id, .. }
            | Self::Message { client_id, .. }
            | Self::State { client_id, .. }
            | Self::Inactive { client_id, .. } => Some(client_id),
            Self::Error { client_id, .. } => client_id.as_deref(),
        }
    }

    fn request_id(&self) -> Option<&str> {
        match self {
            Self::Ack { request_id, .. }
            | Self::Receipt { request_id, .. }
            | Self::Message { request_id, .. }
            | Self::State { request_id, .. }
            | Self::Inactive { request_id, .. } => Some(request_id),
            Self::Error { request_id, .. } => request_id.as_deref(),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExchangeState {
    Open,
    Closing,
    Settled,
    Expired,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum MessageState {
    Absent,
    Accepted,
    Delivered,
    Discarded,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApplicationResponse<R> {
    Message(R),
    Error(UnauthenticatedError),
}

#[derive(Deserialize)]
struct UnauthenticatedError {
    error: String,
    message: String,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("relay returned invalid JSON: {0}")]
    InvalidJson(serde_json::Error),

    #[error("relay returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),

    #[error("relay protocol error: {0}")]
    Protocol(String),

    #[error("relay response doesn't include a response message")]
    MissingResponse,

    #[error("received unauthenticated error {code}: {message:?}")]
    Unauthenticated { code: String, message: String },

    #[error("relay rejected the exchange with {code}: {message}")]
    RelayRejected { code: String, message: String },

    #[error("relay reported that the exchange is inactive")]
    Inactive { kind: Option<MessageKind> },

    #[error("paired client is inactive ({code} {reason})")]
    ClientInactive { code: u16, reason: String },

    #[error("relay remained unavailable after {failures} consecutive failures: {last_error}")]
    RetriesExhausted { failures: usize, last_error: String },

    #[error("timed out handing off the completion to the relay")]
    CompletionTimedOut,

    #[error("WebSocket frame has {0} bytes, exceeding the 256 KiB limit")]
    FrameTooLarge(usize),

    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(String),

    #[error("invalid proxy configuration: {0}")]
    ProxyConfiguration(#[from] proxy::ConfigurationError),

    #[error("proxy rejected the relay connection with HTTP status {0}")]
    ProxyRejected(u16),

    #[error("client token can't be used in an Authorization header")]
    InvalidClientToken,

    #[error("WebSocket setup failed: {0}")]
    WebSocket(#[from] tokio_websockets::Error),
}

#[cfg(test)]
mod tests {
    use crate::ApplicationInfo;
    use serde::Deserialize;
    use serde_json::json;

    use super::ApplicationResponse;

    #[derive(Deserialize)]
    struct ProtectedResponse {
        nonce: String,
        ciphertext: String,
    }

    #[test]
    fn installs_rustls_crypto_provider() {
        super::ensure_rustls_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    fn identifies_the_application_and_library_in_the_user_agent() {
        let application = ApplicationInfo::new("example-app", "1.2.3");

        assert_eq!(
            super::user_agent(&application),
            format!("example-app/1.2.3 agentknock/{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn avoids_duplicate_or_invalid_user_agent_products() {
        let agentknock = ApplicationInfo::new("agentknock", env!("CARGO_PKG_VERSION"));
        let invalid = ApplicationInfo::new("example app", "1.2.3");
        let expected = format!("agentknock/{}", env!("CARGO_PKG_VERSION"));

        assert_eq!(super::user_agent(&agentknock), expected);
        assert_eq!(super::user_agent(&invalid), expected);
    }

    #[cfg(all(feature = "integration-tests", debug_assertions))]
    #[test]
    fn accepts_a_loopback_test_relay() {
        let url = "ws://127.0.0.1:12345".to_owned();

        assert_eq!(super::validate_test_relay_url(url.clone()).unwrap(), url);
    }

    #[cfg(all(feature = "integration-tests", debug_assertions))]
    #[test]
    fn rejects_a_remote_test_relay() {
        assert!(super::validate_test_relay_url("ws://relay.example:12345".into()).is_err());
    }

    #[test]
    fn ignores_error_members_in_a_protected_response() {
        let response: ApplicationResponse<ProtectedResponse> = serde_json::from_value(json!({
            "nonce": "response random",
            "ciphertext": "protected contents",
            "error": "UNKNOWN_EXTENSION",
            "message": "ignored extension contents",
        }))
        .unwrap();

        let ApplicationResponse::Message(response) = response else {
            panic!("protected response was interpreted as an unauthenticated error");
        };
        assert_eq!(response.nonce, "response random");
        assert_eq!(response.ciphertext, "protected contents");
    }

    #[test]
    fn accepts_an_unauthenticated_error_without_a_protected_response() {
        let response: ApplicationResponse<ProtectedResponse> = serde_json::from_value(json!({
            "error": "CLIENT_INACTIVE",
            "message": "client is inactive",
        }))
        .unwrap();

        let ApplicationResponse::Error(error) = response else {
            panic!("unauthenticated error was interpreted as a protected response");
        };
        assert_eq!(error.error, "CLIENT_INACTIVE");
        assert_eq!(error.message, "client is inactive");
    }
}
