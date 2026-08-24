use std::{env, ffi::OsString, io};

use http::{HeaderValue, Uri};
use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::TcpStream,
};
use tokio_websockets::Connector;

const MAXIMUM_CONNECT_RESPONSE_SIZE: usize = 8 * 1024;

pub(crate) trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Transport for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type Stream = Box<dyn Transport>;

pub(crate) struct Config {
    proxy: Option<Intercept>,
}

struct Setting {
    name: &'static str,
    value: String,
}

impl Config {
    pub(crate) fn from_env(destination: &Uri) -> Result<Self, ConfigurationError> {
        let target = proxy_target(destination)?;
        let specific = match target.scheme_str() {
            Some("https") => first_setting(&["https_proxy", "HTTPS_PROXY"]),
            Some("http") => first_setting(&["http_proxy", "HTTP_PROXY"]),
            _ => unreachable!("proxy targets use HTTP schemes"),
        }?;
        let setting = match specific {
            Some(setting) => Some(setting),
            None => first_setting(&["all_proxy", "ALL_PROXY"])?,
        };
        let Some(setting) = setting else {
            return Ok(Self { proxy: None });
        };

        let validation = matcher(&target, &setting.value, None)
            .intercept(&target)
            .ok_or(ConfigurationError::InvalidProxyUrl(setting.name))?;
        let scheme = validation.uri().scheme_str().unwrap_or_default();
        if !matches!(scheme, "http" | "https") {
            return Err(ConfigurationError::UnsupportedProxyScheme {
                variable: setting.name,
                scheme: scheme.to_owned(),
            });
        }

        let no_proxy = first_setting(&["no_proxy", "NO_PROXY"])?;
        let proxy = matcher(
            &target,
            &setting.value,
            no_proxy.as_ref().map(|setting| setting.value.as_str()),
        )
        .intercept(&target);

        Ok(Self { proxy })
    }

    pub(crate) async fn connect(&self, destination: &Uri) -> Result<Stream, ConnectionError> {
        let Some(proxy) = &self.proxy else {
            return Ok(Box::new(connect_tcp(destination).await?));
        };

        let tcp = connect_tcp(proxy.uri()).await?;
        let proxy_host = host(proxy.uri())?;
        let mut stream: Stream = match proxy.uri().scheme_str() {
            Some("http") => Box::new(tcp),
            Some("https") => {
                let connector = Connector::new()?;
                Box::new(connector.wrap(proxy_host, Box::new(tcp) as Stream).await?)
            }
            _ => unreachable!("proxy schemes are validated during configuration"),
        };

        establish_tunnel(
            &mut stream,
            connect_authority(destination)?,
            proxy.basic_auth(),
        )
        .await?;
        Ok(stream)
    }
}

fn matcher(target: &Uri, proxy: &str, no_proxy: Option<&str>) -> Matcher {
    let mut builder = Matcher::builder();
    builder = match target.scheme_str() {
        Some("https") => builder.https(proxy),
        Some("http") => builder.http(proxy),
        _ => unreachable!("proxy targets use HTTP schemes"),
    };
    if let Some(no_proxy) = no_proxy {
        builder = builder.no(no_proxy);
    }
    builder.build()
}

fn first_setting(names: &[&'static str]) -> Result<Option<Setting>, ConfigurationError> {
    for &name in names {
        let Some(value) = env::var_os(name) else {
            continue;
        };
        let value = environment_string(name, value)?;
        if !value.is_empty() {
            return Ok(Some(Setting { name, value }));
        }
    }
    Ok(None)
}

fn environment_string(name: &'static str, value: OsString) -> Result<String, ConfigurationError> {
    value
        .into_string()
        .map_err(|_| ConfigurationError::NonUtf8(name))
}

fn proxy_target(destination: &Uri) -> Result<Uri, ConfigurationError> {
    let scheme = match destination.scheme_str() {
        Some("wss") => "https",
        Some("ws") => "http",
        _ => return Err(ConfigurationError::InvalidDestination),
    };
    Uri::builder()
        .scheme(scheme)
        .authority(
            destination
                .authority()
                .ok_or(ConfigurationError::InvalidDestination)?
                .clone(),
        )
        .path_and_query("/")
        .build()
        .map_err(|_| ConfigurationError::InvalidDestination)
}

async fn connect_tcp(uri: &Uri) -> Result<TcpStream, ConnectionError> {
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("https" | "wss") => 443,
        _ => 80,
    });
    Ok(TcpStream::connect((host(uri)?, port)).await?)
}

fn host(uri: &Uri) -> Result<&str, ConnectionError> {
    uri.host()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .ok_or(ConnectionError::MissingHost)
}

fn connect_authority(uri: &Uri) -> Result<String, ConnectionError> {
    let host = uri.host().ok_or(ConnectionError::MissingHost)?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss" | "https") => 443,
        _ => 80,
    });
    Ok(format!("{host}:{port}"))
}

async fn establish_tunnel<S>(
    stream: &mut S,
    authority: String,
    authorization: Option<&HeaderValue>,
) -> Result<(), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\n\
         Host: {authority}\r\n"
    )
    .into_bytes();
    if let Some(authorization) = authorization {
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(authorization.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(1024);
    loop {
        if response.len() == MAXIMUM_CONNECT_RESPONSE_SIZE {
            return Err(ConnectionError::ResponseTooLarge);
        }
        let mut buffer = [0_u8; 1024];
        let available = (MAXIMUM_CONNECT_RESPONSE_SIZE - response.len()).min(buffer.len());
        let read = stream.read(&mut buffer[..available]).await?;
        if read == 0 {
            return Err(ConnectionError::UnexpectedEof);
        }
        response.extend_from_slice(&buffer[..read]);
        if response.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            break;
        }
    }

    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or(ConnectionError::InvalidResponse)?;
    let mut fields = status_line.split_ascii_whitespace();
    let version = fields.next().ok_or(ConnectionError::InvalidResponse)?;
    let status = fields
        .next()
        .ok_or(ConnectionError::InvalidResponse)?
        .parse::<u16>()
        .map_err(|_| ConnectionError::InvalidResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ConnectionError::InvalidResponse);
    }
    if !(200..300).contains(&status) {
        return Err(ConnectionError::Rejected(status));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum ConfigurationError {
    #[error("relay URL can't be used with proxy settings")]
    InvalidDestination,

    #[error("{0} does not contain a valid proxy URL")]
    InvalidProxyUrl(&'static str),

    #[error("{variable} uses unsupported proxy scheme {scheme:?}; use HTTP or HTTPS")]
    UnsupportedProxyScheme {
        variable: &'static str,
        scheme: String,
    },

    #[error("{0} isn't valid UTF-8")]
    NonUtf8(&'static str),
}

#[derive(Debug, Error)]
pub(crate) enum ConnectionError {
    #[error("TCP connection failed: {0}")]
    Io(#[from] io::Error),

    #[error("TLS setup failed: {0}")]
    WebSocket(#[from] tokio_websockets::Error),

    #[error("proxy returned HTTP status {0} for the CONNECT request")]
    Rejected(u16),

    #[error("proxy returned an invalid CONNECT response")]
    InvalidResponse,

    #[error("proxy closed the connection before completing the CONNECT response")]
    UnexpectedEof,

    #[error("proxy CONNECT response headers exceed 8 KiB")]
    ResponseTooLarge,

    #[error("connection URL doesn't contain a host")]
    MissingHost,

    #[error("connection URL doesn't use the WS or WSS scheme")]
    UnsupportedDestination,
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::establish_tunnel;

    #[tokio::test]
    async fn establishes_an_authenticated_connect_tunnel() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 4096];
            let length = server.read(&mut request).await.unwrap();
            let request = std::str::from_utf8(&request[..length]).unwrap();
            assert_eq!(
                request,
                "CONNECT relay.agentknock.dev:443 HTTP/1.1\r\n\
                 Host: relay.agentknock.dev:443\r\n\
                 Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
            );
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\nX-Proxy: test\r\n\r\n")
                .await
                .unwrap();
        });

        establish_tunnel(
            &mut client,
            "relay.agentknock.dev:443".into(),
            Some(&HeaderValue::from_static("Basic dXNlcjpwYXNz")),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn reports_a_rejected_connect_tunnel() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 1];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });

        let error = establish_tunnel(&mut client, "relay.agentknock.dev:443".into(), None)
            .await
            .unwrap_err();
        assert!(matches!(error, super::ConnectionError::Rejected(407)));
        server_task.await.unwrap();
    }
}
