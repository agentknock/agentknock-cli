use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    io,
    path::Path,
};

use agentknock::SshSignatureAlgorithm;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub const SOCKET_NAME: &str = "agent.sock";

const MAX_PACKET_LENGTH: usize = 256 * 1024;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyKind {
    Ed25519,
    Rsa,
}

pub struct SelectedIdentity {
    key_blob: Vec<u8>,
    key_kind: Option<KeyKind>,
    comment: String,
}

pub struct AgentConnection<'a> {
    selected: &'a SelectedIdentity,
    upstream: Upstream,
}

pub enum Action {
    Respond(Vec<u8>),
    Authenticate {
        algorithm: SshSignatureAlgorithm,
        message: Vec<u8>,
    },
}

enum Route {
    ListIdentities,
    Authenticate {
        algorithm: SshSignatureAlgorithm,
        message: Vec<u8>,
    },
    Forward,
    ExtensionQuery,
    Refuse,
}

enum Upstream {
    Unconnected(OsString),
    Connected(tokio::net::UnixStream),
    Unavailable,
}

struct ListedIdentity {
    key_blob: Vec<u8>,
    comment: Vec<u8>,
}

impl SelectedIdentity {
    pub fn from_openssh(public_key: &str, comment: String) -> io::Result<Self> {
        let mut fields = public_key.split_ascii_whitespace();
        let algorithm = fields.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH public key has no algorithm",
            )
        })?;
        let encoded = fields.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "SSH public key has no key data")
        })?;
        let key_blob = BASE64_STANDARD.decode(encoded).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SSH public key has invalid Base64 data: {error}"),
            )
        })?;
        let mut blob = Cursor::new(&key_blob);
        if blob.string()? != algorithm.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH public key algorithm doesn't match its key data",
            ));
        }
        let key_kind = match algorithm {
            "ssh-ed25519" => {
                if blob.string()?.len() != 32 {
                    return Err(invalid_data("invalid Ed25519 public key"));
                }
                Some(KeyKind::Ed25519)
            }
            "ssh-rsa" => {
                if blob.string()?.is_empty() || blob.string()?.is_empty() {
                    return Err(invalid_data("invalid RSA public key"));
                }
                Some(KeyKind::Rsa)
            }
            _ => {
                if blob.remaining.is_empty() {
                    return Err(invalid_data("SSH public key has no key data"));
                }
                None
            }
        };
        if key_kind.is_some() {
            blob.end()?;
        }
        Ok(Self {
            key_blob,
            key_kind,
            comment,
        })
    }

    fn route(&self, packet: &[u8]) -> Route {
        let Some((&message_type, contents)) = packet.split_first() else {
            return Route::Refuse;
        };
        match message_type {
            SSH_AGENTC_REQUEST_IDENTITIES if contents.is_empty() => Route::ListIdentities,
            SSH_AGENTC_SIGN_REQUEST => self.parse_authentication(contents),
            SSH_AGENTC_EXTENSION if is_extension_query(contents) => Route::ExtensionQuery,
            SSH_AGENTC_EXTENSION => Route::Forward,
            _ => Route::Refuse,
        }
    }

    fn identities_response(&self, upstream: Option<&[u8]>) -> Vec<u8> {
        let mut identities = Vec::new();
        let mut seen = BTreeSet::from([self.key_blob.clone()]);
        if self.key_kind.is_some() {
            identities.push(ListedIdentity {
                key_blob: self.key_blob.clone(),
                comment: self.comment.as_bytes().to_vec(),
            });
        }
        if let Some(upstream) = upstream
            && let Ok(upstream) = parse_identities_response(upstream)
        {
            identities.extend(
                upstream
                    .into_iter()
                    .filter(|identity| seen.insert(identity.key_blob.clone())),
            );
        }
        encode_identities_response(&identities)
    }

    fn parse_authentication(&self, contents: &[u8]) -> Route {
        let mut request = Cursor::new(contents);
        let Ok(key_blob) = request.string() else {
            return Route::Refuse;
        };
        if key_blob != self.key_blob {
            return Route::Forward;
        }
        let result = (|| {
            let message = request.string()?;
            let flags = request.u32()?;
            request.end()?;
            let algorithm = match (self.key_kind, flags) {
                (Some(KeyKind::Ed25519), 0) => SshSignatureAlgorithm::Ed25519,
                (Some(KeyKind::Rsa), SSH_AGENT_RSA_SHA2_256) => SshSignatureAlgorithm::RsaSha256,
                (Some(KeyKind::Rsa), SSH_AGENT_RSA_SHA2_512) => SshSignatureAlgorithm::RsaSha512,
                _ => return Err(invalid_data("unsupported SSH signature flags")),
            };
            validate_authentication_message(message, &self.key_blob, algorithm)?;
            Ok(Route::Authenticate {
                algorithm,
                message: message.to_vec(),
            })
        })();
        result.unwrap_or(Route::Refuse)
    }
}

impl<'a> AgentConnection<'a> {
    pub fn new(selected: &'a SelectedIdentity, upstream_socket: Option<&OsStr>) -> Self {
        let upstream = match upstream_socket {
            Some(socket) => Upstream::Unconnected(socket.to_owned()),
            None => Upstream::Unavailable,
        };
        Self { selected, upstream }
    }

    pub async fn handle(&mut self, packet: &[u8]) -> Action {
        match self.selected.route(packet) {
            Route::ListIdentities => {
                let upstream = self.forward(packet).await;
                Action::Respond(self.selected.identities_response(upstream.as_deref()))
            }
            Route::Authenticate { algorithm, message } => {
                Action::Authenticate { algorithm, message }
            }
            Route::Forward => Action::Respond(
                self.forward(packet)
                    .await
                    .unwrap_or_else(|| failure_response().to_vec()),
            ),
            Route::ExtensionQuery => {
                let response = self.forward(packet).await;
                Action::Respond(
                    response
                        .filter(|response| valid_extension_query_response(response))
                        .unwrap_or_else(extension_query_response),
                )
            }
            Route::Refuse => Action::Respond(failure_response().to_vec()),
        }
    }

    async fn forward(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if let Upstream::Unconnected(socket) = &self.upstream {
            let socket = socket.clone();
            self.upstream = match tokio::net::UnixStream::connect(Path::new(&socket)).await {
                Ok(connection) => Upstream::Connected(connection),
                Err(_) => Upstream::Unavailable,
            };
        }
        let Upstream::Connected(upstream) = &mut self.upstream else {
            return None;
        };
        let response = async {
            write_packet(upstream, packet).await?;
            read_packet(upstream)
                .await?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "SSH agent closed"))
        }
        .await;
        match response {
            Ok(response) => Some(response),
            Err(_) => {
                self.upstream = Upstream::Unavailable;
                None
            }
        }
    }
}

pub async fn read_packet(connection: &mut tokio::net::UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    if connection.read(&mut length[..1]).await? == 0 {
        return Ok(None);
    }
    connection.read_exact(&mut length[1..]).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PACKET_LENGTH {
        return Err(invalid_data("invalid SSH agent packet length"));
    }
    let mut packet = vec![0; length];
    connection.read_exact(&mut packet).await?;
    Ok(Some(packet))
}

pub async fn write_packet(
    connection: &mut tokio::net::UnixStream,
    packet: &[u8],
) -> io::Result<()> {
    let length =
        u32::try_from(packet.len()).map_err(|_| invalid_data("SSH agent response is too large"))?;
    connection.write_all(&length.to_be_bytes()).await?;
    connection.write_all(packet).await?;
    connection.flush().await
}

pub fn failure_response() -> &'static [u8] {
    &[SSH_AGENT_FAILURE]
}

fn extension_query_response() -> Vec<u8> {
    let mut response = vec![SSH_AGENT_EXTENSION_RESPONSE];
    put_string(&mut response, b"query");
    response
}

pub fn signature_response(signature: &[u8]) -> Vec<u8> {
    let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut response, signature);
    response
}

fn is_extension_query(contents: &[u8]) -> bool {
    let mut request = Cursor::new(contents);
    matches!(request.string(), Ok(b"query")) && request.end().is_ok()
}

fn valid_extension_query_response(packet: &[u8]) -> bool {
    let mut response = Cursor::new(packet);
    if !matches!(response.byte(), Ok(SSH_AGENT_EXTENSION_RESPONSE))
        || !matches!(response.string(), Ok(b"query"))
    {
        return false;
    }
    while !response.remaining.is_empty() {
        if response.string().is_err() {
            return false;
        }
    }
    true
}

fn parse_identities_response(packet: &[u8]) -> io::Result<Vec<ListedIdentity>> {
    let mut response = Cursor::new(packet);
    if response.byte()? != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(invalid_data("SSH agent returned an unexpected response"));
    }
    let count = response.u32()?;
    let mut identities = Vec::new();
    for _ in 0..count {
        identities.push(ListedIdentity {
            key_blob: response.string()?.to_vec(),
            comment: response.string()?.to_vec(),
        });
    }
    response.end()?;
    Ok(identities)
}

fn encode_identities_response(identities: &[ListedIdentity]) -> Vec<u8> {
    let mut response = vec![SSH_AGENT_IDENTITIES_ANSWER];
    put_u32(
        &mut response,
        u32::try_from(identities.len()).expect("identity count fits in an SSH packet"),
    );
    for identity in identities {
        put_string(&mut response, &identity.key_blob);
        put_string(&mut response, &identity.comment);
    }
    response
}

fn validate_authentication_message(
    message: &[u8],
    expected_key: &[u8],
    algorithm: SshSignatureAlgorithm,
) -> io::Result<()> {
    let mut message = Cursor::new(message);
    if message.string()?.is_empty() {
        return Err(invalid_data(
            "SSH authentication has an empty session identifier",
        ));
    }
    if message.byte()? != SSH_MSG_USERAUTH_REQUEST {
        return Err(invalid_data(
            "SSH signature isn't a user-authentication request",
        ));
    }
    message.string()?;
    if message.string()? != b"ssh-connection" {
        return Err(invalid_data(
            "SSH authentication has an unsupported service",
        ));
    }
    let method = message.string()?;
    if !matches!(
        method,
        b"publickey" | b"publickey-hostbound-v00@openssh.com"
    ) {
        return Err(invalid_data("SSH authentication has an unsupported method"));
    }
    if message.byte()? != 1 {
        return Err(invalid_data(
            "SSH authentication doesn't contain a signature",
        ));
    }
    if message.string()? != algorithm.as_str().as_bytes() {
        return Err(invalid_data(
            "SSH authentication algorithm doesn't match the request",
        ));
    }
    if message.string()? != expected_key {
        return Err(invalid_data(
            "SSH authentication contains a different public key",
        ));
    }
    if method == b"publickey-hostbound-v00@openssh.com" {
        let host_key = message.string()?;
        let mut host_key = Cursor::new(host_key);
        if host_key.string()?.is_empty() || host_key.remaining.is_empty() {
            return Err(invalid_data(
                "host-bound SSH authentication has an invalid host key",
            ));
        }
    }
    message.end()
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    fn byte(&mut self) -> io::Result<u8> {
        let (&value, remaining) = self
            .remaining
            .split_first()
            .ok_or_else(|| invalid_data("truncated SSH data"))?;
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let value = self
            .remaining
            .get(..4)
            .ok_or_else(|| invalid_data("truncated SSH data"))?;
        self.remaining = &self.remaining[4..];
        Ok(u32::from_be_bytes(
            value.try_into().expect("four bytes were selected"),
        ))
    }

    fn string(&mut self) -> io::Result<&'a [u8]> {
        let length = self.u32()? as usize;
        let value = self
            .remaining
            .get(..length)
            .ok_or_else(|| invalid_data("truncated SSH string"))?;
        self.remaining = &self.remaining[length..];
        Ok(value)
    }

    fn end(&self) -> io::Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(invalid_data("SSH data has trailing bytes"))
        }
    }
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_string(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(
        output,
        u32::try_from(value.len()).expect("SSH values fit in a packet"),
    );
    output.extend_from_slice(value);
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB test";

    #[test]
    fn parses_an_ed25519_authentication_request() {
        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "test-key".into()).unwrap();
        let message =
            authentication_message(b"ssh-ed25519", &identity.key_blob, b"publickey", None);
        let request = sign_request(&identity.key_blob, &message, 0);
        let Route::Authenticate {
            algorithm,
            message: parsed,
        } = identity.route(&request)
        else {
            panic!("authentication request was rejected");
        };
        assert_eq!(algorithm, SshSignatureAlgorithm::Ed25519);
        assert_eq!(parsed, message);
    }

    #[test]
    fn accepts_both_rsa_sha2_algorithms() {
        let key_blob = ssh_string_sequence(&[b"ssh-rsa", b"exponent", b"modulus"]);
        let key = format!("ssh-rsa {}", BASE64_STANDARD.encode(&key_blob));
        let identity = SelectedIdentity::from_openssh(&key, "test-key".into()).unwrap();
        for (flags, name, expected) in [
            (
                SSH_AGENT_RSA_SHA2_256,
                b"rsa-sha2-256".as_slice(),
                SshSignatureAlgorithm::RsaSha256,
            ),
            (
                SSH_AGENT_RSA_SHA2_512,
                b"rsa-sha2-512".as_slice(),
                SshSignatureAlgorithm::RsaSha512,
            ),
        ] {
            let message = authentication_message(name, &key_blob, b"publickey", None);
            let Route::Authenticate { algorithm, .. } =
                identity.route(&sign_request(&key_blob, &message, flags))
            else {
                panic!("RSA authentication request was rejected");
            };
            assert_eq!(algorithm, expected);
        }
    }

    #[test]
    fn rejects_non_authentication_signatures_and_legacy_rsa() {
        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "test-key".into()).unwrap();
        assert!(matches!(
            identity.route(&sign_request(&identity.key_blob, b"arbitrary", 0)),
            Route::Refuse
        ));

        let key_blob = ssh_string_sequence(&[b"ssh-rsa", b"exponent", b"modulus"]);
        let key = format!("ssh-rsa {}", BASE64_STANDARD.encode(&key_blob));
        let identity = SelectedIdentity::from_openssh(&key, "test-key".into()).unwrap();
        let message = authentication_message(b"ssh-rsa", &key_blob, b"publickey", None);
        assert!(matches!(
            identity.route(&sign_request(&key_blob, &message, 0)),
            Route::Refuse
        ));
    }

    #[test]
    fn accepts_host_bound_authentication() {
        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "test-key".into()).unwrap();
        let host_key = ssh_string_sequence(&[b"ssh-ed25519", &[2; 32]]);
        let message = authentication_message(
            b"ssh-ed25519",
            &identity.key_blob,
            b"publickey-hostbound-v00@openssh.com",
            Some(&host_key),
        );
        assert!(matches!(
            identity.route(&sign_request(&identity.key_blob, &message, 0)),
            Route::Authenticate { .. }
        ));
    }

    #[test]
    fn advertises_one_identity_and_no_extensions() {
        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "test-key".into()).unwrap();
        assert_eq!(
            identity.identities_response(None)[0],
            SSH_AGENT_IDENTITIES_ANSWER
        );
        let mut contents = Vec::new();
        put_string(&mut contents, b"query");
        assert!(matches!(
            identity.route(&[&[SSH_AGENTC_EXTENSION], contents.as_slice()].concat()),
            Route::ExtensionQuery
        ));
        assert_eq!(extension_query_response()[0], SSH_AGENT_EXTENSION_RESPONSE);
    }

    #[test]
    fn does_not_advertise_an_unsupported_authentication_key() {
        let key_blob =
            ssh_string_sequence(&[b"ecdsa-sha2-nistp256", b"nistp256", b"unsupported point"]);
        let key = format!("ecdsa-sha2-nistp256 {}", BASE64_STANDARD.encode(key_blob));
        let identity = SelectedIdentity::from_openssh(&key, "signing-only".into()).unwrap();
        assert_eq!(
            identity.identities_response(None),
            [SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]
        );
    }

    #[test]
    fn prepends_the_selected_identity_and_removes_its_upstream_duplicate() {
        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "selected".into()).unwrap();
        let other_key = ssh_string_sequence(&[b"ssh-ed25519", &[2; 32]]);
        let upstream = encode_identities_response(&[
            ListedIdentity {
                key_blob: other_key.clone(),
                comment: b"other".to_vec(),
            },
            ListedIdentity {
                key_blob: identity.key_blob.clone(),
                comment: b"upstream duplicate".to_vec(),
            },
            ListedIdentity {
                key_blob: other_key.clone(),
                comment: b"second upstream duplicate".to_vec(),
            },
        ]);

        let merged = parse_identities_response(&identity.identities_response(Some(&upstream)))
            .expect("parse merged identities");
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].key_blob, identity.key_blob);
        assert_eq!(merged[0].comment, b"selected");
        assert_eq!(merged[1].key_blob, other_key);
        assert_eq!(merged[1].comment, b"other");
    }

    #[test]
    fn suppresses_an_unsupported_selected_identity_from_the_upstream_agent() {
        let selected_key = ssh_string_sequence(&[b"ecdsa-sha2-nistp256", b"nistp256", b"point"]);
        let selected = format!(
            "ecdsa-sha2-nistp256 {}",
            BASE64_STANDARD.encode(&selected_key)
        );
        let identity = SelectedIdentity::from_openssh(&selected, "selected".into()).unwrap();
        let other_key = ssh_string_sequence(&[b"ssh-ed25519", &[2; 32]]);
        let upstream = encode_identities_response(&[
            ListedIdentity {
                key_blob: selected_key.clone(),
                comment: b"duplicate".to_vec(),
            },
            ListedIdentity {
                key_blob: other_key.clone(),
                comment: b"other".to_vec(),
            },
        ]);

        let merged = parse_identities_response(&identity.identities_response(Some(&upstream)))
            .expect("parse merged identities");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].key_blob, other_key);
        assert!(matches!(
            identity.route(&sign_request(&selected_key, b"anything", 0)),
            Route::Refuse
        ));
    }

    #[test]
    fn forwards_only_other_keys_and_extensions() {
        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "selected".into()).unwrap();
        let other_key = ssh_string_sequence(&[b"ssh-ed25519", &[2; 32]]);
        assert!(matches!(
            identity.route(&sign_request(&other_key, b"anything", 0)),
            Route::Forward
        ));
        assert!(matches!(
            identity.route(&[SSH_AGENTC_EXTENSION, 0, 0, 0, 3, b'f', b'o', b'o']),
            Route::Forward
        ));
        assert!(matches!(identity.route(&[19]), Route::Refuse));
    }

    #[test]
    fn validates_extension_query_responses() {
        let mut response = extension_query_response();
        put_string(&mut response, b"session-bind@openssh.com");
        assert!(valid_extension_query_response(&response));
        response.push(0);
        assert!(!valid_extension_query_response(&response));
        assert!(!valid_extension_query_response(failure_response()));
    }

    #[tokio::test]
    async fn preserves_one_upstream_connection_for_extensions_and_signatures() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let other_key = ssh_string_sequence(&[b"ssh-ed25519", &[2; 32]]);
        let sign = sign_request(&other_key, b"upstream data", 0);
        let expected_sign = sign.clone();
        let query = extension_request(b"query", b"");
        let expected_query = query.clone();
        let extension = extension_request(b"session-bind@openssh.com", b"binding");
        let expected_extension = extension.clone();
        let upstream = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();

            assert_eq!(
                read_packet(&mut connection).await.unwrap().unwrap(),
                expected_query
            );
            let mut response = extension_query_response();
            put_string(&mut response, b"session-bind@openssh.com");
            write_packet(&mut connection, &response).await.unwrap();

            assert_eq!(
                read_packet(&mut connection).await.unwrap().unwrap(),
                expected_extension
            );
            write_packet(&mut connection, &[6]).await.unwrap();

            assert_eq!(
                read_packet(&mut connection).await.unwrap().unwrap(),
                expected_sign
            );
            write_packet(&mut connection, &[SSH_AGENT_SIGN_RESPONSE, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let identity = SelectedIdentity::from_openssh(ED25519_KEY, "selected".into()).unwrap();
        let mut connection = AgentConnection::new(&identity, Some(socket.as_os_str()));
        let Action::Respond(response) = connection.handle(&query).await else {
            panic!("extension query required authentication");
        };
        assert!(valid_extension_query_response(&response));
        assert!(
            response
                .windows(24)
                .any(|value| value == b"session-bind@openssh.com")
        );

        let Action::Respond(response) = connection.handle(&extension).await else {
            panic!("extension required authentication");
        };
        assert_eq!(response, [6]);

        let Action::Respond(response) = connection.handle(&sign).await else {
            panic!("upstream key required Agentknock authentication");
        };
        assert_eq!(response, [SSH_AGENT_SIGN_RESPONSE, 0, 0, 0, 0]);
        upstream.await.unwrap();
    }

    #[test]
    fn rejects_malformed_public_keys() {
        let short_ed25519 = ssh_string_sequence(&[b"ssh-ed25519", &[0; 31]]);
        assert!(
            SelectedIdentity::from_openssh(
                &format!("ssh-ed25519 {}", BASE64_STANDARD.encode(short_ed25519)),
                "test-key".into(),
            )
            .is_err()
        );

        let trailing_rsa = ssh_string_sequence(&[b"ssh-rsa", b"exponent", b"modulus", b"extra"]);
        assert!(
            SelectedIdentity::from_openssh(
                &format!("ssh-rsa {}", BASE64_STANDARD.encode(trailing_rsa)),
                "test-key".into(),
            )
            .is_err()
        );
    }

    fn sign_request(key: &[u8], message: &[u8], flags: u32) -> Vec<u8> {
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut request, key);
        put_string(&mut request, message);
        put_u32(&mut request, flags);
        request
    }

    fn extension_request(name: &[u8], contents: &[u8]) -> Vec<u8> {
        let mut request = vec![SSH_AGENTC_EXTENSION];
        put_string(&mut request, name);
        request.extend_from_slice(contents);
        request
    }

    fn authentication_message(
        algorithm: &[u8],
        key: &[u8],
        method: &[u8],
        host_key: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        put_string(&mut message, b"session identifier");
        message.push(SSH_MSG_USERAUTH_REQUEST);
        put_string(&mut message, b"user");
        put_string(&mut message, b"ssh-connection");
        put_string(&mut message, method);
        message.push(1);
        put_string(&mut message, algorithm);
        put_string(&mut message, key);
        if let Some(host_key) = host_key {
            put_string(&mut message, host_key);
        }
        message
    }

    fn ssh_string_sequence(values: &[&[u8]]) -> Vec<u8> {
        let mut output = Vec::new();
        for value in values {
            put_string(&mut output, value);
        }
        output
    }
}
