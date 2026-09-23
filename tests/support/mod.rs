#![allow(dead_code)]

use std::{
    ffi::OsStr,
    fs,
    fs::OpenOptions,
    future::Future,
    io::Read as _,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE},
};
use chacha20poly1305::aead::{Aead as _, Key as AeadKey, KeyInit as _, Nonce as AeadNonce};
use futures_util::{SinkExt as _, StreamExt as _};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, PskBundle, Serializable,
    aead::{Aead as HpkeAeadTrait, AeadCtxR, ChaCha20Poly1305},
    hybrid_array::Array,
    kdf::{HkdfSha256, Kdf as HpkeKdfTrait},
    kem::X25519HkdfSha256,
    setup_receiver,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_websockets::{Message, ServerBuilder, WebSocketStream};
use ulid::Ulid;

pub type Aead = ChaCha20Poly1305;
pub type Kdf = HkdfSha256;
pub type Kem = X25519HkdfSha256;
pub type ReceiverContext = AeadCtxR<Aead, Kdf, Kem>;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

pub const DEVICE_ID: &str = "01K2ENXDTW1P3XAR4J7V7C9D0H";
pub const CLIENT_ID: &str = "01K2EP16NWNAGJYF8J1Q2V6P3X";
pub const CLIENT_PSK: [u8; 32] = [0x42; 32];
pub const CLIENT_TOKEN: [u8; 32] = [0x24; 32];
pub const PROTOCOL_VERSION_INFO: [u8; 16] = *b"agentknock-v1\0\0\0";
const RESPONSE_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 response";
// Agentknock honors these even for the loopback test relay.
const PROXY_VARIABLES: [&str; 8] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

pub struct TestHome {
    directory: tempfile::TempDir,
    pub device_private_key: <Kem as KemTrait>::PrivateKey,
    pub device_public_key: <Kem as KemTrait>::PublicKey,
}

impl TestHome {
    pub fn active() -> Self {
        Self::new(false)
    }

    pub fn pending() -> Self {
        Self::new(true)
    }

    fn new(pending: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config_dir = directory.path().join(".agentknock");
        fs::create_dir_all(&config_dir).unwrap();
        let (device_private_key, device_public_key) = Kem::gen_keypair();
        let mut pairing = json!({
            "device_id": DEVICE_ID,
            "client_id": CLIENT_ID,
            "client_token": BASE64_URL_SAFE.encode(CLIENT_TOKEN),
            "client_psk": BASE64_STANDARD.encode(CLIENT_PSK),
            "device_key": BASE64_STANDARD.encode(device_public_key.to_bytes()),
            "rotated_at": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        if pending {
            pairing["pending"] = true.into();
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(config_dir.join("pairing.json"))
            .unwrap();
        serde_json::to_writer_pretty(&mut file, &pairing).unwrap();

        Self {
            directory,
            device_private_key,
            device_public_key,
        }
    }

    pub fn empty() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let (device_private_key, device_public_key) = Kem::gen_keypair();
        Self {
            directory,
            device_private_key,
            device_public_key,
        }
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn pairing_path(&self) -> PathBuf {
        self.directory.path().join(".agentknock/pairing.json")
    }

    pub fn command(&self) -> Command {
        let mut command = isolated_command(env!("CARGO_BIN_EXE_agentknock"));
        command.env("HOME", self.path());
        command
    }

    pub fn relay_command(&self, relay_url: impl AsRef<OsStr>) -> Command {
        let mut command = self.command();
        command.env("AGENTKNOCK_TEST_RELAY_URL", relay_url);
        command
    }
}

/// Builds a command that ignores the developer's Agentknock home and proxies.
pub fn isolated_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_remove("AGENTKNOCK_HOME");
    for variable in PROXY_VARIABLES {
        command.env_remove(variable);
    }
    command
}

pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn interrupt(child: &Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

pub fn wait_for_path(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if child.try_wait().unwrap().is_some() {
            panic!(
                "process exited before creating {}: {}",
                path.display(),
                child_stderr(child)
            );
        }
        assert!(
            Instant::now() < deadline,
            "process didn't create {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Stops the child and returns what it wrote to a piped stderr.
pub fn child_stderr(child: &mut Child) -> String {
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    if let Some(mut input) = child.stderr.take() {
        let _ = input.read_to_string(&mut stderr);
    }
    stderr
}

pub async fn websocket_server<F, Fut, T>(handler: F) -> (String, JoinHandle<T>)
where
    F: FnOnce(TcpListener) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(handler(listener));
    (format!("ws://{address}"), task)
}

pub async fn http_connect_proxy() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut request = Vec::with_capacity(1024);
        loop {
            let mut buffer = [0_u8; 1024];
            let length = client.read(&mut buffer).await.unwrap();
            assert_ne!(length, 0, "proxy client closed during CONNECT request");
            request.extend_from_slice(&buffer[..length]);
            if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 8 * 1024, "CONNECT request is too large");
        }

        let request = std::str::from_utf8(&request).unwrap();
        let authority = request
            .lines()
            .next()
            .unwrap()
            .strip_prefix("CONNECT ")
            .unwrap()
            .strip_suffix(" HTTP/1.1")
            .unwrap();
        let mut relay = TcpStream::connect(authority).await.unwrap();
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        tokio::io::copy_bidirectional(&mut client, &mut relay)
            .await
            .unwrap();
    });
    (format!("http://{address}"), task)
}

pub async fn accept(
    listener: &TcpListener,
) -> (http::Request<()>, WebSocketStream<tokio::net::TcpStream>) {
    let (stream, _) = listener.accept().await.unwrap();
    ServerBuilder::new().accept(stream).await.unwrap()
}

pub async fn receive_json<S>(socket: &mut WebSocketStream<S>) -> Value
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let message = socket.next().await.unwrap().unwrap();
        if message.is_ping() {
            socket
                .send(Message::pong(message.into_payload()))
                .await
                .unwrap();
            continue;
        }
        return serde_json::from_str(message.as_text().expect("expected text frame")).unwrap();
    }
}

pub async fn send_json<S>(socket: &mut WebSocketStream<S>, value: impl Serialize)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    socket
        .send(Message::text(serde_json::to_string(&value).unwrap()))
        .await
        .unwrap();
}

pub fn assert_authenticated_request(request: &http::Request<()>) {
    assert_eq!(
        request.uri().path(),
        format!("/v1/device/{DEVICE_ID}/client/{CLIENT_ID}")
    );
    assert_eq!(
        request.headers()[http::header::AUTHORIZATION],
        format!("Bearer {}", BASE64_URL_SAFE.encode(CLIENT_TOKEN))
    );
}

pub fn open_request(
    device_private_key: &<Kem as KemTrait>::PrivateKey,
    request_id: &str,
    request: &Value,
) -> (ReceiverContext, Vec<u8>, Value) {
    let key = BASE64_STANDARD
        .decode(request["key"].as_str().unwrap())
        .unwrap();
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&key).unwrap();
    let request_id = request_id.parse::<Ulid>().unwrap();
    let device_id = DEVICE_ID.parse::<Ulid>().unwrap().to_bytes();
    let client_id = CLIENT_ID.parse::<Ulid>().unwrap().to_bytes();
    let info = [PROTOCOL_VERSION_INFO, device_id, request_id.to_bytes()].concat();
    let psk = PskBundle::new(&CLIENT_PSK, &client_id).unwrap();
    let mut context = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Psk(psk),
        device_private_key,
        &encapped_key,
        &info,
    )
    .unwrap();
    let ciphertext = BASE64_STANDARD
        .decode(request["ciphertext"].as_str().unwrap())
        .unwrap();
    let plaintext = context.open(&ciphertext, b"").unwrap();
    (context, key, serde_json::from_slice(&plaintext).unwrap())
}

pub fn encrypt_response(context: &ReceiverContext, encapped_key: &[u8], response: &Value) -> Value {
    let public_nonce = [0x77; 32];
    let mut salt = Vec::with_capacity(encapped_key.len() + public_nonce.len());
    salt.extend_from_slice(encapped_key);
    salt.extend_from_slice(&public_nonce);
    let mut exported_secret = ResponseSecret::default();
    context
        .export(RESPONSE_EXPORT_CONTEXT, &mut exported_secret)
        .unwrap();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &exported_secret);
    let mut key = ResponseKey::default();
    hkdf.expand(b"key", &mut key).unwrap();
    let mut nonce = ResponseNonce::default();
    hkdf.expand(b"nonce", &mut nonce).unwrap();
    let ciphertext = ResponseAead::new(&key)
        .encrypt(&nonce, serde_json::to_vec(response).unwrap().as_ref())
        .unwrap();
    json!({
        "nonce": BASE64_STANDARD.encode(public_nonce),
        "ciphertext": BASE64_STANDARD.encode(ciphertext),
    })
}

pub fn open_completion(context: &mut ReceiverContext, completion: &Value) -> Value {
    let ciphertext = BASE64_STANDARD
        .decode(completion["ciphertext"].as_str().unwrap())
        .unwrap();
    let plaintext = context.open(&ciphertext, b"").unwrap();
    serde_json::from_slice(&plaintext).unwrap()
}

/// The device's side of one request exchange.
pub struct ReceivedRequest {
    pub client_id: String,
    pub request_id: String,
    pub context: ReceiverContext,
    pub key: Vec<u8>,
}

impl ReceivedRequest {
    /// Opens a request frame from the test pairing and returns its plaintext.
    pub fn open(
        device_private_key: &<Kem as KemTrait>::PrivateKey,
        frame: &Value,
    ) -> (Self, Value) {
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let (context, key, plaintext) =
            open_request(device_private_key, &request_id, &frame["payload"]);
        let request = Self {
            client_id,
            request_id,
            context,
            key,
        };
        (request, plaintext)
    }

    pub fn ack(&self, kind: &str) -> Value {
        self.frame("ack", kind)
    }

    pub fn receipt(&self) -> Value {
        self.frame("receipt", "request")
    }

    pub fn response(&self, response: &Value) -> Value {
        let mut frame = self.frame("message", "response");
        frame["payload"] = encrypt_response(&self.context, &self.key, response);
        frame
    }

    /// Receives the client's completion and returns its plaintext.
    pub async fn receive_completion<S>(&mut self, socket: &mut WebSocketStream<S>) -> Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let completion = receive_json(socket).await;
        assert_eq!(completion["kind"], "completion");
        open_completion(&mut self.context, &completion["payload"])
    }

    fn frame(&self, frame_type: &str, kind: &str) -> Value {
        json!({
            "type": frame_type,
            "client_id": self.client_id,
            "request_id": self.request_id,
            "kind": kind,
        })
    }
}

pub async fn receive_request<S>(
    socket: &mut WebSocketStream<S>,
    device_private_key: &<Kem as KemTrait>::PrivateKey,
) -> (ReceivedRequest, Value)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    ReceivedRequest::open(device_private_key, &receive_json(socket).await)
}
