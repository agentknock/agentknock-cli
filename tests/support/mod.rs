#![allow(dead_code)]

use std::{
    env, fs,
    fs::OpenOptions,
    future::Future,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
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

pub struct TestHome {
    path: PathBuf,
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
        let path = env::temp_dir().join(format!("agentknock-test-{}", Ulid::generate()));
        let config_dir = path.join(".agentknock");
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
            path,
            device_private_key,
            device_public_key,
        }
    }

    pub fn empty() -> Self {
        let path = env::temp_dir().join(format!("agentknock-test-{}", Ulid::generate()));
        fs::create_dir(&path).unwrap();
        let (device_private_key, device_public_key) = Kem::gen_keypair();
        Self {
            path,
            device_private_key,
            device_public_key,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pairing_path(&self) -> PathBuf {
        self.path.join(".agentknock/pairing.json")
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
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
