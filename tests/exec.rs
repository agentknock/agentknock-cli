#![cfg(unix)]

use std::{
    env, fs,
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FilePath, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response as AxumResponse},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::aead::{Aead as _, Key as AeadKey, KeyInit as _, Nonce as AeadNonce};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, PskBundle, Serializable,
    aead::{Aead as HpkeAeadTrait, ChaCha20Poly1305},
    hybrid_array::Array,
    kdf::{HkdfSha256, Kdf as HpkeKdfTrait},
    kem::X25519HkdfSha256,
    setup_receiver,
};
use serde_json::{Value, json};
use sha2::Sha256;
use ulid::Ulid;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

const ROUTE_ID: &str = "00112233445566778899aabbccddeeff";
const PAIRING_ID: &str = "ffeeddccbbaa99887766554433221100";
const PAIRING_PSK: [u8; 32] = [0x42; 32];
const RESPONSE_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 response";

#[derive(Clone, Debug)]
struct ReceivedMessage {
    route_id: String,
    request_id: String,
    part: String,
    body: Value,
}

type ReceivedMessages = Arc<Mutex<Vec<ReceivedMessage>>>;

#[derive(Clone)]
struct TestState {
    messages: ReceivedMessages,
    route_private_key: <Kem as KemTrait>::PrivateKey,
    response: Value,
}

#[derive(Clone)]
struct RetryTestState {
    route_private_key: <Kem as KemTrait>::PrivateKey,
    request_attempts: Arc<AtomicUsize>,
    completion_attempts: Arc<AtomicUsize>,
}

struct TestHome {
    path: PathBuf,
    route_private_key: <Kem as KemTrait>::PrivateKey,
}

impl TestHome {
    fn new(file_mode: u32) -> Self {
        let home = env::temp_dir().join(format!("agentknock-test-{}", Ulid::generate()));
        let config_dir = home.join(".agentknock");
        fs::create_dir_all(&config_dir).unwrap();
        let (route_private_key, route_public_key) = Kem::gen_keypair();

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(config_dir.join("pairing.json"))
            .unwrap();
        serde_json::to_writer(
            &mut file,
            &json!({
                "route_id": ROUTE_ID,
                "pairing_id": PAIRING_ID,
                "pairing_psk": BASE64_STANDARD.encode(PAIRING_PSK),
                "route_key": BASE64_STANDARD.encode(route_public_key.to_bytes()),
                "rotated_at": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }),
        )
        .unwrap();
        file.set_permissions(fs::Permissions::from_mode(file_mode))
            .unwrap();

        Self {
            path: home,
            route_private_key,
        }
    }

    fn path(&self) -> &FilePath {
        &self.path
    }

    fn set_rotation_key(&self, rotation_key: &str) {
        let path = self.path.join(".agentknock/pairing.json");
        let mut pairing: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        pairing
            .as_object_mut()
            .unwrap()
            .insert("rotation_key".into(), rotation_key.into());
        fs::write(path, serde_json::to_vec(&pairing).unwrap()).unwrap();
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

async fn receive_message(
    State(state): State<TestState>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let response = match part.as_str() {
        "request" => json!({
            "state": "RESPONSE_DELIVERED",
            "response": encrypt_response(
                &state.route_private_key,
                &request_id,
                &body,
                &state.response,
            )
        }),
        "complete" => json!({
            "state": "COMPLETION_DELIVERED"
        }),
        part => panic!("unexpected message part: {part}"),
    };

    state.messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part,
        body,
    });

    Json(response)
}

async fn receive_message_with_retries(
    State(state): State<RetryTestState>,
    Path((_, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> AxumResponse {
    match part.as_str() {
        "request" => match state.request_attempts.fetch_add(1, Ordering::SeqCst) {
            0 => (StatusCode::SERVICE_UNAVAILABLE, [(RETRY_AFTER, "0")]).into_response(),
            1 => Json(json!({"state": "REQUEST_PENDING"})).into_response(),
            2 => Json(json!({"state": "REQUEST_DELIVERED"})).into_response(),
            3 => Json(json!({
                "state": "RESPONSE_PENDING",
                "response": encrypt_response(
                    &state.route_private_key,
                    &request_id,
                    &body,
                    &json!({
                        "result": "APPROVED",
                        "environment": {"AGENTKNOCK_RETRY_TEST": "retried"},
                    }),
                ),
            }))
            .into_response(),
            attempt => panic!("unexpected request attempt {attempt}"),
        },
        "complete" => match state.completion_attempts.fetch_add(1, Ordering::SeqCst) {
            0 => (StatusCode::BAD_GATEWAY, [(RETRY_AFTER, "0")]).into_response(),
            1 => Json(json!({"state": "COMPLETION_PENDING"})).into_response(),
            attempt => panic!("unexpected completion attempt {attempt}"),
        },
        part => panic!("unexpected message part: {part}"),
    }
}

async fn reject_request(State(attempts): State<Arc<AtomicUsize>>) -> StatusCode {
    attempts.fetch_add(1, Ordering::SeqCst);
    StatusCode::BAD_REQUEST
}

async fn return_invalid_encrypted_response(
    State(messages): State<ReceivedMessages>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Json<Value> {
    assert_eq!(part, "request");
    messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part,
        body,
    });

    Json(json!({
        "state": "RESPONSE_DELIVERED",
        "response": {
            "nonce": BASE64_STANDARD.encode([0; 32]),
            "ciphertext": BASE64_STANDARD.encode([0; 16]),
        },
    }))
}

fn encrypt_response(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    request_id: &str,
    body: &Value,
    response: &Value,
) -> Value {
    let request = &body["request"];
    let key = BASE64_STANDARD
        .decode(request["key"].as_str().unwrap())
        .unwrap();
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&key).unwrap();
    let request_id = request_id.parse::<Ulid>().unwrap();
    let route_id = u128::from_str_radix(ROUTE_ID, 16).unwrap().to_be_bytes();
    let pairing_id = u128::from_str_radix(PAIRING_ID, 16).unwrap().to_be_bytes();
    let info = [route_id, pairing_id, request_id.to_bytes()].concat();
    let psk = PskBundle::new(&PAIRING_PSK, &pairing_id).unwrap();
    let mut receiver_context = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Psk(psk),
        route_private_key,
        &encapped_key,
        &info,
    )
    .unwrap();
    let request_ciphertext = BASE64_STANDARD
        .decode(request["ciphertext"].as_str().unwrap())
        .unwrap();
    receiver_context.open(&request_ciphertext, b"").unwrap();

    let mut random_nonce = [0; 32];
    getrandom::fill(&mut random_nonce).unwrap();
    let mut salt = Vec::with_capacity(key.len() + random_nonce.len());
    salt.extend_from_slice(&key);
    salt.extend_from_slice(&random_nonce);
    let mut exported_secret = ResponseSecret::default();
    receiver_context
        .export(RESPONSE_EXPORT_CONTEXT, &mut exported_secret)
        .unwrap();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &exported_secret);
    let mut response_key = ResponseKey::default();
    hkdf.expand(b"key", &mut response_key).unwrap();
    let mut response_nonce = ResponseNonce::default();
    hkdf.expand(b"nonce", &mut response_nonce).unwrap();
    let cipher = ResponseAead::new(&response_key);
    let ciphertext = cipher
        .encrypt(
            &response_nonce,
            serde_json::to_vec(response).unwrap().as_ref(),
        )
        .unwrap();

    json!({
        "nonce": BASE64_STANDARD.encode(random_nonce),
        "ciphertext": BASE64_STANDARD.encode(ciphertext),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exchanges_messages_then_replaces_itself_with_command() {
    let home = TestHome::new(0o600);
    let rotation_key = "cm90YXRpb24ga2V5";
    home.set_rotation_key(rotation_key);
    let messages = ReceivedMessages::default();
    let state = TestState {
        messages: messages.clone(),
        route_private_key: home.route_private_key.clone(),
        response: json!({
            "result": "APPROVED",
            "environment": {
                "AGENTKNOCK_TEST_ONE": "first secret value",
                "AGENTKNOCK_TEST_TWO": "second secret value",
            }
        }),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(receive_message),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args([
            "--reason",
            "needed verbatim: $TOKEN, \"quotes\"",
            "--exec",
            "gh-token,cf-wrangler",
            "--",
            "sh",
            "-c",
            "test \"$AGENTKNOCK_TEST_ONE\" = 'first secret value' && test \"$AGENTKNOCK_TEST_TWO\" = 'second secret value' && printf '%s' \"$$\"",
        ])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let child_id = child.id();
    let output = child.wait_with_output().unwrap();

    server.abort();
    let _ = server.await;

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        child_id.to_string()
    );

    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].route_id, ROUTE_ID);
    assert_eq!(messages[0].part, "request");
    let request = &messages[0].body["request"];
    assert_eq!(request["version"], "1");
    assert_eq!(request["pairing_id"], PAIRING_ID);
    assert_eq!(request["rotation_key"], rotation_key);
    assert_eq!(messages[1].route_id, ROUTE_ID);
    assert_eq!(messages[1].part, "complete");
    assert_eq!(messages[1].body["request"], *request);
    let completion = &messages[1].body["completion"];
    assert_eq!(completion.as_object().unwrap().len(), 1);
    assert!(completion.get("version").is_none());
    assert!(completion.get("pairing_id").is_none());
    assert!(completion.get("key").is_none());
    assert_eq!(messages[0].request_id, messages[1].request_id);

    let pairing: Value =
        serde_json::from_slice(&fs::read(home.path().join(".agentknock/pairing.json")).unwrap())
            .unwrap();
    assert!(pairing.get("rotation_key").is_none());

    let (request_plaintext, completion_plaintext) =
        decrypt_messages(&home.route_private_key, &messages);
    assert_eq!(
        request_plaintext,
        json!({
            "method": "CredentialRequest",
            "profiles": ["gh-token", "cf-wrangler"],
            "operation": "exec",
            "command": "sh",
            "arguments": [
                "-c",
                "test \"$AGENTKNOCK_TEST_ONE\" = 'first secret value' && test \"$AGENTKNOCK_TEST_TWO\" = 'second secret value' && printf '%s' \"$$\""
            ],
            "reason": "needed verbatim: $TOKEN, \"quotes\"",
        })
    );
    assert_eq!(completion_plaintext, json!({"result": "APPROVED"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_rotation_key_when_response_cannot_be_decrypted() {
    let home = TestHome::new(0o600);
    let rotation_key = "cm90YXRpb24ga2V5";
    home.set_rotation_key(rotation_key);
    let messages = ReceivedMessages::default();
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(return_invalid_encrypted_response),
        )
        .with_state(messages.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    server.abort();
    let _ = server.await;

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("response decryption failed")
    );
    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body["request"]["rotation_key"], rotation_key);
    drop(messages);
    let pairing: Value =
        serde_json::from_slice(&fs::read(home.path().join(".agentknock/pairing.json")).unwrap())
            .unwrap();
    assert_eq!(pairing["rotation_key"], rotation_key);
}

fn decrypt_messages(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    messages: &[ReceivedMessage],
) -> (Value, Value) {
    let request = &messages[0].body["request"];
    let completion = &messages[1].body["completion"];
    let key = BASE64_STANDARD
        .decode(request["key"].as_str().unwrap())
        .unwrap();
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&key).unwrap();
    let ciphertext = BASE64_STANDARD
        .decode(request["ciphertext"].as_str().unwrap())
        .unwrap();
    let completion_ciphertext = BASE64_STANDARD
        .decode(completion["ciphertext"].as_str().unwrap())
        .unwrap();
    let request_id = messages[0].request_id.parse::<Ulid>().unwrap();
    let route_id = u128::from_str_radix(ROUTE_ID, 16).unwrap().to_be_bytes();
    let pairing_id = u128::from_str_radix(PAIRING_ID, 16).unwrap().to_be_bytes();
    let info = [route_id, pairing_id, request_id.to_bytes()].concat();
    let psk = PskBundle::new(&PAIRING_PSK, &pairing_id).unwrap();
    let mut receiver_context = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Psk(psk),
        route_private_key,
        &encapped_key,
        &info,
    )
    .unwrap();
    let request_plaintext = receiver_context.open(&ciphertext, b"").unwrap();
    let completion_plaintext = receiver_context.open(&completion_ciphertext, b"").unwrap();

    (
        serde_json::from_slice(&request_plaintext).unwrap(),
        serde_json::from_slice(&completion_plaintext).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copies_denial_to_completion_without_running_command() {
    let home = TestHome::new(0o600);
    let messages = ReceivedMessages::default();
    let state = TestState {
        messages: messages.clone(),
        route_private_key: home.route_private_key.clone(),
        response: json!({
            "result": "DENIED",
            "reason": "POLICY_DENIED",
            "message": "profile is not allowed for this command",
        }),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(receive_message),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "sh", "-c", "printf command-ran"])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    server.abort();
    let _ = server.await;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "denied command was executed");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("request denied (POLICY_DENIED): profile is not allowed for this command")
    );

    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 2);
    let (_, completion) = decrypt_messages(&home.route_private_key, &messages);
    assert_eq!(
        completion,
        json!({
            "result": "DENIED",
            "reason": "POLICY_DENIED",
            "message": "profile is not allowed for this command",
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_pending_states_and_server_errors() {
    let home = TestHome::new(0o600);
    let request_attempts = Arc::new(AtomicUsize::new(0));
    let completion_attempts = Arc::new(AtomicUsize::new(0));
    let state = RetryTestState {
        route_private_key: home.route_private_key.clone(),
        request_attempts: request_attempts.clone(),
        completion_attempts: completion_attempts.clone(),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(receive_message_with_retries),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args([
            "--exec",
            "gh-token",
            "--",
            "sh",
            "-c",
            "test \"$AGENTKNOCK_RETRY_TEST\" = retried",
        ])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    server.abort();
    let _ = server.await;

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(request_attempts.load(Ordering::SeqCst), 4);
    assert_eq!(completion_attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_retry_client_errors() {
    let home = TestHome::new(0o600);
    let attempts = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/request",
            post(reject_request),
        )
        .with_state(attempts.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    server.abort();
    let _ = server.await;

    assert!(!output.status.success());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("400 Bad Request")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_network_errors() {
    let home = TestHome::new(0o600);
    let messages = ReceivedMessages::default();
    let state = TestState {
        messages: messages.clone(),
        route_private_key: home.route_private_key.clone(),
        response: json!({
            "result": "APPROVED",
            "environment": {},
        }),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(receive_message),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (connection, _) = listener.accept().await.unwrap();
        drop(connection);
        axum::serve(listener, app).await.unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    server.abort();
    let _ = server.await;

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(messages.lock().unwrap().len(), 2);
}

#[test]
fn rejects_pairing_file_with_insecure_permissions() {
    let home = TestHome::new(0o644);
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("must have mode 0600, found 0644")
    );
}
