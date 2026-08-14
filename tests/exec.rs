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
    time::{Duration, SystemTime, UNIX_EPOCH},
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
const PROTOCOL_VERSION_INFO: [u8; 16] = *b"agentknock-v1\0\0\0";
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

#[derive(Clone)]
struct FailedRequestState {
    messages: ReceivedMessages,
    request_attempts: Arc<AtomicUsize>,
    completion_attempts: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct SignalTestState {
    messages: ReceivedMessages,
    request_attempts: Arc<AtomicUsize>,
    completion_attempts: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct SignalAfterResponseState {
    messages: ReceivedMessages,
    route_private_key: <Kem as KemTrait>::PrivateKey,
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
            0..=8 | 10..=18 => {
                (StatusCode::SERVICE_UNAVAILABLE, [(RETRY_AFTER, "0")]).into_response()
            }
            9 => Json(json!({"state": "REQUEST_PENDING"})).into_response(),
            19 => Json(json!({
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

async fn reject_message(
    State(state): State<FailedRequestState>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> StatusCode {
    match part.as_str() {
        "request" => &state.request_attempts,
        "complete" => &state.completion_attempts,
        part => panic!("unexpected message part: {part}"),
    }
    .fetch_add(1, Ordering::SeqCst);
    state.messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part,
        body,
    });
    StatusCode::BAD_REQUEST
}

async fn exhaust_request_retries(
    State(state): State<FailedRequestState>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> AxumResponse {
    state.messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part: part.clone(),
        body,
    });
    match part.as_str() {
        "request" => {
            state.request_attempts.fetch_add(1, Ordering::SeqCst);
            (StatusCode::SERVICE_UNAVAILABLE, [(RETRY_AFTER, "0")]).into_response()
        }
        "complete" => match state.completion_attempts.fetch_add(1, Ordering::SeqCst) {
            0 => (StatusCode::BAD_GATEWAY, [(RETRY_AFTER, "0")]).into_response(),
            1 => Json(json!({"state": "COMPLETION_DELIVERED"})).into_response(),
            attempt => panic!("unexpected completion attempt {attempt}"),
        },
        part => panic!("unexpected message part: {part}"),
    }
}

async fn wait_for_signal(
    State(state): State<SignalTestState>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> AxumResponse {
    state.messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part: part.clone(),
        body,
    });

    match part.as_str() {
        "request" => match state.request_attempts.fetch_add(1, Ordering::SeqCst) {
            0 => Json(json!({"state": "REQUEST_PENDING"})).into_response(),
            1 => std::future::pending().await,
            attempt => panic!("unexpected request attempt {attempt}"),
        },
        "complete" => match state.completion_attempts.fetch_add(1, Ordering::SeqCst) {
            0 => (StatusCode::BAD_GATEWAY, [(RETRY_AFTER, "0")]).into_response(),
            1 => Json(json!({"state": "COMPLETION_DELIVERED"})).into_response(),
            attempt => panic!("unexpected completion attempt {attempt}"),
        },
        part => panic!("unexpected message part: {part}"),
    }
}

async fn wait_for_signal_after_response(
    State(state): State<SignalAfterResponseState>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> AxumResponse {
    let response = match part.as_str() {
        "request" => Json(json!({
            "state": "RESPONSE_DELIVERED",
            "response": encrypt_response(
                &state.route_private_key,
                &request_id,
                &body,
                &json!({
                    "result": "APPROVED",
                    "environment": {},
                }),
            ),
        }))
        .into_response(),
        "complete" => match state.completion_attempts.fetch_add(1, Ordering::SeqCst) {
            0 => std::future::pending().await,
            1 => (StatusCode::BAD_GATEWAY, [(RETRY_AFTER, "0")]).into_response(),
            2 => Json(json!({"state": "COMPLETION_DELIVERED"})).into_response(),
            attempt => panic!("unexpected completion attempt {attempt}"),
        },
        part => panic!("unexpected message part: {part}"),
    };

    state.messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part,
        body,
    });
    response
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
    let info = [
        PROTOCOL_VERSION_INFO,
        route_id,
        pairing_id,
        request_id.to_bytes(),
    ]
    .concat();
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
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        child_id.to_string()
    );

    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].route_id, ROUTE_ID);
    assert_eq!(messages[0].part, "request");
    let request = &messages[0].body["request"];
    assert_eq!(request["version"], "agentknock-v1");
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
    let info = [
        PROTOCOL_VERSION_INFO,
        route_id,
        pairing_id,
        request_id.to_bytes(),
    ]
    .concat();
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

fn decrypt_completion(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    messages: &[ReceivedMessage],
) -> Value {
    let request = messages
        .iter()
        .find(|message| message.part == "request")
        .unwrap()
        .clone();
    let completion = messages
        .iter()
        .find(|message| message.part == "complete")
        .unwrap()
        .clone();
    decrypt_messages(route_private_key, &[request, completion]).1
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
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        concat!(
            "AGENTKNOCK: The policy denied the credentials request: profile is not allowed for this command\n",
            "AGENTKNOCK: The command did not start.\n",
        )
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
            "--verbose",
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
    assert_eq!(request_attempts.load(Ordering::SeqCst), 20);
    assert_eq!(completion_attempts.load(Ordering::SeqCst), 2);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(
        "AGENTKNOCK: AgentKnock waits for the phone to receive the credentials request.\n"
    ));
    assert!(stderr.contains(
        "AGENTKNOCK: AgentKnock received the credentials response. AgentKnock completes the request.\n"
    ));
    assert!(stderr.contains("AGENTKNOCK: AgentKnock completed the credentials request.\n"));
    assert!(stderr.contains("AGENTKNOCK: AgentKnock received these environment variables:\n"));
    assert!(stderr.contains("AGENTKNOCK: - AGENTKNOCK_RETRY_TEST\n"));
    assert!(!stderr.contains("retried"));
    assert!(stderr.ends_with("AGENTKNOCK: AgentKnock executes the command: sh.\n"));
    assert!(stderr.lines().all(|line| line.starts_with("AGENTKNOCK: ")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_retry_client_errors() {
    let home = TestHome::new(0o600);
    let messages = ReceivedMessages::default();
    let request_attempts = Arc::new(AtomicUsize::new(0));
    let completion_attempts = Arc::new(AtomicUsize::new(0));
    let state = FailedRequestState {
        messages: messages.clone(),
        request_attempts: request_attempts.clone(),
        completion_attempts: completion_attempts.clone(),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(reject_message),
        )
        .with_state(state);
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
    assert_eq!(request_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(completion_attempts.load(Ordering::SeqCst), 1);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("400 Bad Request")
    );
    let messages = messages.lock().unwrap();
    let completion = decrypt_completion(&home.route_private_key, &messages);
    assert_eq!(completion["result"], "ABORTED");
    assert_eq!(completion["reason"], "CLIENT_ERROR");
    assert!(completion["message"].as_str().unwrap().contains("400"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborts_after_consecutive_server_errors() {
    let home = TestHome::new(0o600);
    let messages = ReceivedMessages::default();
    let request_attempts = Arc::new(AtomicUsize::new(0));
    let completion_attempts = Arc::new(AtomicUsize::new(0));
    let state = FailedRequestState {
        messages: messages.clone(),
        request_attempts: request_attempts.clone(),
        completion_attempts: completion_attempts.clone(),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(exhaust_request_retries),
        )
        .with_state(state);
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
    assert_eq!(request_attempts.load(Ordering::SeqCst), 10);
    assert_eq!(completion_attempts.load(Ordering::SeqCst), 2);
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("after 10 consecutive errors")
    );
    let messages = messages.lock().unwrap();
    let completion = decrypt_completion(&home.route_private_key, &messages);
    assert_eq!(completion["result"], "ABORTED");
    assert_eq!(completion["reason"], "TIMED_OUT");
    assert!(
        completion["message"]
            .as_str()
            .unwrap()
            .contains("after 10 consecutive failures")
    );
}

async fn assert_signal_aborts_credential_request(signal: &str) {
    let home = TestHome::new(0o600);
    let messages = ReceivedMessages::default();
    let request_attempts = Arc::new(AtomicUsize::new(0));
    let completion_attempts = Arc::new(AtomicUsize::new(0));
    let state = SignalTestState {
        messages: messages.clone(),
        request_attempts: request_attempts.clone(),
        completion_attempts: completion_attempts.clone(),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(wait_for_signal),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if request_attempts.load(Ordering::SeqCst) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if request_attempts.load(Ordering::SeqCst) != 2 {
        let _ = child.kill();
        panic!("credential request did not reach the relay");
    }
    let status = Command::new("kill")
        .args([signal, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let mut exit_status = None;
    for _ in 0..700 {
        if let Some(status) = child.try_wait().unwrap() {
            exit_status = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = exit_status.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("agentknock did not exit after receiving {signal}");
    });

    server.abort();
    let _ = server.await;

    assert!(!status.success());
    assert_eq!(completion_attempts.load(Ordering::SeqCst), 2);
    let messages = messages.lock().unwrap();
    assert_eq!(
        decrypt_completion(&home.route_private_key, &messages),
        json!({
            "result": "ABORTED",
            "reason": "CANCELLED",
            "message": "credential request interrupted",
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_aborts_an_outstanding_credential_request() {
    assert_signal_aborts_credential_request("-INT").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_aborts_an_outstanding_credential_request() {
    assert_signal_aborts_credential_request("-TERM").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_after_response_finishes_the_existing_completion_without_execing() {
    let home = TestHome::new(0o600);
    let messages = ReceivedMessages::default();
    let completion_attempts = Arc::new(AtomicUsize::new(0));
    let state = SignalAfterResponseState {
        messages: messages.clone(),
        route_private_key: home.route_private_key.clone(),
        completion_attempts: completion_attempts.clone(),
    };
    let app = Router::new()
        .route(
            "/v1/route/{route_id}/msg/{request_id}/{part}",
            post(wait_for_signal_after_response),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if completion_attempts.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if completion_attempts.load(Ordering::SeqCst) != 1 {
        let _ = child.kill();
        panic!("credential response did not reach completion delivery");
    }
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let mut exit_status = None;
    for _ in 0..700 {
        if let Some(status) = child.try_wait().unwrap() {
            exit_status = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = exit_status.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("agentknock did not exit after receiving SIGINT");
    });

    server.abort();
    let _ = server.await;

    assert!(!status.success(), "requested command was executed");
    assert_eq!(completion_attempts.load(Ordering::SeqCst), 3);
    let messages = messages.lock().unwrap();
    assert_eq!(
        decrypt_completion(&home.route_private_key, &messages),
        json!({"result": "APPROVED"})
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
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("AGENTKNOCK: "));
    assert!(stderr.contains("has mode 0644. Mode 0600 is required"));
    assert!(stderr.contains("AGENTKNOCK: chmod 600 "));
}

#[test]
fn explains_how_to_pair_before_exec() {
    let home = TestHome::new(0o600);
    fs::remove_file(home.path().join(".agentknock/pairing.json")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "AGENTKNOCK: AgentKnock is not paired. The command did not start.\n",
            "AGENTKNOCK: Suggested action: Get a pairing address.\n",
            "AGENTKNOCK: Suggested action: Run this command:\n",
            "AGENTKNOCK: agentknock --start-pairing <PAIRING_ADDRESS>\n",
            "AGENTKNOCK: Suggested action: Complete pairing.\n",
            "AGENTKNOCK: Suggested action: Run the original command again.\n",
        )
    );
}

#[test]
fn quiet_suppresses_agentknock_errors() {
    let home = TestHome::new(0o644);
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--quiet", "--exec", "gh-token", "--", "true"])
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn verbose_reports_immediate_progress_with_prefixed_lines() {
    let home = TestHome::new(0o644);
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--verbose", "--exec", "gh-token", "--", "true"])
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("AGENTKNOCK: AgentKnock prepares the credentials request.\n"));
    assert!(stderr.lines().all(|line| line.starts_with("AGENTKNOCK: ")));
}
