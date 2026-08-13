#![cfg(unix)]

use std::{
    env, fs,
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FilePath, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, State},
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
const RESPONSE_EXPORTER_CONTEXT: &[u8] = b"agentknock-v1 response";

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
        .export(RESPONSE_EXPORTER_CONTEXT, &mut exported_secret)
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
    assert_eq!(messages[1].route_id, ROUTE_ID);
    assert_eq!(messages[1].part, "complete");
    assert_eq!(messages[1].body["request"], *request);
    let completion = &messages[1].body["completion"];
    assert_eq!(completion.as_object().unwrap().len(), 3);
    assert!(completion.get("version").is_none());
    assert_eq!(completion["pairing_id"], PAIRING_ID);
    assert_eq!(completion["key"], request["key"]);
    assert_eq!(messages[0].request_id, messages[1].request_id);

    let (request_plaintext, completion_plaintext) =
        decrypt_messages(&home.route_private_key, &messages);
    assert_eq!(
        request_plaintext,
        json!({
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
            .contains("request denied (PolicyDenied): profile is not allowed for this command")
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
