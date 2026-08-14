#![cfg(unix)]

use std::{
    env, fs,
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    path::{Path as FilePath, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
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
    aead::{Aead as HpkeAeadTrait, AeadCtxR, ChaCha20Poly1305},
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
type ReceiverContext = AeadCtxR<Aead, Kdf, Kem>;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

const ROUTE_ID: &str = "00112233445566778899aabbccddeeff";
const PAIRING_ID: &str = "ffeeddccbbaa99887766554433221100";
const PAIRING_PSK: [u8; 32] = [0x42; 32];
const PROTOCOL_VERSION_INFO: [u8; 16] = *b"agentknock-v1\0\0\0";
const RESPONSE_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 response";

#[derive(Clone)]
struct TestState {
    route_private_key: <Kem as KemTrait>::PrivateKey,
    request: Arc<Mutex<Option<Value>>>,
    completion: Arc<Mutex<Option<Value>>>,
}

struct TestHome {
    path: PathBuf,
    route_private_key: <Kem as KemTrait>::PrivateKey,
}

impl TestHome {
    fn new() -> Self {
        let path = env::temp_dir().join(format!("agentknock-list-test-{}", Ulid::generate()));
        let config_dir = path.join(".agentknock");
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

        Self {
            path,
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
    assert_eq!(route_id, ROUTE_ID);
    match part.as_str() {
        "request" => {
            let request = &body["request"];
            let (receiver_context, key, plaintext) =
                open_request(&state.route_private_key, &request_id, request);
            *state.request.lock().unwrap() = Some(plaintext);
            let response = json!({
                "profiles": {
                    "github": {
                        "description": "GitHub API access",
                        "environment": {
                            "GH_TOKEN": "STORED"
                        }
                    },
                    "cloudflare": {
                        "description": "Cloudflare deployment access",
                        "environment": {
                            "CF_API_TOKEN": "ISSUED",
                            "CF_ACCOUNT_ID": "STORED"
                        }
                    }
                }
            });
            Json(json!({
                "state": "RESPONSE_DELIVERED",
                "response": encrypt_response(&receiver_context, &key, &response),
            }))
        }
        "complete" => {
            let (mut receiver_context, _, _) =
                open_request(&state.route_private_key, &request_id, &body["request"]);
            let ciphertext = BASE64_STANDARD
                .decode(body["completion"]["ciphertext"].as_str().unwrap())
                .unwrap();
            let plaintext = receiver_context.open(&ciphertext, b"").unwrap();
            *state.completion.lock().unwrap() = Some(serde_json::from_slice(&plaintext).unwrap());
            Json(json!({"state": "COMPLETION_DELIVERED"}))
        }
        part => panic!("unexpected message part: {part}"),
    }
}

fn open_request(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    request_id: &str,
    request: &Value,
) -> (ReceiverContext, Vec<u8>, Value) {
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
    let ciphertext = BASE64_STANDARD
        .decode(request["ciphertext"].as_str().unwrap())
        .unwrap();
    let plaintext = receiver_context.open(&ciphertext, b"").unwrap();

    (
        receiver_context,
        key,
        serde_json::from_slice(&plaintext).unwrap(),
    )
}

fn encrypt_response(receiver_context: &ReceiverContext, key: &[u8], response: &Value) -> Value {
    let mut public_nonce = [0; 32];
    getrandom::fill(&mut public_nonce).unwrap();
    let mut salt = Vec::with_capacity(key.len() + public_nonce.len());
    salt.extend_from_slice(key);
    salt.extend_from_slice(&public_nonce);
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
        "nonce": BASE64_STANDARD.encode(public_nonce),
        "ciphertext": BASE64_STANDARD.encode(ciphertext),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_profile_metadata_without_values() {
    let home = TestHome::new();
    let request = Arc::new(Mutex::new(None));
    let completion = Arc::new(Mutex::new(None));
    let state = TestState {
        route_private_key: home.route_private_key.clone(),
        request: request.clone(),
        completion: completion.clone(),
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
        .arg("--list")
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
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "{\n",
            "  \"profiles\": {\n",
            "    \"cloudflare\": {\n",
            "      \"description\": \"Cloudflare deployment access\",\n",
            "      \"environment\": {\n",
            "        \"CF_ACCOUNT_ID\": \"STORED\",\n",
            "        \"CF_API_TOKEN\": \"ISSUED\"\n",
            "      }\n",
            "    },\n",
            "    \"github\": {\n",
            "      \"description\": \"GitHub API access\",\n",
            "      \"environment\": {\n",
            "        \"GH_TOKEN\": \"STORED\"\n",
            "      }\n",
            "    }\n",
            "  }\n",
            "}\n",
        )
    );
    assert_eq!(*request.lock().unwrap(), Some(json!({"method": "List"})));
    assert_eq!(*completion.lock().unwrap(), Some(json!({})));
}

#[test]
fn explains_that_pairing_is_required() {
    let home = TestHome::new();
    fs::remove_file(home.path().join(".agentknock/pairing.json")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .arg("--list")
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "AgentKnock is not paired. It cannot list profiles.\n",
            "Suggested action: Get a pairing address.\n",
            "Suggested action: Run this command:\n",
            "agentknock --start-pairing <PAIRING_ADDRESS>\n",
        )
    );
}
