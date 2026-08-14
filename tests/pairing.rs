#![cfg(unix)]

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::aead::{Aead as _, Key as AeadKey, KeyInit as _, Nonce as AeadNonce};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, PskBundle, Serializable,
    aead::{Aead as HpkeAeadTrait, AeadCtxR, ChaCha20Poly1305},
    hybrid_array::Array,
    kdf::{HkdfSha256, Kdf as KdfTrait},
    kem::X25519HkdfSha256,
    setup_receiver,
};
use serde_json::{Value, json};
use sha2::Sha256;
use ulid::Ulid;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type PairingPsk = Array<u8, <Kdf as KdfTrait>::Nh>;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

const PAIRING_ID: &str = "ffeeddccbbaa99887766554433221100";
const BASE_DERIVATION_SALT: &[u8] = b"agentknock-v1";
const COMMITMENT_DERIVATION_INFO: &[u8] = b"agentknock-v1 commitment";
const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
const RESPONSE_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 response";
const SAS_DERIVATION_INFO: &[u8] = b"agentknock-v1 sas";
const SAS_DECIMAL_MODULUS: u64 = 1_000_000_000_000;
const ROUTE_ID: &str = "0b7d7963604cba911e9c03e727688b89";

#[derive(Debug)]
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
    route_public_key: <Kem as KemTrait>::PublicKey,
    pairing_psk: Arc<Mutex<Option<Vec<u8>>>>,
    sas: Arc<Mutex<Option<String>>>,
    contents: Arc<Mutex<Option<Value>>>,
    commitment_matches: Arc<Mutex<Option<bool>>>,
    finish_result: Value,
    finish_request: Arc<Mutex<Option<Value>>>,
    finish_completion: Arc<Mutex<Option<Value>>>,
}

struct TestHome(PathBuf);

impl TestHome {
    fn new() -> Self {
        let path = env::temp_dir().join(format!("agentknock-pairing-test-{}", Ulid::generate()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write_pending_pairing(
        &self,
        route_public_key: &<Kem as KemTrait>::PublicKey,
        pairing_psk: &[u8],
    ) -> PathBuf {
        let directory = self.path().join(".agentknock");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("pairing.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "pending": true,
                "route_id": ROUTE_ID,
                "pairing_id": PAIRING_ID,
                "pairing_psk": BASE64_STANDARD.encode(pairing_psk),
                "route_key": BASE64_STANDARD.encode(route_public_key.to_bytes()),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn receive_message(
    State(state): State<TestState>,
    AxumPath((route_id, request_id, part)): AxumPath<(String, String, String)>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let response = match part.as_str() {
        "request" if body["request"].get("commitment").is_some() => json!({
            "state": "RESPONSE_DELIVERED",
            "response": {
                "pairing_id": PAIRING_ID,
                "route_key": BASE64_STANDARD.encode(state.route_public_key.to_bytes()),
            },
        }),
        "request" => {
            let pairing_psk = state.pairing_psk.lock().unwrap().clone().unwrap();
            let (response, request) = encrypt_finish_response(
                &state.route_private_key,
                &pairing_psk,
                &route_id,
                &request_id,
                &body,
                &state.finish_result,
            );
            *state.finish_request.lock().unwrap() = Some(request);

            json!({
                "state": "RESPONSE_DELIVERED",
                "response": response,
            })
        }
        "complete" if body["completion"].get("key").is_some() => {
            let completion = &body["completion"];
            let key = BASE64_STANDARD
                .decode(completion["key"].as_str().unwrap())
                .unwrap();
            let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&key).unwrap();
            let ciphertext = BASE64_STANDARD
                .decode(completion["ciphertext"].as_str().unwrap())
                .unwrap();
            let pairing_id = u128::from_str_radix(PAIRING_ID, 16).unwrap().to_be_bytes();
            let route_id = u128::from_str_radix(&route_id, 16).unwrap().to_be_bytes();
            let request_id = request_id.parse::<Ulid>().unwrap();
            let info = [route_id, pairing_id, request_id.to_bytes()].concat();
            let mut receiver_context = setup_receiver::<Aead, Kdf, Kem>(
                &OpModeR::Base,
                &state.route_private_key,
                &encapped_key,
                &info,
            )
            .unwrap();
            let plaintext = receiver_context.open(&ciphertext, b"").unwrap();
            let contents: Value = serde_json::from_slice(&plaintext).unwrap();
            let client_random = BASE64_STANDARD
                .decode(contents["client_random"].as_str().unwrap())
                .unwrap();
            let hkdf = Hkdf::<Sha256>::new(Some(BASE_DERIVATION_SALT), b"yup-its-free");
            let mut commitment = PairingPsk::default();
            hkdf.expand(COMMITMENT_DERIVATION_INFO, &mut commitment)
                .unwrap();
            *state.commitment_matches.lock().unwrap() =
                Some(body["request"]["commitment"] == BASE64_STANDARD.encode(commitment));
            *state.contents.lock().unwrap() = Some(contents);
            let mut pairing_psk = PairingPsk::default();
            receiver_context
                .export(PSK_EXPORT_CONTEXT, &mut pairing_psk)
                .unwrap();
            *state.pairing_psk.lock().unwrap() = Some(pairing_psk.to_vec());
            let mut sas_ikm = client_random;
            sas_ikm.extend_from_slice(&state.route_public_key.to_bytes());
            let hkdf = Hkdf::<Sha256>::new(Some(&pairing_id), &sas_ikm);
            let mut sas = [0; 8];
            hkdf.expand(SAS_DERIVATION_INFO, &mut sas).unwrap();
            let sas = u64::from_be_bytes(sas) % SAS_DECIMAL_MODULUS;
            *state.sas.lock().unwrap() = Some(format!(
                "{:04} {:04} {:04}\n",
                sas / 100_000_000,
                sas / 10_000 % 10_000,
                sas % 10_000,
            ));

            json!({"state": "COMPLETION_DELIVERED"})
        }
        "complete" => {
            let pairing_psk = state.pairing_psk.lock().unwrap().clone().unwrap();
            let completion = decrypt_finish_completion(
                &state.route_private_key,
                &pairing_psk,
                &route_id,
                &request_id,
                &body,
            );
            *state.finish_completion.lock().unwrap() = Some(completion);

            json!({"state": "COMPLETION_DELIVERED"})
        }
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

fn finish_receiver_context(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    pairing_psk: &[u8],
    route_id: &str,
    request_id: &str,
    body: &Value,
) -> (AeadCtxR<Aead, Kdf, Kem>, Vec<u8>) {
    let request = &body["request"];
    let key = BASE64_STANDARD
        .decode(request["key"].as_str().unwrap())
        .unwrap();
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&key).unwrap();
    let route_id = u128::from_str_radix(route_id, 16).unwrap().to_be_bytes();
    let pairing_id = u128::from_str_radix(PAIRING_ID, 16).unwrap().to_be_bytes();
    let request_id = request_id.parse::<Ulid>().unwrap();
    let info = [route_id, pairing_id, request_id.to_bytes()].concat();
    let psk = PskBundle::new(pairing_psk, &pairing_id).unwrap();
    let context = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Psk(psk),
        route_private_key,
        &encapped_key,
        &info,
    )
    .unwrap();

    (context, key)
}

fn encrypt_finish_response(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    pairing_psk: &[u8],
    route_id: &str,
    request_id: &str,
    body: &Value,
    response: &Value,
) -> (Value, Value) {
    let (mut receiver_context, key) =
        finish_receiver_context(route_private_key, pairing_psk, route_id, request_id, body);
    let ciphertext = BASE64_STANDARD
        .decode(body["request"]["ciphertext"].as_str().unwrap())
        .unwrap();
    let request = receiver_context.open(&ciphertext, b"").unwrap();

    let mut random_nonce = [0; 32];
    getrandom::fill(&mut random_nonce).unwrap();
    let mut salt = Vec::with_capacity(key.len() + random_nonce.len());
    salt.extend_from_slice(&key);
    salt.extend_from_slice(&random_nonce);
    let mut exported_secret = PairingPsk::default();
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

    (
        json!({
            "nonce": BASE64_STANDARD.encode(random_nonce),
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
        }),
        serde_json::from_slice(&request).unwrap(),
    )
}

fn decrypt_finish_completion(
    route_private_key: &<Kem as KemTrait>::PrivateKey,
    pairing_psk: &[u8],
    route_id: &str,
    request_id: &str,
    body: &Value,
) -> Value {
    let (mut receiver_context, _) =
        finish_receiver_context(route_private_key, pairing_psk, route_id, request_id, body);
    let request = BASE64_STANDARD
        .decode(body["request"]["ciphertext"].as_str().unwrap())
        .unwrap();
    receiver_context.open(&request, b"").unwrap();
    let completion = BASE64_STANDARD
        .decode(body["completion"]["ciphertext"].as_str().unwrap())
        .unwrap();
    let completion = receiver_context.open(&completion, b"").unwrap();

    serde_json::from_slice(&completion).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starts_and_finishes_pairing_message_exchanges() {
    let home = TestHome::new();
    let messages = ReceivedMessages::default();
    let pairing_psk = Arc::new(Mutex::new(None));
    let sas = Arc::new(Mutex::new(None));
    let contents = Arc::new(Mutex::new(None));
    let commitment_matches = Arc::new(Mutex::new(None));
    let finish_request = Arc::new(Mutex::new(None));
    let finish_completion = Arc::new(Mutex::new(None));
    let (route_private_key, route_public_key) = Kem::gen_keypair();
    let encoded_route_key = BASE64_STANDARD.encode(route_public_key.to_bytes());
    let state = TestState {
        messages: messages.clone(),
        route_private_key,
        route_public_key,
        pairing_psk: pairing_psk.clone(),
        sas: sas.clone(),
        contents: contents.clone(),
        commitment_matches: commitment_matches.clone(),
        finish_result: json!({"result": "ACCEPTED"}),
        finish_request: finish_request.clone(),
        finish_completion: finish_completion.clone(),
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
        .args(["--start-pairing", "yup-its-free"])
        .env("AGENTKNOCK_TEST_RELAY_URL", &relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    let repeated_start = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--start-pairing", "yup-its-free"])
        .env("AGENTKNOCK_TEST_RELAY_URL", &relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        *sas.lock().unwrap().as_ref().unwrap()
    );
    assert!(!repeated_start.status.success());
    assert!(
        String::from_utf8(repeated_start.stderr)
            .unwrap()
            .contains("already exists")
    );
    {
        let start_messages = messages.lock().unwrap();
        assert_eq!(start_messages.len(), 2);
        assert_eq!(start_messages[0].route_id, ROUTE_ID);
        assert_eq!(start_messages[0].part, "request");
        assert!(start_messages[0].request_id.parse::<Ulid>().is_ok());
        assert_eq!(start_messages[0].body["request"]["version"], 1);
        assert_eq!(
            BASE64_STANDARD
                .decode(
                    start_messages[0].body["request"]["commitment"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .len(),
            PairingPsk::default().len()
        );
        assert_eq!(start_messages[1].route_id, ROUTE_ID);
        assert_eq!(start_messages[1].request_id, start_messages[0].request_id);
        assert_eq!(start_messages[1].part, "complete");
        assert_eq!(
            start_messages[1].body["request"],
            start_messages[0].body["request"]
        );
        assert_eq!(
            start_messages[1].body["completion"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
    }
    assert_eq!(*commitment_matches.lock().unwrap(), Some(true));

    {
        let contents = contents.lock().unwrap();
        let contents = contents.as_ref().unwrap();
        assert_eq!(
            BASE64_STANDARD
                .decode(contents["client_random"].as_str().unwrap())
                .unwrap()
                .len(),
            PairingPsk::default().len()
        );
        if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
            assert_eq!(contents["hostname"], hostname.trim());
        }
        if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
            assert_eq!(contents["machine_id"], machine_id.trim());
        }
        if let Ok(os_release) = fs::read_to_string("/etc/os-release")
            && let Some(version) = os_release
                .lines()
                .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        {
            assert_eq!(contents["os_version"], version.trim_matches('"'));
        }
    }

    let pairing_path = home.path().join(".agentknock/pairing.json");
    assert_eq!(
        fs::metadata(&pairing_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let pairing: Value = serde_json::from_slice(&fs::read(&pairing_path).unwrap()).unwrap();
    assert_eq!(pairing["pending"], true);
    assert_eq!(pairing["route_id"], ROUTE_ID);
    assert_eq!(pairing["pairing_id"], PAIRING_ID);
    assert_eq!(pairing["route_key"], encoded_route_key);
    assert_eq!(
        BASE64_STANDARD
            .decode(pairing["pairing_psk"].as_str().unwrap())
            .unwrap(),
        pairing_psk.lock().unwrap().as_ref().unwrap().as_slice()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["--exec", "gh-token", "--", "true"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("is still pending")
    );

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .arg("--finish-pairing")
        .env("AGENTKNOCK_TEST_RELAY_URL", &relay_url)
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let active_pairing: Value = serde_json::from_slice(&fs::read(&pairing_path).unwrap()).unwrap();
    let mut expected_pairing = pairing;
    expected_pairing.as_object_mut().unwrap().remove("pending");
    assert_eq!(active_pairing, expected_pairing);
    assert_eq!(
        fs::metadata(&pairing_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        *finish_request.lock().unwrap(),
        Some(json!({"method": "FinishPairing"}))
    );
    assert_eq!(
        *finish_completion.lock().unwrap(),
        Some(json!({"result": "ACCEPTED"}))
    );
    {
        let messages = messages.lock().unwrap();
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[2].route_id, ROUTE_ID);
        assert_eq!(messages[2].part, "request");
        assert_ne!(messages[2].request_id, messages[0].request_id);
        assert_eq!(messages[3].route_id, ROUTE_ID);
        assert_eq!(messages[3].request_id, messages[2].request_id);
        assert_eq!(messages[3].part, "complete");
        assert_eq!(messages[3].body["request"], messages[2].body["request"]);
    }

    server.abort();
    let _ = server.await;

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .arg("--finish-pairing")
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no pending pairing exists")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaves_rejected_pairing_pending() {
    let home = TestHome::new();
    let messages = ReceivedMessages::default();
    let pairing_psk = vec![0x42; PairingPsk::default().len()];
    let (route_private_key, route_public_key) = Kem::gen_keypair();
    let pairing_path = home.write_pending_pairing(&route_public_key, &pairing_psk);
    let finish_request = Arc::new(Mutex::new(None));
    let finish_completion = Arc::new(Mutex::new(None));
    let state = TestState {
        messages: messages.clone(),
        route_private_key,
        route_public_key,
        pairing_psk: Arc::new(Mutex::new(Some(pairing_psk))),
        sas: Arc::new(Mutex::new(None)),
        contents: Arc::new(Mutex::new(None)),
        commitment_matches: Arc::new(Mutex::new(None)),
        finish_result: json!({"result": "REJECTED"}),
        finish_request: finish_request.clone(),
        finish_completion: finish_completion.clone(),
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
        .arg("--finish-pairing")
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
            .contains("pairing was rejected")
    );
    let pairing: Value = serde_json::from_slice(&fs::read(pairing_path).unwrap()).unwrap();
    assert_eq!(pairing["pending"], true);
    assert_eq!(
        *finish_request.lock().unwrap(),
        Some(json!({"method": "FinishPairing"}))
    );
    assert_eq!(*finish_completion.lock().unwrap(), None);
    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].route_id, ROUTE_ID);
    assert_eq!(messages[0].part, "request");
}

#[test]
fn aborts_pending_pairing_without_removing_directory() {
    let home = TestHome::new();
    let directory = home.path().join(".agentknock");
    fs::create_dir(&directory).unwrap();
    let pairing_path = directory.join("pairing.json");
    fs::write(&pairing_path, br#"{"pending":true}"#).unwrap();
    fs::set_permissions(&pairing_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .arg("--abort-pairing")
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!pairing_path.exists());
    assert!(directory.is_dir());

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .arg("--abort-pairing")
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no pending pairing exists")
    );
}
