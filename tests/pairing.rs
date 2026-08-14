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
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, Serializable,
    aead::ChaCha20Poly1305,
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

const PAIRING_ID: &str = "ffeeddccbbaa99887766554433221100";
const BASE_DERIVATION_SALT: &[u8] = b"agentknock-v1";
const COMMITMENT_DERIVATION_INFO: &[u8] = b"agentknock-v1 commitment";
const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
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
        "request" => json!({
            "state": "RESPONSE_DELIVERED",
            "response": {
                "pairing_id": PAIRING_ID,
                "route_key": BASE64_STANDARD.encode(state.route_public_key.to_bytes()),
            },
        }),
        "complete" => {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starts_pairing_message_exchange() {
    let home = TestHome::new();
    let messages = ReceivedMessages::default();
    let pairing_psk = Arc::new(Mutex::new(None));
    let sas = Arc::new(Mutex::new(None));
    let contents = Arc::new(Mutex::new(None));
    let commitment_matches = Arc::new(Mutex::new(None));
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

    server.abort();
    let _ = server.await;

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
    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].route_id, ROUTE_ID);
    assert_eq!(messages[0].part, "request");
    assert!(messages[0].request_id.parse::<Ulid>().is_ok());
    assert_eq!(messages[0].body["request"]["version"], 1);
    assert_eq!(
        BASE64_STANDARD
            .decode(messages[0].body["request"]["commitment"].as_str().unwrap())
            .unwrap()
            .len(),
        PairingPsk::default().len()
    );
    assert_eq!(messages[1].route_id, ROUTE_ID);
    assert_eq!(messages[1].request_id, messages[0].request_id);
    assert_eq!(messages[1].part, "complete");
    assert_eq!(messages[1].body["request"], messages[0].body["request"]);
    assert_eq!(messages[1].body["completion"].as_object().unwrap().len(), 2);
    drop(messages);
    assert_eq!(*commitment_matches.lock().unwrap(), Some(true));

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
