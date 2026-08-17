#![cfg(unix)]

mod support;

use std::{fs, os::unix::fs::PermissionsExt as _, process::Command};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE},
};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, PskBundle, Serializable,
    hybrid_array::Array,
    kdf::{HkdfSha256, Kdf as KdfTrait},
    setup_receiver,
};
use serde_json::{Value, json};
use sha2::Sha256;
use ulid::Ulid;

use support::{
    Aead, DEVICE_ID, Kem, PROTOCOL_VERSION_INFO, ReceiverContext, TestHome, accept,
    assert_authenticated_request, encrypt_response, open_completion, open_request, receive_json,
    send_json, websocket_server,
};

const ADDRESS_ID: &str = "9e6f33bf47382846903dffa0962ea313";
const DEVICE_RANDOM: [u8; 32] = [0x55; 32];
const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
const SAS_DERIVATION_INFO: &[u8] = b"agentknock-v1 sas";
const SAS_DECIMAL_MODULUS: u64 = 1_000_000_000_000;

struct PairingResult {
    client_id: String,
    client_token: String,
    client_psk: Vec<u8>,
    sas: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starts_and_finishes_pairing_over_websockets() {
    let home = TestHome::empty();
    let pairing_path = home.pairing_path();
    let device_private_key = home.device_private_key.clone();
    let device_public_key = home.device_public_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        let path = upgrade.uri().path();
        let prefix = format!("/v1/address/{ADDRESS_ID}/request/");
        let client_id = path.strip_prefix(&prefix).unwrap().to_owned();
        assert_eq!(client_id.parse::<Ulid>().unwrap().to_string(), client_id);
        let client_token = upgrade.headers()[http::header::AUTHORIZATION]
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .to_owned();
        assert_eq!(BASE64_URL_SAFE.decode(&client_token).unwrap().len(), 32);

        let request_frame = receive_json(&mut socket).await;
        assert_eq!(request_frame["client_id"], client_id);
        assert_eq!(request_frame["request_id"], client_id);
        assert_eq!(request_frame["kind"], "request");
        assert!(request_frame["payload"].get("method").is_none());
        assert_eq!(request_frame["payload"]["version"], "agentknock-v1");
        let commitment = BASE64_STANDARD
            .decode(request_frame["payload"]["commitment"].as_str().unwrap())
            .unwrap();
        assert_eq!(commitment.len(), 32);
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": client_id,
                "kind": "request",
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "receipt",
                "client_id": client_id,
                "request_id": client_id,
                "kind": "request",
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "message",
                "client_id": client_id,
                "request_id": client_id,
                "kind": "response",
                "payload": {
                    "device_id": DEVICE_ID,
                    "device_key": BASE64_STANDARD.encode(device_public_key.to_bytes()),
                    "device_random": BASE64_STANDARD.encode(DEVICE_RANDOM),
                },
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion_frame = receive_json(&mut socket).await;
        assert_eq!(completion_frame["kind"], "completion");
        assert!(
            pairing_path.exists(),
            "pairing must be durable before completion is sent"
        );

        let completion = &completion_frame["payload"];
        let encapped_key = BASE64_STANDARD
            .decode(completion["key"].as_str().unwrap())
            .unwrap();
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped_key).unwrap();
        let info = [
            PROTOCOL_VERSION_INFO,
            DEVICE_ID.parse::<Ulid>().unwrap().to_bytes(),
            client_id.parse::<Ulid>().unwrap().to_bytes(),
        ]
        .concat();
        let mut context = setup_receiver::<Aead, HkdfSha256, Kem>(
            &OpModeR::Base,
            &device_private_key,
            &encapped_key,
            &info,
        )
        .unwrap();
        let ciphertext = BASE64_STANDARD
            .decode(completion["ciphertext"].as_str().unwrap())
            .unwrap();
        let plaintext: Value =
            serde_json::from_slice(&context.open(&ciphertext, b"").unwrap()).unwrap();
        assert_eq!(plaintext["cli_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(plaintext["platform"], std::env::consts::OS);
        assert_eq!(plaintext["architecture"], std::env::consts::ARCH);
        let client_random = BASE64_STANDARD
            .decode(plaintext["client_random"].as_str().unwrap())
            .unwrap();
        assert_eq!(client_random.len(), 32);
        let expected_commitment = {
            let hkdf = Hkdf::<Sha256>::new(Some(b"agentknock-v1"), &client_random);
            let mut commitment = Array::<u8, <HkdfSha256 as KdfTrait>::Nh>::default();
            hkdf.expand(b"agentknock-v1 commitment", &mut commitment)
                .unwrap();
            commitment
        };
        assert_eq!(commitment.as_slice(), expected_commitment.as_slice());
        let mut client_psk = Array::<u8, <HkdfSha256 as KdfTrait>::Nh>::default();
        context.export(PSK_EXPORT_CONTEXT, &mut client_psk).unwrap();

        let mut sas_info = Vec::new();
        sas_info.extend_from_slice(SAS_DERIVATION_INFO);
        sas_info.extend_from_slice(&DEVICE_ID.parse::<Ulid>().unwrap().to_bytes());
        sas_info.extend_from_slice(&client_id.parse::<Ulid>().unwrap().to_bytes());
        sas_info.extend_from_slice(&device_public_key.to_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(&DEVICE_RANDOM), &client_random);
        let mut sas = [0; 8];
        hkdf.expand(&sas_info, &mut sas).unwrap();
        let sas = u64::from_be_bytes(sas) % SAS_DECIMAL_MODULUS;
        let sas = format!(
            "{:04} {:04} {:04}",
            sas / 100_000_000,
            sas / 10_000 % 10_000,
            sas % 10_000,
        );
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": client_id,
                "kind": "completion",
            }),
        )
        .await;
        drop(socket);

        let (upgrade, mut socket) = accept(&listener).await;
        assert_eq!(
            upgrade.uri().path(),
            format!("/v1/device/{DEVICE_ID}/client/{client_id}")
        );
        assert_eq!(
            upgrade.headers()[http::header::AUTHORIZATION],
            format!("Bearer {client_token}")
        );
        let finish_request = receive_json(&mut socket).await;
        let finish_request_id = finish_request["request_id"].as_str().unwrap().to_owned();
        let (mut finish_context, key, finish_plaintext) = open_authenticated_request(
            &device_private_key,
            &client_id,
            &client_psk,
            &finish_request_id,
            &finish_request["payload"],
        );
        assert_eq!(finish_plaintext["method"], "PairingFinish");
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": finish_request_id,
                "kind": "request",
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "message",
                "client_id": client_id,
                "request_id": finish_request_id,
                "kind": "response",
                "payload": encrypt_response(
                    &finish_context,
                    &key,
                    &json!({"result": "ACCEPTED"}),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let finish_completion = receive_json(&mut socket).await;
        assert_eq!(
            open_completion(&mut finish_context, &finish_completion["payload"])["result"],
            "ACCEPTED"
        );
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": finish_request_id,
                "kind": "completion",
            }),
        )
        .await;

        PairingResult {
            client_id,
            client_token,
            client_psk: client_psk.to_vec(),
            sas,
        }
    })
    .await;

    let start = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", &relay_url)
        .args(["pairing", "start", "yup-its-free"])
        .output()
        .unwrap();
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let pending: Value = serde_json::from_slice(&fs::read(home.pairing_path()).unwrap()).unwrap();
    assert_eq!(pending["pending"], true);
    assert_eq!(pending["device_id"], DEVICE_ID);
    assert!(pending.get("mailbox_id").is_none());
    assert!(pending.get("route_id").is_none());
    assert!(pending.get("pairing_id").is_none());
    assert!(pending.get("pairing_psk").is_none());
    assert!(pending.get("route_key").is_none());
    assert_eq!(
        fs::metadata(home.pairing_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let finish = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", &relay_url)
        .args(["pairing", "finish"])
        .output()
        .unwrap();
    assert!(
        finish.status.success(),
        "{}",
        String::from_utf8_lossy(&finish.stderr)
    );
    assert!(
        String::from_utf8(finish.stdout)
            .unwrap()
            .contains("finished pairing")
    );

    let result = server.await.unwrap();
    assert!(
        String::from_utf8(start.stdout)
            .unwrap()
            .contains(&result.sas)
    );
    let active: Value = serde_json::from_slice(&fs::read(home.pairing_path()).unwrap()).unwrap();
    assert!(active.get("pending").is_none());
    assert_eq!(active["client_id"], result.client_id);
    assert_eq!(active["client_token"], result.client_token);
    assert_eq!(
        BASE64_STANDARD
            .decode(active["client_psk"].as_str().unwrap())
            .unwrap(),
        result.client_psk
    );
    assert_eq!(
        active["device_key"],
        BASE64_STANDARD.encode(home.device_public_key.to_bytes())
    );
}

#[test]
fn abort_pairing_removes_only_a_pending_pairing() {
    let home = TestHome::pending();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .args(["pairing", "abort"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!home.pairing_path().exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removes_pairing_after_an_authenticated_device_response() {
    let home = TestHome::active();
    let pairing_path = home.pairing_path();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&upgrade);
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &request["payload"]);
        assert_eq!(plaintext["method"], "PairingRemove");
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": request_id,
                "kind": "request",
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "message",
                "client_id": client_id,
                "request_id": request_id,
                "kind": "response",
                "payload": encrypt_response(&context, &key, &json!({})),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        assert!(!pairing_path.exists());
        assert_eq!(
            open_completion(&mut context, &completion["payload"]),
            json!({"cli_version": env!("CARGO_PKG_VERSION")})
        );
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": request_id,
                "kind": "completion",
            }),
        )
        .await;
    })
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args(["pairing", "remove"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.pairing_path().exists());
    server.await.unwrap();
}

fn open_authenticated_request(
    device_private_key: &<Kem as KemTrait>::PrivateKey,
    client_id: &str,
    client_psk: &[u8],
    request_id: &str,
    request: &Value,
) -> (ReceiverContext, Vec<u8>, Value) {
    let key = BASE64_STANDARD
        .decode(request["key"].as_str().unwrap())
        .unwrap();
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&key).unwrap();
    let client_id = client_id.parse::<Ulid>().unwrap().to_bytes();
    let info = [
        PROTOCOL_VERSION_INFO,
        DEVICE_ID.parse::<Ulid>().unwrap().to_bytes(),
        request_id.parse::<Ulid>().unwrap().to_bytes(),
    ]
    .concat();
    let psk = PskBundle::new(client_psk, &client_id).unwrap();
    let mut context = setup_receiver::<Aead, HkdfSha256, Kem>(
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
