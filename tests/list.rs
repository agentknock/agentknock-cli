#![cfg(unix)]

mod support;

use std::process::Command;

use serde_json::json;
use tokio::io::AsyncWriteExt as _;

use support::{
    TestHome, accept, assert_authenticated_request, encrypt_response, open_completion,
    open_request, receive_json, send_json, websocket_server,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_profile_metadata_without_secret_values() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&upgrade);
        let frame = receive_json(&mut socket).await;
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &frame["payload"]);
        assert_eq!(plaintext["method"], "ProfileList");
        assert_eq!(plaintext["cli_version"], env!("CARGO_PKG_VERSION"));

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
                "payload": encrypt_response(
                    &context,
                    &key,
                    &json!({
                        "profiles": {
                            "github": {
                                "description": "GitHub API access",
                                "type": "environment",
                                "variables": ["GH_TOKEN"],
                            },
                            "cloudflare": {
                                "description": "Cloudflare deployment access",
                                "type": "environment",
                                "variables": ["CF_API_TOKEN", "CF_ACCOUNT_ID"],
                            },
                        },
                    }),
                ),
            }),
        )
        .await;
        let response_ack = receive_json(&mut socket).await;
        assert_eq!(response_ack["kind"], "response");
        let completion = receive_json(&mut socket).await;
        assert_eq!(
            open_completion(&mut context, &completion["payload"]),
            json!({
                "cli_version": env!("CARGO_PKG_VERSION")
            })
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
        .args(["profile", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!({
            "profiles": {
                "cloudflare": {
                    "description": "Cloudflare deployment access",
                    "type": "environment",
                    "variables": ["CF_ACCOUNT_ID", "CF_API_TOKEN"],
                },
                "github": {
                    "description": "GitHub API access",
                    "type": "environment",
                    "variables": ["GH_TOKEN"],
                },
            },
        })
    );
    server.await.unwrap();
}

#[test]
fn reports_when_no_pairing_exists() {
    let home = TestHome::empty();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .args(["profile", "list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Agentknock is not paired")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_inactive_client_without_suggesting_recovery() {
    let home = TestHome::active();
    let (relay_url, server) = websocket_server(|listener| async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    })
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args(["profile", "list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("paired client is not active"), "{stderr}");
    assert!(!stderr.contains("Suggested action:"), "{stderr}");
    server.await.unwrap();
}
