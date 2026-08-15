#![cfg(unix)]

mod support;

use std::process::Command;

use serde_json::json;

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
        assert_eq!(plaintext["method"], "List");
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
                                "environment": {"GH_TOKEN": "STORED"},
                            },
                            "cloudflare": {
                                "description": "Cloudflare deployment access",
                                "environment": {
                                    "CF_ACCOUNT_ID": "STORED",
                                    "CF_API_TOKEN": "ISSUED",
                                },
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
        .arg("--list")
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
                    "environment": {
                        "CF_ACCOUNT_ID": "STORED",
                        "CF_API_TOKEN": "ISSUED",
                    },
                },
                "github": {
                    "description": "GitHub API access",
                    "environment": {"GH_TOKEN": "STORED"},
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
        .arg("--list")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("AgentKnock is not paired")
    );
}
