#![cfg(unix)]

mod support;

use std::{
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use serde_json::json;
use tokio::io::AsyncWriteExt as _;

use support::{
    TestHome, accept, assert_authenticated_request, encrypt_response, http_connect_proxy,
    open_completion, open_request, receive_json, send_json, websocket_server,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_secret_metadata_without_secret_values() {
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
        assert_eq!(plaintext["method"], "SecretList");
        assert_eq!(plaintext["app_info"]["name"], "agentknock");
        assert_eq!(plaintext["app_info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(plaintext["lib_info"]["name"], "agentknock");
        assert_eq!(plaintext["lib_info"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(plaintext.get("cli_version").is_none());

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
                        "secrets": {
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
                            "production-ssh": {
                                "description": "Production host access",
                                "type": "ssh",
                                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample user@host",
                            },
                            "future": {
                                "description": "A future secret type",
                                "type": "future_type",
                                "future_metadata": {"value": true},
                                "variables": {"different": "shape"},
                                "public_key": 42,
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
                "app_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "lib_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
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
    let (proxy_url, proxy) = http_connect_proxy().await;

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("ALL_PROXY", proxy_url)
        .env_remove("all_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .args(["secret", "list"])
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
            "secrets": {
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
                "production-ssh": {
                    "description": "Production host access",
                    "type": "ssh",
                    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample user@host",
                },
                "future": {
                    "description": "A future secret type",
                    "type": "future_type",
                },
            },
        })
    );
    server.await.unwrap();
    proxy.await.unwrap();
}

#[test]
fn reports_when_no_pairing_exists() {
    let home = TestHome::empty();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .args(["secret", "list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Agentknock isn't paired")
    );
}

#[test]
fn reports_an_invalid_https_proxy() {
    let home = TestHome::active();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("HTTPS_PROXY", "not a proxy URL")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .args(["secret", "list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr).unwrap().contains(
            "invalid proxy configuration: HTTPS_PROXY does not contain a valid proxy URL"
        )
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
        .args(["secret", "list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("paired client is inactive"), "{stderr}");
    assert!(!stderr.contains("Suggested action:"), "{stderr}");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_cancels_a_waiting_secret_list_request() {
    let home = TestHome::active();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": request["client_id"],
                "request_id": request["request_id"],
                "kind": "request",
            }),
        )
        .await;
        ready_sender.send(()).unwrap();
        release_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
    })
    .await;

    let child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args(["secret", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready_receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    interrupt(&child);
    release_sender.send(()).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("canceled the secret list request")
    );
    server.await.unwrap();
}

fn interrupt(child: &std::process::Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}
