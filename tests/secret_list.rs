#![cfg(unix)]

mod support;

use std::{process::Stdio, time::Duration};

use serde_json::json;
use tokio::io::AsyncWriteExt as _;

use support::{
    TestHome, accept, assert_authenticated_request, http_connect_proxy, interrupt, receive_json,
    receive_request, send_json, websocket_server,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lists_secret_metadata_without_secret_values() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&upgrade);
        let (mut request, plaintext) = receive_request(&mut socket, &device_private_key).await;
        assert_eq!(plaintext["method"], "SecretList");
        assert_eq!(plaintext["app_info"]["name"], "agentknock");
        assert_eq!(plaintext["app_info"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(plaintext["lib_info"]["name"], "agentknock");
        assert_eq!(plaintext["lib_info"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(plaintext.get("cli_version").is_none());

        send_json(&mut socket, request.ack("request")).await;
        send_json(
            &mut socket,
            request.response(&json!({
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
            })),
        )
        .await;
        let response_ack = receive_json(&mut socket).await;
        assert_eq!(response_ack["kind"], "response");
        assert_eq!(
            request.receive_completion(&mut socket).await,
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
        send_json(&mut socket, request.ack("completion")).await;
    })
    .await;
    let (proxy_url, proxy) = http_connect_proxy().await;

    let output = home
        .relay_command(relay_url)
        .env("ALL_PROXY", proxy_url)
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
    let output = home.command().args(["secret", "list"]).output().unwrap();
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
    let output = home
        .command()
        .env("HTTPS_PROXY", "not a proxy URL")
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

    let output = home
        .relay_command(relay_url)
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
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
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
        tokio::time::timeout(Duration::from_secs(5), release_receiver)
            .await
            .unwrap()
            .unwrap();
    })
    .await;

    let child = home
        .relay_command(relay_url)
        .args(["secret", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), ready_receiver)
        .await
        .unwrap()
        .unwrap();
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
