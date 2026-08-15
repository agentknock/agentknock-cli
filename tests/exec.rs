#![cfg(unix)]

mod support;

use std::{
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use futures_util::SinkExt as _;
use serde_json::{Value, json};
use tokio_websockets::Message;

use support::{
    TestHome, accept, assert_authenticated_request, encrypt_response, open_completion,
    open_request, receive_json, send_json, websocket_server,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_credentials_and_executes_with_the_returned_environment() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&upgrade);

        let frame = receive_json(&mut socket).await;
        assert_eq!(frame["type"], "message");
        assert_eq!(frame["kind"], "request");
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let request = frame["payload"].clone();
        assert!(request.get("pairing_id").is_none());
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &request);
        assert_eq!(plaintext["method"], "CredentialRequest");
        assert_eq!(plaintext["profiles"], json!(["github", "cloudflare"]));
        assert_eq!(plaintext["reason"], "integration test");
        assert_eq!(plaintext["operation"]["command"], "env");
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
                "type": "receipt",
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
                        "result": "APPROVED",
                        "environment": {"AGENTKNOCK_EXEC_TEST": "secret"},
                    }),
                ),
            }),
        )
        .await;

        let response_ack = receive_json(&mut socket).await;
        assert_eq!(response_ack["type"], "ack");
        assert_eq!(response_ack["kind"], "response");

        let completion = receive_json(&mut socket).await;
        assert_eq!(completion["type"], "message");
        assert_eq!(completion["kind"], "completion");
        let completion_plaintext = open_completion(&mut context, &completion["payload"]);
        assert_eq!(completion_plaintext["result"], "APPROVED");
        assert!(completion_plaintext.get("environment").is_none());
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

        plaintext
    })
    .await;

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args([
            "--exec",
            "github,cloudflare",
            "--reason",
            "integration test",
            "--",
            "env",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .any(|line| line == "AGENTKNOCK_EXEC_TEST=secret")
    );
    assert_eq!(output.stderr, b"");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resends_the_exact_request_when_the_connection_closes_before_ack() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (first_upgrade, mut first_socket) = accept(&listener).await;
        assert_authenticated_request(&first_upgrade);
        let first = receive_json(&mut first_socket).await;
        first_socket.send(Message::close(None, "")).await.unwrap();
        drop(first_socket);

        let (second_upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&second_upgrade);
        let second = receive_json(&mut socket).await;
        assert_eq!(second, first);
        let client_id = second["client_id"].as_str().unwrap().to_owned();
        let request_id = second["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, _) =
            open_request(&device_private_key, &request_id, &second["payload"]);
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
                    &json!({"result": "APPROVED", "environment": {}}),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        let _: Value = open_completion(&mut context, &completion["payload"]);
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
        .args(["--exec", "github", "--", "env"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumes_after_request_ack_and_replays_an_unacknowledged_completion() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut first_socket) = accept(&listener).await;
        let request = receive_json(&mut first_socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        send_json(
            &mut first_socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": request_id,
                "kind": "request",
            }),
        )
        .await;
        first_socket.send(Message::close(None, "")).await.unwrap();
        drop(first_socket);

        let (_, mut second_socket) = accept(&listener).await;
        let resume = receive_json(&mut second_socket).await;
        assert_eq!(resume["type"], "resume");
        assert_eq!(resume["request_id"], request_id);
        send_json(
            &mut second_socket,
            json!({
                "type": "state",
                "client_id": client_id,
                "request_id": request_id,
                "exchange": "open",
                "request": "accepted",
                "response": "absent",
                "completion": "absent",
            }),
        )
        .await;
        let (mut context, key, _) =
            open_request(&device_private_key, &request_id, &request["payload"]);
        send_json(
            &mut second_socket,
            json!({
                "type": "message",
                "client_id": client_id,
                "request_id": request_id,
                "kind": "response",
                "payload": encrypt_response(
                    &context,
                    &key,
                    &json!({"result": "APPROVED", "environment": {}}),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut second_socket).await["kind"], "response");
        let first_completion = receive_json(&mut second_socket).await;
        let _: Value = open_completion(&mut context, &first_completion["payload"]);
        second_socket.send(Message::close(None, "")).await.unwrap();
        drop(second_socket);

        let (_, mut third_socket) = accept(&listener).await;
        let resume = receive_json(&mut third_socket).await;
        assert_eq!(resume["type"], "resume");
        send_json(
            &mut third_socket,
            json!({
                "type": "state",
                "client_id": client_id,
                "request_id": request_id,
                "exchange": "open",
                "request": "delivered",
                "response": "delivered",
                "completion": "absent",
            }),
        )
        .await;
        let second_completion = receive_json(&mut third_socket).await;
        assert_eq!(second_completion, first_completion);
        send_json(
            &mut third_socket,
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
        .args(["--exec", "github", "--", "env"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_before_response_sends_an_aborted_completion() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, _, _) =
            open_request(&device_private_key, &request_id, &request["payload"]);
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
        ready_sender.send(()).unwrap();
        release_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        let completion = receive_json(&mut socket).await;
        let plaintext = open_completion(&mut context, &completion["payload"]);
        assert_eq!(plaintext["result"], "ABORTED");
        assert_eq!(plaintext["reason"], "CANCELLED");
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

    let child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args(["--exec", "github", "--", "env"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready_receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    interrupt(&child);
    release_sender.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("A signal interrupted"));
    assert!(!stderr.contains("Suggested action:"));
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_after_response_keeps_the_approved_completion_and_does_not_exec() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, _) =
            open_request(&device_private_key, &request_id, &request["payload"]);
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
                        "result": "APPROVED",
                        "environment": {"AGENTKNOCK_MUST_NOT_EXEC": "yes"},
                    }),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        let plaintext = open_completion(&mut context, &completion["payload"]);
        assert_eq!(plaintext["result"], "APPROVED");
        ready_sender.send(()).unwrap();
        release_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
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

    let child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args(["--exec", "github", "--", "env"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready_receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    interrupt(&child);
    release_sender.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("AGENTKNOCK_MUST_NOT_EXEC")
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("A signal interrupted"));
    assert!(!stderr.contains("Suggested action:"));
    server.await.unwrap();
}

fn interrupt(child: &std::process::Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}
