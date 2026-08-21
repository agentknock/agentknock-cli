#![cfg(target_os = "linux")]

mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures_util::SinkExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio_websockets::Message;

use support::{
    TestHome, accept, assert_authenticated_request, encrypt_response, open_completion,
    open_request, receive_json, send_json, websocket_server,
};

fn approved_environment(secret: &str, variables: serde_json::Map<String, Value>) -> Value {
    let secret_name = secret.to_owned();
    let variables = variables
        .into_iter()
        .map(|(name, value)| (name, json!({"value": value})))
        .collect::<serde_json::Map<_, _>>();
    let secret = json!({
        "description": null,
        "type": "environment",
        "variables": variables,
    });
    json!({
        "result": "APPROVED",
        "secrets": serde_json::Map::from_iter([(secret_name, secret)]),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_secret_use_and_executes_with_the_returned_environment() {
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
        assert_eq!(plaintext["method"], "SecretUse");
        assert_eq!(plaintext["secrets"], json!(["cloudflare", "github"]));
        assert_eq!(plaintext["reason"], "integration test");
        assert_eq!(plaintext["operation"]["command"], "env");
        assert_eq!(plaintext["operation"]["executable_mode"], "BINARY");
        let executable_path = plaintext["operation"]["executable_path"].as_str().unwrap();
        let executable_hash = BASE64_STANDARD
            .decode(plaintext["operation"]["executable_hash"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            executable_hash,
            Sha256::digest(fs::read(executable_path).unwrap()).as_slice()
        );
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
                        "secrets": {
                            "github": {
                                "description": "GitHub access",
                                "type": "environment",
                                "variables": {
                                    "AGENTKNOCK_EXEC_TEST": {"value": "secret"},
                                },
                            },
                            "cloudflare": {
                                "description": "Cloudflare access",
                                "type": "environment",
                                "variables": {},
                            }
                        },
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
        assert!(completion_plaintext.get("secrets").is_none());
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
            "exec",
            "-s",
            "github",
            "-s",
            "cloudflare",
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
async fn reports_and_executes_a_shebang_script() {
    let home = TestHome::active();
    let script = home.path().join("script");
    let script_contents = b"#!/bin/sh\nprintf 'script:%s' \"$AGENTKNOCK_SCRIPT_TEST\"\n";
    fs::write(&script, script_contents).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let expected_path = script.to_str().unwrap().to_owned();
    let expected_hash = BASE64_STANDARD.encode(Sha256::digest(script_contents));
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &request["payload"]);
        assert_eq!(plaintext["operation"]["executable_mode"], "SCRIPT");
        assert_eq!(plaintext["operation"]["executable_path"], expected_path);
        assert_eq!(plaintext["operation"]["executable_hash"], expected_hash);
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
                    &approved_environment(
                        "test",
                        serde_json::Map::from_iter([(
                            "AGENTKNOCK_SCRIPT_TEST".into(),
                            "approved".into(),
                        )]),
                    ),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        assert_eq!(
            open_completion(&mut context, &completion["payload"])["result"],
            "APPROVED"
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
        .args(["exec", "-s", "test", "--", script.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"script:approved");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executes_the_selected_native_file_after_its_path_is_replaced() {
    let home = TestHome::active();
    let selected_path = home.path().join("selected-native");
    let replacement_path = home.path().join("replacement-native");
    fs::copy(std::env::current_exe().unwrap(), &selected_path).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_agentknock"), &replacement_path).unwrap();
    let server_selected_path = selected_path.clone();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &request["payload"]);
        assert_eq!(plaintext["operation"]["executable_mode"], "BINARY");
        assert_eq!(
            plaintext["operation"]["executable_path"],
            server_selected_path.to_str().unwrap()
        );
        fs::rename(&replacement_path, &server_selected_path).unwrap();
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
                    &approved_environment(
                        "test",
                        serde_json::Map::from_iter([
                            ("AGENTKNOCK_PINNED_EXEC_TEST".into(), "selected".into()),
                            (
                                "PATH".into(),
                                "/agentknock-returned-path-must-not-be-searched".into(),
                            ),
                        ]),
                    ),
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
        .env("PATH", home.path())
        .arg("exec")
        .arg("-s")
        .arg("test")
        .arg("--")
        .arg("selected-native")
        .args(["--exact", "native_exec_probe", "--nocapture"])
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
            .contains("PINNED_EXECUTABLE=selected")
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restores_sigpipe_before_executing_the_command() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
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
                    &approved_environment("test", serde_json::Map::new()),
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
        .args([
            "exec",
            "-s",
            "test",
            "--",
            "sh",
            "-c",
            "kill -PIPE $$; printf survived",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("survived")
    );
    server.await.unwrap();
}

#[test]
fn native_exec_probe() {
    if let Ok(value) = std::env::var("AGENTKNOCK_PINNED_EXEC_TEST") {
        println!("PINNED_EXECUTABLE={value}");
    }
}

#[test]
fn rejects_a_missing_command_before_requesting_secret_use() {
    let home = TestHome::active();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", "ws://127.0.0.1:1")
        .args([
            "exec",
            "-s",
            "test",
            "--",
            "agentknock-command-that-does-not-exist",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("wasn't found"), "{stderr}");
    assert!(
        stderr.contains("No secret use request was sent."),
        "{stderr}"
    );
    assert!(!stderr.contains("relay"), "{stderr}");
}

#[test]
fn explains_that_the_command_separator_is_required() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["exec", "-s", "github", "gh", "issue", "list"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "error: add `--` before the command to run\n\
         \n\
         Usage: agentknock exec -s <SECRET>... -- <COMMAND> [ARGUMENT]...\n\
         \n\
         For more information, run 'agentknock exec --help'.\n"
    );
}

#[test]
fn rejects_a_duplicate_secret() {
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args(["exec", "-s", "github", "--secret", "github", "--", "true"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "error: secret \"github\" was specified more than once\n\
         \n\
         Usage: agentknock exec -s <SECRET>... -- <COMMAND> [ARGUMENT]...\n\
         \n\
         For more information, run 'agentknock exec --help'.\n"
    );
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
                    &approved_environment("github", serde_json::Map::new()),
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
        .args(["exec", "-s", "github", "--", "env"])
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
                    &approved_environment("github", serde_json::Map::new()),
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
        .args(["exec", "-s", "github", "--", "env"])
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
        .args(["exec", "-s", "github", "--", "env"])
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
    assert!(stderr.contains("received a signal"));
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
                    &approved_environment(
                        "github",
                        serde_json::Map::from_iter([(
                            "AGENTKNOCK_MUST_NOT_EXEC".into(),
                            "yes".into(),
                        )]),
                    ),
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
        .args(["exec", "-s", "github", "--", "env"])
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
    assert!(stderr.contains("received a signal"), "{stderr}");
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
