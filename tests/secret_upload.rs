#![cfg(unix)]

mod support;

use std::{
    fs,
    io::Write as _,
    process::{Command, Stdio},
};

use serde_json::json;

use support::{
    TestHome, accept, assert_authenticated_request, encrypt_response, open_completion,
    open_request, receive_json, send_json, websocket_server,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_an_environment_secret_from_multiple_sources() {
    let home = TestHome::active();
    let value_path = home.path().join("token");
    let environment_path = home.path().join("secret.env");
    fs::write(&value_path, "file value\n").unwrap();
    fs::write(&environment_path, "FROM_ENV_FILE='dotenv value'\n").unwrap();

    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&upgrade);
        let frame = receive_json(&mut socket).await;
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &frame["payload"]);
        assert_eq!(
            plaintext,
            json!({
                "app_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "lib_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "method": "SecretUpload",
                "mode": "CREATE",
                "secret": {
                    "name": "bootstrap",
                    "description": "Initial imported values",
                    "type": "environment",
                    "variables": {
                        "FROM_ENV_FILE": {"value": "dotenv value"},
                        "FROM_FILE": {"value": "file value\n"},
                        "FROM_PROCESS": {"value": "process value"},
                    },
                },
            })
        );

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
                "payload": encrypt_response(&context, &key, &json!({"result": "RECEIVED"})),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
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
                "result": "RECEIVED",
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
        .env("FROM_PROCESS", "process value")
        .args([
            "secret",
            "upload",
            "bootstrap",
            "--description",
            "Initial imported values",
            "--from-env",
            "FROM_PROCESS",
            "--from-file",
            &format!("FROM_FILE={}", value_path.display()),
            "--from-env-file",
            environment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!(
            "Secret upload \"bootstrap\" delivered to the device.\n",
            "The secret isn't available until you approve the upload on the device.\n",
            "Suggested action: Review the secret upload on the device.\n",
        )
    );
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("process value")
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_an_ssh_private_key() {
    let home = TestHome::active();
    let key_path = home.path().join("id_ed25519");
    let private_key = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "example\n",
        "-----END OPENSSH PRIVATE KEY-----\n",
    );
    fs::write(&key_path, private_key).unwrap();

    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (upgrade, mut socket) = accept(&listener).await;
        assert_authenticated_request(&upgrade);
        let frame = receive_json(&mut socket).await;
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &frame["payload"]);
        assert_eq!(
            plaintext,
            json!({
                "app_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "lib_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "method": "SecretUpload",
                "mode": "CREATE",
                "secret": {
                    "name": "production-ssh",
                    "description": "Production host access",
                    "type": "ssh",
                    "private_key": private_key,
                },
            })
        );

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
                "payload": encrypt_response(&context, &key, &json!({"result": "RECEIVED"})),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        assert_eq!(
            open_completion(&mut context, &completion["payload"])["result"],
            "RECEIVED"
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
        .args([
            "secret",
            "upload",
            "production-ssh",
            "--description",
            "Production host access",
            "--from-ssh-key",
            key_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains(private_key)
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn updates_an_environment_variable_from_standard_input() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let frame = receive_json(&mut socket).await;
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &frame["payload"]);
        assert_eq!(plaintext["mode"], "UPDATE");
        assert_eq!(plaintext["secret"]["type"], "environment");
        assert_eq!(
            plaintext["secret"]["variables"]["TOKEN"]["value"],
            "standard input value\n"
        );

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
                "payload": encrypt_response(&context, &key, &json!({"result": "RECEIVED"})),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        let _ = open_completion(&mut context, &completion["payload"]);
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args([
            "secret",
            "upload",
            "existing",
            "--update",
            "--from-file",
            "TOKEN=-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"standard input value\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_a_rejected_secret_upload() {
    let home = TestHome::active();
    let device_private_key = home.device_private_key.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let frame = receive_json(&mut socket).await;
        let client_id = frame["client_id"].as_str().unwrap().to_owned();
        let request_id = frame["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, _) =
            open_request(&device_private_key, &request_id, &frame["payload"]);
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
                        "result": "REJECTED",
                        "message": "The upload is not valid.",
                    }),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        assert_eq!(
            open_completion(&mut context, &completion["payload"])["result"],
            "REJECTED"
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
        .env("TOKEN", "must not appear")
        .args(["secret", "upload", "rejected", "--from-env", "TOKEN"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("The device rejected the secret upload"));
    assert!(stderr.contains("The upload is not valid."));
    assert!(!stderr.contains("must not appear"));
    server.await.unwrap();
}

#[test]
fn rejects_multiple_standard_input_sources_before_connecting() {
    let home = TestHome::active();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .args([
            "secret",
            "upload",
            "invalid",
            "--from-file",
            "TOKEN=-",
            "--from-env-file",
            "-",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("only one secret source can read from standard input")
    );
}

#[test]
fn does_not_print_a_secret_from_an_invalid_environment_file() {
    let home = TestHome::active();
    let environment_path = home.path().join("invalid.env");
    fs::write(&environment_path, "TOKEN='do-not-print-this\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .args([
            "secret",
            "upload",
            "invalid",
            "--from-env-file",
            environment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("environment file"));
    assert!(stderr.contains("isn't valid"));
    assert!(!stderr.contains("do-not-print-this"));
}
