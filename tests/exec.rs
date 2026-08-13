#![cfg(unix)]

use std::{
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde_json::{Value, json};
use ulid::Ulid;

#[derive(Clone, Debug)]
struct ReceivedMessage {
    route_id: String,
    request_id: String,
    part: String,
    body: Value,
}

type ReceivedMessages = Arc<Mutex<Vec<ReceivedMessage>>>;

async fn receive_message(
    State(messages): State<ReceivedMessages>,
    Path((route_id, request_id, part)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Json<Value> {
    messages.lock().unwrap().push(ReceivedMessage {
        route_id,
        request_id,
        part,
        body,
    });

    Json(json!({}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exchanges_messages_then_replaces_itself_with_command() {
    let messages = ReceivedMessages::default();
    let app = Router::new()
        .route(
            "/route/{route_id}/msg/{request_id}/{part}",
            post(receive_message),
        )
        .with_state(messages.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args([
            "--exec",
            "gh-token,cf-wrangler",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$$\"",
        ])
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let child_id = child.id();
    let output = child.wait_with_output().unwrap();

    server.abort();
    let _ = server.await;

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        child_id.to_string()
    );

    let messages = messages.lock().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].route_id, "placeholder-route");
    assert_eq!(messages[0].part, "request");
    assert_eq!(messages[0].body, json!({}));
    assert_eq!(messages[1].route_id, "placeholder-route");
    assert_eq!(messages[1].part, "complete");
    assert_eq!(messages[1].body, json!({}));
    assert_eq!(messages[0].request_id, messages[1].request_id);
    messages[0].request_id.parse::<Ulid>().unwrap();
}
