use std::process::Command;

use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct PostRequest {
    message: String,
}

#[derive(Deserialize, Serialize)]
struct PostResponse {
    echoed_message: String,
}

async fn echo(Json(request): Json<PostRequest>) -> Json<PostResponse> {
    Json(PostResponse {
        echoed_message: request.message,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn posts_and_receives_json() {
    let app = Router::new().route("/message", post(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args([
            "post",
            &format!("http://{address}/message"),
            "hello from the client",
        ])
        .output()
        .unwrap();

    server.abort();
    let _ = server.await;

    assert!(
        output.status.success(),
        "agentknock failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let response: PostResponse = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response.echoed_message, "hello from the client");
}
