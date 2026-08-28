#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::{fs::PermissionsExt as _, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

const STARTUP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn creates_a_private_runtime_directory_and_follows_the_owner_lifetime() {
    let mut owner = ChildGuard(
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("start invocation owner"),
    );
    let mut service = ChildGuard(start_service());
    let response = send_startup(
        &mut service.0,
        &json!({
            "owner_pid": owner.0.id(),
            "invocation_id": "01K00000000000000000000000",
            "invocation_token": STARTUP,
            "secret": "test-ssh",
            "public_key": "ssh-ed25519 AAAA test",
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let runtime_directory = response["runtime_directory"].as_str().unwrap();
    let metadata = fs::metadata(runtime_directory).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

    let mut unauthorized = UnixStream::connect(Path::new(runtime_directory).join("service.sock"))
        .expect("connect from a process outside the invocation");
    if let Err(error) = unauthorized.write_all(br#"{"operation":"public_key"}"#) {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
    }
    let _ = unauthorized.shutdown(std::net::Shutdown::Write);
    let mut response = Vec::new();
    if let Err(error) = unauthorized.read_to_end(&mut response) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    assert!(response.is_empty());
    assert!(service.0.try_wait().unwrap().is_none());

    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    wait_for_exit(&mut service.0);
    assert!(!fs::exists(runtime_directory).unwrap());
}

#[test]
fn reports_a_malformed_startup_request() {
    let mut service = ChildGuard(start_service());
    service
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"not json")
        .unwrap();
    let response: Value =
        serde_json::from_reader(service.0.stdout.take().unwrap()).expect("startup error response");
    assert_eq!(response["status"], "error");
    assert!(
        response["message"]
            .as_str()
            .unwrap()
            .contains("invalid invocation service startup request")
    );
    assert!(!service.0.wait().unwrap().success());
}

#[test]
fn delegates_other_signing_keys_to_ssh_keygen() {
    let directory = tempfile::tempdir().unwrap();
    let private_key = directory.path().join("signing-key");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private_key));
    let message = directory.path().join("message");
    fs::write(&message, "signed by the configured key\n").unwrap();

    let mut service = ChildGuard(start_service());
    let response = send_startup(
        &mut service.0,
        &json!({
            "owner_pid": std::process::id(),
            "invocation_id": "01K00000000000000000000000",
            "invocation_token": STARTUP,
            "secret": "test-ssh",
            "public_key": "ssh-ed25519 AAAA agentknock",
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let helper = Path::new(response["runtime_directory"].as_str().unwrap()).join("git-sign");
    run(Command::new(helper)
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&private_key)
        .arg(&message));

    let mut signature = message.into_os_string();
    signature.push(".sig");
    assert!(fs::exists(signature).unwrap());
}

fn start_service() -> Child {
    Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .arg("__invocation-service")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start invocation service")
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn send_startup(service: &mut Child, request: &Value) -> Value {
    serde_json::to_writer(service.stdin.take().unwrap(), request).unwrap();
    serde_json::from_reader(service.stdout.take().unwrap()).expect("startup response")
}

fn wait_for_exit(process: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        assert!(Instant::now() < deadline, "invocation service didn't exit");
        thread::sleep(Duration::from_millis(10));
    }
}
