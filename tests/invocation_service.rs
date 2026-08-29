#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde_json::{Value, json};

const STARTUP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB test";

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
            "public_key": PUBLIC_KEY,
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let runtime_directory = response["runtime_directory"].as_str().unwrap();
    let metadata = fs::metadata(runtime_directory).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert!(Path::new(runtime_directory).join("agent.sock").exists());

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

    let mut unauthorized = UnixStream::connect(Path::new(runtime_directory).join("agent.sock"))
        .expect("connect to the SSH agent from outside the invocation");
    let _ = unauthorized.write_all(&[0, 0, 0, 1, 11]);
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
fn exposes_the_selected_key_through_ssh_auth_sock() {
    let directory = tempfile::tempdir().unwrap();
    let unavailable_agent = directory.path().join("unavailable-agent.sock");
    let mut service = ChildGuard(start_service());
    let response = send_startup(
        &mut service.0,
        &json!({
            "owner_pid": std::process::id(),
            "invocation_id": "01K00000000000000000000000",
            "invocation_token": STARTUP,
            "secret": "test-ssh",
            "public_key": PUBLIC_KEY,
            "upstream_agent_socket": BASE64_STANDARD.encode(unavailable_agent.as_os_str().as_bytes()),
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let agent_socket =
        Path::new(response["runtime_directory"].as_str().unwrap()).join("agent.sock");
    let output = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", agent_socket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        PUBLIC_KEY.rsplit_once(' ').unwrap().0.to_owned() + " test-ssh"
    );
}

#[test]
fn serves_agent_and_helper_connections_concurrently() {
    let mut service = ChildGuard(start_service());
    let response = send_startup(
        &mut service.0,
        &json!({
            "owner_pid": std::process::id(),
            "invocation_id": "01K00000000000000000000000",
            "invocation_token": STARTUP,
            "secret": "test-ssh",
            "public_key": PUBLIC_KEY,
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let runtime_directory = Path::new(response["runtime_directory"].as_str().unwrap());
    let agent_socket = runtime_directory.join("agent.sock");

    let mut first = UnixStream::connect(&agent_socket).unwrap();
    assert_eq!(request_identities(&mut first)[0], 12);

    let mut second = UnixStream::connect(&agent_socket).unwrap();
    second
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(request_identities(&mut second)[0], 12);

    let mut helper = UnixStream::connect(runtime_directory.join("service.sock")).unwrap();
    helper
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    helper.write_all(br#"{"operation":"public_key"}"#).unwrap();
    helper.shutdown(std::net::Shutdown::Write).unwrap();
    let response: Value = serde_json::from_reader(helper).unwrap();
    assert_eq!(response["status"], "public_key");
    assert_eq!(response["public_key"], PUBLIC_KEY);
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
fn uses_the_upstream_agent_for_another_git_signing_key() {
    let directory = tempfile::tempdir().unwrap();
    let private_key = directory.path().join("signing-key");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&private_key));
    let public_key = private_key.with_extension("pub");
    let agent_socket = directory.path().join("original-agent.sock");
    let mut agent = ChildGuard(
        Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&agent_socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    wait_for_path(&agent_socket, &mut agent.0);
    run(Command::new("ssh-add")
        .arg(&private_key)
        .env("SSH_AUTH_SOCK", &agent_socket));
    fs::remove_file(&private_key).unwrap();
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
            "public_key": PUBLIC_KEY,
            "upstream_agent_socket": BASE64_STANDARD.encode(agent_socket.as_os_str().as_bytes()),
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let runtime_directory = Path::new(response["runtime_directory"].as_str().unwrap());
    let helper = runtime_directory.join("git-sign");
    let multiplexed_agent = runtime_directory.join("agent.sock");
    let identities = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &multiplexed_agent)
        .output()
        .unwrap();
    assert!(identities.status.success());
    let identities = String::from_utf8(identities.stdout).unwrap();
    let identities = identities.lines().collect::<Vec<_>>();
    assert_eq!(identities.len(), 2);
    assert_eq!(
        identities[0],
        PUBLIC_KEY.rsplit_once(' ').unwrap().0.to_owned() + " test-ssh"
    );
    let upstream_public_key = fs::read_to_string(&public_key).unwrap();
    assert_eq!(
        identities[1]
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>(),
        upstream_public_key
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
    );
    run(Command::new(helper)
        .env("SSH_AUTH_SOCK", multiplexed_agent)
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&public_key)
        .arg("-U")
        .arg(&message));

    let mut signature = message.into_os_string();
    signature.push(".sig");
    assert!(fs::exists(signature).unwrap());
}

fn request_identities(connection: &mut UnixStream) -> Vec<u8> {
    connection.write_all(&[0, 0, 0, 1, 11]).unwrap();
    let mut length = [0; 4];
    connection.read_exact(&mut length).unwrap();
    let mut response = vec![0; u32::from_be_bytes(length) as usize];
    connection.read_exact(&mut response).unwrap();
    response
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

fn wait_for_path(path: &Path, process: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            process.try_wait().unwrap().is_none(),
            "process exited before creating {}",
            path.display()
        );
        assert!(Instant::now() < deadline, "process didn't create a socket");
        thread::sleep(Duration::from_millis(10));
    }
}
