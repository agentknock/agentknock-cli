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

#[cfg(target_os = "linux")]
use std::path::PathBuf;

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
            "ssh_agent": true,
            "ssh_passthrough": true,
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
    if let Err(error) = unauthorized.write_all(br#"{"operation":"configuration"}"#) {
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

#[cfg(target_os = "linux")]
#[test]
fn prefers_the_xdg_runtime_directory() {
    let runtime_base = tempfile::tempdir().unwrap();
    fs::set_permissions(runtime_base.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fallback_base = tempfile::tempdir().unwrap();
    let mut command = service_command();
    command
        .env("XDG_RUNTIME_DIR", runtime_base.path())
        .env("TMPDIR", fallback_base.path());
    let (_service, runtime_directory) = start_ready_service(command);

    assert_eq!(runtime_directory.parent(), Some(runtime_base.path()));
}

#[cfg(target_os = "linux")]
#[test]
fn uses_the_temporary_directory_without_an_xdg_runtime_directory() {
    let temporary_base = tempfile::tempdir().unwrap();
    let mut command = service_command();
    command
        .env_remove("XDG_RUNTIME_DIR")
        .env("TMPDIR", temporary_base.path());
    let (_service, runtime_directory) = start_ready_service(command);

    assert_eq!(runtime_directory.parent(), Some(temporary_base.path()));
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_a_nonprivate_xdg_runtime_directory() {
    let runtime_base = tempfile::tempdir().unwrap();
    fs::set_permissions(runtime_base.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let fallback_base = tempfile::tempdir().unwrap();
    let mut command = service_command();
    command
        .env("XDG_RUNTIME_DIR", runtime_base.path())
        .env("TMPDIR", fallback_base.path());
    let (_service, runtime_directory) = start_ready_service(command);

    assert_eq!(runtime_directory.parent(), Some(fallback_base.path()));
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_an_xdg_runtime_directory_below_an_unsafe_ancestor() {
    let unsafe_parent = tempfile::tempdir().unwrap();
    fs::set_permissions(unsafe_parent.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let runtime_base = unsafe_parent.path().join("runtime");
    fs::create_dir(&runtime_base).unwrap();
    fs::set_permissions(&runtime_base, fs::Permissions::from_mode(0o700)).unwrap();
    let fallback_base = tempfile::tempdir().unwrap();
    let mut command = service_command();
    command
        .env("XDG_RUNTIME_DIR", &runtime_base)
        .env("TMPDIR", fallback_base.path());
    let (_service, runtime_directory) = start_ready_service(command);

    assert_eq!(runtime_directory.parent(), Some(fallback_base.path()));
}

#[cfg(target_os = "linux")]
#[test]
fn falls_back_when_the_xdg_runtime_directory_is_unavailable() {
    let unavailable_parent = tempfile::tempdir().unwrap();
    let unavailable_base = unavailable_parent.path().join("missing");
    let fallback_base = tempfile::tempdir().unwrap();
    let mut command = service_command();
    command
        .env("XDG_RUNTIME_DIR", unavailable_base)
        .env("TMPDIR", fallback_base.path());
    let (_service, runtime_directory) = start_ready_service(command);

    assert_eq!(runtime_directory.parent(), Some(fallback_base.path()));
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
            "ssh_agent": true,
            "ssh_passthrough": true,
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
fn does_not_create_an_ssh_agent_when_unused() {
    let mut service = ChildGuard(start_service());
    let response = send_startup(
        &mut service.0,
        &json!({
            "owner_pid": std::process::id(),
            "invocation_id": "01K00000000000000000000000",
            "invocation_token": STARTUP,
            "secret": "test-ssh",
            "public_key": PUBLIC_KEY,
            "ssh_agent": false,
            "ssh_passthrough": false,
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let runtime_directory = Path::new(response["runtime_directory"].as_str().unwrap());
    assert!(!runtime_directory.join("agent.sock").exists());
    assert!(runtime_directory.join("service.sock").exists());
    assert!(runtime_directory.join("git-sign").exists());
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
            "ssh_agent": true,
            "ssh_passthrough": true,
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
    helper
        .write_all(br#"{"operation":"configuration"}"#)
        .unwrap();
    helper.shutdown(std::net::Shutdown::Write).unwrap();
    let response: Value = serde_json::from_reader(helper).unwrap();
    assert_eq!(response["status"], "configuration");
    assert_eq!(response["public_key"], PUBLIC_KEY);
    assert_eq!(response["ssh_passthrough"], true);
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
    checks_git_signing_key_passthrough(true, true);
}

#[test]
fn uses_the_upstream_agent_for_git_signing_without_exposing_it_to_the_command() {
    checks_git_signing_key_passthrough(false, true);
}

#[test]
fn rejects_another_git_signing_key_when_passthrough_is_disabled() {
    checks_git_signing_key_passthrough(true, false);
}

fn checks_git_signing_key_passthrough(ssh_agent: bool, ssh_passthrough: bool) {
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
            "ssh_agent": ssh_agent,
            "ssh_passthrough": ssh_passthrough,
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
    assert_eq!(identities.len(), if ssh_passthrough { 2 } else { 1 });
    assert_eq!(
        identities[0],
        PUBLIC_KEY.rsplit_once(' ').unwrap().0.to_owned() + " test-ssh"
    );
    let upstream_public_key = fs::read_to_string(&public_key).unwrap();
    if ssh_passthrough {
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
    }
    let output = Command::new(helper)
        .env("SSH_AUTH_SOCK", multiplexed_agent)
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&public_key)
        .arg("-U")
        .arg(&message)
        .output()
        .unwrap();

    let mut signature = message.into_os_string();
    signature.push(".sig");
    if ssh_passthrough {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(fs::exists(signature).unwrap());
    } else {
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("SSH passthrough is disabled"));
        assert!(!fs::exists(signature).unwrap());
    }
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
    service_command().spawn().expect("start invocation service")
}

fn service_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentknock"));
    command
        .arg("__invocation-service")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(target_os = "linux")]
fn start_ready_service(mut command: Command) -> (ChildGuard, PathBuf) {
    let mut service = ChildGuard(command.spawn().expect("start invocation service"));
    let response = send_startup(
        &mut service.0,
        &json!({
            "owner_pid": std::process::id(),
            "invocation_id": "01K00000000000000000000000",
            "invocation_token": STARTUP,
            "secret": "test-ssh",
            "public_key": PUBLIC_KEY,
            "ssh_agent": true,
            "ssh_passthrough": true,
            "quiet": false,
            "verbose": false,
        }),
    );
    assert_eq!(response["status"], "ready", "{response}");
    let runtime_directory = PathBuf::from(response["runtime_directory"].as_str().unwrap());
    (service, runtime_directory)
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
