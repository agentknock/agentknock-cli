#![cfg(any(target_os = "linux", target_os = "macos"))]

mod support;

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::Child,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticates_ssh_and_pushes_git_with_an_ed25519_secret() {
    uses_an_ssh_secret("ed25519", &[], SshCommandTest::GitPush).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticates_ssh_with_an_rsa_secret() {
    uses_an_ssh_secret(
        "rsa",
        &["-b", "3072"],
        SshCommandTest::Authenticate {
            ssh_agent: true,
            ssh_passthrough: true,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disables_ssh_key_passthrough() {
    uses_an_ssh_secret(
        "ed25519",
        &[],
        SshCommandTest::Authenticate {
            ssh_agent: true,
            ssh_passthrough: false,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removes_the_ssh_agent_from_the_command() {
    uses_an_ssh_secret(
        "ed25519",
        &[],
        SshCommandTest::Authenticate {
            ssh_agent: false,
            ssh_passthrough: true,
        },
    )
    .await;
}

#[derive(Clone, Copy)]
enum SshCommandTest {
    Authenticate {
        ssh_agent: bool,
        ssh_passthrough: bool,
    },
    GitPush,
}

async fn uses_an_ssh_secret(key_type: &str, key_options: &[&str], test: SshCommandTest) {
    let push_git = matches!(test, SshCommandTest::GitPush);
    let (ssh_agent, ssh_passthrough) = match test {
        SshCommandTest::Authenticate {
            ssh_agent,
            ssh_passthrough,
        } => (ssh_agent, ssh_passthrough),
        SshCommandTest::GitPush => (true, true),
    };
    let home = TestHome::active();
    let private_key = home.path().join("ssh-key");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", key_type])
        .args(key_options)
        .args(["-N", "", "-f"])
        .arg(&private_key));
    let public_key_path = private_key.with_extension("pub");
    let public_key = fs::read_to_string(&public_key_path)
        .unwrap()
        .trim()
        .to_owned();
    let key_blob = BASE64_STANDARD
        .decode(public_key.split_ascii_whitespace().nth(1).unwrap())
        .unwrap();

    let reference_socket = home.path().join("reference-agent.sock");
    let mut reference_agent = ChildGuard(
        Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&reference_socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    wait_for_path(&reference_socket, &mut reference_agent.0);
    run(Command::new("ssh-add")
        .arg(&private_key)
        .env("SSH_AUTH_SOCK", &reference_socket));

    let upstream_private_key = home.path().join("upstream-key");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&upstream_private_key));
    let upstream_public_key_path = upstream_private_key.with_extension("pub");
    let upstream_public_key = fs::read_to_string(&upstream_public_key_path)
        .unwrap()
        .trim()
        .to_owned();
    let upstream_socket = home.path().join("upstream-agent.sock");
    let mut upstream_agent = ChildGuard(
        Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&upstream_socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    wait_for_path(&upstream_socket, &mut upstream_agent.0);
    run(Command::new("ssh-add")
        .arg(&upstream_private_key)
        .env("SSH_AUTH_SOCK", &upstream_socket));
    fs::remove_file(&private_key).unwrap();
    fs::remove_file(&upstream_private_key).unwrap();

    let authorized_keys = home.path().join("authorized_keys");
    fs::write(
        &authorized_keys,
        format!("{public_key}\n{upstream_public_key}\n"),
    )
    .unwrap();
    fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600)).unwrap();
    let host_key = home.path().join("host-key");
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host_key));
    let port = available_port();
    let user = std::env::var("USER").expect("USER is set for the SSH integration test");
    let mut sshd = start_sshd(port, &user, &host_key, &authorized_keys, home.path());

    let device_private_key = home.device_private_key.clone();
    let server_public_key = public_key.clone();
    let server_key_blob = key_blob.clone();
    let server_agent_socket = reference_socket.clone();
    let probe = std::env::current_exe().unwrap();
    let expected_commands = if push_git {
        vec!["ssh".to_owned(), "git".to_owned()]
    } else {
        vec![probe.to_str().unwrap().to_owned()]
    };
    let (relay_url, server) = websocket_server(move |listener| async move {
        for expected_command in expected_commands {
            let (_, mut socket) = accept(&listener).await;
            let request = receive_json(&mut socket).await;
            let client_id = request["client_id"].as_str().unwrap().to_owned();
            let invocation_id = request["request_id"].as_str().unwrap().to_owned();
            let (mut context, key, plaintext) =
                open_request(&device_private_key, &invocation_id, &request["payload"]);
            assert_eq!(plaintext["method"], "Invocation");
            assert_eq!(plaintext["operation"]["command"], expected_command);
            let invocation_token = plaintext["invocation_token"].as_str().unwrap().to_owned();
            send_json(
                &mut socket,
                json!({
                    "type": "ack",
                    "client_id": client_id,
                    "request_id": invocation_id,
                    "kind": "request",
                }),
            )
            .await;
            send_json(
                &mut socket,
                json!({
                    "type": "message",
                    "client_id": client_id,
                    "request_id": invocation_id,
                    "kind": "response",
                    "payload": encrypt_response(
                        &context,
                        &key,
                        &json!({
                            "result": "APPROVED",
                            "secrets": {
                                "ssh-login": {
                                    "type": "ssh",
                                    "public_key": server_public_key,
                                },
                            },
                        }),
                    ),
                }),
            )
            .await;
            assert_eq!(receive_json(&mut socket).await["kind"], "response");
            let completion = receive_json(&mut socket).await;
            let completion = open_completion(&mut context, &completion["payload"]);
            assert_eq!(completion["result"], "APPROVED");
            assert!(completion.get("signature").is_none());
            send_json(
                &mut socket,
                json!({
                    "type": "ack",
                    "client_id": client_id,
                    "request_id": invocation_id,
                    "kind": "completion",
                }),
            )
            .await;
            drop(socket);

            if !ssh_agent {
                continue;
            }

            let (_, mut socket) = accept(&listener).await;
            let request = receive_json(&mut socket).await;
            let client_id = request["client_id"].as_str().unwrap().to_owned();
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            let (mut context, key, plaintext) =
                open_request(&device_private_key, &request_id, &request["payload"]);
            assert_eq!(plaintext["method"], "SshAuthenticate");
            assert_eq!(plaintext["invocation_id"], invocation_id);
            assert_eq!(plaintext["invocation_token"], invocation_token);
            assert_eq!(plaintext["secret"], "ssh-login");
            assert!(plaintext.get("algorithm").is_none());
            let message = BASE64_STANDARD
                .decode(plaintext["message"].as_str().unwrap())
                .unwrap();
            let signature = sign_with_agent(
                &server_agent_socket,
                &server_key_blob,
                &message,
                ssh_signature_flags(&message),
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
                    "payload": encrypt_response(
                        &context,
                        &key,
                        &json!({
                            "result": "APPROVED",
                            "signature": BASE64_STANDARD.encode(signature),
                        }),
                    ),
                }),
            )
            .await;
            assert_eq!(receive_json(&mut socket).await["kind"], "response");
            let completion = receive_json(&mut socket).await;
            let completion = open_completion(&mut context, &completion["payload"]);
            assert_eq!(completion["result"], "APPROVED");
            assert!(completion.get("signature").is_none());
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
        }
    })
    .await;

    let ssh_options = ssh_options(port);
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentknock"));
    command
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", &relay_url)
        .env("SSH_AUTH_SOCK", &upstream_socket)
        .args(["exec", "-s", "ssh-login"]);
    if !ssh_passthrough {
        command.arg("--no-ssh-passthrough");
    }
    if !ssh_agent {
        command.arg("--no-ssh-agent");
    }
    command.arg("--");
    if push_git {
        command
            .arg("ssh")
            .args(&ssh_options)
            .arg(format!("{user}@127.0.0.1"))
            .args(["printf", "ssh-authenticated"]);
    } else {
        command
            .arg(&probe)
            .args([
                "--exact",
                "authenticates_with_configured_ssh_passthrough_probe",
                "--nocapture",
            ])
            .env("AGENTKNOCK_TEST_SSH_PORT", port.to_string())
            .env("AGENTKNOCK_TEST_SSH_USER", &user)
            .env("AGENTKNOCK_TEST_SELECTED_KEY", &public_key_path)
            .env("AGENTKNOCK_TEST_UPSTREAM_KEY", &upstream_public_key_path)
            .env(
                "AGENTKNOCK_TEST_SSH_PASSTHROUGH",
                ssh_passthrough.to_string(),
            )
            .env("AGENTKNOCK_TEST_SSH_AGENT", ssh_agent.to_string());
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\nsshd: {}",
        String::from_utf8_lossy(&output.stderr),
        child_stderr(&mut sshd.0),
    );
    if push_git {
        assert_eq!(output.stdout, b"ssh-authenticated");
    }

    if !push_git {
        server.await.unwrap();
        return;
    }

    let remote = home.path().join("remote.git");
    let repository = home.path().join("git-worktree");
    run(Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&remote));
    run(Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .arg(&repository));
    fs::write(repository.join("example.txt"), "example\n").unwrap();
    run(Command::new("git")
        .args(["-C"])
        .arg(&repository)
        .args(["add", "example.txt"]));
    run(Command::new("git").args(["-C"]).arg(&repository).args([
        "-c",
        "user.name=Agentknock Test",
        "-c",
        "user.email=test@example.com",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "--quiet",
        "-m",
        "Initial commit",
    ]));
    let remote_url = format!("ssh://{user}@127.0.0.1:{port}{}", remote.display());
    run(Command::new("git").args(["-C"]).arg(&repository).args([
        "remote",
        "add",
        "origin",
        &remote_url,
    ]));
    let ssh_command = std::iter::once("ssh".to_owned())
        .chain(ssh_options.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    let output = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .env("HOME", home.path())
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .env("SSH_AUTH_SOCK", upstream_socket)
        .args(["exec", "-s", "ssh-login", "--", "git", "-C"])
        .arg(&repository)
        .args(["-c", &format!("core.sshCommand={ssh_command}")])
        .args(["push", "--quiet", "origin", "main"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\nsshd: {}",
        String::from_utf8_lossy(&output.stderr),
        child_stderr(&mut sshd.0),
    );
    server.await.unwrap();
    let pushed = Command::new("git")
        .args(["--git-dir"])
        .arg(&remote)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap();
    assert!(pushed.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signs_a_git_commit_with_an_ed25519_secret() {
    signs_a_git_commit_with_an_ssh_secret("ed25519", &[], true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signs_a_git_commit_with_an_rsa_secret() {
    signs_a_git_commit_with_an_ssh_secret("rsa", &["-b", "3072"], true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signs_a_git_commit_with_an_ecdsa_secret() {
    signs_a_git_commit_with_an_ssh_secret("ecdsa", &["-b", "256"], true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signs_a_git_commit_without_providing_an_ssh_agent() {
    signs_a_git_commit_with_an_ssh_secret("ed25519", &[], false).await;
}

async fn signs_a_git_commit_with_an_ssh_secret(
    key_type: &str,
    key_options: &[&str],
    ssh_agent: bool,
) {
    let home = TestHome::active();
    let repository = home.path().join("repository");
    let temporary_directory = home.path().join("temporary files");
    fs::create_dir(&repository).unwrap();
    fs::create_dir(&temporary_directory).unwrap();
    run(Command::new("git")
        .args(["init", "--quiet", "--initial-branch=main"])
        .current_dir(&repository));
    run(Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            "https://user:token@example.com/agentknock/example.git",
        ])
        .current_dir(&repository));
    fs::write(repository.join("example.txt"), "example\n").unwrap();
    run(Command::new("git")
        .args(["add", "example.txt"])
        .current_dir(&repository));
    run(Command::new("git")
        .args([
            "-c",
            "user.name=Agentknock Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "Base commit",
        ])
        .current_dir(&repository));
    run(Command::new("git")
        .args(["update-ref", "refs/remotes/origin/main", "HEAD"])
        .current_dir(&repository));
    run(Command::new("git")
        .args(["branch", "--set-upstream-to=origin/main", "main"])
        .current_dir(&repository));
    fs::write(repository.join("example.txt"), "changed\n").unwrap();
    fs::write(repository.join("new.txt"), "new\n").unwrap();
    run(Command::new("git")
        .args(["add", "example.txt", "new.txt"])
        .current_dir(&repository));

    let private_key = home.path().join("signing-key");
    let mut keygen = Command::new("ssh-keygen");
    keygen.args(["-q", "-t", key_type]);
    keygen.args(key_options);
    keygen.args(["-N", "", "-f"]).arg(&private_key);
    run(&mut keygen);
    let public_key = fs::read_to_string(private_key.with_extension("pub"))
        .unwrap()
        .trim()
        .to_owned();

    let device_private_key = home.device_private_key.clone();
    let server_private_key = private_key.clone();
    let server_public_key = public_key.clone();
    let server_repository = repository.clone();
    let (relay_url, server) = websocket_server(move |listener| async move {
        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let invocation_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &invocation_id, &request["payload"]);
        assert_eq!(plaintext["method"], "Invocation");
        let invocation_token = plaintext["invocation_token"].as_str().unwrap().to_owned();
        assert_eq!(BASE64_STANDARD.decode(&invocation_token).unwrap().len(), 32);
        send_json(
            &mut socket,
            json!({
                "type": "ack",
                "client_id": client_id,
                "request_id": invocation_id,
                "kind": "request",
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "message",
                "client_id": client_id,
                "request_id": invocation_id,
                "kind": "response",
                "payload": encrypt_response(
                    &context,
                    &key,
                    &json!({
                        "result": "APPROVED",
                        "secrets": {
                            "git-signing": {
                                "type": "ssh",
                                "public_key": server_public_key,
                            },
                        },
                    }),
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
                "request_id": invocation_id,
                "kind": "completion",
            }),
        )
        .await;
        drop(socket);

        let (_, mut socket) = accept(&listener).await;
        let request = receive_json(&mut socket).await;
        let client_id = request["client_id"].as_str().unwrap().to_owned();
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let (mut context, key, plaintext) =
            open_request(&device_private_key, &request_id, &request["payload"]);
        assert_eq!(plaintext["method"], "GitSign");
        assert_eq!(plaintext["invocation_id"], invocation_id);
        assert_eq!(plaintext["invocation_token"], invocation_token);
        assert_eq!(plaintext["secret"], "git-signing");
        assert!(plaintext.get("namespace").is_none());
        assert_eq!(
            plaintext["repository"]["remote"],
            "example.com/agentknock/example"
        );
        assert_eq!(
            fs::canonicalize(plaintext["repository"]["worktree"].as_str().unwrap()).unwrap(),
            fs::canonicalize(&server_repository).unwrap()
        );
        assert_eq!(plaintext["repository"]["head"]["type"], "BRANCH");
        assert_eq!(plaintext["repository"]["head"]["name"], "main");
        assert_eq!(plaintext["repository"]["head"]["upstream"], "origin/main");
        assert_eq!(plaintext["repository"]["changed_path_count"], 2);
        assert_eq!(
            plaintext["repository"]["changed_paths"],
            json!([
                {"status": "MODIFIED", "path": "example.txt"},
                {"status": "ADDED", "path": "new.txt"},
            ])
        );
        let data = BASE64_STANDARD
            .decode(plaintext["message"].as_str().unwrap())
            .unwrap();
        let data_text = String::from_utf8(data.clone()).unwrap();
        assert!(
            data_text.ends_with("\n\nSign this exact change\n"),
            "{data_text}"
        );

        let payload = tempfile::NamedTempFile::new().unwrap();
        fs::write(payload.path(), data).unwrap();
        run(Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&server_private_key)
            .arg(payload.path()));
        let mut signature_path = payload.path().as_os_str().to_owned();
        signature_path.push(".sig");
        let signature = fs::read_to_string(signature_path).unwrap();

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
                        "signature": signature,
                    }),
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

    let mut command = Command::new(env!("CARGO_BIN_EXE_agentknock"));
    command
        .env("HOME", home.path())
        .env("TMPDIR", temporary_directory)
        .env("AGENTKNOCK_TEST_RELAY_URL", relay_url)
        .args(["exec", "-s", "git-signing"]);
    if !ssh_agent {
        command.arg("--no-ssh-agent");
    }
    let output = command
        .args(["--", "git", "-C"])
        .arg(&repository)
        .args([
            "-c",
            "user.name=Agentknock Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "gpg.format=ssh",
            "commit",
            "-S",
            "-m",
            "Sign this exact change",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();

    let allowed_signers = home.path().join("allowed-signers");
    fs::write(&allowed_signers, format!("test@example.com {public_key}\n")).unwrap();
    run(Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args([
            "-c",
            &format!("gpg.ssh.allowedSignersFile={}", allowed_signers.display()),
        ])
        .args(["verify-commit", "HEAD"]));
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn start_sshd(
    port: u16,
    user: &str,
    host_key: &Path,
    authorized_keys: &Path,
    directory: &Path,
) -> ChildGuard {
    let sshd = command_path("sshd");
    let mut child = ChildGuard(
        Command::new(sshd)
            .args(["-D", "-e", "-f", "/dev/null", "-p", &port.to_string()])
            .arg("-h")
            .arg(host_key)
            .arg("-o")
            .arg("ListenAddress=127.0.0.1")
            .arg("-o")
            .arg(format!("AuthorizedKeysFile={}", authorized_keys.display()))
            .arg("-o")
            .arg("StrictModes=no")
            .arg("-o")
            .arg("PasswordAuthentication=no")
            .arg("-o")
            .arg("KbdInteractiveAuthentication=no")
            .arg("-o")
            .arg("UsePAM=no")
            .arg("-o")
            .arg(format!("PidFile={}", directory.join("sshd.pid").display()))
            .arg("-o")
            .arg(format!("AllowUsers={user}"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return child;
        }
        if child.0.try_wait().unwrap().is_some() {
            panic!("sshd exited during startup: {}", child_stderr(&mut child.0));
        }
        assert!(std::time::Instant::now() < deadline, "sshd didn't start");
        thread::sleep(Duration::from_millis(10));
    }
}

fn ssh_options(port: u16) -> Vec<String> {
    [
        "-F".to_owned(),
        "/dev/null".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=no".to_owned(),
        "-o".to_owned(),
        "UserKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "LogLevel=ERROR".to_owned(),
        "-p".to_owned(),
        port.to_string(),
    ]
    .into()
}

fn available_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn command_path(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set"))
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} isn't available in PATH"))
}

fn wait_for_path(path: &Path, child: &mut Child) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if child.try_wait().unwrap().is_some() {
            panic!(
                "process exited before creating {}: {}",
                path.display(),
                child_stderr(child)
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "process didn't create {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn child_stderr(child: &mut Child) -> String {
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    if let Some(mut input) = child.stderr.take() {
        let _ = input.read_to_string(&mut stderr);
    }
    stderr
}

fn sign_with_agent(socket_path: &Path, key_blob: &[u8], message: &[u8], flags: u32) -> Vec<u8> {
    let mut request = vec![13];
    put_ssh_string(&mut request, key_blob);
    put_ssh_string(&mut request, message);
    request.extend_from_slice(&flags.to_be_bytes());
    let mut connection = UnixStream::connect(socket_path).unwrap();
    connection
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    connection.write_all(&request).unwrap();
    let mut length = [0; 4];
    connection.read_exact(&mut length).unwrap();
    let mut response = vec![0; u32::from_be_bytes(length) as usize];
    connection.read_exact(&mut response).unwrap();
    assert_eq!(
        response.first(),
        Some(&14),
        "reference agent refused to sign"
    );
    let (signature, trailing) = take_ssh_string(&response[1..]);
    assert!(trailing.is_empty());
    signature.to_vec()
}

fn put_ssh_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn take_ssh_string(input: &[u8]) -> (&[u8], &[u8]) {
    let length = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    (&input[4..4 + length], &input[4 + length..])
}

fn ssh_signature_flags(message: &[u8]) -> u32 {
    let (_, message) = take_ssh_string(message);
    assert_eq!(message[0], 50);
    let (_, message) = take_ssh_string(&message[1..]);
    let (_, message) = take_ssh_string(message);
    let (_, message) = take_ssh_string(message);
    assert_eq!(message[0], 1);
    let (algorithm, _) = take_ssh_string(&message[1..]);
    match algorithm {
        b"ssh-ed25519" => 0,
        b"rsa-sha2-256" => 2,
        b"rsa-sha2-512" => 4,
        _ => panic!("unexpected SSH authentication algorithm"),
    }
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
        assert_eq!(plaintext["method"], "Invocation");
        assert_eq!(plaintext["secrets"], json!(["cloudflare", "github"]));
        assert_eq!(plaintext["reason"], "integration test");
        assert_eq!(plaintext["operation"]["command"], "env");
        assert_eq!(plaintext["operation"]["executable_mode"], "BINARY");
        assert_eq!(plaintext["operation"]["stdout"], "PIPE");
        assert_eq!(plaintext["operation"]["stderr"], "PIPE");
        assert!(
            plaintext["launcher_chain"]
                .as_array()
                .is_some_and(|launchers| !launchers.is_empty())
        );
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
    let expected_path = fs::canonicalize(&script)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
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

async fn replace_selected_native_file_after_approval() -> std::process::Output {
    let home = TestHome::active();
    let selected_path = home.path().join("selected-native");
    let replacement_path = home.path().join("replacement-native");
    fs::copy(std::env::current_exe().unwrap(), &selected_path).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_agentknock"), &replacement_path).unwrap();
    let server_selected_path = fs::canonicalize(&selected_path).unwrap();
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

    server.await.unwrap();
    output
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executes_the_selected_native_file_after_its_path_is_replaced() {
    let output = replace_selected_native_file_after_approval().await;
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
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_the_selected_native_file_after_its_path_is_replaced() {
    let output = replace_selected_native_file_after_approval().await;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("selected command changed"), "{stderr}");
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
fn authenticates_with_configured_ssh_passthrough_probe() {
    let Ok(port) = std::env::var("AGENTKNOCK_TEST_SSH_PORT") else {
        return;
    };
    let port = port.parse().unwrap();
    let user = std::env::var("AGENTKNOCK_TEST_SSH_USER").unwrap();
    let selected_key = std::env::var_os("AGENTKNOCK_TEST_SELECTED_KEY").unwrap();
    let upstream_key = std::env::var_os("AGENTKNOCK_TEST_UPSTREAM_KEY").unwrap();
    let ssh_passthrough = std::env::var("AGENTKNOCK_TEST_SSH_PASSTHROUGH").unwrap() == "true";
    let ssh_agent = std::env::var("AGENTKNOCK_TEST_SSH_AGENT").unwrap() == "true";

    if !ssh_agent {
        assert!(std::env::var_os("SSH_AUTH_SOCK").is_none());
        return;
    }

    let authenticate = |key, expected| {
        Command::new("ssh")
            .args(ssh_options(port))
            .args(["-o", "IdentitiesOnly=yes", "-i"])
            .arg(key)
            .arg(format!("{user}@127.0.0.1"))
            .args(["printf", expected])
            .output()
            .unwrap()
    };
    let selected = authenticate(selected_key, "selected-key");
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_eq!(String::from_utf8(selected.stdout).unwrap(), "selected-key");

    let upstream = authenticate(upstream_key, "upstream-key");
    assert_eq!(upstream.status.success(), ssh_passthrough);
    if ssh_passthrough {
        assert_eq!(String::from_utf8(upstream.stdout).unwrap(), "upstream-key");
    }
}

#[test]
fn rejects_a_missing_command_before_sending_an_invocation() {
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
        stderr.contains("Agentknock did not contact the device."),
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
async fn authenticated_device_error_sends_an_aborted_completion() {
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
                    &json!({
                        "error": "UNSUPPORTED_METHOD",
                        "message": "The requested operation is not supported.",
                    }),
                ),
            }),
        )
        .await;
        assert_eq!(receive_json(&mut socket).await["kind"], "response");
        let completion = receive_json(&mut socket).await;
        let plaintext = open_completion(&mut context, &completion["payload"]);
        assert_eq!(plaintext["result"], "ABORTED");
        assert_eq!(plaintext["reason"], "CLIENT_ERROR");
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

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("UNSUPPORTED_METHOD"));
    assert!(stderr.contains("The command didn't run."));
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
