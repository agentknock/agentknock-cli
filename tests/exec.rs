#![cfg(unix)]

use std::process::{Command, Stdio};

#[test]
fn replaces_itself_with_command() {
    let child = Command::new(env!("CARGO_BIN_EXE_agentknock"))
        .args([
            "--exec",
            "gh-token,cf-wrangler",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$$\"",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let child_id = child.id();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        child_id.to_string()
    );
}
