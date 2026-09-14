"""Test executable inspection, secret delivery, SSH, and Git signing without procfs."""

import json
import os
from pathlib import Path
import subprocess

build = subprocess.run(
    [
        "cargo", "test", "--locked", "--all-features", "--no-run",
        "--bin", "agentknock", "--test", "run", "--test", "invocation_service",
        "--message-format=json-render-diagnostics",
    ],
    check=True, stdout=subprocess.PIPE, text=True,
)
executables = {
    artifact["target"]["name"]: artifact["executable"]
    for line in build.stdout.splitlines()
    if (artifact := json.loads(line)).get("reason") == "compiler-artifact"
    and artifact["profile"]["test"] and artifact.get("executable")
}
# Build a fresh root with no /proc entry, and private temporary files/devices.
sandbox = ["bwrap", "--die-with-parent"]
for path in sorted(Path("/").iterdir()):
    if path.name in {"proc", "tmp", "dev"}:
        continue
    if path.is_symlink():
        sandbox += ["--symlink", os.readlink(path), str(path)]
    else:
        sandbox += ["--ro-bind", str(path), str(path)]
sandbox += ["--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(Path.cwd()), str(Path.cwd()), "--"]
tests = {
    "agentknock": [
        "executable::tests::",
        "invocation_service::tests::session_scope_requires_the_same_user_and_live_processes",
    ],
    "invocation_service": [
        "creates_a_private_runtime_directory_and_follows_the_owner_lifetime",
        "git_signing_context_uses_path_and_is_optional",
    ],
    "run": [
        "authenticates_ssh_and_pushes_git_with_an_ed25519_secret",
        "signs_a_git_commit_with_an_ed25519_secret",
        "requests_secret_use_and_executes_with_the_returned_environment",
        "selects_renames_omits_and_pipes_environment_values",
        "delivers_standard_input_when_agentknock_is_invoked_by_relative_path",
        "starts_the_service_after_the_working_directory_is_removed",
        "reports_and_executes_a_shebang_script",
        "sends_maximum_size_scripts_even_with_json_escaping",
        "omits_large_script_contents_without_changing_execution",
        "replaces_invalid_utf8_in_script_evidence_without_changing_execution",
        "executes_the_selected_native_file_after_its_path_is_replaced",
        "reports_an_unavailable_working_directory_without_calling_the_command_missing",
    ],
}
for target, filters in tests.items():
    subprocess.run(
        sandbox + ["sh", "-c", 'test ! -e /proc && exec "$@"', "without-procfs", executables[target], *filters],
        check=True,
    )
