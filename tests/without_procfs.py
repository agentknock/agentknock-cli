"""Run execution tests in a Linux mount namespace without procfs (requires bwrap)."""

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
    check=True,
    stdout=subprocess.PIPE,
    text=True,
)
executables = [
    artifact["executable"]
    for line in build.stdout.splitlines()
    if (artifact := json.loads(line)).get("reason") == "compiler-artifact"
    and artifact["profile"]["test"] and artifact.get("executable")
]
assert len(executables) == 3, executables
# A fresh root avoids unmapped ownership on the host root in a user namespace.
# Bind its other entries, but give tests private temporary files and devices.
sandbox = ["bwrap", "--die-with-parent"]
for path in sorted(Path("/").iterdir()):
    if path.name in {"proc", "tmp", "dev"}:
        continue
    if path.is_symlink():
        sandbox += ["--symlink", os.readlink(path), str(path)]
    else:
        sandbox += ["--bind", str(path), str(path)]
sandbox += ["--setenv", "AGENTKNOCK_TEST_WITHOUT_PROCFS", "1", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(Path.cwd()), str(Path.cwd()), "--"]
for executable in executables:
    subprocess.run(
        sandbox + ["sh", "-c", 'test ! -e /proc && exec "$@"', "without-procfs", executable],
        check=True,
    )
