# Agentknock command execution semantics

This document explains how the Agentknock CLI selects and starts a command,
delivers environment values, and supports deferred operations such as Git
signing. It describes the operating-system mechanisms, the consistency
properties they provide, and the limits of those properties.

The [Agentknock v1 client-device protocol](client-device-protocol.md) defines
the command metadata sent to the device. The [Agentknock v1
cryptosystem](cryptosystem.md) defines how Agentknock protects requests,
responses, and returned secret values.

## Security model and scope

Agentknock is a same-user command launcher, not a local security boundary. It
runs with the same identity, privileges, and operating-system context as the
command it starts. It does not try to protect command selection or secret
values when the host, the current user account, or another process with
equivalent access is compromised.

For example, a capable same-user process might be able to modify Agentknock or
a user-owned executable, inspect process memory or environment data, influence
an interpreter or dynamic loader, or replace configuration and plugins. A
command that receives secrets can disclose them deliberately or accidentally.
The command can print them, write them to disk, transmit them, pass them to a
descendant, or expose them in a crash dump.

The measures in this document are best-effort host hygiene. They make approval
metadata correspond more closely to the command that Agentknock starts, avoid
some ordinary pathname races, and provide useful executable identity fields
for approval decisions. They do not provide remote attestation, endpoint
protection, or strong guarantees against active local compromise. A normal
path lookup followed by `execve` would often have similar practical security
on a compromised host.

Agentknock uses the Linux facilities described here because they are available
at modest complexity. Failure instead of an implicit fallback keeps the
behavior and reported metadata predictable; it does not turn the launcher into
a sandbox or privilege boundary.

## Common execution semantics

`agentknock exec` follows this sequence:

1. Capture the working directory and executable search path.
2. Select, open, inspect, and retain the top-level executable.
3. Send the invocation, selected secrets, and executable metadata to the
   device.
4. Wait for an authenticated response and complete the protocol exchange.
5. If the response contains an SSH secret, start an invocation service for
   deferred operations and add its Git settings to the command environment.
6. Revalidate the executable when a hash is available.
7. Overlay returned environment variables and Agentknock's Git settings on the
   inherited environment.
8. Check for a pending termination signal.
9. Replace the Agentknock process with the command.

Agentknock selects the executable before sending the invocation request.
Returned environment variables therefore cannot affect Agentknock's initial
`PATH` search.

Agentknock does not invoke an implicit shell. It keeps the command and each
argument as separate strings and passes them directly to the operating system.
The mandatory `--` separator prevents Agentknock from interpreting command
arguments as its own options.

After a successful process replacement, the command retains Agentknock's
process ID and ordinary process relationships. When deferred operations are
enabled, a separate invocation service remains until that process exits. The
service does not supervise the command or determine its exit status.

## Atomicity boundaries

The sequence is not one atomic transaction. The remote protocol exchange and
operating-system process replacement cannot be committed together. Agentknock
completes the protocol exchange before it attempts process replacement. The
client can therefore exit, receive a signal, or encounter an execution error
after the device has returned a result. A protocol completion confirms the
client result; it does not prove that the command started.

The Linux implementation uses individual kernel operations to narrow specific
races:

| Boundary | Mechanism | Remaining limitation |
| --- | --- | --- |
| Path lookup to selected object | Open the candidate and retain its file descriptor. | The opened file's contents can still change. |
| Approval wait to native execution | Execute the retained descriptor with `execveat`. | Loaders, libraries, plugins, and other dependencies are not retained. |
| Approval metadata to executable contents | Hash before the request and again before execution. | The file can change after the second hash observation. |
| Approval wait to script execution | Rehash the captured script path immediately before `execve`. | The pathname or file can change after revalidation. |
| Signal handling to process replacement | Block termination signals, check pending signals, then restore the caller's state. | A later signal follows the restored disposition as normal. |
| Invocation to deferred helper | Keep the invocation token in a service tied to the command PID and check helper ancestry. | A capable same-user process remains inside the threat boundary. |

An executable hash is an observation, not an execution handle. Revalidating a
hash can detect a change, but it cannot make mutable bytes immutable or make
the check and execution one operation.

## Approval context

The invocation request reports:

- The original command string and structured arguments.
- The captured working directory.
- The selected executable path.
- Whether the executable is a binary or shebang script.
- The SHA-256 executable hash, when the file is readable.
- The connection type of standard input, output, and error.
- A bounded chain of launcher executable paths.
- The requested secret names and optional reason.

Agentknock reports a standard stream as a terminal, null device, pipe, socket,
regular file, or unknown connection. On Linux, it reads launcher paths from
`/proc`, up to four ancestors, and orders them from the oldest reported
ancestor to the direct launcher. Missing, inaccessible, or non-UTF-8 process
information shortens the chain.

This information helps a person or automated policy evaluate a request, but it
is entirely client-reported. It is not attestation, and a modified client can
send different values.

The hash supports exact comparison in a reusable approval rule. It is not
intended for a person to recognize. A useful rule might also consider the
client, requested secrets, executable path, arguments, and expiry. The device
defines that policy; this document does not prescribe it.
The path can remain meaningful when a hash matches because identical bytes can
behave differently based on their location, adjacent files, configuration, or
program self-inspection.

## Environment construction

After an authenticated response, Agentknock builds the command environment:

1. Start with the complete inherited environment. Unrelated non-UTF-8 names
   and values remain byte-preserving operating-system strings.
2. Overlay each environment variable returned by the device. A returned value
   replaces an inherited value with the same name.
3. Reject an empty returned name, a name containing `=` or NUL, or a value
   containing NUL.
4. If an SSH secret enables deferred Git signing, add the Git configuration
   entries described below.
5. Produce at most one entry for each environment variable name.

When multiple requested secrets provide the same environment variable, their
values must match exactly. Agentknock rejects conflicting values. It never
prints or writes a returned value, although verbose output can list variable
names.

Agentknock does not remove control variables such as `PATH`, `LD_PRELOAD`,
`BASH_ENV`, `NODE_OPTIONS`, `PYTHONPATH`, or Git configuration. Unlike `sudo`,
Agentknock does not cross an identity or privilege boundary. The set of
influential variables is open-ended, and commands can legitimately require
them. Sanitizing a small known set would provide incomplete protection while
breaking valid uses.

The command and its descendants control every value they receive. Users must
approve environment delivery and signing operations only for commands they
trust to handle them.

## Linux implementation

The current command-execution implementation supports Linux. It requires:

- Linux 5.8 or later for `faccessat2` with `AT_EMPTY_PATH` and `AT_EACCESS`.
- The `execveat` system call.
- The `pidfd_open` system call for deferred operations.
- A mounted `/proc` file system with usable file-descriptor and process-status
  views.
- UTF-8 command arguments, working-directory paths, and selected executable
  paths at the protocol boundary.

Agentknock stops before sending the invocation request when the host cannot
provide a required facility.

### Working directory and search path

Agentknock opens the current directory with
`O_PATH | O_DIRECTORY | O_CLOEXEC`. The directory descriptor remains the base
for relative executable paths and relative `PATH` entries, even if a pathname
leading to that directory changes later.

Agentknock captures `PATH` before the request. If `PATH` is absent, it uses the
system `_CS_PATH` value.

If the command contains `/`, Agentknock opens that path directly. An absolute
path starts at the file-system root. A relative path starts at the retained
working-directory descriptor.

If the command contains no `/`, Agentknock searches the captured `PATH` in
order. Empty and relative components start at the retained working directory.
The search continues after errors that ordinary executable lookup treats as a
missing candidate, including a candidate that is not executable. Other errors
stop the search.

Agentknock does not canonicalize a pathname and later reopen it. A canonical
path is still a mutable name, not a stable reference to a file-system object.
It also does not repeat the `PATH` search after approval because the directory
contents and final environment might then select a different command.

### Selected executable

Agentknock opens each candidate with `O_PATH | O_CLOEXEC`. It requires a
regular file and checks effective-ID execute access with:

```text
faccessat2(fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS)
```

This access check provides normal command-selection behavior. It is not a
security authorization decision. The execution system call remains
authoritative, and mount options, Linux security modules, file capabilities,
interpreter rules, and other kernel policy can still reject execution.

Agentknock does not require a particular owner or writable-mode policy. Many
intended commands are installed and controlled by the current user, and
Agentknock does not claim that a user-controlled executable is trusted merely
because it passed selection.

Normal path resolution follows symbolic links. Agentknock retains the object
to which a link resolved during selection instead of rejecting links or
retaining the link itself.

Agentknock obtains the displayed `executable_path` by reading
`/proc/self/fd/<fd>` for the opened object. If the resulting path is not valid
UTF-8, Agentknock stops before sending a request. The selected descriptor
remains open during request delivery, approval, response authentication, and
completion handoff.

### Executable inspection and revalidation

Agentknock tries to read the selected object through its retained descriptor.
When the object is readable, one pass calculates the SHA-256 digest of the
complete file and checks whether the first two bytes are `#!`.

The request identifies a detected shebang file as a script and another file as
a binary. It includes the standard Base64 encoding of the 32-byte digest when
hashing succeeds.

An execute-only file might not be readable. In that case, Agentknock omits the
hash and treats the target as a binary. If the kernel cannot execute it through
the retained descriptor, execution fails without a pathname or shell fallback.

After approval and before execution, Agentknock recalculates an available
hash. It reads a binary through the retained descriptor and a script through
the pathname that the kernel will use. A read failure or mismatch stops
execution.

Each hash calculation is a streaming read, not an atomic file snapshot.
Concurrent writes can affect the bytes observed during a hash calculation, and
the file can change again after the calculation finishes.

Agentknock does not copy the executable into a sealed memory file. A copy would
be a different execution object and could change path behavior, file
attributes, capabilities, signatures, or security-policy treatment. It would
also leave interpreters and runtime dependencies unpinned.

### Invocation service and Git signing

An invocation response containing an SSH secret includes its name and public
key, not its private key. Agentknock starts a separate copy of its executable
as an invocation service before replacing the launcher process. The launcher
sends the service the invocation identifier, a fresh 32-byte invocation token,
the SSH secret name and public key, the owner process ID, and output settings
through the service's standard input. It does not pass a live HPKE context to
the service.

The service creates a mode-0700 temporary directory containing a Unix-domain
socket and a symlink to `/proc/<service-pid>/exe`. The symlink lets Git invoke
the same Agentknock binary as its signing helper without installing another
executable or adding a directory to `PATH`. The directory and its entries are
removed when the service exits normally; an abrupt service failure can leave
them behind.

The launcher adds two Git settings through `GIT_CONFIG_COUNT`:

- `gpg.ssh.program` names the helper symlink.
- `gpg.ssh.defaultKeyCommand` asks the same helper for the selected SSH public
  key when Git has no configured `user.signingKey`.

These settings affect Git processes in the command's environment. Agentknock
does not set `gpg.format`, `commit.gpgSign`, `tag.gpgSign`, or
`user.signingKey`; those remain under user and repository control.

For an SSHSIG signing operation in the `git` namespace, the helper compares
Git's requested key with the selected Agentknock public key. A match sends the
exact signing payload supplied by Git to the invocation service. The service
creates a new protected `GitSign` exchange containing the original invocation
identifier and token, the SSH secret name, and those bytes. When Git invokes
the helper directly, the helper also uses that Git executable to collect
advisory repository, branch, and changed-path context. The changed paths come
from the tree and first parent named by the signing payload, not from mutable
index or worktree state. Failure to collect this context does not prevent
signing. The service writes an approved SSHSIG response to the signature file
expected by Git. Every signature receives a separate device decision.

If Git requests another key or invokes the configured program for another
operation, the helper replaces itself with `ssh-keygen` from `PATH` and passes
the original arguments unchanged.

The service opens a pidfd for the owner process, whose PID remains stable when
the launcher replaces itself with the command. It exits when that process
exits. Before serving a helper connection, it reads the peer PID from the Unix
socket and walks Linux parent-process records to require that the helper is a
descendant of the owner. If the owner exits during a signing request, the
service cancels the request and attempts a short aborted completion.

These checks keep ordinary unrelated processes from accidentally using an
invocation service. They are not a same-user security boundary. The security
model described above still applies to the socket, process tree, invocation
token, and service memory.

### Native executable replacement

For a target classified as a binary, Agentknock makes the system call
equivalent of:

```text
execveat(fd, "", argv, envp, AT_EMPTY_PATH)
```

The descriptor identifies the file-system object selected before approval.
Replacing or redirecting the original pathname does not select another
top-level object. The file itself remains mutable, so descriptor execution does
not promise that its bytes stayed unchanged after the final hash observation.

Agentknock uses the original command string as `argv[0]`, followed by the
original arguments. It does not perform another path lookup. Every execution
error is terminal, including an error caused by a missing loader.

Descriptor execution can appear through `AT_EXECFN`, auditing, path-oriented
policy, or program self-inspection. `/proc/self/exe` refers to the executed
object, but software that depends on its exact execution path can behave
differently.

A hash-only design would not provide the same selection consistency. A hash
can compare observed contents, but it does not identify the object that the
kernel must execute. Agentknock therefore retains the descriptor even when it
also reports a hash.

### Script execution

Linux cannot execute a shebang script through a close-on-exec descriptor
without preventing the interpreter from reopening the script. Removing
close-on-exec would leak the descriptor into the command. Agentknock instead
calls `execve` once on the exact candidate pathname captured during selection.

This choice preserves normal shebang behavior, including the kernel's argument
transformation. It has weaker consistency than native descriptor execution:
another process can replace or modify the script after the final path-based
hash check.

Agentknock does not parse or retain the shebang interpreter. In particular, a
script that uses `/usr/bin/env` causes that program to select an interpreter
from the final command environment. Agentknock reports and hashes the script,
not the selected interpreter.

Agentknock also does not inspect ELF interpreters, shared libraries, plugins,
configuration files, or executables started by the command. Recursively
pinning a complete runtime is not feasible for a transparent general-purpose
launcher.

### Signals and process state

SIGINT and SIGTERM cancel the operation while Agentknock waits for approval. If
the request reached the relay, Agentknock attempts to send an aborted
completion. A signal after response authentication prevents execution but does
not change the authenticated result.

Immediately before process replacement, Agentknock blocks SIGINT and SIGTERM,
checks for a pending signal, restores their original dispositions, restores
the caller's signal mask, and sets SIGPIPE to its default disposition. This
prevents the asynchronous waiting handler from consuming a termination signal
during the transition. A signal received after restoration follows the
caller's normal disposition.

Agentknock does not deliberately change:

- User IDs, group IDs, supplementary groups, or capabilities.
- The current directory, umask, or resource limits.
- Standard streams, terminal, process group, or session.
- Namespaces, control groups, Linux security context, or seccomp state.
- Caller-owned inherited file descriptors.
- The inherited `no_new_privs` state.

Agentknock-owned descriptors use close-on-exec or are closed before process
replacement. Agentknock does not close every inherited descriptor because
applications can intentionally use descriptor inheritance as an interface.

Keeping the launcher as a supervisor would change process IDs, signals, job
control, and exit-status handling. Process replacement avoids those
differences. The optional invocation service is independent of that lifecycle
and communicates with helpers rather than supervising the command.

## macOS status

Agentknock does not currently implement command execution on macOS. A future
implementation belongs in this document because the execution model, approval
context, environment behavior, and security scope should remain common across
platforms.

The macOS section must document the mechanisms it actually uses and the races
that remain. It does not need to reproduce Linux system calls or claim stronger
consistency than macOS can provide. Keeping both implementations here makes
platform differences visible instead of hiding them behind a general claim.

## Limits

Agentknock does not provide:

- Immutable executable bytes.
- Remote attestation of a path, owner, hash, or file contents.
- Stable pathname execution for shebang scripts.
- Pinning of interpreters, libraries, plugins, configuration, or descendants.
- Isolation from inherited or returned environment data.
- A sandbox, privilege boundary, or `sudo`-like authorization boundary.
- Protection of secret values from the approved process tree.
- Protection from a modified Agentknock client or a compromised host.

These limits are fundamental to the same-user execution model. The selected
mechanisms improve consistency where doing so is straightforward, but they do
not change which local components ultimately have access to the command or its
secrets.

## References

- [Linux `execveat(2)` manual page](https://man7.org/linux/man-pages/man2/execveat.2.html)
- [Linux `faccessat2(2)` manual page](https://man7.org/linux/man-pages/man2/access.2.html)
- [Linux `openat(2)` manual page](https://man7.org/linux/man-pages/man2/open.2.html)
- [Linux `pidfd_open(2)` manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
- [Linux `proc_pid_fd(5)` manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [Linux `proc_pid_status(5)` manual page](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [Linux `unix(7)` manual page](https://man7.org/linux/man-pages/man7/unix.7.html)
- [POSIX `exec` specification](https://pubs.opengroup.org/onlinepubs/9799919799/functions/exec.html)
