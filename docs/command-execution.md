# Agentknock command execution

This document defines how the Agentknock CLI selects and starts a command on
Linux after the paired device approves secret use. It describes the security
properties that the executable metadata supports and the limits of environment
variable delivery.

The [Agentknock v1 client-device protocol](client-device-protocol.md) defines
the command metadata sent to the device. The [Agentknock v1
cryptosystem](cryptosystem.md) defines how Agentknock protects that request and
the returned secret values.

## Execution model

`agentknock exec` is a transparent, same-user launcher. It performs the
following sequence:

1. Resolve, open, inspect, and retain the selected top-level executable.
2. Send the selected executable and invocation metadata to the device.
3. Wait for an authenticated response and complete the protocol exchange.
4. Overlay the returned environment variables on the inherited environment.
5. Replace the Agentknock process with the approved command.

Agentknock does not invoke an implicit shell. It keeps the command and each
argument as separate strings and passes them directly to the operating system.
The `--` separator in the CLI prevents Agentknock from interpreting command
arguments as its own options.

Agentknock does not remain as a supervisor after a successful process
replacement. The command retains the process ID and ordinary process
relationships of the Agentknock invocation.

## Platform requirements

The CLI command-execution implementation supports Linux. It requires:

- Linux 5.8 or later for `faccessat2` with `AT_EMPTY_PATH` and `AT_EACCESS`.
- The `execveat` system call.
- A mounted `/proc` file system with a usable `/proc/self/fd` view.
- UTF-8 command arguments, working-directory paths, and resolved executable
  paths at the protocol boundary.

Agentknock fails before requesting secret use when the host cannot provide a
required facility. It does not silently fall back to a second path lookup or a
weaker mode-bit access check.

## Command selection

Agentknock selects the executable before it contacts the relay. This ordering
binds the approval metadata to the object selected without any returned secret
values in the environment.

### Working directory and search path

Agentknock opens the current directory with
`O_PATH | O_DIRECTORY | O_CLOEXEC`. The directory descriptor remains the base
for relative executable paths and relative `PATH` entries, even if a path name
leading to that directory changes later.

Agentknock captures `PATH` before the request. If `PATH` is absent, it uses the
system `_CS_PATH` value. Returned environment variables cannot change this
selection.

If the command contains `/`, Agentknock opens that path directly. An absolute
path is relative to the file-system root. A relative path is relative to the
opened working directory.

If the command contains no `/`, Agentknock searches the captured `PATH` in
order. Empty and relative path components remain relative to the opened
working directory. The search continues after errors that ordinary executable
lookup treats as a missing candidate, including a candidate that exists but is
not executable. Other errors stop the search.

### Opened executable

Agentknock opens each candidate with `O_PATH | O_CLOEXEC`, then checks the
opened object. The object must be a regular file and pass an effective-ID
execute-access check through:

```text
faccessat2(fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS)
```

The later execution system call remains the authoritative permission check.
Mount options, Linux security modules, file capabilities, interpreter rules,
and other kernel policy can still reject execution.

Agentknock derives the displayed `executable_path` by reading
`/proc/self/fd/<fd>` for the opened object. It does not canonicalize one path
and reopen it after approval. If the resulting path is not valid UTF-8,
Agentknock stops before sending a request.

The selected descriptor remains open throughout request delivery, device
approval, response authentication, and completion handoff.

## Executable inspection

Agentknock tries to read the selected object through its retained descriptor.
When the object is readable, it performs both of these operations in one pass:

- Calculate the SHA-256 digest of the complete file.
- Check whether the first two bytes are `#!`.

The request contains `executable_mode: "SCRIPT"` for a detected shebang
script and `executable_mode: "BINARY"` otherwise. It contains
`executable_hash` when Agentknock could read and hash the file. The field is the
standard Base64 encoding of the 32-byte SHA-256 digest.

If an execute-only file cannot be read, Agentknock omits the hash and treats
the target as a binary. A descriptor execution that the kernel cannot complete
then fails without a path or shell fallback.

Agentknock does not parse a shebang or recursively resolve its interpreter. It
also does not inspect ELF interpreters, shared libraries, plugins,
configuration files, or descendant executables.

## Approval metadata

The secret use request reports the following command context:

- The original command string and structured arguments.
- The captured working directory.
- The resolved executable path.
- The executable mode.
- The optional SHA-256 executable hash.
- The connection type of standard input, output, and error.
- A bounded chain of launcher executable paths.
- The requested secret names and optional reason.

Agentknock reports a standard stream as a terminal, null device, pipe, socket,
regular file, or unknown connection. It reads launcher paths from Linux
`/proc`, up to four ancestors, and orders them from the oldest reported
ancestor to the direct launcher. Missing, inaccessible, or non-UTF-8 process
information shortens the chain.

All metadata is client-reported approval context. It is not remote
attestation. A compromised client can lie about any field.

## Executable hash and reusable approval

The raw executable hash is not useful as a standalone prompt for a person or
language model. Its purpose is exact comparison when the device offers a
time-bounded approval rule such as allowing the same executable version to use
the same secrets for four hours.

A conservative reusable approval condition includes at least:

- The client ID.
- The requested secret set.
- The operation type.
- The original command string.
- The resolved executable path.
- The executable hash.
- The rule expiry.

The path remains relevant when the hash matches. Identical bytes at different
paths can behave differently because of argument zero, adjacent files,
configuration, plugins, loader behavior, or program self-inspection.

Arguments require an explicit rule scope. A match on executable path and hash
alone must not imply that every argument vector is approved. The device can
offer an exact command, a defined argument pattern, or an explicitly broad
executable-wide rule.

The launcher chain is useful for display but is not part of the default
reusable condition. It is same-user-controlled and can change across shells,
wrappers, terminals, and agent versions without changing the requested
authority.

Agentknock verifies a supplied hash again after the protocol exchange and
before execution. For a native executable, it reads the retained object. For a
script, it reads the captured path that the kernel will execute. A mismatch or
read failure stops execution.

## Environment construction

After an authenticated approval, Agentknock builds one environment for the
command:

1. Start with the complete environment inherited by Agentknock. Unrelated
   non-UTF-8 names and values remain byte-preserving operating-system strings.
2. Overlay every environment variable returned by the device. A returned value
   replaces an inherited value with the same name.
3. Reject an empty returned name, a name containing `=` or NUL, or a value
   containing NUL.
4. Produce at most one entry for each environment variable name.

When several requested secrets provide the same environment variable, their
values must match exactly. Agentknock rejects the response if they differ.

Agentknock never prints or writes a returned value. Verbose output can list
the environment variable names.

Agentknock does not remove environment-control values such as `PATH`,
`LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONPATH`, or Git configuration.
The set of influential environment variables is open-ended, and many commands
legitimately depend on them. The approved command and its descendants receive
the resulting environment and can interpret it in any way.

## Native executable replacement

For a target classified as a binary, Agentknock calls the Linux system call
equivalent of:

```text
execveat(fd, "", argv, envp, AT_EMPTY_PATH)
```

The descriptor identifies the object opened before approval. Replacing or
redirecting its original path does not select another top-level object.

Agentknock uses the original command string as `argv[0]`, followed by the
original argument strings. It does not repeat a `PATH` search. Every execution
error is terminal, including `ENOENT` caused by a missing loader or unsupported
interpreter mechanism.

Descriptor execution can be visible through `AT_EXECFN`, auditing,
path-oriented policy, or program self-inspection. `/proc/self/exe` still refers
to the executed object, but software that depends on its exact execution path
can behave differently.

## Script execution

Linux cannot safely execute a shebang script through a close-on-exec descriptor
without changing the path presented to its interpreter or leaking the
descriptor. Agentknock instead calls `execve` once on the exact candidate path
captured during selection.

This preserves normal shebang behavior, including the kernel's argument
transformation and interpreters such as `/usr/bin/env`. It also means scripts
have weaker pathname protection than native executables. Agentknock rehashes
the path immediately before execution, but another process can replace or
modify the script after that check.

The executable hash covers the script file only. It does not cover the
interpreter selected by the shebang or anything that the interpreter later
loads.

## Signals and process state

SIGINT and SIGTERM cancel the operation while Agentknock waits for the device.
If the request reached the relay, Agentknock attempts to send an aborted
completion. A signal after response authentication prevents execution but does
not rewrite the authenticated device result.

Immediately before process replacement, Agentknock blocks SIGINT and SIGTERM,
checks for a pending signal, restores their dispositions, restores the
caller's signal mask, and sets SIGPIPE to its default disposition. This closes
the narrow interval in which a termination signal could otherwise be consumed
by the no-longer-needed asynchronous signal handler.

Agentknock does not deliberately change:

- User IDs, group IDs, supplementary groups, or capabilities.
- The current directory, umask, or resource limits.
- Standard streams, terminal, process group, or session.
- Namespaces, control groups, Linux security context, or seccomp state.
- Caller-owned inherited file descriptors.
- The inherited `no_new_privs` state.

Agentknock-owned descriptors use close-on-exec or are closed before
replacement. It does not sweep all inherited descriptors because an
application can intentionally use descriptor inheritance as an interface.

## Guarantees

For a native top-level executable on a supported Linux host, Agentknock
provides these properties:

- It resolves and opens the command before requesting secret use.
- It executes the same opened file-system object after approval.
- Returned environment variables cannot change the selected top-level native
  executable.
- It passes the original argument vector without an implicit shell.
- It replaces itself after completing the protocol exchange.
- It detects a readable executable whose contents changed between the two hash
  observations.

The strongest ordinary case is a native system executable that the invoking
user cannot modify. A user-owned executable still benefits from pathname
pinning, but another same-user process can modify its opened file contents.

## Limits

Agentknock does not provide any of the following properties:

- Immutable executable bytes.
- Remote attestation of a path, owner, hash, or file contents.
- Path pinning for shebang scripts.
- Pinning for interpreters, libraries, plugins, configuration, or descendants.
- Isolation from the inherited or returned environment.
- A sandbox, privilege boundary, or sudo-like authorization boundary.
- Protection of secret values from the approved process tree.
- Protection from another process with sufficient same-user inspection or
  modification access.

The approved command controls every value that it receives. It can print the
values, write them to disk, transmit them, pass them to descendants, or expose
them through a crash dump. The user must approve only commands that are trusted
to handle the requested secrets.

## References

- [Linux `execveat(2)` manual page](https://man7.org/linux/man-pages/man2/execveat.2.html)
- [Linux `faccessat2(2)` manual page](https://man7.org/linux/man-pages/man2/access.2.html)
- [Linux `openat(2)` manual page](https://man7.org/linux/man-pages/man2/open.2.html)
- [Linux `proc_pid_fd(5)` manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [POSIX `exec` specification](https://pubs.opengroup.org/onlinepubs/9799919799/functions/exec.html)
