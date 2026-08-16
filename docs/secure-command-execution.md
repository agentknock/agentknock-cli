# Secure command execution in AgentKnock

Status: implemented for Linux in the current worktree; design rationale and limits

Last reviewed: 2026-08-16

## Decision

On Linux, AgentKnock should resolve and open the requested executable before it
sends the credential request. It should keep that file descriptor through the
approval wait and, for a native executable, replace itself with that descriptor
using `execveat(AT_EMPTY_PATH)`.

This gives AgentKnock one precise and useful guarantee:

> For a native executable, AgentKnock executes the same opened filesystem object
> from which it derived the resolved path in the approval request.

The guarantee prevents a routine `PATH` change, symlink change, rename,
unlink-and-recreate, or atomic package replacement from selecting a different
top-level native executable during an approval that can last minutes or hours.
It is especially useful for a system executable that the invoking user cannot
modify in place, such as a normally installed `/usr/bin/ssh`.

AgentKnock must not describe this as a sudo-like security boundary. It does not
change user ID, capabilities, namespaces, or operating-system authority. It
delivers credentials to a process controlled by the same user that invoked it.
The executable's interpreter, dynamic loader, shared libraries, configuration,
plugins, working-directory contents, and descendant commands remain outside the
guarantee. An executable that the same user can modify in place is not made
immutable by holding it open.

Known `#!` scripts should use a deliberately weaker, path-based execution mode.
AgentKnock should capture the candidate pathname that selected the script before
approval and call `execve` once on that same pathname after approval, without a
second `PATH` search and without an implicit shell. It should not leak an
executable descriptor into the interpreter or change the script's apparent path
merely to pin the script. Interpreter-chain pinning is out of scope.

AgentKnock should also send a SHA-256 hash of the selected executable when the
file is readable. The hash is not useful standalone evidence for a person or an
LLM, and AgentKnock should not build a history of executable hashes. Its narrow
purpose is to give the device an exact equality condition for a reusable grant,
such as "allow this executable to use these profiles for four hours." The grant
stores the hash from the approved request and later requests must match it.

AgentKnock should otherwise remain a transparent, same-user launcher. It should
preserve the caller's environment, current directory, standard streams, process
group, terminal, umask, resource limits, credentials, and deliberately inherited
file descriptors. It should overlay the approved environment variables and then
replace itself. Sudo-style environment reconstruction, a PTY monitor, descriptor
sweeps, privilege changes, and sandboxing would change command behavior without
creating a meaningful secret boundary here.

## Research method

The research followed six steps:

1. Audit AgentKnock's current resolution, request construction, credential
   overlay, signal handling, and process replacement code.
2. Establish the exact Linux and POSIX behavior of `open`, `execve`, `execvp`,
   `execveat`, effective-access checks, scripts, descriptors, signals, dynamic
   loading, process environments, ptrace, and core dumps from primary sources.
3. Inspect current implementations of privilege and service launchers: classic
   sudo, sudo-rs, OpenBSD doas, OpenDoas, pkexec, systemd/run0, and Bubblewrap.
4. Inspect secret-injection tools: 1Password CLI documentation, Doppler,
   Infisical, aws-vault, SOPS, Chamber, Vault Agent, Envconsul, vaultenv, vals,
   CyberArk Summon, and systemd credentials.
5. Separate techniques that defend a real OS privilege boundary from techniques
   that improve fidelity or convenience for a same-user launcher.
6. Select the smallest design that closes AgentKnock's actual executable race,
   state its limits precisely, and derive adversarial tests from every claimed
   property.

Source repositories are linked at pinned reviewed revisions where practical.
Closed-source behavior is not inferred beyond public documentation; in
particular, 1Password's internal executable-resolution mechanics remain unknown.

## Scope and threat model

### Assets and desired properties

The relevant assets are:

- the credential values returned by the paired device;
- the command, arguments, working directory, and execution context shown for
  approval;
- the binding between the approved request and the process that receives the
  credential values; and
- normal command-line behavior, including direct argument passing and process
  replacement.

The desired execution properties are:

1. AgentKnock never introduces an implicit shell.
2. Credential response data cannot change which top-level native executable was
   selected before approval.
3. Ordinary pathname replacement during the approval wait cannot substitute a
   different top-level native executable.
4. A native executable receives the original argument vector, including the
   originally typed `argv[0]`. A script receives the kernel's normal shebang
   argument transformation.
5. AgentKnock disappears after protocol completion, so no unnecessary
   supervisor retains decrypted credentials or changes signal and process
   behavior.
6. Failures are explicit. AgentKnock must not silently downgrade from pinned
   native execution to a new pathname lookup.

### Assumptions

The useful guarantee assumes that:

- the installed AgentKnock process and its memory are not modified while it is
  running;
- the kernel and the invoking user's operating-system account are not fully
  compromised; and
- the paired device and the end-to-end protocol authorize the returned
  credential values.

These assumptions are narrower than assuming that all user-controlled files or
environment values are trustworthy. A user-local tool may still be replaced by
another process before AgentKnock opens it. Once opened, however, pathname
replacement does not change the filesystem object referenced by the descriptor.

### What a same-user attacker can already do

AgentKnock is not set-user-ID and does not cross a kernel privilege boundary. A
hostile process with the invoking user's authority can commonly do one or more
of the following, subject to host policy:

- read or replace user-owned AgentKnock configuration and executables;
- inspect another process through `ptrace`-governed interfaces;
- read a process's initial environment through `/proc/<pid>/environ`;
- arrange core dumps or inspect process memory;
- modify a user-writable executable in place; or
- influence a dynamically linked AgentKnock process before `main` by setting
  loader-control environment variables.

Linux only enables the dynamic loader's restricted secure-execution mode for
conditions such as set-user-ID, set-group-ID, file capabilities, or an LSM
decision. A normal same-user AgentKnock invocation does not receive that
protection. Clearing `LD_PRELOAD` immediately before the final `exec` would be
too late to protect AgentKnock itself.

Environment delivery is therefore an inheritance mechanism, not containment.
This is consistent with the product threat model: once a credential is released,
the approved process tree can use and disclose it. Executable pinning improves
the fidelity of what was approved; it does not make credential delivery safe
from a malicious invoking account.

## Current AgentKnock behavior

The current Linux/Unix execution path has four important weaknesses:

1. `resolve_command_path` performs one path search for request metadata, while
   `std::process::Command::exec` performs another search after approval. The two
   searches are not bound together.
2. The response environment is added before `Command::exec`. If a returned
   profile contains `PATH`, the final `execvp` lookup can select a different
   executable from the one reported in the request.
3. The metadata resolver accepts a regular file when any execute bit is set. It
   does not test effective execute access for the invoking process, so its first
   result can differ from the result of the later `execvp` search.
4. `Command::exec` uses the `execvp` family for a command without a slash. POSIX
   and the Linux implementation require an `ENOEXEC` candidate to be passed to
   a shell. This violates AgentKnock's requirement that a shell is used only
   when the caller explicitly requests one.

Canonicalizing a path does not solve these problems. Canonicalization provides
a useful display path, but a later pathname execution can still open a different
filesystem object.

The current use of `Command::exec` also performs one subtle service that a direct
`execveat` implementation must preserve: Rust restores `SIGPIPE` to its default
disposition in the child execution path. Rust ignores `SIGPIPE` in its own
runtime so that socket and pipe writes return errors. AgentKnock must restore the
disposition explicitly before a direct system call.

Rust's Unix runtime also opens `/dev/null` on standard descriptors that were
closed when the Rust process started. AgentKnock should preserve the descriptor
state visible after that runtime initialization. It must still ensure that none
of its own later opens accidentally occupies descriptor 0, 1, or 2.

## What other launchers do

The tools below solve different problems. Privilege launchers defend a
higher-privilege target from a less-privileged caller. Secret launchers mostly
provide convenient delivery to a same-user child. Neither category can be
copied without accounting for that boundary.

### Privilege and service launchers

| Tool | Executable selection | Environment and process controls | Relevant lesson |
| --- | --- | --- | --- |
| classic `sudo` | Resolves before authentication. Optional `fdexec=always` opens during policy matching and later uses `fexecve`; the default only does this for digest-matched commands. | Reconstructs or filters environment, can use `secure_path`, closes descriptors, changes credentials and limits, and commonly uses a PTY monitor. | Descriptor execution is a direct precedent for closing the approval-to-execution pathname race. Most other controls exist because sudo crosses a privilege boundary. |
| `sudo-rs` | Canonicalizes a selected path but currently executes the path with Rust `Command::exec`; digest rules are unsupported. | Always builds a filtered environment, marks extra descriptors close-on-exec, restores signals, and normally uses a PTY. | Memory safety and a smaller implementation do not themselves close executable TOCTOU. Canonicalization is not pinning. |
| OpenBSD `doas` | Matches exact commands and optional exact arguments, uses a restricted path policy, then executes by path. | Rebuilds a small target environment, closes descriptors, and uses OpenBSD `pledge`/`unveil`. | A deliberately small privilege launcher still changes semantics that AgentKnock should preserve and still does not pin the opened file. |
| `pkexec` | Resolves and canonicalizes a program before authorization, but later executes the path. It warns that a joined command-line string is not suitable for security decisions. | Clears the environment, restores a small validated set, closes descriptors, uses PAM, and changes credentials. | Authorization data must remain structured. A canonical path alone leaves a long authorization race. |
| systemd service execution and `run0` | The service manager opens the selected executable with `O_PATH|O_CLOEXEC`, validates it, and calls `execveat(AT_EMPTY_PATH)`. | A fresh service receives controlled credentials, environment, limits, and usually a new PTY. | This is the strongest Linux precedent for native executable pinning. Its path fallback is less suitable for AgentKnock because AgentKnock can wait far longer before execution. |
| Bubblewrap | Executes after constructing namespaces, mounts, capability rules, seccomp filters, and `no_new_privs`. | Intentionally creates a sandbox and changes the target's view of the system. | Sandboxing is a separate product contract, not free launcher hardening. |

Two cautions from these implementations matter directly:

- Sudo documents that an open descriptor does not stop in-place modification of
  a writable inode. A digest does not fix that without a trusted expected digest
  and an immutable execution object.
- Systemd falls back to pathname execution when descriptor execution returns
  `ENOENT`, partly to support `O_CLOEXEC` scripts. For AgentKnock, `ENOENT` is
  ambiguous: it can also mean that a native ELF interpreter is missing. A blind
  fallback after a long approval creates a new substitution opportunity.

`run0` obtains polkit authorization before PID 1 opens the service executable.
Systemd therefore pins its final setup-to-execution interval, not the file that
was present throughout the user's authorization wait. AgentKnock must open
earlier because executable identity is part of its approval request.

### Secret-injection launchers

| Tool | Execution model | Environment policy | Relevant lesson |
| --- | --- | --- | --- |
| 1Password `op run` | Runs a child and remains resident to mask output. | Inherits environment; configured sources override it. | Output masking changes I/O behavior, cannot stop encoded or alternate exfiltration, and requires a supervisor. |
| Doppler `run` | Direct child argv, with a separate explicit shell-string mode. | Inherits and overlays secrets, blocks a few names, and warns about a longer non-exhaustive execution-control list. | Doppler explicitly warns that environment-variable names such as loader and runtime controls can cause code execution. Its warning list also demonstrates why a complete blacklist is unrealistic. |
| Infisical `run` | Direct child argv, or an explicit shell-string mode. | Inherits and overlays while rejecting a reserved-name list. | Direct argv should be the default. Name filtering varies widely and remains incomplete. |
| `aws-vault exec` | Normally resolves with `LookPath` and replaces itself with `exec`; an optional local credential server stays resident. | Removes conflicting AWS names and injects a fixed, program-owned schema. | Fixed credential names make collision policy tractable. A local credential protocol is useful for future renewable credentials, but not necessary for static environment delivery. |
| SOPS `exec-env` | Always invokes `/bin/sh -c`; optional same-process mode replaces SOPS with the shell. | Inherits by default; optional pristine mode. | An implicit shell makes lookup, quoting, expansion, startup files, and signals part of the interface. AgentKnock should avoid it. |
| Chamber | Direct replacement on Unix. | Supports inherited or pristine environment. Its strict mode injects only variables declared by sentinel values in advance. | Explicitly declared destination names are stronger than a denylist when the workflow can support them. |
| Vault Agent and Envconsul | Remain as supervisors for refresh and restart behavior. | Inherit and append by default, with varying allow/deny/pristine controls. | A resident parent is justified for renewal or restart, not for AgentKnock's one-time `exec` flow. |
| `vaultenv` | Replaces itself directly. | Offers no-inherit, blacklist, and explicit collision policies. | Collision behavior should be deterministic and documented. |
| `vals exec` | Runs a direct child. | Uses a pristine environment by default; inheritance is opt-in. | Pristine behavior is viable for a purpose-built workflow but would be a substantial compatibility change for an `env`-like wrapper. |
| CyberArk Summon | Runs a child and remains for signal forwarding and temporary-file cleanup. | Maps declared environment names to secrets. | Declarative destination names are reviewable. Plaintext file delivery needs a lifecycle owner and careful storage semantics. |
| systemd credentials | Gives a service immutable credential files rather than environment values. | Uses a per-service credential directory, preferably memory-backed. | File or protocol delivery is a better future shape for large, binary, scoped, or renewable credentials. It does not help arbitrary tools that require environment variables. |

None of the inspected open-source secret launchers pins the executable across an
interactive authorization delay. AgentKnock can provide a stronger binding than
the current same-user secret-launcher norm without adopting privilege-launcher
semantics.

### Technique decisions

| Technique | Decision for AgentKnock | Reason |
| --- | --- | --- |
| Direct structured argv | Adopt | Avoids shell parsing and preserves the request's exact argument boundaries. |
| Resolve and open before approval | Adopt on Linux | Binds displayed native identity to later execution. |
| `execveat(AT_EMPTY_PATH)` | Adopt for native/unknown targets | Removes the second pathname lookup. |
| Captured path `execve` | Adopt only for known `#!` scripts | Preserves normal script identity and avoids a leaked descriptor, with an explicit weaker guarantee. |
| Native-to-path error fallback | Reject | An ambiguous failure after a long wait must not trigger a fresh pathname selection. |
| `secure_path` or absolute-only commands | Reject | User-local tools are an intentional use case; the caller's original `PATH` selects the command. |
| Canonical path alone | Reject as a security control | Useful for display, but it does not bind the later open. |
| Executable hash | Adopt only as a reusable-grant match key | A stored grant supplies the expected value. The hash is not standalone approval evidence or remote attestation. |
| Sealed executable copy | Reject | Changes executable identity and breaks capabilities, labels, self-location, and other filesystem semantics. |
| Preserve inherited environment | Adopt | Required for transparent general-purpose command behavior. |
| Overlay approved variables | Adopt | Matches the credential-delivery contract; collisions must be deterministic. |
| Environment denylist | Reject as a security boundary | Incomplete, too late for AgentKnock itself, and incompatible with some real tools. |
| Clean environment | Defer to an explicit future mode | Potentially useful for a separate workflow, but too disruptive as the default. |
| Close AgentKnock-owned descriptors | Adopt | Prevents accidental relay, config, lock, and runtime descriptor leakage. |
| Close all descriptors above stderr | Reject | Caller-owned descriptors can be intentional command inputs or control channels. |
| Restore signals changed by AgentKnock/Rust | Adopt | Preserves ordinary native program behavior, notably for `SIGPIPE`. |
| Preserve cwd, stdio, tty, PID, process group, umask, and limits | Adopt | These are part of transparent invocation semantics. |
| PTY or resident monitor | Reject for environment `exec` | Changes I/O and process behavior without adding a same-user boundary. |
| `no_new_privs`, namespaces, seccomp, or chroot | Reject | This is sandbox policy, can break legitimate commands, and does not protect released values from the target. |
| Output masking | Reject | Requires interposition, is bypassable, and conflicts with direct replacement. |
| Local credential broker | Defer to renewable/helper modes | Useful only when renewal or a protocol-aware consumer justifies a resident service. |

## Recommended Linux design

### 1. Represent a selected executable in the CLI

Add a Linux-only CLI type, conceptually named `SelectedExecutable`, that owns:

- an `O_PATH|O_CLOEXEC` descriptor for the selected file;
- the original command string, retained as `argv[0]`;
- an absolute display path derived from the opened descriptor;
- an optional SHA-256 hash read from that selected object;
- the executable mode: binary or script; and
- for a known script only, the exact candidate pathname used to select it.

This type belongs in the CLI implementation. The AgentKnock library receives
only the request metadata and remains unaware of file descriptors, process
replacement, or command-line parsing.

Do not send device/inode numbers to the phone. They are useful implementation
identifiers but poor approval context for either a person or an LLM. The
resolved path remains the useful displayed fact. Do not add a writability field
until a phone policy or approval UI will actually use it; it would be
host-reported advisory context, not attestation.

The initial strong Linux implementation should require Linux 5.8 or newer and a
mounted, usable `/proc/self/fd`. `execveat` itself arrived in Linux 3.19, but the
fd-relative effective-access check used here requires `faccessat2` from Linux
5.8. The reference Debian target satisfies both requirements. On an older kernel
or a host without the required procfs view, fail before sending a credential
request. Do not silently substitute a mode-bit-only check or a metadata path
that was not derived from the opened file. The glibc `execveat` wrapper requires
glibc 2.34; using the Linux syscall directly avoids adding that separate
user-space version floor.

### 2. Resolve and open before sending the request

Use this sequence:

1. Open the current directory as
   `O_PATH|O_DIRECTORY|O_CLOEXEC`, then capture its display name and the original
   `PATH` before any credentials are requested. The directory descriptor, not a
   reconstructed `getcwd()` string, is the base for every relative open.
2. If the command contains `/`, open an absolute path directly or use `openat`
   relative to the captured current-directory descriptor.
3. Otherwise, search the captured `PATH` in order. Preserve empty and relative
   components by using `openat` relative to the captured current-directory
   descriptor. If `PATH` is absent, use the platform's `_CS_PATH` value rather
   than inventing an application-specific search path.
4. Open each candidate with `O_PATH|O_CLOEXEC`. If an internal descriptor is
   unexpectedly numbered 0, 1, or 2, close it and fail an internal invariant
   before the request. Rust normally filled initially closed standard
   descriptors with `/dev/null` before `main`; guessing how to reconstruct an
   unexpected standard-descriptor state is less safe than failing.
5. Use `fstat` on the descriptor and require a regular file.
6. Use
   `faccessat2(fd, "", X_OK, AT_EMPTY_PATH|AT_EACCESS)` as an effective-access
   preflight. `execveat` remains the authoritative kernel permission check.
7. Derive the display path by reading `/proc/self/fd/<fd>` after opening, rather
   than canonicalizing a name and opening it later. If the selected display path
   is not valid UTF-8, fail before the credential request because the current
   protocol represents it as a JSON string.
8. Keep the descriptor alive through request, response, and completion.

For the reference Linux/glibc behavior, a `PATH` search should remember
`EACCES` and continue after `EACCES`, `ENOENT`, `ESTALE`, `ENOTDIR`, `ENODEV`, or
`ETIMEDOUT`. It should stop on other errors. If no candidate is selected, report
`EACCES` when at least one candidate produced it; otherwise report the final
lookup error. A directory or a regular file that fails effective execute access
counts as `EACCES`. This mirrors glibc's treatment of lookup and access errors,
not its complete execute-at-each-candidate behavior. AgentKnock selects before
the kernel checks file format and interpreter dependencies; a later format or
interpreter failure is terminal rather than a reason to select another path or
invoke a shell. A command containing `/` has no search and returns its own error
directly.

Opening must happen before the request. Opening only after approval would bind
setup to execution but would not bind the executable shown during approval.

The resolver should return a real error rather than `None`. A missing,
non-executable, non-regular, inaccessible, or non-UTF-8 target should stop before
any request is sent. This avoids asking for credentials for a command that
AgentKnock already knows it cannot launch.

### 3. Classify scripts before approval

After opening the `O_PATH` descriptor, try to open the same object read-only
through `/proc/self/fd/<fd>` and inspect only the initial bytes needed to detect
`#!`.

- If the bytes start with `#!`, mark the target as a known script.
- If they do not, use pinned execution.
- If read access is unavailable, use pinned execution and fail closed if the
  kernel later cannot execute it. Do not assume that an execute-only file is a
  script merely because descriptor execution returns `ENOENT`.

This classification is about execution mechanics, not recursive identity. Do
not parse, resolve, open, or report the shebang interpreter. A shebang such as
`#!/usr/bin/env node` intentionally retains its normal interpreter and `PATH`
semantics. Other kernel interpreter mechanisms, including `binfmt_misc`, remain
outside this classification and may fail closed if descriptor execution cannot
support them.

### 4. Send request metadata for the selected object

Continue to send:

- the original command and structured arguments;
- the resolved display path;
- the optional executable hash;
- the executable mode, as `BINARY` or `SCRIPT`;
- the captured working directory;
- stream kinds, launcher chain, profiles, and reason; and
- other existing request context.

The command and arguments must remain separate values. A joined command line is
only suitable for display because quoting is not canonical and cannot safely
reconstruct the original argument vector.

The resolved path is authenticated host-reported context. It is not remote
attestation. A compromised host can lie in the request or interfere with the
launcher, so the phone must not present it as independently verified by the
operating system.

#### Executable hash for reusable grants

Protocol version 1 should define `executable_hash` as the base64-encoded SHA-256
hash of the selected file. The algorithm does not need a separately negotiated
field: changing it would be a protocol-version change. Internally, keep the
digest as 32 bytes and encode it only at the protocol boundary.

Read and hash the file through the already selected descriptor, not by reopening
the reported pathname. The read-only descriptor used for shebang detection can
also supply the hash. If the selected file is execute-only and cannot be read,
omit the field. A one-time approval can still proceed, but the device must not
create or apply an executable-hash-bound reusable grant for that request.

The device does not need to show the raw hash to a person or an LLM. It can
describe the stored condition as "same executable version" while comparing the
bytes exactly. This requires no history database: each reusable grant stores
only the digest it approved.

Keep the resolved path in the grant even when the hash is present. Identical
bytes at different paths can behave differently through `argv[0]`, `$ORIGIN`,
`/proc/self/exe`, adjacent resources, configuration, or plugins. A hash-only
grant would authorize any copy of those bytes at any path. The conservative
baseline for a time-bounded executable grant is therefore:

- the exact `client_id`;
- the operation or method;
- the exact, canonicalized profile set;
- the original command or `argv[0]`;
- the resolved executable path;
- the executable hash; and
- the grant expiry.

Sort and deduplicate profiles before creating or matching this key. A request
for additional profiles must not match a grant for a smaller set. Arguments
need a separately defined policy: the same `ssh`, `gh`, or `aws` executable can
perform materially different operations, so path and hash must not silently
mean "all arguments are approved." Exact arguments, a constrained command
shape, or an intentionally executable-wide grant are possible choices for a
future policy design.

Do not bind the parent or launcher chain by default. That context is useful to
show during approval, but it is host-reported, same-user-spoofable, and unstable
across shells, wrappers, terminals, and agent upgrades. It would make grants
expire for reasons that do not necessarily change the requested authority. It
can become an explicit additional policy condition later if a concrete policy
uses it.

When a hash was sent, recompute it after the authenticated response and
completion exchange, but before process replacement. For pinned execution,
read the retained selected object. For a shebang script, read the captured
pathname that will actually be executed; otherwise a pathname replacement could
pass a check of the obsolete descriptor. If the hash changed, do not execute. In
accordance with the existing completion semantics, a signal or local failure
after an authenticated response does not rewrite the device's result as
`ABORTED`. This check narrows the mutation window, but it cannot eliminate a
final in-place write or pathname race. Descriptor execution pins a native
filesystem object, not immutable contents, and the script mode remains weaker.

The hash covers only the selected top-level file. It does not cover an ELF
interpreter, shared libraries, script interpreter, plugins, configuration,
working-directory contents, or descendants. It is also reported by the client,
not remotely attested; a compromised client can lie. It is nevertheless useful
for an honest client because an edit or package update stops a previous
time-bounded grant from matching.

### 5. Construct the final environment deterministically

After a valid approved response and completion exchange:

1. Start with the environment inherited by AgentKnock, using `vars_os` or an
   equivalent byte-preserving API so unrelated non-UTF-8 entries survive.
2. Overlay the returned profile variables, with returned values winning on a
   name collision. This preserves the current intended credential-injection
   behavior.
3. Reject an empty variable name, a name containing `=` or NUL, or a value
   containing NUL. The protocol is UTF-8, so no additional byte-encoding policy
   is needed today.
4. Ensure the representation contains at most one entry for each name. Never
   pass duplicate `NAME=value` entries with implementation-dependent lookup
   behavior.
5. Never log values. Verbose output may continue to print sorted variable names.

Do not maintain a blacklist of `LD_*`, `PATH`, `BASH_ENV`, `NODE_OPTIONS`,
`PYTHONPATH`, `GIT_*`, and similar names as a claimed security boundary. The set
is open-ended, inherited values may have affected AgentKnock already, and many
tools legitimately depend on environment-controlled configuration. Descriptor
execution ensures that even an overlaid `PATH` does not change the selected
top-level native executable, but such values can still affect loaders,
interpreters, plugins, and descendant commands. This limitation must be stated
plainly.

If a later workflow needs stronger environment control, design an explicit
`--clean-env`-style mode with a small allowlist and clear compatibility costs.
Do not silently change the default execution environment.

### 6. Replace the process directly

Immediately before execution:

1. Preserve the existing SIGINT/SIGTERM request state machine through protocol
   completion. Only after completion is finished and the CLI has decided to
   execute, set SIGINT, SIGTERM, and SIGPIPE to `SIG_DFL` immediately before the
   exec call. This preserves Rust's current `SIGPIPE` child behavior and ensures
   that a termination signal in the final narrow window stops AgentKnock instead
   of being swallowed by a now-unused Tokio handler. Do not alter the inherited
   signal mask unless AgentKnock itself changed it.
2. Verify that every AgentKnock-owned descriptor other than the selected
   executable descriptor is close-on-exec or already closed. This includes
   WebSocket, configuration, lock, random-source, timer, and runtime descriptors.
3. Preserve caller-owned inherited descriptors. Do not run `closefrom` or
   `close_range` across them; descriptor inheritance can be part of an
   intentional command interface.
4. Build `argv` with the original command string as `argv[0]`, followed by the
   exact parsed arguments. This is the native program's `argv`; the kernel
   applies normal shebang transformation for a script. Build a single
   deterministic `envp`.
5. For a pinned target, call
   `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`.
6. For a known shebang script, call `execve` once on the captured candidate
   pathname. This preserves distinctions such as `./tool` versus
   `/absolute/path/tool` and a selected symlink path. Do not call `execvp`, do
   another `PATH` search, or add an `ENOEXEC` shell fallback.

For pinned execution, any error is terminal. In particular, do not retry by
path after `ENOENT`. This keeps a missing ELF interpreter, unsupported script,
or other ambiguous failure from becoming a pathname substitution after
approval.

Descriptor execution still performs the kernel's ordinary execute-permission,
mount `noexec`, set-user-ID/file-capability, LSM, and interpreter checks. Holding
an `O_PATH` descriptor does not bypass them.

Descriptor execution is not completely invisible to the target or the host.
Linux constructs a `/dev/fd/<n>`-style execution name for
`execveat(AT_EMPTY_PATH)`; this can appear through `AT_EXECFN`, auditing,
path-oriented policy, or program self-inspection. `/proc/self/exe` still refers
to the executed file object, but compatibility-sensitive programs and policies
must be tested.

For known scripts, path replacement remains possible during the approval wait.
That limitation is accepted in preference to leaking the descriptor through the
interpreter and changing the script path. An immediate device/inode comparison
before `execve` could detect some replacements but cannot remove the final race;
it should not be presented as pinning and is not necessary for the initial
implementation.

### 7. Preserve transparent process semantics

Do not change the following as part of this work:

- real, effective, or saved user and group IDs;
- supplementary groups or capabilities;
- current working directory;
- stdin, stdout, stderr, terminal, process group, or session;
- process ID after the final replacement;
- umask or resource limits;
- namespaces, cgroups, LSM context, or seccomp state; or
- the caller's existing `no_new_privs` state.

In particular, AgentKnock must not set `no_new_privs`. That flag is inherited and
irreversible, and it prevents set-user-ID, set-group-ID, and file-capability
transitions while also affecting LSM behavior. It would unexpectedly break
commands such as `sudo` and would not stop a same-user target from reading the
credentials it was given.

Do not allocate a PTY or keep a monitoring parent. Those mechanisms are useful
for sudo I/O policy, output masking, renewal, or process supervision, but they
conflict with AgentKnock's direct-replacement contract.

## Exact guarantee and non-guarantees

After implementation, documentation and UI may accurately say:

- AgentKnock resolves the top-level command before requesting credentials.
- On Linux, AgentKnock pins a native top-level executable and executes that same
  opened filesystem object after approval.
- AgentKnock passes the approved argument vector without an implicit shell.
- AgentKnock resolves the top-level executable before applying returned
  environment variables.
- AgentKnock replaces itself with the command after protocol completion.

They must not say:

- that the executable bytes are immutable;
- that the executable path, owner, or contents are remotely attested;
- that scripts or interpreter chains are pinned;
- that the ELF interpreter, libraries, plugins, configuration, or descendants
  are pinned;
- that descriptor execution is unobservable through `AT_EXECFN`, auditing,
  path-oriented policy, or self-inspection;
- that the process is unaffected by its environment;
- that credentials are hidden from the approved process tree or other actors
  with sufficient same-user inspection authority; or
- that AgentKnock provides sudo, sandbox, or privilege-separation guarantees.

The strongest ordinary case is a non-user-writable native system executable:
path replacement is ineffective after selection, and the invoking user normally
cannot alter the pinned inode in place. A user-owned native executable still
benefits from pathname pinning, but another same-user process may be able to
modify its opened inode. A script receives only the weaker captured-path
behavior.

## Techniques considered and rejected

### Using a hash as standalone approval evidence

A newly computed digest has no external meaning to a person or an LLM, so do
not present it as proof that an executable is safe and do not build per-host
hash history. Hash-then-path-exec would also remain racy, and hashing does not
stop later in-place writes to an open writable inode. Descriptor pinning remains
the mechanism that binds selection to native execution. The adopted hash has a
different and narrower role: exact matching against the value stored in a
previously approved reusable grant.

### Copying into a sealed `memfd`

A sealed memory file could freeze copied bytes, but it creates a different
execution object. It can lose file capabilities, extended attributes, LSM/IMA
identity, filesystem provenance, signatures, fs-verity semantics, and normal
`/proc/self/exe` or self-location behavior. `$ORIGIN`-relative library and
resource lookup can change, and hosts can prohibit executable memory files.
This is not a transparent launcher mechanism.

### File leases or repeated metadata checks

Leases have ownership and filesystem limitations, can be broken, and are a poor
fit for an unbounded human approval wait. Repeated `stat`, owner, mode, time, or
inode checks on a pathname only narrow races. The descriptor itself is the
correct identity handle.

### `openat2` path restrictions

Flags that prohibit symlinks, mount crossings, or paths outside a chosen root
are useful when resolving an untrusted path beneath a trusted directory.
AgentKnock has no such trusted root and must support symlinks, bind mounts, Nix
profiles, and user toolchains. These restrictions would reject normal commands
without strengthening the same-user boundary.

### Environment sanitization

Sudo, doas, and pkexec reconstruct environments because an untrusted caller is
crossing into a more privileged security domain. AgentKnock stays in the same
domain and intentionally runs general developer tools. A clean environment
would break common authentication, configuration, toolchain, locale, terminal,
and home-directory behavior. An incomplete denylist would create a misleading
security claim. Preserve-and-overlay is the honest default.

### Closing all extra descriptors

Privilege launchers close unexpected descriptors so a privileged child cannot
inherit attacker-selected communication channels. AgentKnock receives no new OS
privilege, and inherited descriptors may be deliberate inputs, outputs, sockets,
or control channels. Only AgentKnock-owned descriptors should be close-on-exec.

### PTY, monitor, sandbox, or system service

These are appropriate when enforcing I/O policy, changing privilege, refreshing
credentials, restarting a target, or containing it. They alter process
identity, signals, terminal behavior, namespaces, and output. AgentKnock's
environment mode needs none of those functions. Future renewable-token,
credential-helper, SSH-agent, or file-credential modes may justify a separate
resident broker design.

## Implementation outline

The implementation can remain small:

1. Add a direct Linux dependency or feature for the few descriptor and exec
   operations. The project already receives `nix` transitively, but a direct
   dependency is appropriate if its API is used. A small audited `libc` wrapper
   is also viable; avoid a new abstraction-heavy process library.
2. Replace `resolve_command_path` with the owning `SelectedExecutable` resolver.
3. Pass its display path and optional SHA-256 hash into the existing credential
   request.
4. Retain the object across the asynchronous WebSocket exchange.
5. Replace the current `ProcessCommand::exec` function with explicit environment
   construction, signal restoration, and `execveat`/`execve` calls.
6. Keep the entire change in the CLI except for any protocol field that is
   explicitly chosen for the phone. Credential retrieval remains library work;
   process selection and replacement remain CLI work.

No daemon, helper process, privilege transition, hash-history database, new
client config file, or client-side policy language is required. Reusable grants
and their expected hashes belong on the approving device.

## Verification plan

### Resolver tests

- A slashless command selects the first effectively executable regular file in
  the captured `PATH`.
- Search continues past a directory, a non-executable file, and an inaccessible
  candidate as normal lookup requires.
- Empty and relative `PATH` components use the captured working directory.
- A command containing `/` does not search `PATH`.
- An absent `PATH` uses `_CS_PATH`.
- A selected non-UTF-8 display path fails before any credential request.
- AgentKnock's own descriptors never replace the standard-descriptor state
  established by the Rust runtime.
- Relative qualified commands and relative or empty `PATH` entries resolve from
  the captured current-directory descriptor even if its pathname is renamed.
- Lookup continues and stops on the documented Linux/glibc error classes and
  preserves final `EACCES` precedence.
- Linux older than 5.8 or a missing `/proc/self/fd` fails before the credential
  request.

### Identity-race integration tests

Use a test relay that pauses between request and approval:

- Put native executable A at a searched path, receive the request, atomically
  replace the path with executable B, approve, and verify that A runs.
- Repeat with a symlink retarget, parent-directory rename, unlink/recreate, and
  returned `PATH` pointing to B.
- Delete the selected path entirely before approval and verify that the pinned
  native executable still runs.
- Modify the bytes of a user-writable selected inode in place and document the
  observed limitation rather than treating it as protected.
- Make a pinned native executable's ELF interpreter unavailable and verify that
  AgentKnock fails without path fallback.

### Reusable-grant hash tests

- The hash is read from the selected object rather than from a later pathname
  lookup.
- Replacing or retargeting the pathname after selection does not change the hash
  sent for the retained object.
- A later request with the same client, method, exact profile set, original
  command, resolved path, and hash matches the grant.
- Changing either the file contents or resolved path prevents a match, including
  when identical bytes exist at a different path.
- A larger or smaller profile set does not match.
- An unreadable execute-only file omits the hash and cannot use an
  executable-hash-bound reusable grant.
- An in-place modification detected after approval aborts execution, while the
  remaining final-write race is documented rather than claimed to be solved.
- A script hash covers the script file only; changing its interpreter or other
  dependencies remains outside the grant's file-identity check.

### Script tests

- A `#!` script runs through its captured candidate pathname with its normal
  apparent path and kernel-defined argument transformation.
- Script execution never invokes `/bin/sh` unless the shebang or the explicit
  user command selects it.
- A non-shebang text file produces an execution error rather than the historical
  `execvp` shell fallback.
- Replacing a script path during approval demonstrates and documents the weaker
  script guarantee.
- `#!/usr/bin/env ...` retains normal interpreter lookup behavior.

### Environment and process tests

- Returned values override inherited values deterministically.
- Invalid names and embedded NUL bytes are rejected before execution.
- A returned `PATH` cannot change the pinned top-level native executable.
- Variable names can appear in verbose diagnostics, but values never do.
- PID, cwd, stdio, process group, session, umask, resource limits, and
  deliberately inherited descriptors have the expected direct-exec behavior.
- AgentKnock-owned descriptors do not survive into the target.
- `SIGPIPE` has its default disposition in the executed process.
- SIGINT or SIGTERM received after completion but before the exec system call
  prevents the command from starting.
- Native probes record and validate observable `AT_EXECFN`, `/proc/self/exe`,
  and relevant audit or path-policy behavior.
- SIGINT and SIGTERM behavior before response, after response, and during
  completion remains consistent with the existing protocol semantics.

### Platform behavior

The strong executable-binding guarantee is Linux-specific. Non-Linux behavior
should either remain explicitly unsupported for `exec` or receive a separately
designed platform implementation. It must not silently claim Linux descriptor
pinning when it only performs path execution.

## Primary sources

Sources were reviewed on 2026-08-16. Repository links are pinned to the reviewed
revision where practical.

### Linux and Rust execution semantics

- [`execveat(2)`](https://man7.org/linux/man-pages/man2/execveat.2.html)
- [`fexecve(3)`](https://man7.org/linux/man-pages/man3/fexecve.3.html)
- [`execvp(3)`](https://man7.org/linux/man-pages/man3/execvp.3.html)
- [glibc `execvpe` lookup and error handling](https://codebrowser.dev/glibc/glibc/posix/execvpe.c.html)
- [POSIX `exec` family](https://pubs.opengroup.org/onlinepubs/9799919799/functions/exec.html)
- [`open(2)` and `O_PATH`](https://man7.org/linux/man-pages/man2/open.2.html)
- [`faccessat2(2)`](https://man7.org/linux/man-pages/man2/faccessat.2.html)
- [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [dynamic loader secure-execution mode](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Linux `no_new_privs`](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [`/proc/<pid>/environ`](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)
- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [core dumps](https://man7.org/linux/man-pages/man5/core.5.html)
- [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [executable `memfd` policy](https://docs.kernel.org/userspace-api/mfd_noexec.html)
- [Rust Unix `CommandExt`](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html)
- [Rust runtime signal initialization](https://doc.rust-lang.org/src/std/rt.rs.html)
- [Rust Unix runtime initialization](https://doc.rust-lang.org/stable/src/std/sys/pal/unix/mod.rs.html)
- [Rust Unix command execution and `SIGPIPE` reset](https://doc.rust-lang.org/src/std/sys/process/unix/unix.rs.html)
- [`nix::unistd::execveat`](https://docs.rs/nix/latest/nix/unistd/fn.execveat.html)

### Privilege and service launchers

- [sudo path resolution](https://github.com/sudo-project/sudo/blob/3b1617ff2f17b962bdd1d1074bdccca030a9dbf6/plugins/sudoers/find_path.c#L87-L166)
- [sudo executable opening and matching](https://github.com/sudo-project/sudo/blob/3b1617ff2f17b962bdd1d1074bdccca030a9dbf6/plugins/sudoers/match_command.c#L163-L243)
- [sudo descriptor execution](https://github.com/sudo-project/sudo/blob/3b1617ff2f17b962bdd1d1074bdccca030a9dbf6/src/exec_common.c#L91-L130)
- [sudo `fdexec` documentation](https://github.com/sudo-project/sudo/blob/3b1617ff2f17b962bdd1d1074bdccca030a9dbf6/docs/sudoers.mdoc.in#L4933-L4978)
- [sudo environment policy](https://github.com/sudo-project/sudo/blob/3b1617ff2f17b962bdd1d1074bdccca030a9dbf6/plugins/sudoers/env.c#L129-L229)
- [sudo-rs command resolution](https://github.com/trifectatechfoundation/sudo-rs/blob/538f5af64d34c40e8ee97004793553c573675d83/src/common/command.rs#L59-L109)
- [sudo-rs path execution](https://github.com/trifectatechfoundation/sudo-rs/blob/538f5af64d34c40e8ee97004793553c573675d83/src/exec/mod.rs#L229-L268)
- [OpenBSD `doas(1)`](https://man.openbsd.org/doas)
- [OpenBSD `doas.conf(5)`](https://man.openbsd.org/doas.conf)
- [OpenBSD doas execution](https://github.com/openbsd/src/blob/63d30f6f93ff9faed796cfea1af89df9fa4894de/usr.bin/doas/doas.c#L327-L497)
- [`pkexec(1)`](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [pkexec resolution and execution](https://github.com/polkit-org/polkit/blob/b3492d5ea73e030dedf53a08091d54c0ccb08acc/src/programs/pkexec.c#L650-L732)
- [systemd executable search and opening](https://github.com/systemd/systemd/blob/c44e9527b7208345605c108d56a82c0820946a7f/src/basic/path-util.c#L672-L785)
- [systemd descriptor execution](https://github.com/systemd/systemd/blob/c44e9527b7208345605c108d56a82c0820946a7f/src/shared/exec-util.c#L522-L552)
- [`run0` documentation](https://github.com/systemd/systemd/blob/c44e9527b7208345605c108d56a82c0820946a7f/man/run0.xml)
- [Bubblewrap](https://github.com/containers/bubblewrap)

### Secret launchers

- [1Password `op run`](https://www.1password.dev/cli/reference/commands/run)
- [Doppler run implementation](https://github.com/DopplerHQ/cli/blob/a8671b86a839187fcbfdbd449fc5787dc62ab42f/pkg/cmd/run.go)
- [Doppler environment security warning](https://docs.doppler.com/docs/accessing-secrets)
- [Infisical run implementation](https://github.com/Infisical/cli/blob/242df555bcbef217c288ca7df5e7ce5389830d82/packages/cmd/run.go)
- [`aws-vault` execution](https://github.com/99designs/aws-vault/blob/74e2f7ac256f4da1efbc8a48a4c0c364e454acd4/cli/exec.go)
- [SOPS execution implementation](https://github.com/getsops/sops/blob/30332a959e3d987f622702519f6b52d8ff81e1dc/cmd/sops/subcommand/exec/exec_unix.go)
- [Chamber execution](https://github.com/segmentio/chamber/blob/5f93f5f357740686db56a037935b4dfd9805ca57/cmd/exec.go)
- [Chamber strict environment handling](https://github.com/segmentio/chamber/blob/5f93f5f357740686db56a037935b4dfd9805ca57/environ/environ.go)
- [Vault Agent process supervisor](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/process-supervisor)
- [Envconsul environment and signal policy](https://github.com/hashicorp/envconsul/blob/43f72e275f6cf2deb94ea40f179e393e75cd6000/README.md)
- [`vaultenv`](https://github.com/channable/vaultenv/blob/d6fda1a1710176a316c382aeaf08d98845f74db3/README.md)
- [`vals exec`](https://github.com/helmfile/vals/blob/3e5f8f0519858eff501356d69b17098ddf3c565f/vals.go)
- [CyberArk Summon](https://cyberark.github.io/summon/)
- [systemd service credentials](https://systemd.io/CREDENTIALS/)
