# Agentknock

[Agentknock](https://agentknock.dev/) lets command-line tools use secrets
without storing long-lived credentials in agent configuration or project
files. A paired mobile device authorizes each request and sends the requested
secrets to the command.

## How Agentknock works

Agentknock delivers secrets from a paired mobile device when a command needs
them. For example:

1. Run a command with the `gh-token` secret:

   ```sh
   agentknock exec -s gh-token -- gh pr merge 123
   ```

2. The paired mobile device displays the request. Approve the use of
   `gh-token` for this command.

3. Agentknock runs `gh pr merge 123` with access to `gh-token`. The secret is
   available only to that execution and is not printed or written to disk.

## Install the Agentknock client

Choose one of the following installation methods.

### Use the installation script

The installation script downloads the latest prebuilt release to
`~/.local/bin`:

```sh
curl -fsSL https://agentknock.dev/install.sh | bash
```

Run the same command again to update Agentknock.

### Use mise

Use the GitHub release through mise:

```sh
mise use --global github:nakedible/agentknock-cli
```

Run `mise upgrade github:nakedible/agentknock-cli` to update Agentknock.

### Build from source with Cargo

Install Rust 1.89 or later, then build and install Agentknock from crates.io:

```sh
cargo install --locked agentknock
```

Run the same command again to update Agentknock.

## Install the Agentknock mobile app

### Google Play

Install the Agentknock app from
[Google Play](https://play.google.com/store/apps/details?id=dev.agentknock).

### App Store

The Agentknock app for iOS isn't available yet.

## Get started

Agentknock includes its complete command-line reference in `--help`. Run
`agentknock --help` for an overview, or use `--help` with any command for
detailed instructions.

### Pair the client

Use the pairing address that you selected when you set up the mobile app. For
example, if the address is `calm-river-lantern`:

1. Start pairing on the client:

   ```sh
   agentknock pairing start calm-river-lantern
   ```

2. Confirm the full 12-digit verification code on the mobile device, then
   approve the pairing. If the code doesn't match, reject the pairing and run
   `agentknock pairing abort`.

3. After you approve the pairing, activate it on the client:

   ```sh
   agentknock pairing finish
   ```

The client can now request secrets from the paired mobile device.

### Run a command with secrets

The `exec` command requires at least one secret. Repeat `-s` when a command
needs more than one, and use `--reason` to add context to the request:

```sh
agentknock exec -s gh-token -s cloudflare --reason "Publish release" -- ./release.sh
```

The `--` separator is required. Agentknock passes the command and every
argument after the separator unchanged.

Agentknock waits for the paired mobile device to authorize the request and
return the secrets before it starts the command. If the request is still
waiting after 30 seconds, Agentknock writes a progress update with the elapsed
time to standard error every 30 seconds. Press Ctrl-C to cancel the request.

## Manage secrets

Manage secrets primarily in the mobile app. The commands in this section
contact the paired mobile device and wait for its response. During a long wait,
Agentknock reports progress and elapsed time every 30 seconds.

### List secrets

Request the secrets available to this client:

```sh
agentknock secret list
```

The command writes a JSON object to standard output. It maps each secret name
to its type, description, and the environment variable names that it provides.
It never includes secret values. Progress and errors go to standard error, so
you can process or redirect the JSON separately.

### Upload an environment secret

Agentknock can migrate existing environment variables to the mobile app. It
reads values from the sources that you specify; the values do not appear in
the command arguments.

To migrate a variable from the current environment:

```sh
agentknock secret upload gh-token \
  --description "GitHub API access" \
  --from-env GH_TOKEN
```

To migrate all variables from a dotenv file:

```sh
agentknock secret upload development --from-env-file .env
```

To enter values without displaying them:

```sh
agentknock secret upload cloudflare --from-prompt CLOUDFLARE_API_TOKEN
```

To read one variable from a file:

```sh
agentknock secret upload npm --from-file NPM_TOKEN=/path/to/token
```

You can repeat and combine `--from-env`, `--from-env-file`, `--from-file`, and
`--from-prompt`. Use `--from-env-file -` to read dotenv data from standard
input, or `--from-file NAME=-` to read one value from standard input.

An upload is a proposal, not an immediate change to the secrets on the mobile
device. The command finishes after the mobile app confirms receipt of the
proposal. Review and accept the proposal in the mobile app before the secret
becomes available to this client.

By default, an upload proposes a new secret. Use `--update` to change the
values that you provide while retaining the other values in an existing
secret:

```sh
agentknock secret upload gh-token --update --from-prompt GH_TOKEN
```

Use `--replace` to propose a complete replacement. Values that you don't
provide are removed if you accept the proposal. When you propose a new secret,
you can change its name before you accept it in the mobile app.

Uploading does not modify or delete the source environment variables or files.
After you accept the proposal and verify the secret, remove old local copies
that you no longer need.

## Security

Agentknock uses a relay service to carry messages between the client and mobile
device. The security design treats the relay as untrusted. The client and
mobile app are both open source and protect messages with end-to-end encryption
and authentication. After you verify a pairing, the relay cannot obtain secret
values, read other protected contents, or alter an accepted protected message
without detection. It can observe routing metadata, message sizes, timing, and
traffic relationships, and it can deny service.

Starting a pairing is unauthenticated: anyone who knows the pairing address can
send a request. Confirm the full 12-digit verification code before you approve
a pairing on the mobile device. The code identifies the exact client that you
intend to trust, including when multiple pairing requests are pending. It also
detects substitution by the relay and lets the relay remain outside the trust
boundary. Reject the pairing if you cannot confirm the complete code.

Agentknock never writes delivered secret values to disk. On Linux, it opens a
native executable before requesting secret use and executes that same
filesystem object after approval. This prevents a path, symlink, or file
replacement during the wait from selecting a different top-level native
executable.

Agentknock is not a sandbox or privilege boundary. The approved command
controls the secrets that it receives and can print them, write them to disk,
or otherwise disclose them. Only approve secret access for commands that you
trust to handle the values safely. Descendant commands and other processes
with sufficient same-user inspection access might also observe them.

For the complete design, threat model, and limitations, read the
[Agentknock v1 cryptosystem](https://github.com/nakedible/agentknock-cli/blob/master/docs/CRYPTOSYSTEM.md)
and [secure command execution analysis](https://github.com/nakedible/agentknock-cli/blob/master/docs/secure-command-execution.md).
Report suspected vulnerabilities according to the
[security policy](https://github.com/nakedible/agentknock-cli/security/policy).

## Supported platforms

## Use the Rust library

## Documentation

## Contribute

## License
