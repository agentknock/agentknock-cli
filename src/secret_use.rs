use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Client, RequestError, RequestProgress, protocol::Method};

const INVOCATION_TOKEN_LENGTH: usize = 32;

/// Describes an invocation request that selects one or more secrets.
///
/// The device uses this metadata to decide how to answer the request. The client
/// that constructs it is responsible for reporting the operation and launcher
/// information accurately.
pub struct SecretUseRequest<'a> {
    /// The unique secrets requested together and their delivery options.
    pub secrets: &'a BTreeMap<String, SecretUseOptions>,

    /// The operation that will receive or use the selected secrets.
    pub operation: SecretUseOperation<'a>,

    /// An optional explanation of why the operation needs each selected secret.
    ///
    /// Agentknock transmits this value unchanged.
    pub reason: Option<&'a str>,

    /// The programs that launched the embedding application.
    ///
    /// Order and selection are defined by the embedding application.
    pub launcher_chain: &'a [String],
}

/// Configures how one requested secret is delivered.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretUseOptions {
    /// Options for an environment-variable secret.
    pub environment: EnvironmentVariableOptions,
}

/// Configures which variables an environment secret delivers and where.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentVariableOptions {
    /// The only stored variable names to deliver.
    ///
    /// `None` selects all variables that aren't omitted. A present set must
    /// not be empty.
    pub only: Option<BTreeSet<String>>,

    /// Stored variable names not to deliver.
    pub omit: BTreeSet<String>,

    /// Stored variable names mapped to command environment names.
    pub rename: BTreeMap<String, String>,

    /// A stored variable to deliver to the command's standard input instead
    /// of its environment.
    pub stdin: Option<String>,
}

impl EnvironmentVariableOptions {
    fn is_empty(&self) -> bool {
        self.only.is_none()
            && self.omit.is_empty()
            && self.rename.is_empty()
            && self.stdin.is_none()
    }
}

/// Describes how a command's standard stream is connected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    /// The stream is connected to a terminal.
    Terminal,

    /// The stream is connected to a null device such as `/dev/null`.
    NullDevice,

    /// The stream is connected to a pipe.
    Pipe,

    /// The stream is connected to a socket.
    Socket,

    /// The stream is connected to a regular file.
    RegularFile,

    /// The connection type is unavailable or isn't represented by another variant.
    Unknown,
}

/// A command operation described by an invocation request.
#[non_exhaustive]
pub enum SecretUseOperation<'a> {
    /// Executes a program with selected secrets available to it.
    Exec {
        /// The executable name or path supplied by the caller.
        command: &'a str,

        /// The executable arguments, excluding argument zero.
        arguments: &'a [String],

        /// The working directory in which the executable will run.
        working_directory: &'a str,

        /// The resolved path of the executable selected for execution.
        executable_path: &'a str,

        /// The SHA-256 digest of the selected executable, when available.
        executable_hash: Option<&'a [u8; 32]>,

        /// Whether the selected executable is a native binary or a script.
        executable_mode: ExecutableMode,

        /// The entire selected shebang script, when included for review.
        ///
        /// Invalid UTF-8 sequences are replaced with U+FFFD. The executable hash
        /// identifies the original file bytes, not this potentially lossy text.
        script_contents: Option<&'a str>,

        /// How the executable's standard input is connected.
        stdin: StreamKind,

        /// How the executable's standard output is connected.
        stdout: StreamKind,

        /// How the executable's standard error is connected.
        stderr: StreamKind,
    },
}

/// The form of a selected executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutableMode {
    /// A native executable binary.
    Binary,

    /// A script that selects an interpreter with a shebang line.
    Script,
}

/// Secret material and related authorization returned for an invocation.
///
/// This type doesn't implement [`Debug`](std::fmt::Debug) because it contains
/// secret values. Use [`SecretUseOutput::environment_variable_names`] to
/// inspect names without exposing values. Use
/// [`SecretUseOutput::stdin_value`] to access requested standard-input
/// delivery before consuming the output with
/// [`SecretUseOutput::into_environment`].
pub struct SecretUseOutput {
    environment: BTreeMap<String, String>,
    stdin: Option<String>,
    ssh: Option<SshSecretUse>,
    invocation: SecretUseInvocation,
}

/// An SSH secret made available to a command invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshSecretUse {
    name: String,
    public_key: String,
}

/// Identifies and authenticates operations that belong to one command invocation.
///
/// Treat the token as secret. Child processes don't receive it directly; an
/// invocation service can retain it and perform deferred operations for them.
#[derive(Clone)]
pub struct SecretUseInvocation {
    id: String,
    token: [u8; INVOCATION_TOKEN_LENGTH],
}

impl SecretUseOutput {
    /// Returns the names of the approved environment variables.
    ///
    /// Names are yielded in lexicographic order. Values aren't exposed by this
    /// iterator.
    pub fn environment_variable_names(&self) -> impl Iterator<Item = &str> {
        self.environment.keys().map(String::as_str)
    }

    /// Returns one approved environment variable value by name.
    pub fn environment_variable(&self, name: &str) -> Option<&str> {
        self.environment.get(name).map(String::as_str)
    }

    /// Returns the approved value to deliver to standard input, if requested.
    pub fn stdin_value(&self) -> Option<&str> {
        self.stdin.as_deref()
    }

    /// Returns the SSH secret available to the invocation, if one was requested.
    pub fn ssh(&self) -> Option<&SshSecretUse> {
        self.ssh.as_ref()
    }

    /// Returns the authorization for operations that belong to this invocation.
    pub fn invocation(&self) -> &SecretUseInvocation {
        &self.invocation
    }

    /// Consumes the output and returns its environment variables and values.
    ///
    /// The map is keyed by environment variable name and ordered
    /// lexicographically. This discards any standard-input value, SSH public
    /// key, and invocation authorization retained by the output.
    pub fn into_environment(self) -> BTreeMap<String, String> {
        self.environment
    }
}

impl SshSecretUse {
    /// Returns the secret name requested by the client.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the SSH public key in OpenSSH format.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

impl SecretUseInvocation {
    /// Returns the request identifier for the initial invocation request.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the authorization token for related operations.
    pub fn token(&self) -> &[u8; 32] {
        &self.token
    }
}

impl Client {
    /// Requests selected secrets for an invocation.
    ///
    /// The authenticated response must contain exactly the requested secret
    /// names and honor their delivery options. Environment values are selected,
    /// omitted, renamed, or separated for standard-input delivery as requested.
    /// An SSH secret returns its public key and authorization for related
    /// operations. If multiple values have the same final environment name,
    /// they must be identical. The response can contain at most one SSH secret.
    /// Otherwise, the method sends an aborted completion and returns an error.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. If `cancellation` resolves before a response is
    /// returned, Agentknock sends a best-effort aborted completion when the
    /// request was sent and returns [`RequestError::Interrupted`]. Cancellation
    /// after a response prevents approved values from being returned. Pass
    /// [`std::future::pending()`] when the operation doesn't need cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] if local pairing state isn't active, the relay
    /// exchange fails, the device denies the request, the response is invalid,
    /// or the operation is canceled.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{collections::BTreeMap, future};
    ///
    /// use agentknock::{
    ///     Client, ExecutableMode, RequestError, SecretUseOperation, SecretUseOptions,
    ///     SecretUseRequest, StreamKind,
    /// };
    ///
    /// # async fn request_secrets(client: &Client) -> Result<(), RequestError> {
    /// let secrets = BTreeMap::from([(
    ///     "github".to_owned(),
    ///     SecretUseOptions::default(),
    /// )]);
    /// let arguments = ["issue".to_owned(), "list".to_owned()];
    /// let launcher_chain = ["/usr/bin/bash".to_owned()];
    /// let request = SecretUseRequest {
    ///     secrets: &secrets,
    ///     operation: SecretUseOperation::Exec {
    ///         command: "gh",
    ///         arguments: &arguments,
    ///         working_directory: "/work/project",
    ///         executable_path: "/usr/bin/gh",
    ///         executable_hash: None,
    ///         executable_mode: ExecutableMode::Binary,
    ///         script_contents: None,
    ///         stdin: StreamKind::Terminal,
    ///         stdout: StreamKind::Terminal,
    ///         stderr: StreamKind::Terminal,
    ///     },
    ///     reason: Some("GitHub token provides access to private repository issues"),
    ///     launcher_chain: &launcher_chain,
    /// };
    ///
    /// let output = client
    ///     .request_secret_use(request, future::pending(), |_| {})
    ///     .await?;
    /// let environment = output.into_environment();
    /// # let _ = environment;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request_secret_use<P>(
        &self,
        request: SecretUseRequest<'_>,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<SecretUseOutput, RequestError>
    where
        P: FnMut(RequestProgress),
    {
        progress(RequestProgress::Preparing);
        validate_secret_options(request.secrets).map_err(RequestError::other)?;
        let request_id = Ulid::generate();
        let mut invocation_token = [0_u8; INVOCATION_TOKEN_LENGTH];
        getrandom::fill(&mut invocation_token).map_err(RequestError::other)?;
        let invocation = SecretUseInvocation {
            id: request_id.to_string(),
            token: invocation_token,
        };
        let operation = match request.operation {
            SecretUseOperation::Exec {
                command,
                arguments,
                working_directory,
                executable_path,
                executable_hash,
                executable_mode,
                script_contents,
                stdin,
                stdout,
                stderr,
            } => InvocationOperationMessage::Exec {
                command,
                arguments,
                working_directory,
                executable_path,
                executable_hash: executable_hash.map(|hash| BASE64_STANDARD.encode(hash)),
                executable_mode,
                script_contents,
                stdin: stdin.into(),
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        };
        let secrets = secret_options_message(request.secrets);
        let payload = InvocationRequestPayload {
            method: Method::Invocation,
            secrets,
            reason: request.reason,
            operation,
            launcher_chain: request.launcher_chain,
            invocation_token: BASE64_STANDARD.encode(invocation_token),
        };
        self.approval_exchange(
            request_id,
            &payload,
            cancellation,
            progress,
            |response: ApprovedInvocation| {
                let secrets = response
                    .secrets
                    .ok_or_else(|| io::Error::other("approved response doesn't contain secrets"))?;
                secret_use_output_from_secrets(secrets, request.secrets, invocation)
            },
        )
        .await
    }
}

fn secret_use_output_from_secrets(
    secrets: BTreeMap<String, ApprovedSecret>,
    requested_secrets: &BTreeMap<String, SecretUseOptions>,
    invocation: SecretUseInvocation,
) -> io::Result<SecretUseOutput> {
    let mut environment = BTreeMap::new();
    let mut stdin = None;
    let mut ssh = None;
    if !secrets.keys().eq(requested_secrets.keys()) {
        return Err(io::Error::other(format!(
            "approved response contains secrets {:?}, expected {:?}",
            secrets.keys().collect::<Vec<_>>(),
            requested_secrets.keys().collect::<Vec<_>>()
        )));
    }
    for ((name, secret), options) in secrets.into_iter().zip(requested_secrets.values()) {
        match secret {
            ApprovedSecret::Environment { variables } => {
                let environment_options = &options.environment;
                validate_returned_variables(&name, &variables, environment_options)?;
                for (source_name, variable) in variables {
                    if environment_options.stdin.as_deref() == Some(&source_name) {
                        stdin = Some(variable.value);
                        continue;
                    }
                    let final_name = environment_options
                        .rename
                        .get(&source_name)
                        .cloned()
                        .unwrap_or(source_name);
                    if let Some(previous) = environment.get(&final_name)
                        && previous != &variable.value
                    {
                        return Err(io::Error::other(format!(
                            "approved secrets contain different values for environment variable {final_name:?}"
                        )));
                    }
                    environment.insert(final_name, variable.value);
                }
            }
            ApprovedSecret::Ssh { public_key } => {
                if !options.environment.is_empty() {
                    return Err(io::Error::other(format!(
                        "approved SSH secret {name:?} has environment-variable options"
                    )));
                }
                if public_key.is_empty() {
                    return Err(io::Error::other(format!(
                        "approved SSH secret {name:?} has an empty public key"
                    )));
                }
                if ssh.is_some() {
                    return Err(io::Error::other(
                        "approved response contains more than one SSH secret",
                    ));
                }
                ssh = Some(SshSecretUse { name, public_key });
            }
        }
    }
    Ok(SecretUseOutput {
        environment,
        stdin,
        ssh,
        invocation,
    })
}

fn validate_secret_options(secrets: &BTreeMap<String, SecretUseOptions>) -> io::Result<()> {
    if secrets.is_empty() {
        return Err(invalid_input(
            "an invocation must request at least one secret",
        ));
    }
    let mut has_stdin = false;
    for (secret, options) in secrets {
        if secret.is_empty() {
            return Err(invalid_input("a requested secret has an empty name"));
        }
        let options = &options.environment;
        if options.only.as_ref().is_some_and(BTreeSet::is_empty) {
            return Err(invalid_input(format!(
                "secret {secret:?} has an empty only set"
            )));
        }
        if options.only.is_some() && !options.omit.is_empty() {
            return Err(invalid_input(format!(
                "secret {secret:?} uses both only and omit"
            )));
        }
        for name in options
            .only
            .iter()
            .flatten()
            .chain(options.omit.iter())
            .chain(options.rename.keys())
            .chain(options.rename.values())
            .chain(options.stdin.iter())
        {
            validate_environment_name(name)?;
        }
        if let Some(only) = &options.only {
            for source in options.rename.keys().chain(options.stdin.iter()) {
                if !only.contains(source) {
                    return Err(invalid_input(format!(
                        "environment variable {source:?} is configured for secret {secret:?} but isn't selected by only"
                    )));
                }
            }
        }
        for source in options.rename.keys().chain(options.stdin.iter()) {
            if options.omit.contains(source) {
                return Err(invalid_input(format!(
                    "environment variable {source:?} is both used and omitted for secret {secret:?}"
                )));
            }
        }
        if let Some(source) = &options.stdin {
            if options.rename.contains_key(source) {
                return Err(invalid_input(format!(
                    "environment variable {source:?} is both renamed and sent to standard input for secret {secret:?}"
                )));
            }
            if has_stdin {
                return Err(invalid_input(
                    "an invocation can send only one environment variable to standard input",
                ));
            }
            has_stdin = true;
        }
    }
    Ok(())
}

fn invalid_input(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn validate_environment_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.contains('=') || name.contains('\0') {
        return Err(invalid_input(format!(
            "invalid environment variable name {name:?}"
        )));
    }
    Ok(())
}

fn validate_returned_variables(
    secret: &str,
    variables: &BTreeMap<String, EnvironmentVariableMessage>,
    options: &EnvironmentVariableOptions,
) -> io::Result<()> {
    if let Some(only) = &options.only
        && !variables.keys().eq(only.iter())
    {
        return Err(io::Error::other(format!(
            "approved environment secret {secret:?} contains variables {:?}, expected {:?}",
            variables.keys().collect::<Vec<_>>(),
            only.iter().collect::<Vec<_>>()
        )));
    }
    if let Some(omitted) = options
        .omit
        .iter()
        .find(|name| variables.contains_key(*name))
    {
        return Err(io::Error::other(format!(
            "approved environment secret {secret:?} contains omitted variable {omitted:?}"
        )));
    }
    for source in options.rename.keys().chain(options.stdin.iter()) {
        if !variables.contains_key(source) {
            return Err(io::Error::other(format!(
                "approved environment secret {secret:?} doesn't contain requested variable {source:?}"
            )));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct InvocationRequestPayload<'a> {
    method: Method,
    secrets: BTreeMap<&'a str, SecretUseOptionsMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    operation: InvocationOperationMessage<'a>,
    launcher_chain: &'a [String],
    invocation_token: String,
}

#[derive(Serialize)]
struct SecretUseOptionsMessage<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<EnvironmentVariableOptionsMessage<'a>>,
}

#[derive(Serialize)]
struct EnvironmentVariableOptionsMessage<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    only: Option<&'a BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    omit: Option<&'a BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rename: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdin: Option<&'a str>,
}

fn secret_options_message(
    secrets: &BTreeMap<String, SecretUseOptions>,
) -> BTreeMap<&str, SecretUseOptionsMessage<'_>> {
    secrets
        .iter()
        .map(|(name, options)| {
            let environment = (!options.environment.is_empty()).then(|| {
                let options = &options.environment;
                EnvironmentVariableOptionsMessage {
                    only: options.only.as_ref(),
                    omit: (!options.omit.is_empty()).then_some(&options.omit),
                    rename: (!options.rename.is_empty()).then_some(&options.rename),
                    stdin: options.stdin.as_deref(),
                }
            });
            (name.as_str(), SecretUseOptionsMessage { environment })
        })
        .collect()
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum InvocationOperationMessage<'a> {
    Exec {
        command: &'a str,
        arguments: &'a [String],
        working_directory: &'a str,
        executable_path: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        executable_hash: Option<String>,
        executable_mode: ExecutableMode,
        #[serde(skip_serializing_if = "Option::is_none")]
        script_contents: Option<&'a str>,
        stdin: StreamKindMessage,
        stdout: StreamKindMessage,
        stderr: StreamKindMessage,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum StreamKindMessage {
    Terminal,
    NullDevice,
    Pipe,
    Socket,
    RegularFile,
    Unknown,
}

impl From<StreamKind> for StreamKindMessage {
    fn from(kind: StreamKind) -> Self {
        match kind {
            StreamKind::Terminal => Self::Terminal,
            StreamKind::NullDevice => Self::NullDevice,
            StreamKind::Pipe => Self::Pipe,
            StreamKind::Socket => Self::Socket,
            StreamKind::RegularFile => Self::RegularFile,
            StreamKind::Unknown => Self::Unknown,
        }
    }
}

#[derive(Deserialize)]
struct ApprovedInvocation {
    secrets: Option<BTreeMap<String, ApprovedSecret>>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ApprovedSecret {
    Environment {
        variables: BTreeMap<String, EnvironmentVariableMessage>,
    },
    Ssh {
        public_key: String,
    },
}

#[derive(Deserialize)]
struct EnvironmentVariableMessage {
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_executable_modes_and_stream_kinds_on_the_wire() {
        fn wire(value: impl Serialize) -> serde_json::Value {
            serde_json::to_value(value).unwrap()
        }
        assert_eq!(wire(ExecutableMode::Binary), "BINARY");
        assert_eq!(wire(ExecutableMode::Script), "SCRIPT");
        for (kind, name) in [
            (StreamKind::Terminal, "TERMINAL"),
            (StreamKind::NullDevice, "NULL_DEVICE"),
            (StreamKind::Pipe, "PIPE"),
            (StreamKind::Socket, "SOCKET"),
            (StreamKind::RegularFile, "REGULAR_FILE"),
            (StreamKind::Unknown, "UNKNOWN"),
        ] {
            assert_eq!(wire(StreamKindMessage::from(kind)), name);
        }
    }

    #[test]
    fn coalesces_equal_environment_values_from_different_secrets() {
        let secrets = BTreeMap::from([
            ("first".into(), environment_secret([("TOKEN", "same")])),
            (
                "second".into(),
                environment_secret([("TOKEN", "same"), ("OTHER", "value")]),
            ),
        ]);
        let requested = requested(["first", "second"]);

        let secret_use_output =
            secret_use_output_from_secrets(secrets, &requested, invocation()).unwrap();

        assert_eq!(
            secret_use_output.environment,
            BTreeMap::from([
                ("OTHER".into(), "value".into()),
                ("TOKEN".into(), "same".into()),
            ])
        );
    }

    #[test]
    fn rejects_conflicting_environment_values() {
        let secrets = BTreeMap::from([
            ("first".into(), environment_secret([("TOKEN", "one")])),
            ("second".into(), environment_secret([("TOKEN", "two")])),
        ]);
        let requested = requested(["first", "second"]);

        let error = secret_use_output_from_secrets(secrets, &requested, invocation())
            .err()
            .expect("conflicting values should fail");
        assert_eq!(
            error.to_string(),
            "approved secrets contain different values for environment variable \"TOKEN\""
        );
    }

    #[test]
    fn rejects_a_different_secret_set() {
        let secrets = BTreeMap::from([("other".into(), environment_secret([("TOKEN", "value")]))]);
        let requested = requested(["requested"]);

        let error = secret_use_output_from_secrets(secrets, &requested, invocation())
            .err()
            .expect("a different secret set should fail");
        assert_eq!(
            error.to_string(),
            "approved response contains secrets [\"other\"], expected [\"requested\"]"
        );
    }

    #[test]
    fn combines_environment_values_with_one_ssh_secret() {
        let secrets = BTreeMap::from([
            (
                "environment".into(),
                environment_secret([("TOKEN", "value")]),
            ),
            ("ssh".into(), ssh_secret("ssh-ed25519 AAAA test")),
        ]);
        let requested = requested(["environment", "ssh"]);

        let output = secret_use_output_from_secrets(secrets, &requested, invocation()).unwrap();

        assert_eq!(output.environment_variable("TOKEN"), Some("value"));
        assert_eq!(output.ssh().unwrap().name(), "ssh");
        assert_eq!(output.ssh().unwrap().public_key(), "ssh-ed25519 AAAA test");
    }

    #[test]
    fn rejects_more_than_one_ssh_secret() {
        let secrets = BTreeMap::from([
            ("first".into(), ssh_secret("ssh-ed25519 AAAA first")),
            ("second".into(), ssh_secret("ssh-ed25519 BBBB second")),
        ]);
        let requested = requested(["first", "second"]);

        let error = secret_use_output_from_secrets(secrets, &requested, invocation())
            .err()
            .expect("multiple SSH secrets should fail");

        assert_eq!(
            error.to_string(),
            "approved response contains more than one SSH secret"
        );
    }

    #[test]
    fn routes_environment_values_after_selecting_them() {
        let secrets = BTreeMap::from([
            (
                "first".into(),
                environment_secret([("TOKEN", "one"), ("INPUT", "exact input")]),
            ),
            ("second".into(), environment_secret([("TOKEN", "two")])),
        ]);
        let requested = BTreeMap::from([
            (
                "first".into(),
                SecretUseOptions {
                    environment: EnvironmentVariableOptions {
                        only: Some(BTreeSet::from(["INPUT".into(), "TOKEN".into()])),
                        rename: BTreeMap::from([("TOKEN".into(), "FIRST_TOKEN".into())]),
                        stdin: Some("INPUT".into()),
                        ..EnvironmentVariableOptions::default()
                    },
                },
            ),
            (
                "second".into(),
                SecretUseOptions {
                    environment: EnvironmentVariableOptions {
                        rename: BTreeMap::from([("TOKEN".into(), "SECOND_TOKEN".into())]),
                        ..EnvironmentVariableOptions::default()
                    },
                },
            ),
        ]);

        let output = secret_use_output_from_secrets(secrets, &requested, invocation()).unwrap();

        assert_eq!(
            output.environment,
            BTreeMap::from([
                ("FIRST_TOKEN".into(), "one".into()),
                ("SECOND_TOKEN".into(), "two".into()),
            ])
        );
        assert_eq!(output.stdin_value(), Some("exact input"));
    }

    #[test]
    fn rejects_environment_values_excluded_by_the_request() {
        let secrets = BTreeMap::from([(
            "test".into(),
            environment_secret([("TOKEN", "value"), ("OTHER", "unexpected")]),
        )]);
        let requested = BTreeMap::from([(
            "test".into(),
            SecretUseOptions {
                environment: EnvironmentVariableOptions {
                    only: Some(BTreeSet::from(["TOKEN".into()])),
                    ..EnvironmentVariableOptions::default()
                },
            },
        )]);

        let error = secret_use_output_from_secrets(secrets, &requested, invocation())
            .err()
            .expect("an excluded environment value should fail");

        assert!(error.to_string().contains("contains variables"));
    }

    #[test]
    fn rejects_an_omitted_environment_value() {
        let secrets =
            BTreeMap::from([("test".into(), environment_secret([("TOKEN", "unexpected")]))]);
        let requested = BTreeMap::from([(
            "test".into(),
            SecretUseOptions {
                environment: EnvironmentVariableOptions {
                    omit: BTreeSet::from(["TOKEN".into()]),
                    ..EnvironmentVariableOptions::default()
                },
            },
        )]);

        let error = secret_use_output_from_secrets(secrets, &requested, invocation())
            .err()
            .expect("an omitted environment value should fail");

        assert_eq!(
            error.to_string(),
            "approved environment secret \"test\" contains omitted variable \"TOKEN\""
        );
    }

    #[test]
    fn validates_environment_delivery_options() {
        let empty_only = BTreeMap::from([(
            "test".into(),
            SecretUseOptions {
                environment: EnvironmentVariableOptions {
                    only: Some(BTreeSet::new()),
                    ..EnvironmentVariableOptions::default()
                },
            },
        )]);
        assert_eq!(
            validate_secret_options(&empty_only)
                .unwrap_err()
                .to_string(),
            "secret \"test\" has an empty only set"
        );

        let both_only_and_omit = BTreeMap::from([(
            "test".into(),
            SecretUseOptions {
                environment: EnvironmentVariableOptions {
                    only: Some(BTreeSet::from(["TOKEN".into()])),
                    omit: BTreeSet::from(["OTHER".into()]),
                    ..EnvironmentVariableOptions::default()
                },
            },
        )]);
        assert_eq!(
            validate_secret_options(&both_only_and_omit)
                .unwrap_err()
                .to_string(),
            "secret \"test\" uses both only and omit"
        );

        let two_stdin_values = BTreeMap::from([
            (
                "first".into(),
                SecretUseOptions {
                    environment: EnvironmentVariableOptions {
                        stdin: Some("ONE".into()),
                        ..EnvironmentVariableOptions::default()
                    },
                },
            ),
            (
                "second".into(),
                SecretUseOptions {
                    environment: EnvironmentVariableOptions {
                        stdin: Some("TWO".into()),
                        ..EnvironmentVariableOptions::default()
                    },
                },
            ),
        ]);
        assert_eq!(
            validate_secret_options(&two_stdin_values)
                .unwrap_err()
                .to_string(),
            "an invocation can send only one environment variable to standard input"
        );
    }

    #[test]
    fn serializes_secret_options_as_a_map() {
        let secrets: BTreeMap<String, SecretUseOptions> = BTreeMap::from([
            ("plain".into(), SecretUseOptions::default()),
            (
                "selected".into(),
                SecretUseOptions {
                    environment: EnvironmentVariableOptions {
                        only: Some(BTreeSet::from(["TOKEN".into()])),
                        rename: BTreeMap::from([("TOKEN".into(), "API_TOKEN".into())]),
                        ..EnvironmentVariableOptions::default()
                    },
                },
            ),
        ]);

        assert_eq!(
            serde_json::to_value(secret_options_message(&secrets)).unwrap(),
            serde_json::json!({
                "plain": {},
                "selected": {
                    "environment": {
                        "only": ["TOKEN"],
                        "rename": {"TOKEN": "API_TOKEN"},
                    },
                },
            })
        );
    }

    fn environment_secret<const N: usize>(variables: [(&str, &str); N]) -> ApprovedSecret {
        ApprovedSecret::Environment {
            variables: variables
                .into_iter()
                .map(|(name, value)| {
                    (
                        name.into(),
                        EnvironmentVariableMessage {
                            value: value.into(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn ssh_secret(public_key: &str) -> ApprovedSecret {
        ApprovedSecret::Ssh {
            public_key: public_key.into(),
        }
    }

    fn invocation() -> SecretUseInvocation {
        SecretUseInvocation {
            id: "01K00000000000000000000000".into(),
            token: [0x42; INVOCATION_TOKEN_LENGTH],
        }
    }

    fn requested<const N: usize>(names: [&str; N]) -> BTreeMap<String, SecretUseOptions> {
        names
            .into_iter()
            .map(|name| (name.into(), SecretUseOptions::default()))
            .collect()
    }
}
