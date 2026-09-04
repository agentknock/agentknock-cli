use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    io,
    path::Path,
    pin::Pin,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    Client, RequestProgress,
    config::{ConfigurationError, Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    protocol::{self, Method, Response},
    secrets::{EnvironmentVariableMessage, SecretContentsMessage, SecretMessage},
    websocket::{self, RelayExchange},
};

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

    /// An optional explanation shown with the request.
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

/// An error during an operation that communicates with the relay or device.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RequestError {
    /// Local pairing state couldn't be read or updated safely.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    /// Consecutive transport or relay failures exhausted the retry policy.
    ///
    /// Valid relay traffic resets the consecutive-failure count.
    #[error("relay remained unavailable after {failures} consecutive failures")]
    RelayUnavailable {
        /// The number of consecutive failures observed.
        failures: usize,
    },

    /// An error report wasn't authenticated by the device.
    ///
    /// Callers must not treat this as a trusted device decision or use it to
    /// change cryptographic state.
    #[error("received unauthenticated error {code}: {message:?}")]
    Unauthenticated {
        /// A machine-readable error code supplied by the relay.
        code: String,
        /// Human-readable diagnostic text supplied by the relay.
        message: String,
    },

    /// The relay reports that the paired client is inactive.
    #[error("paired client is inactive: {message}")]
    ClientInactive {
        /// Human-readable context supplied by the relay.
        message: String,
    },

    /// The device returned an authenticated protocol error.
    #[error("device rejected the request with {code}: {message}")]
    DeviceRejected {
        /// A machine-readable error code supplied by the device.
        code: String,
        /// Human-readable diagnostic text supplied by the device.
        message: String,
    },

    /// The operation failed without a more specific public error category.
    #[error(transparent)]
    Other(#[from] io::Error),

    /// The device denied an authorization request.
    #[error("request denied ({reason}): {message}")]
    Denied {
        /// The device's denial category.
        reason: DenialReason,
        /// Human-readable context supplied by the device.
        message: String,
    },

    /// The device rejected a pending pairing during activation.
    #[error("pairing was rejected")]
    PairingRejected,

    /// The cancellation future resolved before the operation returned its result.
    #[error("request was interrupted")]
    Interrupted,
}

impl RequestError {
    pub(crate) fn other<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Other(io::Error::other(error))
    }
}

/// The reason that the device denied an authorization request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialReason {
    /// A user explicitly denied the request.
    UserDenied,

    /// Device policy denied the request.
    PolicyDenied,

    /// The device considered the request malformed or unsupported.
    InvalidRequest,

    /// The device denied the request for another reason.
    Other,
}

impl fmt::Display for DenialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UserDenied => "USER_DENIED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::Other => "OTHER",
        })
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
    ///         stdin: StreamKind::Terminal,
    ///         stdout: StreamKind::Terminal,
    ///         stderr: StreamKind::Terminal,
    ///     },
    ///     reason: Some("Review open issues"),
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
        tokio::pin!(cancellation);
        progress(RequestProgress::Preparing);
        validate_secret_options(request.secrets).map_err(RequestError::other)?;
        self.maybe_rotate_psk()?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
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
                stdin: stdin.into(),
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        };
        let secrets = secret_options_message(request.secrets);
        let exchange_request = InvocationExchangeRequest {
            message: InvocationRequestPayload {
                method: Method::Invocation,
                secrets,
                reason: request.reason,
                operation,
                launcher_chain: request.launcher_chain,
                invocation_token: BASE64_STANDARD.encode(invocation_token),
            },
            secrets: request.secrets,
        };

        message_exchange(
            self,
            &pairing_path,
            &pairing,
            invocation,
            &exchange_request,
            cancellation.as_mut(),
            &mut progress,
        )
        .await
    }
}

async fn message_exchange<C, P>(
    client: &Client,
    pairing_path: &Path,
    pairing: &Pairing,
    invocation: SecretUseInvocation,
    exchange_request: &InvocationExchangeRequest<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<SecretUseOutput, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(RequestProgress),
{
    let request_id = invocation
        .id
        .parse::<Ulid>()
        .expect("a generated invocation identifier is a ULID");
    let plaintext = client
        .encode(&exchange_request.message)
        .map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(client, pairing, &request_id.to_string())?;

    progress(RequestProgress::WaitingForDelivery);
    let response = match tokio::select! {
        biased;
        _ = cancellation.as_mut() => {
            if relay.request_was_sent() {
                complete_cancelled(client, &mut session, &mut relay).await;
            }
            return Err(RequestError::Interrupted);
        }
        response = relay.request(&request, || {
            progress(RequestProgress::WaitingForResponse);
        }) => response,
    } {
        Ok(response) => response,
        Err(error) => {
            let abort_reason = abort_reason(&error);
            let error = RequestError::from(error);
            let completion = seal_aborted(client, &mut session, abort_reason, error.to_string());
            if let Some(completion) = completion {
                tokio::select! {
                    biased;
                    _ = cancellation.as_mut() => {
                        let _ = relay.complete_briefly(&completion).await;
                        return Err(RequestError::Interrupted);
                    }
                    _ = relay.complete(&completion) => {}
                }
            }
            return Err(error);
        }
    };
    progress(RequestProgress::Completing);
    let response = session
        .open_response(response)
        .map_err(RequestError::other)
        .and_then(|plaintext| {
            if let Some(rotation_key) = pairing.rotation_key() {
                clear_rotation_key(pairing_path, rotation_key)?;
            }
            protocol::decode_response(&plaintext).map_err(RequestError::other)
        });
    let (completion_result, exchange_result) = match response {
        Ok(Response::Error(error)) => {
            if let Some(completion) = protocol::seal_error_completion(client, &mut session, &error)
            {
                let _ = relay.complete_briefly(&completion).await;
            }
            return Err(RequestError::DeviceRejected {
                code: error.code,
                message: error.message,
            });
        }
        Err(error) => (
            InvocationResult::Aborted {
                reason: InvocationAbortReason::InvalidResponse,
                message: error.to_string(),
            },
            Err(error),
        ),
        Ok(Response::Message(result)) => match result {
            InvocationResult::Approved {
                secrets: Some(secrets),
            } => {
                match secret_use_output_from_secrets(secrets, exchange_request.secrets, invocation)
                {
                    Ok(secret_use_output) => (
                        InvocationResult::Approved { secrets: None },
                        Ok(secret_use_output),
                    ),
                    Err(error) => (
                        InvocationResult::Aborted {
                            reason: InvocationAbortReason::InvalidResponse,
                            message: error.to_string(),
                        },
                        Err(error.into()),
                    ),
                }
            }
            InvocationResult::Approved { secrets: None } => (
                InvocationResult::Aborted {
                    reason: InvocationAbortReason::InvalidResponse,
                    message: "approved response doesn't contain secrets".into(),
                },
                Err(RequestError::other(
                    "approved response doesn't contain secrets",
                )),
            ),
            InvocationResult::Denied { reason, message } => (
                InvocationResult::Denied {
                    reason,
                    message: message.clone(),
                },
                Err(RequestError::Denied { reason, message }),
            ),
            InvocationResult::Aborted { .. } => (
                InvocationResult::Aborted {
                    reason: InvocationAbortReason::InvalidResponse,
                    message: "received an ABORTED result in a response".into(),
                },
                Err(RequestError::other(
                    "received an ABORTED result in a response",
                )),
            ),
        },
    };

    let plaintext = client
        .encode(&completion_result)
        .map_err(RequestError::other)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(RequestError::other)?;
    let interrupted = tokio::select! {
        biased;
        _ = cancellation.as_mut() => true,
        result = relay.complete(&completion) => {
            result?;
            progress(RequestProgress::Completed);
            false
        }
    };
    if interrupted {
        let _ = relay.complete_briefly(&completion).await;
        return Err(RequestError::Interrupted);
    }

    exchange_result
}

fn secret_use_output_from_secrets(
    secrets: BTreeMap<String, SecretMessage<BTreeMap<String, EnvironmentVariableMessage>>>,
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
    for (name, secret) in secrets {
        let options = requested_secrets
            .get(&name)
            .expect("the received secret set was checked");
        match secret.contents {
            SecretContentsMessage::Environment { variables } => {
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
            SecretContentsMessage::Ssh { public_key } => {
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an invocation must request at least one secret",
        ));
    }
    let mut has_stdin = false;
    for (secret, options) in secrets {
        if secret.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a requested secret has an empty name",
            ));
        }
        let options = &options.environment;
        if options.only.as_ref().is_some_and(BTreeSet::is_empty) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("secret {secret:?} has an empty only set"),
            ));
        }
        if options.only.is_some() && !options.omit.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("secret {secret:?} uses both only and omit"),
            ));
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "environment variable {source:?} is configured for secret {secret:?} but isn't selected by only"
                        ),
                    ));
                }
            }
        }
        for source in options.rename.keys().chain(options.stdin.iter()) {
            if options.omit.contains(source) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "environment variable {source:?} is both used and omitted for secret {secret:?}"
                    ),
                ));
            }
        }
        if let Some(source) = &options.stdin {
            if options.rename.contains_key(source) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "environment variable {source:?} is both renamed and sent to standard input for secret {secret:?}"
                    ),
                ));
            }
            if has_stdin {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an invocation can send only one environment variable to standard input",
                ));
            }
            has_stdin = true;
        }
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.contains('=') || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid environment variable name {name:?}"),
        ));
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

fn abort_reason(error: &websocket::Error) -> InvocationAbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => InvocationAbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            InvocationAbortReason::ClientError
        }
        _ => InvocationAbortReason::InvalidResponse,
    }
}

fn seal_aborted(
    client: &Client,
    session: &mut Session,
    reason: InvocationAbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let Ok(plaintext) = client.encode(&InvocationResult::Aborted { reason, message }) else {
        return None;
    };
    session.seal_completion(&plaintext).ok()
}

async fn complete_cancelled(client: &Client, session: &mut Session, relay: &mut RelayExchange) {
    let Some(completion) = seal_aborted(
        client,
        session,
        InvocationAbortReason::Cancelled,
        RequestError::Interrupted.to_string(),
    ) else {
        return;
    };
    let _ = relay.complete_briefly(&completion).await;
}

impl From<websocket::Error> for RequestError {
    fn from(error: websocket::Error) -> Self {
        match error {
            websocket::Error::RetriesExhausted { failures, .. } => {
                Self::RelayUnavailable { failures }
            }
            websocket::Error::Unauthenticated { code, message } => {
                Self::Unauthenticated { code, message }
            }
            websocket::Error::RelayRejected { code, message } if code == "CLIENT_INACTIVE" => {
                Self::ClientInactive { message }
            }
            websocket::Error::ClientInactive { reason, .. } => {
                Self::ClientInactive { message: reason }
            }
            error => Self::other(error),
        }
    }
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

struct InvocationExchangeRequest<'a> {
    message: InvocationRequestPayload<'a>,
    secrets: &'a BTreeMap<String, SecretUseOptions>,
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

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum InvocationResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        secrets:
            Option<BTreeMap<String, SecretMessage<BTreeMap<String, EnvironmentVariableMessage>>>>,
    },
    Denied {
        reason: DenialReason,
        message: String,
    },
    Aborted {
        reason: InvocationAbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum InvocationAbortReason {
    Cancelled,
    TimedOut,
    InvalidResponse,
    ClientError,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn environment_secret<const N: usize>(
        variables: [(&str, &str); N],
    ) -> SecretMessage<BTreeMap<String, EnvironmentVariableMessage>> {
        SecretMessage {
            description: None,
            contents: SecretContentsMessage::Environment {
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
            },
        }
    }

    fn ssh_secret(public_key: &str) -> SecretMessage<BTreeMap<String, EnvironmentVariableMessage>> {
        SecretMessage {
            description: None,
            contents: SecretContentsMessage::Ssh {
                public_key: public_key.into(),
            },
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
