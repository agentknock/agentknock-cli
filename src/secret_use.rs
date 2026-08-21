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
    Client,
    config::{ConfigurationError, Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    pairing::RotationError,
    protocol::Method,
    secrets::{EnvironmentVariableMessage, SecretContentsMessage, SecretMessage},
    websocket::{self, RelayExchange},
};

/// Describes a request to use one or more secrets.
///
/// The device uses this metadata to decide whether to approve the request. The
/// client that constructs it is responsible for reporting the operation and
/// launcher information accurately.
pub struct SecretUseRequest<'a> {
    /// The unique names of the secrets requested together.
    pub secrets: &'a BTreeSet<String>,

    /// The operation that will receive or use the approved secret material.
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

/// An operation for which secret use can be requested.
#[non_exhaustive]
pub enum SecretUseOperation<'a> {
    /// Executes a program with approved secret material in its environment.
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

/// Secret material returned for an approved use request.
///
/// This type doesn't implement [`Debug`](std::fmt::Debug) because it contains
/// secret values. Use [`SecretUseOutput::environment_variable_names`] to
/// inspect names without exposing values, or consume the output with
/// [`SecretUseOutput::into_environment`].
pub struct SecretUseOutput {
    environment: BTreeMap<String, String>,
}

/// A stage reported while a secret use request is running.
///
/// A completed exchange reports `Preparing`, `WaitingForDelivery`, optionally
/// one or more `WaitingForResponse` updates, `Completing`, and `Completed`, in
/// that order. A request can still return a device denial after reporting
/// `Completed`; other failures stop without reporting `Completed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecretUseProgress {
    /// Agentknock is reading local state and preparing the protected request.
    Preparing,

    /// The request is waiting to be delivered to the device.
    WaitingForDelivery,

    /// The device has received the request but hasn't returned a decision.
    WaitingForResponse,

    /// Agentknock is validating the response and handing off the completion.
    Completing,

    /// The exchange and completion handoff finished successfully.
    Completed,
}

impl SecretUseOutput {
    /// Returns the names of the approved environment variables.
    ///
    /// Names are yielded in lexicographic order. Values aren't exposed by this
    /// iterator.
    pub fn environment_variable_names(&self) -> impl Iterator<Item = &str> {
        self.environment.keys().map(String::as_str)
    }

    /// Consumes the output and returns its environment variables and values.
    ///
    /// The map is keyed by environment variable name and ordered
    /// lexicographically.
    pub fn into_environment(self) -> BTreeMap<String, String> {
        self.environment
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

    /// The operation failed without a more specific public error category.
    #[error(transparent)]
    Other(#[from] io::Error),

    /// The device denied a secret use request.
    #[error("request denied ({reason}): {message}")]
    Denied {
        /// The device's denial category.
        reason: SecretUseDenialReason,
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

/// The reason that the device denied a secret use request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretUseDenialReason {
    /// A user explicitly denied the request.
    UserDenied,

    /// Device policy denied the request.
    PolicyDenied,

    /// The device considered the request malformed or unsupported.
    InvalidRequest,

    /// The device denied the request for another reason.
    Other,
}

impl fmt::Display for SecretUseDenialReason {
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
    /// Requests secret use and returns the approved environment values.
    ///
    /// The authenticated response must contain exactly the requested secret
    /// names. If multiple secrets provide the same environment variable, their
    /// values must be identical. Otherwise, the method sends an aborted
    /// completion and returns an error.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. If `cancellation` resolves before approval is
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
    /// use std::{collections::BTreeSet, future};
    ///
    /// use agentknock::{
    ///     Client, ExecutableMode, RequestError, SecretUseOperation, SecretUseRequest,
    ///     StreamKind,
    /// };
    ///
    /// # async fn request_secrets(client: &Client) -> Result<(), RequestError> {
    /// let secrets = BTreeSet::from(["github".to_owned()]);
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
        P: FnMut(SecretUseProgress),
    {
        tokio::pin!(cancellation);
        progress(SecretUseProgress::Preparing);
        self.maybe_rotate_psk().map_err(|error| match error {
            RotationError::Configuration(error) => RequestError::Configuration(error),
            RotationError::Other(error) => RequestError::Other(error),
        })?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
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
            } => SecretUseOperationMessage::Exec {
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
        let request_payload = SecretUseRequestPayload {
            method: Method::SecretUse,
            secrets: request.secrets,
            reason: request.reason,
            operation,
            launcher_chain: request.launcher_chain,
        };

        message_exchange(
            self,
            &pairing_path,
            &pairing,
            &request_payload,
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
    request_payload: &SecretUseRequestPayload<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<SecretUseOutput, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(SecretUseProgress),
{
    let request_id = Ulid::generate();
    let plaintext = client
        .encode(request_payload)
        .map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(pairing, &request_id.to_string())?;

    progress(SecretUseProgress::WaitingForDelivery);
    let response = match tokio::select! {
        biased;
        _ = cancellation.as_mut() => {
            if relay.request_was_sent() {
                complete_cancelled(client, &mut session, &mut relay).await;
            }
            return Err(RequestError::Interrupted);
        }
        response = relay.request(&request, || {
            progress(SecretUseProgress::WaitingForResponse);
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
    progress(SecretUseProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(RequestError::other)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(pairing_path, rotation_key)?;
    }
    let result: SecretUseResult =
        serde_json::from_slice(&plaintext).map_err(RequestError::other)?;
    let (completion_result, exchange_result) = match result {
        SecretUseResult::Approved {
            secrets: Some(secrets),
        } => match secret_use_output_from_secrets(secrets, request_payload.secrets) {
            Ok(secret_use_output) => (
                SecretUseResult::Approved { secrets: None },
                Ok(secret_use_output),
            ),
            Err(error) => (
                SecretUseResult::Aborted {
                    reason: SecretUseAbortReason::InvalidResponse,
                    message: error.to_string(),
                },
                Err(error.into()),
            ),
        },
        SecretUseResult::Approved { secrets: None } => (
            SecretUseResult::Aborted {
                reason: SecretUseAbortReason::InvalidResponse,
                message: "approved response doesn't contain secrets".into(),
            },
            Err(RequestError::other(
                "approved response doesn't contain secrets",
            )),
        ),
        SecretUseResult::Denied { reason, message } => (
            SecretUseResult::Denied {
                reason,
                message: message.clone(),
            },
            Err(RequestError::Denied { reason, message }),
        ),
        SecretUseResult::Aborted { .. } => (
            SecretUseResult::Aborted {
                reason: SecretUseAbortReason::InvalidResponse,
                message: "received an ABORTED result in a response".into(),
            },
            Err(RequestError::other(
                "received an ABORTED result in a response",
            )),
        ),
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
            progress(SecretUseProgress::Completed);
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
    requested_secrets: &BTreeSet<String>,
) -> io::Result<SecretUseOutput> {
    let mut environment = BTreeMap::new();
    let received_secrets = secrets.keys().cloned().collect::<BTreeSet<_>>();
    for secret in secrets.into_values() {
        match secret.contents {
            SecretContentsMessage::Environment { variables } => {
                for (name, variable) in variables {
                    if let Some(previous) = environment.get(&name)
                        && previous != &variable.value
                    {
                        return Err(io::Error::other(format!(
                            "approved secrets contain different values for environment variable {name:?}"
                        )));
                    }
                    environment.insert(name, variable.value);
                }
            }
        }
    }
    if &received_secrets != requested_secrets {
        return Err(io::Error::other(format!(
            "approved response contains secrets {:?}, expected {:?}",
            received_secrets.into_iter().collect::<Vec<_>>(),
            requested_secrets.iter().collect::<Vec<_>>()
        )));
    }
    Ok(SecretUseOutput { environment })
}

fn abort_reason(error: &websocket::Error) -> SecretUseAbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => SecretUseAbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            SecretUseAbortReason::ClientError
        }
        _ => SecretUseAbortReason::InvalidResponse,
    }
}

fn seal_aborted(
    client: &Client,
    session: &mut Session,
    reason: SecretUseAbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let Ok(plaintext) = client.encode(&SecretUseResult::Aborted { reason, message }) else {
        return None;
    };
    session.seal_completion(&plaintext).ok()
}

async fn complete_cancelled(client: &Client, session: &mut Session, relay: &mut RelayExchange) {
    let Some(completion) = seal_aborted(
        client,
        session,
        SecretUseAbortReason::Cancelled,
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
struct SecretUseRequestPayload<'a> {
    method: Method,
    secrets: &'a BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    operation: SecretUseOperationMessage<'a>,
    launcher_chain: &'a [String],
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum SecretUseOperationMessage<'a> {
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
enum SecretUseResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        secrets:
            Option<BTreeMap<String, SecretMessage<BTreeMap<String, EnvironmentVariableMessage>>>>,
    },
    Denied {
        reason: SecretUseDenialReason,
        message: String,
    },
    Aborted {
        reason: SecretUseAbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SecretUseAbortReason {
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
        let requested = BTreeSet::from(["first".into(), "second".into()]);

        let secret_use_output = secret_use_output_from_secrets(secrets, &requested).unwrap();

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
        let requested = BTreeSet::from(["first".into(), "second".into()]);

        let error = secret_use_output_from_secrets(secrets, &requested)
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
        let requested = BTreeSet::from(["requested".into()]);

        let error = secret_use_output_from_secrets(secrets, &requested)
            .err()
            .expect("a different secret set should fail");
        assert_eq!(
            error.to_string(),
            "approved response contains secrets [\"other\"], expected [\"requested\"]"
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
}
