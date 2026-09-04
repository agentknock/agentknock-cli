use std::{future::Future, path::Path, pin::Pin};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    Client, DenialReason, RequestError, RequestProgress,
    config::{Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    protocol::{self, Method, Response},
    websocket::{self, RelayExchange},
};

const SSH_SIGNATURE_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const SSH_SIGNATURE_END: &str = "-----END SSH SIGNATURE-----";

/// Describes one Git signature requested by a command invocation.
pub struct GitSignRequest<'a> {
    /// The request identifier of the initial invocation.
    pub invocation_id: &'a str,

    /// The authorization token created for the invocation.
    pub invocation_token: &'a [u8; 32],

    /// The name of the signing secret selected for the invocation.
    pub secret: &'a str,

    /// The exact message bytes to sign.
    pub message: &'a [u8],

    /// Advisory information about the Git repository, if available.
    pub repository: Option<&'a GitSignRepository>,
}

/// Advisory repository information for a Git signature request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSignRepository {
    /// The repository's sanitized remote identity, without credentials.
    pub remote: Option<String>,

    /// The absolute path to the current worktree.
    pub worktree: Option<String>,

    /// The current branch or detached-HEAD state.
    pub head: Option<GitSignHead>,

    /// The number of paths changed by the object being signed.
    pub changed_path_count: Option<usize>,

    /// The complete changed-path list, or [`None`] if it was not collected.
    pub changed_paths: Option<Vec<GitSignChangedPath>>,
}

/// Describes the repository HEAD associated with a Git signature request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitSignHead {
    /// HEAD names a local branch.
    Branch {
        /// The short local branch name.
        name: String,

        /// The configured upstream branch, if one is available.
        upstream: Option<String>,
    },

    /// HEAD is detached.
    Detached,
}

/// Describes one path changed by the object being signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitSignChangedPath {
    /// The kind of change.
    pub status: GitSignChangeStatus,

    /// The repository-relative path.
    pub path: String,
}

/// Describes how a path changed in a signed Git object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitSignChangeStatus {
    /// The path was added.
    Added,

    /// The path was deleted.
    Deleted,

    /// The path's contents or file mode changed.
    Modified,

    /// The path's object type changed.
    TypeChanged,
}

impl Client {
    /// Requests a Git signature from a secret selected for an invocation.
    ///
    /// The device makes a separate decision for each signature. The request
    /// includes the exact bytes that Git asks the signing program to sign.
    /// SSH-backed secrets use the SSHSIG `git` namespace.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] if local pairing state isn't active, the relay
    /// exchange fails, the device denies the signature, the response is
    /// invalid, or the operation is canceled.
    pub async fn request_git_signature<P>(
        &self,
        request: GitSignRequest<'_>,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<String, RequestError>
    where
        P: FnMut(RequestProgress),
    {
        tokio::pin!(cancellation);
        progress(RequestProgress::Preparing);
        request
            .invocation_id
            .parse::<Ulid>()
            .map_err(RequestError::other)?;
        if request.secret.is_empty() {
            return Err(RequestError::other("signing secret name is empty"));
        }
        self.maybe_rotate_psk()?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let request_id = Ulid::generate();
        let payload = GitSignRequestPayload {
            method: Method::GitSign,
            invocation_id: request.invocation_id,
            invocation_token: BASE64_STANDARD.encode(request.invocation_token),
            secret: request.secret,
            message: BASE64_STANDARD.encode(request.message),
            repository: request.repository.map(GitSignRepositoryPayload::from),
        };

        git_sign_exchange(
            self,
            &pairing_path,
            &pairing,
            request_id,
            &payload,
            cancellation.as_mut(),
            &mut progress,
        )
        .await
    }
}

async fn git_sign_exchange<C, P>(
    client: &Client,
    pairing_path: &Path,
    pairing: &Pairing,
    request_id: Ulid,
    request_payload: &GitSignRequestPayload<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<String, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(RequestProgress),
{
    let plaintext = client
        .encode(request_payload)
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
            let reason = abort_reason(&error);
            let error = RequestError::from(error);
            if let Some(completion) = seal_aborted(client, &mut session, reason, error.to_string())
            {
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
            GitSignResult::Aborted {
                reason: GitSignAbortReason::InvalidResponse,
                message: error.to_string(),
            },
            Err(error),
        ),
        Ok(Response::Message(result)) => match result {
            GitSignResult::Approved {
                signature: Some(signature),
            } if valid_ssh_signature_envelope(&signature) => {
                (GitSignResult::Approved { signature: None }, Ok(signature))
            }
            GitSignResult::Approved { .. } => (
                GitSignResult::Aborted {
                    reason: GitSignAbortReason::InvalidResponse,
                    message: "approved response doesn't contain a valid SSH signature envelope"
                        .into(),
                },
                Err(RequestError::other(
                    "approved response doesn't contain a valid SSH signature envelope",
                )),
            ),
            GitSignResult::Denied { reason, message } => (
                GitSignResult::Denied {
                    reason,
                    message: message.clone(),
                },
                Err(RequestError::Denied { reason, message }),
            ),
            GitSignResult::Aborted { .. } => (
                GitSignResult::Aborted {
                    reason: GitSignAbortReason::InvalidResponse,
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

fn valid_ssh_signature_envelope(signature: &str) -> bool {
    signature.starts_with(SSH_SIGNATURE_BEGIN) && signature.trim_end().ends_with(SSH_SIGNATURE_END)
}

fn abort_reason(error: &websocket::Error) -> GitSignAbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => GitSignAbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            GitSignAbortReason::ClientError
        }
        _ => GitSignAbortReason::InvalidResponse,
    }
}

fn seal_aborted(
    client: &Client,
    session: &mut Session,
    reason: GitSignAbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let plaintext = client
        .encode(&GitSignResult::Aborted { reason, message })
        .ok()?;
    session.seal_completion(&plaintext).ok()
}

async fn complete_cancelled(client: &Client, session: &mut Session, relay: &mut RelayExchange) {
    let Some(completion) = seal_aborted(
        client,
        session,
        GitSignAbortReason::Cancelled,
        RequestError::Interrupted.to_string(),
    ) else {
        return;
    };
    let _ = relay.complete_briefly(&completion).await;
}

#[derive(Serialize)]
struct GitSignRequestPayload<'a> {
    method: Method,
    invocation_id: &'a str,
    invocation_token: String,
    secret: &'a str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository: Option<GitSignRepositoryPayload<'a>>,
}

#[derive(Serialize)]
struct GitSignRepositoryPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    remote: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktree: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<GitSignHeadPayload<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_path_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_paths: Option<Vec<GitSignChangedPathPayload<'a>>>,
}

impl<'a> From<&'a GitSignRepository> for GitSignRepositoryPayload<'a> {
    fn from(repository: &'a GitSignRepository) -> Self {
        Self {
            remote: repository.remote.as_deref(),
            worktree: repository.worktree.as_deref(),
            head: repository.head.as_ref().map(GitSignHeadPayload::from),
            changed_path_count: repository.changed_path_count,
            changed_paths: repository
                .changed_paths
                .as_ref()
                .map(|paths| paths.iter().map(GitSignChangedPathPayload::from).collect()),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum GitSignHeadPayload<'a> {
    Branch {
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream: Option<&'a str>,
    },
    Detached,
}

impl<'a> From<&'a GitSignHead> for GitSignHeadPayload<'a> {
    fn from(head: &'a GitSignHead) -> Self {
        match head {
            GitSignHead::Branch { name, upstream } => Self::Branch {
                name,
                upstream: upstream.as_deref(),
            },
            GitSignHead::Detached => Self::Detached,
        }
    }
}

#[derive(Serialize)]
struct GitSignChangedPathPayload<'a> {
    status: GitSignChangeStatusPayload,
    path: &'a str,
}

impl<'a> From<&'a GitSignChangedPath> for GitSignChangedPathPayload<'a> {
    fn from(path: &'a GitSignChangedPath) -> Self {
        Self {
            status: path.status.into(),
            path: &path.path,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GitSignChangeStatusPayload {
    Added,
    Deleted,
    Modified,
    TypeChanged,
}

impl From<GitSignChangeStatus> for GitSignChangeStatusPayload {
    fn from(status: GitSignChangeStatus) -> Self {
        match status {
            GitSignChangeStatus::Added => Self::Added,
            GitSignChangeStatus::Deleted => Self::Deleted,
            GitSignChangeStatus::Modified => Self::Modified,
            GitSignChangeStatus::TypeChanged => Self::TypeChanged,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum GitSignResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    Denied {
        reason: DenialReason,
        message: String,
    },
    Aborted {
        reason: GitSignAbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GitSignAbortReason {
    Cancelled,
    TimedOut,
    InvalidResponse,
    ClientError,
    Other,
}
