use std::{future::Future, io};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Client, RequestError, RequestProgress, protocol::Method};

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
        progress(RequestProgress::Preparing);
        request
            .invocation_id
            .parse::<Ulid>()
            .map_err(RequestError::other)?;
        if request.secret.is_empty() {
            return Err(RequestError::other("signing secret name is empty"));
        }
        let request_id = Ulid::generate();
        let payload = GitSignRequestPayload {
            method: Method::GitSign,
            invocation_id: request.invocation_id,
            invocation_token: BASE64_STANDARD.encode(request.invocation_token),
            secret: request.secret,
            message: BASE64_STANDARD.encode(request.message),
            repository: request.repository.map(GitSignRepositoryPayload::from),
        };

        self.approval_exchange(
            request_id,
            &payload,
            cancellation,
            progress,
            |response: ApprovedSignature| {
                response
                    .signature
                    .filter(|signature| valid_ssh_signature_envelope(signature))
                    .ok_or_else(|| {
                        io::Error::other(
                            "approved response doesn't contain a valid SSH signature envelope",
                        )
                    })
            },
        )
        .await
    }
}

fn valid_ssh_signature_envelope(signature: &str) -> bool {
    signature.starts_with(SSH_SIGNATURE_BEGIN) && signature.trim_end().ends_with(SSH_SIGNATURE_END)
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

#[derive(Deserialize)]
struct ApprovedSignature {
    signature: Option<String>,
}
