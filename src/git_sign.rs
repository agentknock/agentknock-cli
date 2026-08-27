use std::{future::Future, path::Path, pin::Pin};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    Client, DenialReason, RequestError,
    config::{Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    pairing::RotationError,
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
}

/// A stage reported while a Git signature request is running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitSignProgress {
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
        P: FnMut(GitSignProgress),
    {
        tokio::pin!(cancellation);
        progress(GitSignProgress::Preparing);
        request
            .invocation_id
            .parse::<Ulid>()
            .map_err(RequestError::other)?;
        if request.secret.is_empty() {
            return Err(RequestError::other("signing secret name is empty"));
        }
        self.maybe_rotate_psk().map_err(|error| match error {
            RotationError::Configuration(error) => RequestError::Configuration(error),
            RotationError::Other(error) => RequestError::Other(error),
        })?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let request_id = Ulid::generate();
        let payload = GitSignRequestPayload {
            method: Method::GitSign,
            invocation_id: request.invocation_id,
            invocation_token: BASE64_STANDARD.encode(request.invocation_token),
            secret: request.secret,
            message: BASE64_STANDARD.encode(request.message),
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
    P: FnMut(GitSignProgress),
{
    let plaintext = client
        .encode(request_payload)
        .map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(pairing, &request_id.to_string())?;

    progress(GitSignProgress::WaitingForDelivery);
    let response = match tokio::select! {
        biased;
        _ = cancellation.as_mut() => {
            if relay.request_was_sent() {
                complete_cancelled(client, &mut session, &mut relay).await;
            }
            return Err(RequestError::Interrupted);
        }
        response = relay.request(&request, || {
            progress(GitSignProgress::WaitingForResponse);
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

    progress(GitSignProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(RequestError::other)?;
    if let Some(rotation_key) = pairing.rotation_key() {
        clear_rotation_key(pairing_path, rotation_key)?;
    }
    let result: GitSignResult = match protocol::decode_response(&plaintext)
        .map_err(RequestError::other)?
    {
        Response::Message(result) => result,
        Response::Error(error) => {
            if let Some(completion) = protocol::seal_error_completion(client, &mut session, &error)
            {
                let _ = relay.complete_briefly(&completion).await;
            }
            return Err(RequestError::DeviceRejected {
                code: error.code,
                message: error.message,
            });
        }
    };

    let (completion_result, exchange_result) = match result {
        GitSignResult::Approved {
            signature: Some(signature),
        } if valid_ssh_signature_envelope(&signature) => {
            (GitSignResult::Approved { signature: None }, Ok(signature))
        }
        GitSignResult::Approved { .. } => (
            GitSignResult::Aborted {
                reason: GitSignAbortReason::InvalidResponse,
                message: "approved response doesn't contain a valid SSH signature envelope".into(),
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
            progress(GitSignProgress::Completed);
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
