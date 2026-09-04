use std::{future::Future, path::Path, pin::Pin};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    Client, DenialReason, RequestError,
    config::{Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    protocol::{self, Method, Response},
    websocket::{self, RelayExchange},
};

/// Describes one SSH authentication requested by a command invocation.
pub struct SshAuthenticationRequest<'a> {
    /// The request identifier of the initial invocation.
    pub invocation_id: &'a str,

    /// The authorization token created for the invocation.
    pub invocation_token: &'a [u8; 32],

    /// The name of the SSH secret selected for the invocation.
    pub secret: &'a str,

    /// The signature algorithm requested by the SSH client.
    ///
    /// This value must match the algorithm encoded in [`Self::message`].
    pub algorithm: SshSignatureAlgorithm,

    /// The exact message bytes supplied by the SSH client.
    ///
    /// The message must be a valid SSH user-authentication request for the
    /// selected secret's public key.
    pub message: &'a [u8],
}

/// An SSH signature algorithm supported by Agentknock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SshSignatureAlgorithm {
    /// Ed25519 as defined for SSH.
    Ed25519,

    /// RSA with SHA-256 as defined by RFC 8332.
    RsaSha256,

    /// RSA with SHA-512 as defined by RFC 8332.
    RsaSha512,
}

impl SshSignatureAlgorithm {
    /// Returns the SSH protocol name of the signature algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::RsaSha256 => "rsa-sha2-256",
            Self::RsaSha512 => "rsa-sha2-512",
        }
    }
}

/// A stage reported while an SSH authentication request is running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SshAuthenticationProgress {
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
    /// Requests an SSH authentication signature from a selected secret.
    ///
    /// The device makes a separate decision for each authentication. The
    /// request includes the exact SSH user-authentication bytes supplied by
    /// the SSH client.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] if local pairing state isn't active, the relay
    /// exchange fails, the device denies the signature, the response is
    /// invalid, or the operation is canceled.
    pub async fn request_ssh_authentication<P>(
        &self,
        request: SshAuthenticationRequest<'_>,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<Vec<u8>, RequestError>
    where
        P: FnMut(SshAuthenticationProgress),
    {
        tokio::pin!(cancellation);
        progress(SshAuthenticationProgress::Preparing);
        request
            .invocation_id
            .parse::<Ulid>()
            .map_err(RequestError::other)?;
        if request.secret.is_empty() {
            return Err(RequestError::other("SSH secret name is empty"));
        }
        self.maybe_rotate_psk()?;
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let request_id = Ulid::generate();
        let request = PreparedSshAuthentication {
            payload: SshAuthenticationRequestPayload {
                method: Method::SshAuthenticate,
                invocation_id: request.invocation_id,
                invocation_token: BASE64_STANDARD.encode(request.invocation_token),
                secret: request.secret,
                message: BASE64_STANDARD.encode(request.message),
            },
            response_algorithm: request.algorithm,
        };

        ssh_authentication_exchange(
            self,
            &pairing_path,
            &pairing,
            request_id,
            &request,
            cancellation.as_mut(),
            &mut progress,
        )
        .await
    }
}

async fn ssh_authentication_exchange<C, P>(
    client: &Client,
    pairing_path: &Path,
    pairing: &Pairing,
    request_id: Ulid,
    authentication: &PreparedSshAuthentication<'_>,
    mut cancellation: Pin<&mut C>,
    progress: &mut P,
) -> Result<Vec<u8>, RequestError>
where
    C: Future<Output = ()> + ?Sized,
    P: FnMut(SshAuthenticationProgress),
{
    let plaintext = client
        .encode(&authentication.payload)
        .map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(client, pairing, &request_id.to_string())?;

    progress(SshAuthenticationProgress::WaitingForDelivery);
    let response = match tokio::select! {
        biased;
        _ = cancellation.as_mut() => {
            if relay.request_was_sent() {
                complete_cancelled(client, &mut session, &mut relay).await;
            }
            return Err(RequestError::Interrupted);
        }
        response = relay.request(&request, || {
            progress(SshAuthenticationProgress::WaitingForResponse);
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

    progress(SshAuthenticationProgress::Completing);
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
        Ok(Response::Message(result)) => match result {
            SshAuthenticationResult::Approved {
                signature: Some(signature),
            } => match BASE64_STANDARD.decode(signature) {
                Ok(signature) if valid_signature(&signature, authentication.response_algorithm) => {
                    (
                        SshAuthenticationResult::Approved { signature: None },
                        Ok(signature),
                    )
                }
                _ => invalid_response("approved response doesn't contain a valid SSH signature"),
            },
            SshAuthenticationResult::Approved { signature: None } => {
                invalid_response("approved response doesn't contain an SSH signature")
            }
            SshAuthenticationResult::Denied { reason, message } => (
                SshAuthenticationResult::Denied {
                    reason,
                    message: message.clone(),
                },
                Err(RequestError::Denied { reason, message }),
            ),
            SshAuthenticationResult::Aborted { .. } => {
                invalid_response("received an ABORTED result in a response")
            }
        },
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
            SshAuthenticationResult::Aborted {
                reason: SshAuthenticationAbortReason::InvalidResponse,
                message: error.to_string(),
            },
            Err(error),
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
            progress(SshAuthenticationProgress::Completed);
            false
        }
    };
    if interrupted {
        let _ = relay.complete_briefly(&completion).await;
        return Err(RequestError::Interrupted);
    }

    exchange_result
}

fn invalid_response(message: &str) -> (SshAuthenticationResult, Result<Vec<u8>, RequestError>) {
    (
        SshAuthenticationResult::Aborted {
            reason: SshAuthenticationAbortReason::InvalidResponse,
            message: message.to_owned(),
        },
        Err(RequestError::other(message.to_owned())),
    )
}

fn valid_signature(signature: &[u8], expected: SshSignatureAlgorithm) -> bool {
    let Some((algorithm, remainder)) = take_string(signature) else {
        return false;
    };
    let Some((value, remainder)) = take_string(remainder) else {
        return false;
    };
    remainder.is_empty()
        && !value.is_empty()
        && algorithm == expected.as_str().as_bytes()
        && (expected != SshSignatureAlgorithm::Ed25519 || value.len() == 64)
}

fn take_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4_usize.checked_add(length)?)?;
    Some((value, &input[4 + length..]))
}

fn abort_reason(error: &websocket::Error) -> SshAuthenticationAbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => SshAuthenticationAbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            SshAuthenticationAbortReason::ClientError
        }
        _ => SshAuthenticationAbortReason::InvalidResponse,
    }
}

fn seal_aborted(
    client: &Client,
    session: &mut Session,
    reason: SshAuthenticationAbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let plaintext = client
        .encode(&SshAuthenticationResult::Aborted { reason, message })
        .ok()?;
    session.seal_completion(&plaintext).ok()
}

async fn complete_cancelled(client: &Client, session: &mut Session, relay: &mut RelayExchange) {
    let Some(completion) = seal_aborted(
        client,
        session,
        SshAuthenticationAbortReason::Cancelled,
        RequestError::Interrupted.to_string(),
    ) else {
        return;
    };
    let _ = relay.complete_briefly(&completion).await;
}

#[derive(Serialize)]
struct SshAuthenticationRequestPayload<'a> {
    method: Method,
    invocation_id: &'a str,
    invocation_token: String,
    secret: &'a str,
    message: String,
}

struct PreparedSshAuthentication<'a> {
    payload: SshAuthenticationRequestPayload<'a>,
    response_algorithm: SshSignatureAlgorithm,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum SshAuthenticationResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    Denied {
        reason: DenialReason,
        message: String,
    },
    Aborted {
        reason: SshAuthenticationAbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SshAuthenticationAbortReason {
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
    fn validates_the_requested_signature_algorithm() {
        let signature = signature("ssh-ed25519", &[7; 64]);
        assert!(valid_signature(&signature, SshSignatureAlgorithm::Ed25519));
        assert!(!valid_signature(
            &signature,
            SshSignatureAlgorithm::RsaSha512
        ));
    }

    #[test]
    fn rejects_malformed_signatures() {
        assert!(!valid_signature(&[], SshSignatureAlgorithm::Ed25519));
        assert!(!valid_signature(
            &signature("ssh-ed25519", &[7; 63]),
            SshSignatureAlgorithm::Ed25519
        ));
        let mut trailing = signature("ssh-ed25519", &[7; 64]);
        trailing.push(0);
        assert!(!valid_signature(&trailing, SshSignatureAlgorithm::Ed25519));
    }

    fn signature(algorithm: &str, value: &[u8]) -> Vec<u8> {
        let mut signature = Vec::new();
        put_string(&mut signature, algorithm.as_bytes());
        put_string(&mut signature, value);
        signature
    }

    fn put_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }
}
