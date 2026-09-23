use std::{future::Future, io};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::{
    Client, DenialReason, RequestError, RequestProgress,
    config::{Pairing, clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    protocol::{self, AbortReason, DeviceError, Outcome, Response, seal_aborted},
    websocket::{self, RelayExchange},
};

/// Seals an authenticated request and prepares the relay exchange that carries it.
pub(crate) fn seal_request(
    client: &Client,
    pairing: &Pairing,
    request_id: Ulid,
    payload: &impl Serialize,
) -> Result<(Session, crypto::Request, RelayExchange), RequestError> {
    let plaintext = Zeroizing::new(client.encode(payload)?);
    let mut session = Session::new(pairing, &request_id)?;
    let request = session.seal_request(&plaintext)?;
    let relay = RelayExchange::authenticated(client, pairing, &request_id.to_string())?;
    Ok((session, request, relay))
}

/// Ends the exchange after an authenticated device error.
pub(crate) async fn reject_device_error(
    client: &Client,
    session: &mut Session,
    relay: &mut RelayExchange,
    error: DeviceError,
) -> RequestError {
    if let Some(completion) =
        seal_aborted(client, session, AbortReason::ClientError, error.to_string())
    {
        let _ = relay.complete_briefly(&completion).await;
    }
    error.into()
}

impl Client {
    // Invocation and signing requests share approval and cancellation semantics.
    // Pairing and secret management have different state transitions.
    pub(crate) async fn approval_exchange<R: DeserializeOwned, T>(
        &self,
        request_id: Ulid,
        payload: &impl Serialize,
        cancellation: impl Future<Output = ()>,
        mut progress: impl FnMut(RequestProgress),
        validate: impl FnOnce(R) -> io::Result<T>,
    ) -> Result<T, RequestError> {
        tokio::pin!(cancellation);
        self.maybe_rotate_psk()?;
        let pairing_path = self.pairing_path();
        let pairing = read_pairing_from(&pairing_path)?;
        let (mut session, request, mut relay) = seal_request(self, &pairing, request_id, payload)?;

        progress(RequestProgress::WaitingForDelivery);
        let response = match tokio::select! {
            biased;
            _ = cancellation.as_mut() => {
                if relay.request_was_sent() {
                    let completion = seal_aborted(self, &mut session,
                        AbortReason::Cancelled, RequestError::Interrupted.to_string());
                    if let Some(completion) = completion {
                        let _ = relay.complete_briefly(&completion).await;
                    }
                }
                return Err(RequestError::Interrupted);
            }
            response = relay.request(&request, || progress(RequestProgress::WaitingForResponse)) => response,
        } {
            Ok(response) => response,
            Err(error) => {
                let reason = abort_reason(&error);
                let error = RequestError::from(error);
                if let Some(completion) =
                    seal_aborted(self, &mut session, reason, error.to_string())
                {
                    // The relay already failed, so the abort gets only a brief handoff attempt.
                    // Cancellation, even if already pending, still gets that attempt.
                    tokio::select! {
                        biased;
                        _ = cancellation.as_mut() => {
                            let _ = relay.complete_briefly(&completion).await;
                            return Err(RequestError::Interrupted);
                        }
                        _ = relay.complete_briefly(&completion) => {}
                    }
                }
                return Err(error);
            }
        };

        progress(RequestProgress::Completing);
        let response = session
            .open_response(response)
            .map_err(RequestError::from)
            .and_then(|plaintext| {
                if let Some(rotation_key) = pairing.rotation_key() {
                    clear_rotation_key(&pairing_path, rotation_key)?;
                }
                protocol::decode_response::<Decision<R>>(&plaintext)
            });
        let result = match response {
            Ok(Response::Error(error)) => {
                return Err(reject_device_error(self, &mut session, &mut relay, error).await);
            }
            Ok(Response::Message(Decision::Approved { data })) => {
                validate(data).map_err(RequestError::from)
            }
            Ok(Response::Message(Decision::Denied { reason, message })) => {
                Err(RequestError::Denied { reason, message })
            }
            Ok(Response::Message(Decision::Aborted { .. })) => Err(RequestError::other(
                "received an ABORTED result in a response",
            )),
            Err(error) => Err(error),
        };
        let outcome = match &result {
            Ok(_) => Outcome::Approved,
            Err(RequestError::Denied { reason, message }) => Outcome::Denied {
                reason: *reason,
                message: message.clone(),
            },
            Err(error) => Outcome::Aborted {
                reason: AbortReason::InvalidResponse,
                message: error.to_string(),
            },
        };
        let plaintext = self.encode(&outcome)?;
        let completion = session.seal_completion(&plaintext)?;
        tokio::select! {
            biased;
            _ = cancellation.as_mut() => {
                let _ = relay.complete_briefly(&completion).await;
                Err(RequestError::Interrupted)
            }
            handoff = relay.complete(&completion) => {
                handoff?;
                progress(RequestProgress::Completed);
                result
            }
        }
    }
}

fn abort_reason(error: &websocket::Error) -> AbortReason {
    match error {
        websocket::Error::RetriesExhausted { .. } => AbortReason::TimedOut,
        websocket::Error::UnexpectedStatus(status) if (400..500).contains(status) => {
            AbortReason::ClientError
        }
        _ => AbortReason::InvalidResponse,
    }
}

#[derive(Deserialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum Decision<T> {
    Approved {
        #[serde(flatten)]
        data: T,
    },
    Denied {
        reason: DenialReason,
        message: String,
    },
    Aborted {
        #[serde(rename = "reason")]
        _reason: AbortReason,
        #[serde(rename = "message")]
        _message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Deserialize)]
    struct Signature {
        signature: String,
    }

    #[test]
    fn reads_approved_data_from_the_existing_flat_envelope() {
        let decision: Decision<Signature> = serde_json::from_value(json!({
            "result": "APPROVED", "signature": "test signature", "extension": true,
        }))
        .unwrap();
        let Decision::Approved { data } = decision else {
            panic!("expected approval")
        };
        assert_eq!(data.signature, "test signature");
        assert!(
            serde_json::from_value::<Decision<Signature>>(json!({
                "result": "APPROVED", "signature": 7,
            }))
            .is_err()
        );
    }

    #[test]
    fn denied_responses_dont_require_or_decode_approved_data() {
        for extra in [json!({}), json!({"signature": 7})] {
            let mut response = json!({
                "result": "DENIED", "reason": "POLICY_DENIED", "message": "Not permitted.",
            });
            response
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let decision: Decision<Signature> = serde_json::from_value(response).unwrap();
            assert!(matches!(
                decision,
                Decision::Denied {
                    reason: DenialReason::PolicyDenied,
                    ..
                }
            ));
        }
    }
}
