use std::{future::Future, io};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ulid::Ulid;

use crate::{
    Client, DenialReason, RequestError, RequestProgress,
    config::{clear_rotation_key, read_pairing_from},
    crypto::{self, Session},
    protocol::{self, Response},
    websocket::{self, RelayExchange},
};

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
        let pairing_path = self.pairing_path()?;
        let pairing = read_pairing_from(&pairing_path)?;
        let plaintext = self.encode(payload).map_err(RequestError::other)?;
        let mut session = Session::new(&pairing, &request_id).map_err(RequestError::other)?;
        let request = session
            .seal_request(&plaintext)
            .map_err(RequestError::other)?;
        let mut relay = RelayExchange::authenticated(self, &pairing, &request_id.to_string())?;

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
                    clear_rotation_key(&pairing_path, rotation_key)?;
                }
                protocol::decode_response::<Decision<R>>(&plaintext).map_err(RequestError::other)
            });
        let result = match response {
            Ok(Response::Error(error)) => {
                if let Some(completion) =
                    protocol::seal_error_completion(self, &mut session, &error)
                {
                    let _ = relay.complete_briefly(&completion).await;
                }
                return Err(RequestError::DeviceRejected {
                    code: error.code,
                    message: error.message,
                });
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
        let plaintext = self.encode(&outcome).map_err(RequestError::other)?;
        let completion = session
            .seal_completion(&plaintext)
            .map_err(RequestError::other)?;
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

fn seal_aborted(
    client: &Client,
    session: &mut Session,
    reason: AbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let plaintext = client.encode(&Outcome::Aborted { reason, message }).ok()?;
    session.seal_completion(&plaintext).ok()
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

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum Outcome {
    Approved,
    Denied {
        reason: DenialReason,
        message: String,
    },
    Aborted {
        reason: AbortReason,
        message: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AbortReason {
    Cancelled,
    TimedOut,
    InvalidResponse,
    ClientError,
    Other,
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

    #[test]
    fn completion_contains_only_the_outcome() {
        for (outcome, expected) in [
            (Outcome::Approved, json!({"result": "APPROVED"})),
            (
                Outcome::Denied {
                    reason: DenialReason::PolicyDenied,
                    message: "Not permitted.".into(),
                },
                json!({"result": "DENIED", "reason": "POLICY_DENIED", "message": "Not permitted."}),
            ),
            (
                Outcome::Aborted {
                    reason: AbortReason::InvalidResponse,
                    message: "Invalid response.".into(),
                },
                json!({"result": "ABORTED", "reason": "INVALID_RESPONSE", "message": "Invalid response."}),
            ),
        ] {
            assert_eq!(serde_json::to_value(outcome).unwrap(), expected);
        }
    }
}
