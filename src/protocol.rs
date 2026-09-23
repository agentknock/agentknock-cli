use std::fmt;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{ApplicationInfo, Client, DenialReason, crypto, crypto::Session};

pub(crate) const LIBRARY_NAME: &str = env!("CARGO_PKG_NAME");
pub(crate) const LIBRARY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Serialize)]
pub(crate) enum Method {
    Invocation,
    PairingFinish,
    PairingRemove,
    SecretList,
    SecretUpload,
    GitSign,
    SshAuthenticate,
}

/// A request whose contents are only its method.
#[derive(Serialize)]
pub(crate) struct MethodRequest {
    pub(crate) method: Method,
}

/// A response or completion without contents.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyMessage {}

pub(crate) fn encode<T>(
    application_info: &ApplicationInfo,
    contents: &T,
) -> Result<Vec<u8>, serde_json::Error>
where
    T: Serialize,
{
    serde_json::to_vec(&Message {
        app_info: SoftwareInfo {
            name: application_info.name(),
            version: application_info.version(),
        },
        lib_info: SoftwareInfo {
            name: LIBRARY_NAME,
            version: LIBRARY_VERSION,
        },
        contents,
    })
}

pub(crate) fn decode_response<T>(plaintext: &[u8]) -> Result<Response<T>, serde_json::Error>
where
    T: DeserializeOwned,
{
    let value: Value = serde_json::from_slice(plaintext)?;
    if value
        .as_object()
        .is_some_and(|response| response.contains_key("error"))
    {
        let error = serde_json::from_value::<ErrorResponse>(value)?;
        return Ok(Response::Error(DeviceError {
            code: error.error,
            message: error.message,
        }));
    }
    serde_json::from_value(value).map(Response::Message)
}

pub(crate) fn seal_error_completion(
    client: &Client,
    session: &mut Session,
    error: &DeviceError,
) -> Option<crypto::Completion> {
    seal_aborted(client, session, AbortReason::ClientError, error.to_string())
}

pub(crate) fn seal_aborted(
    client: &Client,
    session: &mut Session,
    reason: AbortReason,
    message: String,
) -> Option<crypto::Completion> {
    let plaintext = client.encode(&Outcome::Aborted { reason, message }).ok()?;
    session.seal_completion(&plaintext).ok()
}

pub(crate) enum Response<T> {
    Message(T),
    Error(DeviceError),
}

#[derive(Debug)]
pub(crate) struct DeviceError {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "device rejected the request with {}: {}",
            self.code, self.message
        )
    }
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Outcome {
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
pub(crate) enum AbortReason {
    Cancelled,
    TimedOut,
    InvalidResponse,
    ClientError,
    Other,
}

#[derive(Serialize)]
struct Message<'a, T> {
    app_info: SoftwareInfo<'a>,
    lib_info: SoftwareInfo<'static>,
    #[serde(flatten)]
    contents: &'a T,
}

#[derive(Serialize)]
struct SoftwareInfo<'a> {
    name: &'a str,
    version: &'a str,
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::{AbortReason, Outcome, Response, decode_response, encode};
    use crate::{ApplicationInfo, DenialReason};

    #[derive(Serialize)]
    struct Contents {
        method: &'static str,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct ExampleResponse {
        result: String,
    }

    #[test]
    fn distinguishes_application_and_library_versions() {
        let encoded = encode(
            &ApplicationInfo::new("embedded-application", "2.3.4"),
            &Contents { method: "Example" },
        )
        .unwrap();

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
            json!({
                "app_info": {
                    "name": "embedded-application",
                    "version": "2.3.4",
                },
                "lib_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "method": "Example",
            })
        );
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
                    reason: AbortReason::ClientError,
                    message: "Invalid request.".into(),
                },
                json!({"result": "ABORTED", "reason": "CLIENT_ERROR", "message": "Invalid request."}),
            ),
        ] {
            assert_eq!(serde_json::to_value(outcome).unwrap(), expected);
        }
    }

    #[test]
    fn decodes_a_successful_response() {
        let response: Response<ExampleResponse> = decode_response(br#"{"result":"OK"}"#).unwrap();

        let Response::Message(response) = response else {
            panic!("successful response was interpreted as an error");
        };
        assert_eq!(
            response,
            ExampleResponse {
                result: "OK".into()
            }
        );
    }

    #[test]
    fn decodes_an_authenticated_device_error() {
        let response: Response<ExampleResponse> = decode_response(
            br#"{"error":"INVALID_REQUEST","message":"The request could not be understood."}"#,
        )
        .unwrap();

        let Response::Error(error) = response else {
            panic!("device error was interpreted as a successful response");
        };
        assert_eq!(error.code, "INVALID_REQUEST");
        assert_eq!(error.message, "The request could not be understood.");
    }
}
