use std::{
    collections::BTreeMap,
    env, fmt,
    fs::File,
    io,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::aead::{Aead as _, Key as AeadKey, KeyInit as _, Nonce as AeadNonce};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, PskBundle, Serializable,
    aead::{Aead as HpkeAeadTrait, AeadCtxS, ChaCha20Poly1305},
    hybrid_array::Array,
    kdf::{HkdfSha256, Kdf as HpkeKdfTrait},
    kem::X25519HkdfSha256,
    setup_sender,
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use thiserror::Error;
use ulid::Ulid;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const RELAY_URL: &str = "https://relay.agentknock.dev/";
const RESPONSE_EXPORTER_CONTEXT: &[u8] = b"agentknock-v1 response";
const TEST_RELAY_URL_ENV: &str = "AGENTKNOCK_TEST_RELAY_URL";

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

pub struct CredentialRequest<'a> {
    pub profiles: &'a [String],
    pub operation: RequestOperation<'a>,
    pub reason: Option<&'a str>,
}

pub enum RequestOperation<'a> {
    Exec {
        command: &'a str,
        arguments: &'a [String],
    },
}

pub struct Credentials {
    environment: BTreeMap<String, String>,
}

impl Credentials {
    pub fn into_environment(self) -> BTreeMap<String, String> {
        self.environment
    }
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error("relay request failed: {0}")]
    Relay(#[from] reqwest::Error),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error("request denied ({reason}): {message}")]
    Denied {
        reason: DenialReason,
        message: String,
    },

    #[error("{TEST_RELAY_URL_ENV} is not valid UTF-8")]
    InvalidTestRelayUrl,
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("HOME is not set")]
    HomeNotSet,

    #[error("could not access pairing configuration {path}: {source}")]
    Access {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("{path} must have mode 0600, found {mode:04o}")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("invalid pairing configuration {path}: {source}")]
    Invalid {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("{path} contains an empty pairing PSK")]
    EmptyPsk { path: PathBuf },
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid protocol JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid base64 in encrypted response: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("HPKE operation failed: {0}")]
    Hpke(#[from] hpke::HpkeError),

    #[error("response key derivation failed: {0}")]
    KeyDerivation(#[from] hkdf::InvalidLength),

    #[error("response decryption failed")]
    Decryption(#[from] chacha20poly1305::aead::Error),

    #[error("relay response did not contain a result")]
    MissingResult,

    #[error("approved response did not contain an environment mapping")]
    MissingEnvironment,

    #[error("received an ABORTED result in a response")]
    AbortedResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialReason {
    UserDenied,
    PolicyDenied,
    InvalidRequest,
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

pub async fn request_credentials(
    request: CredentialRequest<'_>,
) -> Result<Credentials, RequestError> {
    let pairing = read_pairing()?;
    let relay_url = relay_url()?;
    let request_contents = match request.operation {
        RequestOperation::Exec { command, arguments } => RequestContents {
            profiles: request.profiles,
            operation: "exec",
            command,
            arguments,
            reason: request.reason,
        },
    };

    message_exchange(&relay_url, &pairing, &request_contents).await
}

#[derive(Deserialize)]
struct Pairing {
    route_id: Identifier,
    pairing_id: Identifier,
    #[serde(deserialize_with = "deserialize_base64")]
    pairing_psk: Vec<u8>,
    #[serde(deserialize_with = "deserialize_route_key")]
    route_key: <Kem as KemTrait>::PublicKey,
}

#[derive(Serialize)]
struct RequestContents<'a> {
    profiles: &'a [String],
    operation: &'static str,
    command: &'a str,
    arguments: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum RequestResult {
    Approved {
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<BTreeMap<String, String>>,
    },
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

#[derive(Serialize)]
struct Request {
    version: &'static str,
    pairing_id: String,
    key: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct Completion {
    pairing_id: String,
    key: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct RequestMessage<'a> {
    request: &'a Request,
}

#[derive(Deserialize)]
struct RequestResponse {
    state: MessageState,
    response: Option<Response>,
}

#[derive(Deserialize)]
struct Response {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct CompletionMessage<'a> {
    request: &'a Request,
    completion: Completion,
}

#[derive(Clone, Copy)]
struct Identifier(u128);

impl Identifier {
    fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:032x}", self.0)
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 32
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "expected a 32-character lowercase hexadecimal identifier",
            ));
        }

        u128::from_str_radix(&encoded, 16)
            .map(Identifier)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct CompletionResponse {
    state: MessageState,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MessageState {
    RequestPending,
    RequestDelivered,
    ResponsePending,
    ResponseDelivered,
    CompletionPending,
    CompletionDelivered,
}

fn read_pairing() -> Result<Pairing, ConfigurationError> {
    let home = env::var_os("HOME").ok_or(ConfigurationError::HomeNotSet)?;
    read_pairing_from(&PathBuf::from(home).join(".agentknock/pairing.json"))
}

fn read_pairing_from(path: &Path) -> Result<Pairing, ConfigurationError> {
    let file = File::open(path).map_err(|source| ConfigurationError::Access {
        path: path.to_owned(),
        source,
    })?;

    #[cfg(unix)]
    {
        let mode = file
            .metadata()
            .map_err(|source| ConfigurationError::Access {
                path: path.to_owned(),
                source,
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(ConfigurationError::InsecurePermissions {
                path: path.to_owned(),
                mode,
            });
        }
    }

    let pairing: Pairing =
        serde_json::from_reader(file).map_err(|source| ConfigurationError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    if pairing.pairing_psk.is_empty() {
        return Err(ConfigurationError::EmptyPsk {
            path: path.to_owned(),
        });
    }

    Ok(pairing)
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    BASE64_STANDARD
        .decode(encoded)
        .map_err(serde::de::Error::custom)
}

fn deserialize_route_key<'de, D>(deserializer: D) -> Result<<Kem as KemTrait>::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_base64(deserializer)?;
    <Kem as KemTrait>::PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
}

fn relay_url() -> Result<String, RequestError> {
    match env::var(TEST_RELAY_URL_ENV) {
        Ok(relay_url) => Ok(relay_url),
        Err(env::VarError::NotPresent) => Ok(RELAY_URL.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(RequestError::InvalidTestRelayUrl),
    }
}

async fn message_exchange(
    relay_url: &str,
    pairing: &Pairing,
    request_contents: &RequestContents<'_>,
) -> Result<Credentials, RequestError> {
    let client = reqwest::Client::new();
    let request_id = Ulid::generate();
    let message_url = format!(
        "{}/v1/route/{}/msg/{request_id}",
        relay_url.trim_end_matches('/'),
        pairing.route_id,
    );
    let info = [
        pairing.route_id.to_bytes(),
        pairing.pairing_id.to_bytes(),
        request_id.to_bytes(),
    ]
    .concat();
    let pairing_id = pairing.pairing_id.to_bytes();
    let psk = PskBundle::new(&pairing.pairing_psk, &pairing_id).map_err(ProtocolError::from)?;
    let (encapped_key, mut sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Psk(psk), &pairing.route_key, &info)
            .map_err(ProtocolError::from)?;
    let plaintext = serde_json::to_vec(request_contents).map_err(ProtocolError::from)?;
    let ciphertext = sender_context
        .seal(&plaintext, b"")
        .map_err(ProtocolError::from)?;
    let encapped_key = encapped_key.to_bytes();
    let request = Request {
        version: "1",
        pairing_id: pairing.pairing_id.to_string(),
        key: BASE64_STANDARD.encode(encapped_key),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };

    let request_response: RequestResponse = post_message(
        &client,
        &format!("{message_url}/request"),
        &RequestMessage { request: &request },
    )
    .await?;
    let _request_state = request_response.state;
    let response = request_response
        .response
        .ok_or(ProtocolError::MissingResult)?;
    let result = decrypt_response(&sender_context, &encapped_key, response)?;
    let (completion_result, exchange_result) = match result {
        RequestResult::Approved {
            environment: Some(environment),
        } => (
            RequestResult::Approved { environment: None },
            Ok(Credentials { environment }),
        ),
        RequestResult::Approved { environment: None } => (
            RequestResult::Aborted {
                reason: AbortReason::InvalidResponse,
                message: ProtocolError::MissingEnvironment.to_string(),
            },
            Err(ProtocolError::MissingEnvironment.into()),
        ),
        RequestResult::Denied { reason, message } => (
            RequestResult::Denied {
                reason,
                message: message.clone(),
            },
            Err(RequestError::Denied { reason, message }),
        ),
        RequestResult::Aborted { .. } => (
            RequestResult::Aborted {
                reason: AbortReason::InvalidResponse,
                message: ProtocolError::AbortedResponse.to_string(),
            },
            Err(ProtocolError::AbortedResponse.into()),
        ),
    };

    let completion_plaintext =
        serde_json::to_vec(&completion_result).map_err(ProtocolError::from)?;
    let completion_ciphertext = sender_context
        .seal(&completion_plaintext, b"")
        .map_err(ProtocolError::from)?;
    let completion = Completion {
        pairing_id: pairing.pairing_id.to_string(),
        key: request.key.clone(),
        ciphertext: BASE64_STANDARD.encode(completion_ciphertext),
    };
    let completion_response: CompletionResponse = post_message(
        &client,
        &format!("{message_url}/complete"),
        &CompletionMessage {
            request: &request,
            completion,
        },
    )
    .await?;
    let _completion_state = completion_response.state;

    exchange_result
}

fn decrypt_response(
    sender_context: &AeadCtxS<Aead, Kdf, Kem>,
    encapped_key: &[u8],
    response: Response,
) -> Result<RequestResult, ProtocolError> {
    let nonce = BASE64_STANDARD.decode(response.nonce)?;
    let ciphertext = BASE64_STANDARD.decode(response.ciphertext)?;
    let mut salt = Vec::with_capacity(encapped_key.len() + nonce.len());
    salt.extend_from_slice(encapped_key);
    salt.extend_from_slice(&nonce);

    let mut exported_secret = ResponseSecret::default();
    sender_context.export(RESPONSE_EXPORTER_CONTEXT, &mut exported_secret)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &exported_secret);
    let mut key = ResponseKey::default();
    hkdf.expand(b"key", &mut key)?;
    let mut nonce = ResponseNonce::default();
    hkdf.expand(b"nonce", &mut nonce)?;
    let cipher = ResponseAead::new(&key);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    Ok(serde_json::from_slice(&plaintext)?)
}

async fn post_message<B, R>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<R, reqwest::Error>
where
    B: Serialize + ?Sized,
    R: DeserializeOwned,
{
    client
        .post(url)
        .json(body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}
