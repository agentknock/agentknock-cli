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
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use ulid::Ulid;

use crate::config::{Identifier, Pairing, PendingPairing, Rotation};

const BASE_DERIVATION_SALT: &[u8] = b"agentknock-v1";
const ROUTE_DERIVATION_INFO: &[u8] = b"agentknock-v1 route";
const COMMITMENT_DERIVATION_INFO: &[u8] = b"agentknock-v1 commitment";
const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
const SAS_DERIVATION_INFO: &[u8] = b"agentknock-v1 sas";
const RESPONSE_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 response";
const SAS_DECIMAL_MODULUS: u64 = 1_000_000_000_000;

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ExporterSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

pub(crate) struct Session {
    pairing_id: String,
    encapped_key: Vec<u8>,
    rotation: Option<Rotation>,
    sender_context: AeadCtxS<Aead, Kdf, Kem>,
    state: SessionState,
}

impl Session {
    pub(crate) fn new(pairing: &Pairing, request_id: &Ulid) -> Result<Self, Error> {
        let route_key = <Kem as KemTrait>::PublicKey::from_bytes(pairing.route_key())?;
        let pairing_id = pairing.pairing_id_bytes();
        let info = [pairing.route_id_bytes(), pairing_id, request_id.to_bytes()].concat();
        let psk = PskBundle::new(pairing.pairing_psk(), &pairing_id)?;
        let (encapped_key, sender_context) =
            setup_sender::<Aead, Kdf, Kem>(&OpModeS::Psk(psk), &route_key, &info)?;
        let encapped_key = encapped_key.to_bytes().to_vec();

        Ok(Self {
            pairing_id: pairing.pairing_id(),
            encapped_key,
            rotation: pairing.rotation().cloned(),
            sender_context,
            state: SessionState::Ready,
        })
    }

    pub(crate) fn seal_request(&mut self, plaintext: &[u8]) -> Result<Request, Error> {
        self.require_state(SessionState::Ready, "seal request")?;
        let ciphertext = self.sender_context.seal(plaintext, b"")?;
        self.state = SessionState::RequestSealed;

        Ok(Request {
            version: "1",
            pairing_id: self.pairing_id.clone(),
            key: BASE64_STANDARD.encode(&self.encapped_key),
            ciphertext: BASE64_STANDARD.encode(ciphertext),
            rotation: self.rotation.clone(),
        })
    }

    pub(crate) fn open_response(&self, response: Response) -> Result<Vec<u8>, Error> {
        let public_nonce = BASE64_STANDARD.decode(response.nonce)?;
        let ciphertext = BASE64_STANDARD.decode(response.ciphertext)?;
        let mut salt = Vec::with_capacity(self.encapped_key.len() + public_nonce.len());
        salt.extend_from_slice(&self.encapped_key);
        salt.extend_from_slice(&public_nonce);

        let mut exported_secret = ExporterSecret::default();
        self.sender_context
            .export(RESPONSE_EXPORT_CONTEXT, &mut exported_secret)?;
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &exported_secret);
        let mut key = ResponseKey::default();
        hkdf.expand(b"key", &mut key)?;
        let mut nonce = ResponseNonce::default();
        hkdf.expand(b"nonce", &mut nonce)?;
        let cipher = ResponseAead::new(&key);
        Ok(cipher.decrypt(&nonce, ciphertext.as_ref())?)
    }

    pub(crate) fn seal_completion(&mut self, plaintext: &[u8]) -> Result<Completion, Error> {
        self.require_state(SessionState::RequestSealed, "seal completion")?;
        let ciphertext = self.sender_context.seal(plaintext, b"")?;
        self.state = SessionState::CompletionSealed;

        Ok(Completion {
            ciphertext: BASE64_STANDARD.encode(ciphertext),
        })
    }

    fn require_state(&self, expected: SessionState, operation: &'static str) -> Result<(), Error> {
        if self.state == expected {
            Ok(())
        } else {
            Err(Error::MessageOrder {
                operation,
                state: self.state.description(),
            })
        }
    }
}

pub(crate) fn seal_pairing(
    route_id: Identifier,
    request_id: &Ulid,
    response: PairingResponse,
    client_random: &[u8],
    plaintext: &[u8],
) -> Result<(PairingCompletion, PendingPairing, u64), Error> {
    let route_key = <Kem as KemTrait>::PublicKey::from_bytes(&response.route_key)?;
    let pairing_id = response.pairing_id.to_bytes();
    let info = [route_id.to_bytes(), pairing_id, request_id.to_bytes()].concat();
    let (encapped_key, mut sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &route_key, &info)?;
    let ciphertext = sender_context.seal(plaintext, b"")?;
    let mut pairing_psk = ExporterSecret::default();
    sender_context.export(PSK_EXPORT_CONTEXT, &mut pairing_psk)?;
    let mut sas_ikm = Vec::with_capacity(client_random.len() + response.route_key.len());
    sas_ikm.extend_from_slice(client_random);
    sas_ikm.extend_from_slice(&response.route_key);
    let hkdf = Hkdf::<Sha256>::new(Some(&pairing_id), &sas_ikm);
    let mut sas = [0; 8];
    hkdf.expand(SAS_DERIVATION_INFO, &mut sas)?;
    let sas = u64::from_be_bytes(sas) % SAS_DECIMAL_MODULUS;
    let completion = PairingCompletion {
        key: BASE64_STANDARD.encode(encapped_key.to_bytes()),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };
    let pairing = PendingPairing::new(
        route_id,
        response.pairing_id,
        pairing_psk.to_vec(),
        response.route_key,
    );

    Ok((completion, pairing, sas))
}

pub(crate) fn derive_route_id(address: &str) -> Result<Identifier, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(BASE_DERIVATION_SALT), address.as_bytes());
    let mut route_id = [0; 16];
    hkdf.expand(ROUTE_DERIVATION_INFO, &mut route_id)?;
    Ok(Identifier::from_bytes(route_id))
}

pub(crate) fn generate_client_random() -> Result<Vec<u8>, Error> {
    let mut client_random = ExporterSecret::default();
    getrandom::fill(&mut client_random)?;
    Ok(client_random.to_vec())
}

pub(crate) fn derive_pairing_commitment(address: &str) -> Result<Vec<u8>, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(BASE_DERIVATION_SALT), address.as_bytes());
    let mut commitment = ExporterSecret::default();
    hkdf.expand(COMMITMENT_DERIVATION_INFO, &mut commitment)?;
    Ok(commitment.to_vec())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SessionState {
    Ready,
    RequestSealed,
    CompletionSealed,
}

impl SessionState {
    fn description(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::RequestSealed => "request sealed",
            Self::CompletionSealed => "completion sealed",
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Request {
    version: &'static str,
    pairing_id: String,
    key: String,
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation: Option<Rotation>,
}

#[derive(Deserialize)]
pub(crate) struct Response {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
pub(crate) struct Completion {
    ciphertext: String,
}

#[derive(Deserialize)]
pub(crate) struct PairingResponse {
    pairing_id: Identifier,
    #[serde(deserialize_with = "deserialize_base64")]
    route_key: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct PairingCompletion {
    key: String,
    ciphertext: String,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("cannot {operation} while cryptographic session is {state}")]
    MessageOrder {
        operation: &'static str,
        state: &'static str,
    },

    #[error("invalid base64 in cryptographic message: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("HPKE operation failed: {0}")]
    Hpke(#[from] hpke::HpkeError),

    #[error("random generation failed: {0}")]
    Random(#[from] getrandom::Error),

    #[error("key derivation failed: {0}")]
    KeyDerivation(#[from] hkdf::InvalidLength),

    #[error("response decryption failed")]
    Decryption(#[from] chacha20poly1305::aead::Error),
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    BASE64_STANDARD
        .decode(encoded)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn derives_route_id_from_pairing_address() {
        assert_eq!(
            derive_route_id("yup-its-free").unwrap().to_string(),
            "0b7d7963604cba911e9c03e727688b89"
        );
    }

    #[test]
    fn derives_pairing_commitment_from_address() {
        assert_eq!(
            BASE64_STANDARD.encode(derive_pairing_commitment("yup-its-free").unwrap()),
            "TSZ1lTkmAPehOPZpnWV5+O6AncZFD5TMKVfG30j6QVY="
        );
    }

    #[test]
    fn rejects_completion_before_request() {
        let mut session = test_session();

        assert!(matches!(
            session.seal_completion(b"completion"),
            Err(Error::MessageOrder {
                operation: "seal completion",
                state: "ready",
            })
        ));
    }

    #[test]
    fn rejects_duplicate_request() {
        let mut session = test_session();
        session.seal_request(b"request").unwrap();

        assert!(matches!(
            session.seal_request(b"another request"),
            Err(Error::MessageOrder {
                operation: "seal request",
                state: "request sealed",
            })
        ));
    }

    #[test]
    fn rejects_duplicate_completion() {
        let mut session = test_session();
        session.seal_request(b"request").unwrap();
        session.seal_completion(b"completion").unwrap();

        assert!(matches!(
            session.seal_completion(b"another completion"),
            Err(Error::MessageOrder {
                operation: "seal completion",
                state: "completion sealed",
            })
        ));
    }

    fn test_session() -> Session {
        let (_, route_key) = Kem::gen_keypair();
        let pairing: Pairing = serde_json::from_value(json!({
            "route_id": "00112233445566778899aabbccddeeff",
            "pairing_id": "ffeeddccbbaa99887766554433221100",
            "pairing_psk": BASE64_STANDARD.encode([0x42; 32]),
            "route_key": BASE64_STANDARD.encode(route_key.to_bytes()),
        }))
        .unwrap();

        Session::new(&pairing, &Ulid::generate()).unwrap()
    }
}
