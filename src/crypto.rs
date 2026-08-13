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

use crate::config::Pairing;

const RESPONSE_EXPORTER_CONTEXT: &[u8] = b"agentknock-v1 response";

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

pub(crate) struct Session {
    pairing_id: String,
    encapped_key: Vec<u8>,
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
        })
    }

    pub(crate) fn open_response(&self, response: Response) -> Result<Vec<u8>, Error> {
        let public_nonce = BASE64_STANDARD.decode(response.nonce)?;
        let ciphertext = BASE64_STANDARD.decode(response.ciphertext)?;
        let mut salt = Vec::with_capacity(self.encapped_key.len() + public_nonce.len());
        salt.extend_from_slice(&self.encapped_key);
        salt.extend_from_slice(&public_nonce);

        let mut exported_secret = ResponseSecret::default();
        self.sender_context
            .export(RESPONSE_EXPORTER_CONTEXT, &mut exported_secret)?;
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
            pairing_id: self.pairing_id.clone(),
            key: BASE64_STANDARD.encode(&self.encapped_key),
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
}

#[derive(Deserialize)]
pub(crate) struct Response {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
pub(crate) struct Completion {
    pairing_id: String,
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

    #[error("invalid base64 in encrypted response: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("HPKE operation failed: {0}")]
    Hpke(#[from] hpke::HpkeError),

    #[error("response key derivation failed: {0}")]
    KeyDerivation(#[from] hkdf::InvalidLength),

    #[error("response decryption failed")]
    Decryption(#[from] chacha20poly1305::aead::Error),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
