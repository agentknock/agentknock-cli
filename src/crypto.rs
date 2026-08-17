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

use crate::config::{AddressId, CanonicalUlid, Pairing, PendingPairing};

const BASE_DERIVATION_SALT: &[u8] = b"agentknock-v1";
const ADDRESS_DERIVATION_INFO: &[u8] = b"agentknock-v1 address";
const COMMITMENT_DERIVATION_INFO: &[u8] = b"agentknock-v1 commitment";
const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
const SAS_DERIVATION_INFO: &[u8] = b"agentknock-v1 sas";
const RESPONSE_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 response";
const SAS_DECIMAL_MODULUS: u64 = 1_000_000_000_000;
pub(crate) const PROTOCOL_VERSION: &str = "agentknock-v1";
pub(crate) const PROTOCOL_VERSION_INFO: [u8; 16] = *b"agentknock-v1\0\0\0";

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type SenderContext = AeadCtxS<Aead, Kdf, Kem>;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type KdfSizedBytes = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

pub(crate) struct PskRotation {
    pub(crate) client_psk: Vec<u8>,
    pub(crate) rotation_key: String,
}

pub(crate) struct Session {
    encapped_key: Vec<u8>,
    rotation_key: Option<String>,
    sender_context: SenderContext,
    state: SessionState,
}

impl Session {
    pub(crate) fn new(pairing: &Pairing, request_id: &Ulid) -> Result<Self, Error> {
        let (encapped_key, sender_context) = setup_psk_sender(pairing, request_id.to_bytes())?;

        Ok(Self {
            encapped_key,
            rotation_key: pairing.rotation_key().map(str::to_owned),
            sender_context,
            state: SessionState::Ready,
        })
    }

    pub(crate) fn seal_request(&mut self, plaintext: &[u8]) -> Result<Request, Error> {
        self.require_state(SessionState::Ready, "seal request")?;
        let ciphertext = self.sender_context.seal(plaintext, b"")?;
        self.state = SessionState::RequestSealed;

        Ok(Request {
            version: PROTOCOL_VERSION,
            key: BASE64_STANDARD.encode(&self.encapped_key),
            ciphertext: BASE64_STANDARD.encode(ciphertext),
            rotation_key: self.rotation_key.clone(),
        })
    }

    pub(crate) fn open_response(&self, response: Response) -> Result<Vec<u8>, Error> {
        let public_nonce = BASE64_STANDARD.decode(response.nonce)?;
        require_length(
            "response random",
            &public_nonce,
            KdfSizedBytes::default().len(),
        )?;
        let ciphertext = BASE64_STANDARD.decode(response.ciphertext)?;
        let mut salt = Vec::with_capacity(self.encapped_key.len() + public_nonce.len());
        salt.extend_from_slice(&self.encapped_key);
        salt.extend_from_slice(&public_nonce);

        let mut exported_secret = KdfSizedBytes::default();
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

pub(crate) fn derive_psk_rotation(pairing: &Pairing) -> Result<PskRotation, Error> {
    let (encapped_key, sender_context) = setup_psk_sender(pairing, [0; 16])?;
    let mut client_psk = KdfSizedBytes::default();
    sender_context.export(PSK_EXPORT_CONTEXT, &mut client_psk)?;

    Ok(PskRotation {
        client_psk: client_psk.to_vec(),
        rotation_key: BASE64_STANDARD.encode(encapped_key),
    })
}

fn setup_psk_sender(
    pairing: &Pairing,
    request_id: [u8; 16],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let device_key = <Kem as KemTrait>::PublicKey::from_bytes(pairing.device_key())?;
    let client_id = pairing.client_id_bytes();
    let info = [PROTOCOL_VERSION_INFO, pairing.device_id_bytes(), request_id].concat();
    let psk = PskBundle::new(pairing.client_psk(), &client_id)?;
    let (encapped_key, sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Psk(psk), &device_key, &info)?;
    Ok((encapped_key.to_bytes().to_vec(), sender_context))
}

pub(crate) fn seal_pairing(
    client_id: CanonicalUlid,
    client_token: String,
    response: PairingResponse,
    client_secret: &[u8],
    application_plaintext: &[u8],
) -> Result<(PairingCompletion, PendingPairing, u64), Error> {
    require_length(
        "client secret",
        client_secret,
        KdfSizedBytes::default().len(),
    )?;
    let device_key = <Kem as KemTrait>::PublicKey::from_bytes(&response.device_key)?;
    let device_id_bytes = response.device_id.to_bytes();
    let client_id_bytes = client_id.to_bytes();
    let info = [PROTOCOL_VERSION_INFO, device_id_bytes, client_id_bytes].concat();
    let (encapped_key, mut sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &device_key, &info)?;
    let secret_ciphertext = sender_context.seal(client_secret, b"")?;
    let ciphertext = sender_context.seal(application_plaintext, b"")?;
    let mut client_psk = KdfSizedBytes::default();
    sender_context.export(PSK_EXPORT_CONTEXT, &mut client_psk)?;
    require_length(
        "device random",
        &response.device_random,
        KdfSizedBytes::default().len(),
    )?;
    let mut sas_info = Vec::with_capacity(
        SAS_DERIVATION_INFO.len()
            + device_id_bytes.len()
            + client_id_bytes.len()
            + response.device_key.len(),
    );
    sas_info.extend_from_slice(SAS_DERIVATION_INFO);
    sas_info.extend_from_slice(&device_id_bytes);
    sas_info.extend_from_slice(&client_id_bytes);
    sas_info.extend_from_slice(&response.device_key);
    let hkdf = Hkdf::<Sha256>::new(Some(&response.device_random), client_secret);
    let mut sas = [0; 8];
    hkdf.expand(&sas_info, &mut sas)?;
    let sas = u64::from_be_bytes(sas) % SAS_DECIMAL_MODULUS;
    let completion = PairingCompletion {
        key: BASE64_STANDARD.encode(encapped_key.to_bytes()),
        secret: BASE64_STANDARD.encode(secret_ciphertext),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };
    let pairing = PendingPairing::new(
        response.device_id,
        client_id,
        client_token,
        client_psk.to_vec(),
        response.device_key,
    );

    Ok((completion, pairing, sas))
}

pub(crate) fn derive_address_id(address: &str) -> Result<AddressId, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(BASE_DERIVATION_SALT), address.as_bytes());
    let mut address_id = [0; 16];
    hkdf.expand(ADDRESS_DERIVATION_INFO, &mut address_id)?;
    Ok(AddressId::from_bytes(address_id))
}

pub(crate) fn generate_client_secret() -> Result<Vec<u8>, Error> {
    let mut client_secret = KdfSizedBytes::default();
    getrandom::fill(&mut client_secret)?;
    Ok(client_secret.to_vec())
}

pub(crate) fn derive_pairing_commitment(client_secret: &[u8]) -> Result<Vec<u8>, Error> {
    require_length(
        "client secret",
        client_secret,
        KdfSizedBytes::default().len(),
    )?;
    let hkdf = Hkdf::<Sha256>::new(Some(BASE_DERIVATION_SALT), client_secret);
    let mut commitment = KdfSizedBytes::default();
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
    key: String,
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation_key: Option<String>,
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
    device_id: CanonicalUlid,
    #[serde(deserialize_with = "deserialize_base64")]
    device_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    device_random: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct PairingCompletion {
    key: String,
    secret: String,
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

    #[error("{field} has length {actual}, expected {expected} bytes")]
    InvalidLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
}

fn require_length(field: &'static str, value: &[u8], expected: usize) -> Result<(), Error> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            field,
            actual: value.len(),
            expected,
        })
    }
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
    fn derives_address_id_from_pairing_address() {
        assert_eq!(
            derive_address_id("yup-its-free").unwrap().to_string(),
            "9e6f33bf47382846903dffa0962ea313"
        );
    }

    #[test]
    fn derives_pairing_commitment_from_client_secret() {
        let client_secret = (0x60_u8..0x80).collect::<Vec<_>>();
        assert_eq!(
            BASE64_STANDARD.encode(derive_pairing_commitment(&client_secret).unwrap()),
            "jUVTSBEimLz6OdfXAA4qxemm4hHyzzc5yOj1ZdzHsq4="
        );
    }

    #[test]
    fn rejects_wrong_length_client_secret_for_pairing_commitment() {
        assert!(derive_pairing_commitment(&[0; 31]).is_err());
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

    #[test]
    fn rejects_a_response_random_with_the_wrong_length() {
        let session = test_session();
        let response = Response {
            nonce: BASE64_STANDARD.encode([0; 12]),
            ciphertext: BASE64_STANDARD.encode([0; 16]),
        };

        assert!(matches!(
            session.open_response(response),
            Err(Error::InvalidLength {
                field: "response random",
                actual: 12,
                expected: 32,
            })
        ));
    }

    #[test]
    fn binds_request_to_protocol_version() {
        use hpke::{OpModeR, setup_receiver};

        let (device_private_key, device_public_key) = Kem::gen_keypair();
        let pairing: Pairing = serde_json::from_value(json!({
            "device_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
            "client_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
            "client_token": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x24; 32]),
            "client_psk": BASE64_STANDARD.encode([0x42; 32]),
            "device_key": BASE64_STANDARD.encode(device_public_key.to_bytes()),
            "rotated_at": 1_700_000_000,
        }))
        .unwrap();
        let request_id = Ulid::generate();
        let mut session = Session::new(&pairing, &request_id).unwrap();
        let request = session.seal_request(b"request").unwrap();

        let encapped_key = BASE64_STANDARD.decode(request.key).unwrap();
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped_key).unwrap();
        let ciphertext = BASE64_STANDARD.decode(request.ciphertext).unwrap();
        let client_id = pairing.client_id_bytes();
        let psk = PskBundle::new(pairing.client_psk(), &client_id).unwrap();
        let mut other_version = PROTOCOL_VERSION_INFO;
        other_version[12] = b'2';
        let info = [
            other_version,
            pairing.device_id_bytes(),
            request_id.to_bytes(),
        ]
        .concat();
        let mut receiver_context = setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Psk(psk),
            &device_private_key,
            &encapped_key,
            &info,
        )
        .unwrap();

        assert!(receiver_context.open(&ciphertext, b"").is_err());
    }

    fn test_session() -> Session {
        let (_, device_key) = Kem::gen_keypair();
        let pairing: Pairing = serde_json::from_value(json!({
            "device_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
            "client_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
            "client_token": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x24; 32]),
            "client_psk": BASE64_STANDARD.encode([0x42; 32]),
            "device_key": BASE64_STANDARD.encode(device_key.to_bytes()),
            "rotated_at": 1_700_000_000,
        }))
        .unwrap();

        Session::new(&pairing, &Ulid::generate()).unwrap()
    }
}
