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

use crate::config::{Identifier, Pairing, PendingPairing, RelayId};

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
type ExporterSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
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
        let (encapped_key, sender_context) = setup_pairing_sender(pairing, request_id.to_bytes())?;

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

pub(crate) fn derive_psk_rotation(pairing: &Pairing) -> Result<PskRotation, Error> {
    let (encapped_key, sender_context) = setup_pairing_sender(pairing, [0; 16])?;
    let mut client_psk = ExporterSecret::default();
    sender_context.export(PSK_EXPORT_CONTEXT, &mut client_psk)?;

    Ok(PskRotation {
        client_psk: client_psk.to_vec(),
        rotation_key: BASE64_STANDARD.encode(encapped_key),
    })
}

fn setup_pairing_sender(
    pairing: &Pairing,
    request_id: [u8; 16],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let device_key = <Kem as KemTrait>::PublicKey::from_bytes(pairing.device_key())?;
    let client_id = pairing.client_id_bytes();
    let info = [
        PROTOCOL_VERSION_INFO,
        pairing.mailbox_id_bytes(),
        request_id,
    ]
    .concat();
    let psk = PskBundle::new(pairing.client_psk(), &client_id)?;
    let (encapped_key, sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Psk(psk), &device_key, &info)?;
    Ok((encapped_key.to_bytes().to_vec(), sender_context))
}

pub(crate) fn seal_pairing(
    client_id: RelayId,
    client_token: String,
    response: PairingResponse,
    client_random: &[u8],
    plaintext: &[u8],
) -> Result<(PairingCompletion, PendingPairing, u64), Error> {
    let device_key = <Kem as KemTrait>::PublicKey::from_bytes(&response.device_key)?;
    let mailbox_id_bytes = response.mailbox_id.to_bytes();
    let client_id_bytes = client_id.to_bytes();
    let info = [PROTOCOL_VERSION_INFO, mailbox_id_bytes, client_id_bytes].concat();
    let (encapped_key, mut sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &device_key, &info)?;
    let ciphertext = sender_context.seal(plaintext, b"")?;
    let mut client_psk = ExporterSecret::default();
    sender_context.export(PSK_EXPORT_CONTEXT, &mut client_psk)?;
    if response.device_random.len() != ExporterSecret::default().len() {
        return Err(Error::InvalidDeviceRandomLength {
            actual: response.device_random.len(),
            expected: ExporterSecret::default().len(),
        });
    }
    let mut sas_ikm = Vec::with_capacity(
        mailbox_id_bytes.len()
            + client_id_bytes.len()
            + client_random.len()
            + response.device_key.len(),
    );
    sas_ikm.extend_from_slice(&mailbox_id_bytes);
    sas_ikm.extend_from_slice(&client_id_bytes);
    sas_ikm.extend_from_slice(client_random);
    sas_ikm.extend_from_slice(&response.device_key);
    let hkdf = Hkdf::<Sha256>::new(Some(&response.device_random), &sas_ikm);
    let mut sas = [0; 8];
    hkdf.expand(SAS_DERIVATION_INFO, &mut sas)?;
    let sas = u64::from_be_bytes(sas) % SAS_DECIMAL_MODULUS;
    let completion = PairingCompletion {
        key: BASE64_STANDARD.encode(encapped_key.to_bytes()),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };
    let pairing = PendingPairing::new(
        response.mailbox_id,
        client_id,
        client_token,
        client_psk.to_vec(),
        response.device_key,
    );

    Ok((completion, pairing, sas))
}

pub(crate) fn derive_address_id(address: &str) -> Result<Identifier, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(BASE_DERIVATION_SALT), address.as_bytes());
    let mut address_id = [0; 16];
    hkdf.expand(ADDRESS_DERIVATION_INFO, &mut address_id)?;
    Ok(Identifier::from_bytes(address_id))
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
    mailbox_id: RelayId,
    #[serde(deserialize_with = "deserialize_base64")]
    device_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    device_random: Vec<u8>,
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

    #[error("device random has length {actual}, expected {expected} bytes")]
    InvalidDeviceRandomLength { actual: usize, expected: usize },
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

    #[test]
    fn binds_request_to_protocol_version() {
        use hpke::{OpModeR, setup_receiver};

        let (route_private_key, route_public_key) = Kem::gen_keypair();
        let pairing: Pairing = serde_json::from_value(json!({
            "mailbox_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
            "client_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
            "client_token": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x24; 32]),
            "client_psk": BASE64_STANDARD.encode([0x42; 32]),
            "device_key": BASE64_STANDARD.encode(route_public_key.to_bytes()),
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
            pairing.mailbox_id_bytes(),
            request_id.to_bytes(),
        ]
        .concat();
        let mut receiver_context = setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Psk(psk),
            &route_private_key,
            &encapped_key,
            &info,
        )
        .unwrap();

        assert!(receiver_context.open(&ciphertext, b"").is_err());
    }

    fn test_session() -> Session {
        let (_, device_key) = Kem::gen_keypair();
        let pairing: Pairing = serde_json::from_value(json!({
            "mailbox_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
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
