use std::{fmt, fs, path::Path};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    ConfigurationError, ProtocolError, RequestError,
    config::{
        CanonicalUlid, LockedPairing, abort_pending_pairing, current_timestamp,
        ensure_pairing_absent, finish_pending_pairing, lock_pairing_for_rotation,
        lock_pairing_if_rotated_before, pairing_path, read_pairing, read_pairing_from,
        read_pending_pairing, remove_active_pairing, remove_pairing as remove_pairing_file,
        write_pending_pairing,
    },
    crypto::{
        self, PROTOCOL_VERSION, PairingResponse, Session, derive_address_id,
        derive_pairing_commitment, derive_psk_rotation, generate_client_random, seal_pairing,
    },
    protocol::Method,
    websocket::RelayExchange,
};

const PSK_ROTATION_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

pub struct PairingSas(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingProgress {
    Preparing,
    WaitingForDelivery,
    WaitingForResponse,
    Completing,
    Completed,
}

impl fmt::Display for PairingSas {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sas = self.0;
        write!(
            formatter,
            "{:04} {:04} {:04}",
            sas / 100_000_000,
            sas / 10_000 % 10_000,
            sas % 10_000,
        )
    }
}

pub async fn start_pairing(address: &str) -> Result<PairingSas, RequestError> {
    start_pairing_with_progress(address, |_| {}).await
}

pub async fn start_pairing_with_progress<P>(
    address: &str,
    mut progress: P,
) -> Result<PairingSas, RequestError>
where
    P: FnMut(PairingProgress),
{
    progress(PairingProgress::Preparing);
    ensure_pairing_absent()?;
    let client_random = generate_client_random().map_err(ProtocolError::from)?;
    let commitment = derive_pairing_commitment(address).map_err(ProtocolError::from)?;
    let request_id = Ulid::generate();
    let client_id = CanonicalUlid::new(request_id);
    let client_token = generate_client_token()?;
    let address_id = derive_address_id(address).map_err(ProtocolError::from)?;
    let mut relay = RelayExchange::pairing(
        &address_id.to_string(),
        &request_id.to_string(),
        &client_token,
    )?;
    let request = PairingRequest {
        version: PROTOCOL_VERSION,
        commitment: BASE64_STANDARD.encode(commitment),
    };
    progress(PairingProgress::WaitingForDelivery);
    let response: PairingResponse = relay
        .request(&request, || {
            progress(PairingProgress::WaitingForResponse);
        })
        .await?;
    progress(PairingProgress::Completing);
    let contents = PairingCompletionPayload {
        client_random: BASE64_STANDARD.encode(&client_random),
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        hostname: read_trimmed("/etc/hostname"),
        machine_id: read_trimmed("/etc/machine-id"),
        os_version: os_version(),
    };
    let plaintext = crate::protocol::encode(&contents).map_err(ProtocolError::from)?;
    let (completion, pairing, sas) = seal_pairing(
        client_id,
        client_token,
        response,
        &client_random,
        &plaintext,
    )
    .map_err(ProtocolError::from)?;
    write_pending_pairing(&pairing)?;

    if let Err(error) = relay.complete(&completion).await {
        let _ = abort_pending_pairing();
        return Err(error.into());
    }
    progress(PairingProgress::Completed);
    Ok(PairingSas(sas))
}

pub async fn finish_pairing() -> Result<(), RequestError> {
    finish_pairing_with_progress(|_| {}).await
}

pub async fn finish_pairing_with_progress<P>(mut progress: P) -> Result<(), RequestError>
where
    P: FnMut(PairingProgress),
{
    progress(PairingProgress::Preparing);
    let pairing = read_pending_pairing()?;
    let request_id = Ulid::generate();
    let plaintext = crate::protocol::encode(&MethodRequest {
        method: Method::PairingFinish,
    })
    .map_err(ProtocolError::from)?;
    let mut session = Session::new(&pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let mut relay = RelayExchange::authenticated(&pairing, &request_id.to_string())?;
    progress(PairingProgress::WaitingForDelivery);
    let response = relay
        .request(&request, || {
            progress(PairingProgress::WaitingForResponse);
        })
        .await?;
    progress(PairingProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(ProtocolError::from)?;
    let result: FinishPairingResult =
        serde_json::from_slice(&plaintext).map_err(ProtocolError::from)?;
    if result == FinishPairingResult::Rejected {
        return Err(RequestError::PairingRejected);
    }

    let plaintext =
        crate::protocol::encode(&FinishPairingResult::Accepted).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;
    finish_pending_pairing()?;
    relay.complete(&completion).await?;
    progress(PairingProgress::Completed);

    Ok(())
}

pub fn abort_pairing() -> Result<(), ConfigurationError> {
    abort_pending_pairing()
}

pub fn force_remove_pairing() -> Result<(), ConfigurationError> {
    remove_pairing_file()
}

pub async fn remove_pairing() -> Result<(), PairingRemoveError> {
    remove_pairing_with_progress(|_| {}).await
}

pub async fn remove_pairing_with_progress<P>(mut progress: P) -> Result<(), PairingRemoveError>
where
    P: FnMut(PairingProgress),
{
    progress(PairingProgress::Preparing);
    let pairing = read_pairing().map_err(PairingRemoveError::Configuration)?;
    let device_id = pairing.device_id_bytes();
    let client_id = pairing.client_id_bytes();
    let (mut relay, completion) = prepare_pairing_removal(&pairing, &mut progress)
        .await
        .map_err(PairingRemoveError::Request)?;
    remove_active_pairing(device_id, client_id).map_err(PairingRemoveError::LocalState)?;
    let _ = relay.complete_briefly(&completion).await;
    progress(PairingProgress::Completed);
    Ok(())
}

async fn prepare_pairing_removal<P>(
    pairing: &crate::config::Pairing,
    progress: &mut P,
) -> Result<(RelayExchange, crypto::Completion), RequestError>
where
    P: FnMut(PairingProgress),
{
    let request_id = Ulid::generate();
    let plaintext = crate::protocol::encode(&MethodRequest {
        method: Method::PairingRemove,
    })
    .map_err(ProtocolError::from)?;
    let mut session = Session::new(pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let mut relay = RelayExchange::authenticated(pairing, &request_id.to_string())?;
    progress(PairingProgress::WaitingForDelivery);
    let response = relay
        .request(&request, || {
            progress(PairingProgress::WaitingForResponse);
        })
        .await?;
    progress(PairingProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(ProtocolError::from)?;
    serde_json::from_slice::<EmptyMessage>(&plaintext).map_err(ProtocolError::from)?;
    let plaintext = crate::protocol::encode(&EmptyMessage {}).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;

    Ok((relay, completion))
}

pub fn rotate_psk() -> Result<(), RotationError> {
    rotate_psk_at(&pairing_path()?, current_timestamp()?)
}

fn rotate_psk_at(path: &Path, rotated_at: u64) -> Result<(), RotationError> {
    let pairing = lock_pairing_for_rotation(path)?;
    rotate_locked(pairing, rotated_at)
}

pub fn maybe_rotate_psk() -> Result<bool, RotationError> {
    maybe_rotate_psk_at(&pairing_path()?, current_timestamp()?)
}

fn maybe_rotate_psk_at(path: &Path, now: u64) -> Result<bool, RotationError> {
    let rotated_before = now.saturating_sub(PSK_ROTATION_INTERVAL_SECONDS);
    let pairing = read_pairing_from(path)?;
    if pairing.rotation_key().is_some() || !pairing.rotated_before(rotated_before) {
        return Ok(false);
    }

    let Some(pairing) = lock_pairing_if_rotated_before(path, rotated_before)? else {
        return Ok(false);
    };
    rotate_locked(pairing, now)?;
    Ok(true)
}

fn rotate_locked(pairing: LockedPairing, rotated_at: u64) -> Result<(), RotationError> {
    let rotation = derive_psk_rotation(pairing.pairing()).map_err(ProtocolError::from)?;
    pairing.write_rotation(&rotation.client_psk, &rotation.rotation_key, rotated_at)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum RotationError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[derive(Debug, Error)]
pub enum PairingRemoveError {
    #[error(transparent)]
    Configuration(ConfigurationError),

    #[error(transparent)]
    Request(RequestError),

    #[error("device accepted pairing removal, but local pairing removal failed: {0}")]
    LocalState(ConfigurationError),
}

#[cfg(test)]
fn format_sas(sas: u64) -> String {
    PairingSas(sas).to_string()
}

#[derive(Serialize)]
struct PairingRequest {
    version: &'static str,
    commitment: String,
}

#[derive(Serialize)]
struct MethodRequest {
    method: Method,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyMessage {}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum FinishPairingResult {
    Accepted,
    Rejected,
}

#[derive(Serialize)]
struct PairingCompletionPayload {
    client_random: String,
    platform: &'static str,
    architecture: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_version: Option<String>,
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let contents = contents.trim();
    (!contents.is_empty()).then(|| contents.to_owned())
}

fn os_version() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"'))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn generate_client_token() -> Result<String, ProtocolError> {
    let mut token = [0; 32];
    getrandom::fill(&mut token).map_err(ProtocolError::Random)?;
    Ok(BASE64_URL_SAFE.encode(token))
}

#[cfg(test)]
mod tests {
    use super::format_sas;

    #[cfg(unix)]
    use std::{
        env, fs,
        fs::OpenOptions,
        io::Write as _,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::PathBuf,
    };

    #[cfg(unix)]
    use base64::{
        Engine as _,
        engine::general_purpose::{
            STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE,
        },
    };
    #[cfg(unix)]
    use hpke::{
        Deserializable, Kem as KemTrait, OpModeR, PskBundle, Serializable,
        aead::ChaCha20Poly1305,
        hybrid_array::Array,
        kdf::{HkdfSha256, Kdf as HpkeKdfTrait},
        kem::X25519HkdfSha256,
        setup_receiver,
    };
    #[cfg(unix)]
    use serde_json::{Value, json};
    #[cfg(unix)]
    use ulid::Ulid;

    #[cfg(unix)]
    use super::{PSK_ROTATION_INTERVAL_SECONDS, RotationError, maybe_rotate_psk_at, rotate_psk_at};
    #[cfg(unix)]
    use crate::ConfigurationError;

    #[test]
    fn formats_sas_as_three_groups() {
        assert_eq!(format_sas(123_456_789), "0001 2345 6789");
    }

    #[cfg(unix)]
    #[test]
    fn rotates_client_psk_locally() {
        type Aead = ChaCha20Poly1305;
        type Kdf = HkdfSha256;
        type Kem = X25519HkdfSha256;
        type KdfSizedBytes = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;

        const DEVICE_ID: &str = "01K2ENXDTW1P3XAR4J7V7C9D0H";
        const CLIENT_ID: &str = "01K2EP16NWNAGJYF8J1Q2V6P3X";
        const OLD_PSK: [u8; 32] = [0x42; 32];
        const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
        const NOW: u64 = 2_000_000_000;

        let directory = TestDirectory::new();
        let path = directory.path.join("pairing.json");
        let (device_private_key, device_public_key) = Kem::gen_keypair();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        serde_json::to_writer_pretty(
            &mut file,
            &json!({
                "device_id": DEVICE_ID,
                "client_id": CLIENT_ID,
                "client_token": BASE64_URL_SAFE.encode([0x24; 32]),
                "client_psk": BASE64_STANDARD.encode(OLD_PSK),
                "device_key": BASE64_STANDARD.encode(device_public_key.to_bytes()),
                "rotated_at": NOW - PSK_ROTATION_INTERVAL_SECONDS,
            }),
        )
        .unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);

        assert!(!maybe_rotate_psk_at(&path, NOW).unwrap());
        assert!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap())
                .unwrap()
                .get("rotation_key")
                .is_none()
        );

        let first_path = path.clone();
        let second_path = path.clone();
        let first = std::thread::spawn(move || maybe_rotate_psk_at(&first_path, NOW + 1));
        let second = std::thread::spawn(move || maybe_rotate_psk_at(&second_path, NOW + 1));
        let mut results = [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ];
        results.sort_unstable();
        assert_eq!(results, [false, true]);

        let contents = fs::read(&path).unwrap();
        let pairing: Value = serde_json::from_slice(&contents).unwrap();
        assert_eq!(pairing["rotated_at"], NOW + 1);
        let rotation_key = BASE64_STANDARD
            .decode(pairing["rotation_key"].as_str().unwrap())
            .unwrap();
        let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(&rotation_key).unwrap();
        let new_psk = BASE64_STANDARD
            .decode(pairing["client_psk"].as_str().unwrap())
            .unwrap();
        assert_ne!(new_psk, OLD_PSK);

        let device_id = DEVICE_ID.parse::<Ulid>().unwrap().to_bytes();
        let client_id = CLIENT_ID.parse::<Ulid>().unwrap().to_bytes();
        let info = [crate::crypto::PROTOCOL_VERSION_INFO, device_id, [0; 16]].concat();
        let psk = PskBundle::new(&OLD_PSK, &client_id).unwrap();
        let receiver_context = setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Psk(psk),
            &device_private_key,
            &encapped_key,
            &info,
        )
        .unwrap();
        let mut expected_psk = KdfSizedBytes::default();
        receiver_context
            .export(PSK_EXPORT_CONTEXT, &mut expected_psk)
            .unwrap();
        assert_eq!(new_psk, expected_psk.as_slice());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        assert!(matches!(
            rotate_psk_at(&path, NOW + 2),
            Err(RotationError::Configuration(
                ConfigurationError::RotationPending { .. }
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), contents);
    }

    #[cfg(unix)]
    struct TestDirectory {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TestDirectory {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("agentknock-test-{}", Ulid::generate()));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
