use std::{fmt, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    ConfigurationError, ProtocolError, RequestError,
    config::{
        LockedPairing, abort_pending_pairing, current_timestamp, ensure_pairing_absent,
        finish_pending_pairing, lock_pairing_for_rotation, lock_pairing_if_rotated_before,
        pairing_path, read_pairing, read_pairing_from, read_pending_pairing, remove_active_pairing,
        remove_pairing, write_pending_pairing,
    },
    crypto::{
        self, PROTOCOL_VERSION, PairingResponse, Session, derive_pairing_commitment,
        derive_psk_rotation, derive_route_id, generate_client_random, seal_pairing,
    },
    rest::{Relay, RequestState},
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
    let route_id = derive_route_id(address).map_err(ProtocolError::from)?;
    let relay = Relay::new(&route_id.to_string(), &request_id.to_string())?;
    let request = PairingRequest {
        version: PROTOCOL_VERSION,
        commitment: BASE64_STANDARD.encode(commitment),
    };
    progress(PairingProgress::WaitingForDelivery);
    let response: PairingResponse = relay
        .request_with_state(&request, |state| {
            progress(match state {
                RequestState::Pending => PairingProgress::WaitingForDelivery,
                RequestState::Delivered => PairingProgress::WaitingForResponse,
            });
        })
        .await?;
    progress(PairingProgress::Completing);
    let contents = PairingContents {
        client_random: BASE64_STANDARD.encode(&client_random),
        hostname: read_trimmed("/etc/hostname"),
        machine_id: read_trimmed("/etc/machine-id"),
        os_version: os_version(),
    };
    let plaintext = serde_json::to_vec(&contents).map_err(ProtocolError::from)?;
    let (completion, pairing, sas) =
        seal_pairing(route_id, &request_id, response, &client_random, &plaintext)
            .map_err(ProtocolError::from)?;
    write_pending_pairing(&pairing)?;

    relay.complete(&request, &completion).await?;
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
    let plaintext = serde_json::to_vec(&FinishPairingRequest {
        method: "FinishPairing",
    })
    .map_err(ProtocolError::from)?;
    let mut session = Session::new(&pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let relay = Relay::new(&pairing.route_id(), &request_id.to_string())?;
    progress(PairingProgress::WaitingForDelivery);
    let response = relay
        .request_with_state(&request, |state| {
            progress(match state {
                RequestState::Pending => PairingProgress::WaitingForDelivery,
                RequestState::Delivered => PairingProgress::WaitingForResponse,
            });
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
        serde_json::to_vec(&FinishPairingResult::Accepted).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;
    finish_pending_pairing()?;
    relay.complete(&request, &completion).await?;
    progress(PairingProgress::Completed);

    Ok(())
}

pub fn abort_pairing() -> Result<(), ConfigurationError> {
    abort_pending_pairing()
}

pub fn force_unpair() -> Result<(), ConfigurationError> {
    remove_pairing()
}

pub async fn unpair() -> Result<(), UnpairError> {
    unpair_with_progress(|_| {}).await
}

pub async fn unpair_with_progress<P>(mut progress: P) -> Result<(), UnpairError>
where
    P: FnMut(PairingProgress),
{
    progress(PairingProgress::Preparing);
    let pairing = read_pairing().map_err(UnpairError::Configuration)?;
    let route_id = pairing.route_id_bytes();
    let pairing_id = pairing.pairing_id_bytes();
    let (relay, request, completion) = prepare_unpair(&pairing, &mut progress)
        .await
        .map_err(UnpairError::Request)?;
    remove_active_pairing(route_id, pairing_id).map_err(UnpairError::LocalState)?;
    let _ = relay.complete_briefly(&request, &completion).await;
    progress(PairingProgress::Completed);
    Ok(())
}

async fn prepare_unpair<P>(
    pairing: &crate::config::Pairing,
    progress: &mut P,
) -> Result<(Relay, crypto::Request, crypto::Completion), RequestError>
where
    P: FnMut(PairingProgress),
{
    let request_id = Ulid::generate();
    let plaintext =
        serde_json::to_vec(&UnpairRequest { method: "Unpair" }).map_err(ProtocolError::from)?;
    let mut session = Session::new(pairing, &request_id).map_err(ProtocolError::from)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(ProtocolError::from)?;
    let relay = Relay::new(&pairing.route_id(), &request_id.to_string())?;
    progress(PairingProgress::WaitingForDelivery);
    let response = relay
        .request_with_state(&request, |state| {
            progress(match state {
                RequestState::Pending => PairingProgress::WaitingForDelivery,
                RequestState::Delivered => PairingProgress::WaitingForResponse,
            });
        })
        .await?;
    progress(PairingProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(ProtocolError::from)?;
    serde_json::from_slice::<EmptyMessage>(&plaintext).map_err(ProtocolError::from)?;
    let plaintext = serde_json::to_vec(&EmptyMessage {}).map_err(ProtocolError::from)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(ProtocolError::from)?;

    Ok((relay, request, completion))
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
    pairing.write_rotation(&rotation.pairing_psk, &rotation.rotation_key, rotated_at)?;
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
pub enum UnpairError {
    #[error(transparent)]
    Configuration(ConfigurationError),

    #[error(transparent)]
    Request(RequestError),

    #[error("phone accepted unpairing, but local pairing removal failed: {0}")]
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
struct FinishPairingRequest {
    method: &'static str,
}

#[derive(Serialize)]
struct UnpairRequest {
    method: &'static str,
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
struct PairingContents {
    client_random: String,
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
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
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
    fn rotates_pairing_psk_locally() {
        type Aead = ChaCha20Poly1305;
        type Kdf = HkdfSha256;
        type Kem = X25519HkdfSha256;
        type ExporterSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;

        const ROUTE_ID: &str = "00112233445566778899aabbccddeeff";
        const PAIRING_ID: &str = "ffeeddccbbaa99887766554433221100";
        const OLD_PSK: [u8; 32] = [0x42; 32];
        const PSK_EXPORT_CONTEXT: &[u8] = b"agentknock-v1 psk";
        const NOW: u64 = 2_000_000_000;

        let directory = TestDirectory::new();
        let path = directory.path.join("pairing.json");
        let (route_private_key, route_public_key) = Kem::gen_keypair();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        serde_json::to_writer_pretty(
            &mut file,
            &json!({
                "route_id": ROUTE_ID,
                "pairing_id": PAIRING_ID,
                "pairing_psk": BASE64_STANDARD.encode(OLD_PSK),
                "route_key": BASE64_STANDARD.encode(route_public_key.to_bytes()),
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
            .decode(pairing["pairing_psk"].as_str().unwrap())
            .unwrap();
        assert_ne!(new_psk, OLD_PSK);

        let route_id = u128::from_str_radix(ROUTE_ID, 16).unwrap().to_be_bytes();
        let pairing_id = u128::from_str_radix(PAIRING_ID, 16).unwrap().to_be_bytes();
        let info = [
            crate::crypto::PROTOCOL_VERSION_INFO,
            route_id,
            pairing_id,
            [0; 16],
        ]
        .concat();
        let psk = PskBundle::new(&OLD_PSK, &pairing_id).unwrap();
        let receiver_context = setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Psk(psk),
            &route_private_key,
            &encapped_key,
            &info,
        )
        .unwrap();
        let mut expected_psk = ExporterSecret::default();
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
