use std::{fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    ConfigurationError, ProtocolError, RequestError,
    config::{
        abort_pending_pairing, ensure_pairing_absent, finish_pending_pairing,
        lock_pairing_for_rotation, pairing_path, read_pending_pairing, write_pending_pairing,
    },
    crypto::{
        PairingResponse, Session, derive_pairing_commitment, derive_psk_rotation, derive_route_id,
        generate_client_random, seal_pairing,
    },
    rest::Relay,
};

pub async fn start_pairing(address: &str) -> Result<(), RequestError> {
    ensure_pairing_absent()?;
    let client_random = generate_client_random().map_err(ProtocolError::from)?;
    let commitment = derive_pairing_commitment(address).map_err(ProtocolError::from)?;
    let request_id = Ulid::generate();
    let route_id = derive_route_id(address).map_err(ProtocolError::from)?;
    let relay = Relay::new(&route_id.to_string(), &request_id.to_string())?;
    let request = PairingRequest {
        version: 1,
        commitment: BASE64_STANDARD.encode(commitment),
    };
    let response: PairingResponse = relay.request(&request).await?;
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
    println!("{}", format_sas(sas));

    Ok(())
}

pub async fn finish_pairing() -> Result<(), RequestError> {
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
    let response = relay.request(&request).await?;
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

    Ok(())
}

pub fn abort_pairing() -> Result<(), ConfigurationError> {
    abort_pending_pairing()
}

pub fn rotate_psk() -> Result<(), RotationError> {
    rotate_psk_at(&pairing_path()?)
}

fn rotate_psk_at(path: &Path) -> Result<(), RotationError> {
    let pairing = lock_pairing_for_rotation(path)?;
    let rotation = derive_psk_rotation(pairing.pairing()).map_err(ProtocolError::from)?;
    pairing.write_rotation(&rotation.pairing_psk, &rotation.rotation_key)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum RotationError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

fn format_sas(sas: u64) -> String {
    format!(
        "{:04} {:04} {:04}",
        sas / 100_000_000,
        sas / 10_000 % 10_000,
        sas % 10_000,
    )
}

#[derive(Serialize)]
struct PairingRequest {
    version: u8,
    commitment: String,
}

#[derive(Serialize)]
struct FinishPairingRequest {
    method: &'static str,
}

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
    use super::{RotationError, rotate_psk_at};
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
            }),
        )
        .unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);

        rotate_psk_at(&path).unwrap();

        let contents = fs::read(&path).unwrap();
        let pairing: Value = serde_json::from_slice(&contents).unwrap();
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
        let info = [route_id, pairing_id, [0; 16]].concat();
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
            rotate_psk_at(&path),
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
