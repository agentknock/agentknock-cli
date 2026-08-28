use std::{fmt, future::Future, io, path::Path, pin::Pin};

#[cfg(target_os = "linux")]
use std::fs;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    Client, ConfigurationError, RequestError,
    config::{
        CanonicalUlid, LockedPairing, abort_pending_pairing, current_timestamp,
        ensure_pairing_absent, finish_pending_pairing, lock_pairing_if_rotated_before,
        read_pairing_from, read_pending_pairing, remove_active_pairing,
        remove_pairing as remove_pairing_file, write_pending_pairing,
    },
    crypto::{
        self, PROTOCOL_VERSION, PairingResponse, Session, derive_address_id,
        derive_pairing_commitment, derive_psk_rotation, generate_client_secret, seal_pairing,
    },
    protocol::{self, Method, Response},
    websocket::RelayExchange,
};

const PSK_ROTATION_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

/// A short authentication string for verifying an initial pairing.
///
/// Its [`fmt::Display`] representation contains 12 decimal digits in three
/// groups, such as `1234 5678 9012`. The user must confirm the full displayed
/// value against the value shown by the device before accepting the pairing.
pub struct PairingSas(u64);

/// A stage reported while a pairing operation is running.
///
/// A successful operation reports `Preparing`, `WaitingForDelivery`,
/// optionally one or more `WaitingForResponse` updates, `Completing`, and
/// `Completed`, in that order. An operation that fails stops without reporting
/// `Completed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PairingProgress {
    /// Agentknock is reading local state and preparing the protected request.
    Preparing,

    /// The request is waiting to be delivered to the device.
    WaitingForDelivery,

    /// The device has received the request but hasn't returned a response.
    WaitingForResponse,

    /// Agentknock is processing the response and handing off the completion.
    Completing,

    /// The operation has finished successfully.
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

impl Client {
    /// Starts pairing with the device displaying `address`.
    ///
    /// `address` must contain one or more lowercase ASCII words separated by
    /// single hyphens. The method creates a pending local pairing and returns
    /// the [`PairingSas`] after the initial exchange is complete. The pairing
    /// remains pending until [`Client::finish_pairing`] succeeds.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. If `cancellation` resolves before the method
    /// returns, Agentknock stops the exchange, removes any pending state it
    /// created, and returns [`RequestError::Interrupted`]. Pass
    /// [`std::future::pending()`] when the operation doesn't need cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid, local pairing state already
    /// exists, the state can't be read or written safely, the exchange fails,
    /// or the operation is canceled.
    pub async fn start_pairing<P>(
        &self,
        address: &str,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<PairingSas, RequestError>
    where
        P: FnMut(PairingProgress),
    {
        tokio::pin!(cancellation);
        if !is_valid_pairing_address(address) {
            return Err(RequestError::other(
                "pairing address must contain lowercase ASCII words separated by single hyphens",
            ));
        }
        progress(PairingProgress::Preparing);
        let pairing_path = self.pairing_path()?;
        ensure_pairing_absent(&pairing_path)?;
        let client_secret = generate_client_secret().map_err(RequestError::other)?;
        let commitment = derive_pairing_commitment(&client_secret).map_err(RequestError::other)?;
        let request_id = Ulid::generate();
        let client_id = CanonicalUlid::new(request_id);
        let client_token = generate_client_token()?;
        let address_id = derive_address_id(address).map_err(RequestError::other)?;
        let mut relay = RelayExchange::pairing(
            self,
            &address_id.to_string(),
            &request_id.to_string(),
            &client_token,
        )?;
        let request = PairingRequest {
            version: PROTOCOL_VERSION,
            commitment: BASE64_STANDARD.encode(commitment),
        };
        progress(PairingProgress::WaitingForDelivery);
        let response: PairingResponse = tokio::select! {
            biased;
            _ = cancellation.as_mut() => return Err(RequestError::Interrupted),
            response = relay.request(&request, || {
                progress(PairingProgress::WaitingForResponse);
            }) => response?,
        };
        progress(PairingProgress::Completing);
        let contents = PairingMetadata {
            platform: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            hostname: hostname(),
            machine_id: machine_id(),
            os_version: os_version(),
        };
        let application_plaintext = self.encode(&contents).map_err(RequestError::other)?;
        let (completion, pairing, sas) = seal_pairing(
            client_id,
            client_token,
            response,
            &client_secret,
            &application_plaintext,
        )
        .map_err(RequestError::other)?;
        write_pending_pairing(&pairing_path, &pairing)?;

        let result = tokio::select! {
            biased;
            _ = cancellation.as_mut() => Err(RequestError::Interrupted),
            result = relay.complete(&completion) => result.map_err(RequestError::from),
        };
        if let Err(error) = result {
            let _ = abort_pending_pairing(&pairing_path);
            return Err(error);
        }
        progress(PairingProgress::Completed);
        Ok(PairingSas(sas))
    }
}

fn is_valid_pairing_address(address: &str) -> bool {
    address
        .split('-')
        .all(|word| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase()))
}

impl Client {
    /// Activates the pending pairing after the user verifies and accepts it.
    ///
    /// Call this only after the user confirms the complete [`PairingSas`] on
    /// the device and accepts the pairing there. Agentknock requires an
    /// authenticated acceptance response before it marks the local pairing as
    /// active.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. Cancellation before authenticated acceptance
    /// leaves the pairing pending and returns [`RequestError::Interrupted`].
    /// Once acceptance is authenticated and local activation is durable, the
    /// pairing remains active even if the completion handoff fails.
    /// Cancellation after activation only shortens that handoff and doesn't
    /// undo or report failure. Pass [`std::future::pending()`] when the
    /// operation doesn't need cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no pending pairing, local state is invalid,
    /// the device rejects the pairing, the operation is canceled before
    /// activation, or the exchange fails. An exchange error during completion
    /// can be returned after the local pairing becomes active.
    pub async fn finish_pairing<P>(
        &self,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<(), RequestError>
    where
        P: FnMut(PairingProgress),
    {
        tokio::pin!(cancellation);
        progress(PairingProgress::Preparing);
        let pairing_path = self.pairing_path()?;
        let pairing = read_pending_pairing(&pairing_path)?;
        let request_id = Ulid::generate();
        let plaintext = self
            .encode(&MethodRequest {
                method: Method::PairingFinish,
            })
            .map_err(RequestError::other)?;
        let mut session = Session::new(&pairing, &request_id).map_err(RequestError::other)?;
        let request = session
            .seal_request(&plaintext)
            .map_err(RequestError::other)?;
        let mut relay = RelayExchange::authenticated(self, &pairing, &request_id.to_string())?;
        progress(PairingProgress::WaitingForDelivery);
        let response = tokio::select! {
            biased;
            _ = cancellation.as_mut() => return Err(RequestError::Interrupted),
            response = relay.request(&request, || {
                progress(PairingProgress::WaitingForResponse);
            }) => response?,
        };
        progress(PairingProgress::Completing);
        let plaintext = session
            .open_response(response)
            .map_err(RequestError::other)?;
        let result: FinishPairingResult =
            match protocol::decode_response(&plaintext).map_err(RequestError::other)? {
                Response::Message(result) => result,
                Response::Error(error) => {
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
            };
        if result == FinishPairingResult::Rejected {
            return Err(RequestError::PairingRejected);
        }

        let plaintext = self
            .encode(&FinishPairingResult::Accepted)
            .map_err(RequestError::other)?;
        let completion = session
            .seal_completion(&plaintext)
            .map_err(RequestError::other)?;
        finish_pending_pairing(&pairing_path)?;
        let interrupted = tokio::select! {
            biased;
            _ = cancellation.as_mut() => true,
            result = relay.complete(&completion) => {
                result?;
                false
            }
        };
        if interrupted {
            let _ = relay.complete_briefly(&completion).await;
        }
        progress(PairingProgress::Completed);

        Ok(())
    }

    /// Deletes a pending local pairing without contacting the device.
    ///
    /// Use this after the user rejects or abandons an initial pairing. This
    /// method refuses to delete an active pairing.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::NoPairing`] if no pairing exists,
    /// [`ConfigurationError::PairingNotPending`] if the pairing is active, or
    /// another configuration error if the pending state can't be removed.
    pub fn abort_pairing(&self) -> Result<(), ConfigurationError> {
        abort_pending_pairing(&self.pairing_path()?)
    }

    /// Deletes the local pairing without contacting the device.
    ///
    /// This is a recovery operation for state that can't be removed through
    /// [`Client::remove_pairing`]. It can delete either a pending or an active
    /// pairing, and it leaves any corresponding device state unchanged.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if no local pairing exists or the pairing
    /// file can't be removed.
    pub fn force_remove_pairing(&self) -> Result<(), ConfigurationError> {
        remove_pairing_file(&self.pairing_path()?)
    }

    /// Removes an active pairing from both the device and this client.
    ///
    /// Agentknock waits for an authenticated device response before deleting
    /// local state. It then hands off a best-effort completion to tell the
    /// device that local removal succeeded.
    ///
    /// The `progress` callback receives lifecycle updates synchronously and
    /// should return promptly. Cancellation before the authenticated response
    /// leaves local state unchanged. Cancellation after local removal only
    /// shortens the best-effort completion attempt. Pass
    /// [`std::future::pending()`] when the operation doesn't need cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`PairingRemoveError`] if the pairing isn't active, the exchange
    /// fails before authenticated removal, or local deletion fails.
    pub async fn remove_pairing<P>(
        &self,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<(), PairingRemoveError>
    where
        P: FnMut(PairingProgress),
    {
        tokio::pin!(cancellation);
        progress(PairingProgress::Preparing);
        let pairing_path = self
            .pairing_path()
            .map_err(PairingRemoveError::Configuration)?;
        let pairing =
            read_pairing_from(&pairing_path).map_err(PairingRemoveError::Configuration)?;
        let device_id = pairing.device_id_bytes();
        let client_id = pairing.client_id_bytes();
        let (mut relay, completion) =
            prepare_pairing_removal(self, &pairing, cancellation.as_mut(), &mut progress)
                .await
                .map_err(PairingRemoveError::Request)?;
        remove_active_pairing(&pairing_path, device_id, client_id)
            .map_err(PairingRemoveError::LocalState)?;
        tokio::select! {
            biased;
            _ = cancellation.as_mut() => {},
            _ = relay.complete_briefly(&completion) => {},
        }
        progress(PairingProgress::Completed);
        Ok(())
    }
}

async fn prepare_pairing_removal<P>(
    client: &Client,
    pairing: &crate::config::Pairing,
    mut cancellation: Pin<&mut impl Future<Output = ()>>,
    progress: &mut P,
) -> Result<(RelayExchange, crypto::Completion), RequestError>
where
    P: FnMut(PairingProgress),
{
    let request_id = Ulid::generate();
    let plaintext = client
        .encode(&MethodRequest {
            method: Method::PairingRemove,
        })
        .map_err(RequestError::other)?;
    let mut session = Session::new(pairing, &request_id).map_err(RequestError::other)?;
    let request = session
        .seal_request(&plaintext)
        .map_err(RequestError::other)?;
    let mut relay = RelayExchange::authenticated(client, pairing, &request_id.to_string())?;
    progress(PairingProgress::WaitingForDelivery);
    let response = tokio::select! {
        biased;
        _ = cancellation.as_mut() => return Err(RequestError::Interrupted),
        response = relay.request(&request, || {
            progress(PairingProgress::WaitingForResponse);
        }) => response?,
    };
    progress(PairingProgress::Completing);
    let plaintext = session
        .open_response(response)
        .map_err(RequestError::other)?;
    match protocol::decode_response::<EmptyMessage>(&plaintext).map_err(RequestError::other)? {
        Response::Message(_) => {}
        Response::Error(error) => {
            if let Some(completion) = protocol::seal_error_completion(client, &mut session, &error)
            {
                let _ = relay.complete_briefly(&completion).await;
            }
            return Err(RequestError::DeviceRejected {
                code: error.code,
                message: error.message,
            });
        }
    }
    let plaintext = client
        .encode(&EmptyMessage {})
        .map_err(RequestError::other)?;
    let completion = session
        .seal_completion(&plaintext)
        .map_err(RequestError::other)?;

    Ok((relay, completion))
}

impl Client {
    pub(crate) fn maybe_rotate_psk(&self) -> Result<bool, RotationError> {
        maybe_rotate_psk_at(&self.pairing_path()?, current_timestamp()?)
    }
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
    let rotation = derive_psk_rotation(pairing.pairing()).map_err(io::Error::other)?;
    pairing.write_rotation(&rotation.client_psk, &rotation.rotation_key, rotated_at)?;
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum RotationError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    #[error(transparent)]
    Other(#[from] io::Error),
}

/// An error removing an active pairing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PairingRemoveError {
    /// Local state prevented the removal request from starting.
    #[error(transparent)]
    Configuration(ConfigurationError),

    /// The authenticated removal exchange didn't complete successfully.
    #[error(transparent)]
    Request(RequestError),

    /// The device accepted removal, but deleting local state failed.
    #[error("device removed the pairing, but local pairing removal failed: {0}")]
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
struct PairingMetadata {
    platform: &'static str,
    architecture: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_version: Option<String>,
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let contents = contents.trim();
    (!contents.is_empty()).then(|| contents.to_owned())
}

#[cfg(target_os = "linux")]
fn hostname() -> Option<String> {
    read_trimmed("/etc/hostname")
}

#[cfg(target_os = "linux")]
fn machine_id() -> Option<String> {
    read_trimmed("/etc/machine-id")
}

#[cfg(target_os = "linux")]
fn os_version() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"'))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn hostname() -> Option<String> {
    sysctl_string(c"kern.hostname")
}

#[cfg(target_os = "macos")]
fn machine_id() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn os_version() -> Option<String> {
    sysctl_string(c"kern.osproductversion").map(|version| format!("macOS {version}"))
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &std::ffi::CStr) -> Option<String> {
    let mut length = 0;
    // SAFETY: A null output buffer asks sysctlbyname for the required length.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } == -1
        || length == 0
    {
        return None;
    }
    let mut value = vec![0_u8; length];
    // SAFETY: value is writable for the length supplied to sysctlbyname.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } == -1
    {
        return None;
    }
    value.truncate(length);
    if value.last() == Some(&0) {
        value.pop();
    }
    String::from_utf8(value)
        .ok()
        .filter(|value| !value.is_empty())
}

fn generate_client_token() -> io::Result<String> {
    let mut token = [0; 32];
    getrandom::fill(&mut token).map_err(io::Error::other)?;
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

    use super::is_valid_pairing_address;
    #[cfg(unix)]
    use super::{PSK_ROTATION_INTERVAL_SECONDS, maybe_rotate_psk_at};

    #[test]
    fn formats_sas_as_three_groups() {
        assert_eq!(format_sas(123_456_789), "0001 2345 6789");
    }

    #[test]
    fn validates_pairing_addresses() {
        for address in ["free", "yup-its-free"] {
            assert!(is_valid_pairing_address(address));
        }
        for address in ["", "-", "--", "-free", "free-", "yup--its-free"] {
            assert!(!is_valid_pairing_address(address));
        }
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

        assert!(!maybe_rotate_psk_at(&path, NOW + 2).unwrap());
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
