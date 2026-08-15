use std::{
    env, fmt,
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use atomic_write_file::AtomicWriteFile;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Deserialize)]
pub(crate) struct Pairing {
    #[serde(default)]
    pending: bool,
    device_id: RelayId,
    client_id: RelayId,
    #[serde(deserialize_with = "deserialize_client_token")]
    client_token: String,
    #[serde(deserialize_with = "deserialize_base64")]
    client_psk: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    device_key: Vec<u8>,
    rotated_at: u64,
    #[serde(default)]
    rotation_key: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct Identifier(u128);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RelayId(Ulid);

pub(crate) struct PendingPairing {
    device_id: RelayId,
    client_id: RelayId,
    client_token: String,
    client_psk: Vec<u8>,
    device_key: Vec<u8>,
}

pub(crate) struct LockedPairing {
    path: PathBuf,
    directory_path: PathBuf,
    directory: File,
    contents: Value,
    pairing: Pairing,
}

impl Pairing {
    pub(crate) fn device_id(&self) -> String {
        self.device_id.to_string()
    }

    pub(crate) fn device_id_bytes(&self) -> [u8; 16] {
        self.device_id.to_bytes()
    }

    pub(crate) fn client_id(&self) -> String {
        self.client_id.to_string()
    }

    pub(crate) fn client_id_bytes(&self) -> [u8; 16] {
        self.client_id.to_bytes()
    }

    pub(crate) fn client_token(&self) -> &str {
        &self.client_token
    }

    pub(crate) fn client_psk(&self) -> &[u8] {
        &self.client_psk
    }

    pub(crate) fn device_key(&self) -> &[u8] {
        &self.device_key
    }

    pub(crate) fn rotation_key(&self) -> Option<&str> {
        self.rotation_key.as_deref()
    }

    pub(crate) fn rotated_before(&self, timestamp: u64) -> bool {
        self.rotated_at < timestamp
    }
}

impl Identifier {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }
}

impl RelayId {
    pub(crate) fn new(id: Ulid) -> Self {
        Self(id)
    }

    pub(crate) fn to_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }
}

impl PendingPairing {
    pub(crate) fn new(
        device_id: RelayId,
        client_id: RelayId,
        client_token: String,
        client_psk: Vec<u8>,
        device_key: Vec<u8>,
    ) -> Self {
        Self {
            device_id,
            client_id,
            client_token,
            client_psk,
            device_key,
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:032x}", self.0)
    }
}

impl fmt::Display for RelayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
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

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RelayId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let id = encoded.parse::<Ulid>().map_err(serde::de::Error::custom)?;
        if id.to_string() != encoded {
            return Err(serde::de::Error::custom(
                "expected a canonical uppercase ULID",
            ));
        }
        Ok(Self(id))
    }
}

impl Serialize for RelayId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
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

    #[error("{path} contains an empty client PSK")]
    EmptyPsk { path: PathBuf },

    #[error("pairing in {path} is still pending")]
    PairingPending { path: PathBuf },

    #[error("pairing configuration {path} already exists")]
    PairingExists { path: PathBuf },

    #[error("no pairing configuration exists at {path}")]
    NoPairing { path: PathBuf },

    #[error("pairing in {path} is already active")]
    PairingNotPending { path: PathBuf },

    #[error("pairing in {path} already has a pending PSK rotation")]
    RotationPending { path: PathBuf },

    #[error("pairing configuration {path} changed during the operation")]
    PairingChanged { path: PathBuf },

    #[error("system clock is before the Unix epoch: {0}")]
    InvalidSystemTime(#[from] SystemTimeError),
}

pub(crate) fn read_pairing() -> Result<Pairing, ConfigurationError> {
    read_pairing_from(&pairing_path()?)
}

pub(crate) fn read_pending_pairing() -> Result<Pairing, ConfigurationError> {
    let (path, contents) = read_pending_pairing_file()?;
    let pairing: Pairing =
        serde_json::from_value(contents).map_err(|source| ConfigurationError::Invalid {
            path: path.clone(),
            source,
        })?;
    if pairing.client_psk.is_empty() {
        return Err(ConfigurationError::EmptyPsk { path });
    }

    Ok(pairing)
}

pub(crate) fn ensure_pairing_absent() -> Result<(), ConfigurationError> {
    ensure_pairing_path_absent(&pairing_path()?)
}

fn ensure_pairing_path_absent(path: &Path) -> Result<(), ConfigurationError> {
    match path.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => {
            let pairing = read_pairing_value(path)?;
            if pairing.get("pending") == Some(&Value::Bool(true)) {
                Err(ConfigurationError::PairingPending {
                    path: path.to_owned(),
                })
            } else {
                parse_pairing(path, pairing)?;
                Err(ConfigurationError::PairingExists {
                    path: path.to_owned(),
                })
            }
        }
        Err(source) => Err(ConfigurationError::Access {
            path: path.to_owned(),
            source,
        }),
    }
}

pub(crate) fn write_pending_pairing(pairing: &PendingPairing) -> Result<(), ConfigurationError> {
    let path = pairing_path()?;
    let directory_path = path.parent().expect("pairing path has a parent").to_owned();
    fs::create_dir_all(&directory_path).map_err(|source| ConfigurationError::Access {
        path: directory_path.clone(),
        source,
    })?;
    let directory = lock_directory(&directory_path)?;
    ensure_pairing_path_absent(&path)?;
    let rotated_at = current_timestamp()?;
    let contents = serde_json::to_vec_pretty(&PendingPairingFile {
        pending: true,
        device_id: pairing.device_id,
        client_id: pairing.client_id,
        client_token: &pairing.client_token,
        client_psk: &pairing.client_psk,
        device_key: &pairing.device_key,
        rotated_at,
    })
    .map_err(|source| ConfigurationError::Invalid {
        path: path.clone(),
        source,
    })?;
    let mut options = AtomicWriteFile::options();
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&path)
        .map_err(|source| ConfigurationError::Access {
            path: path.clone(),
            source,
        })?;
    file.write_all(&contents)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| ConfigurationError::Access {
            path: path.clone(),
            source,
        })?;
    file.commit()
        .map_err(|source| ConfigurationError::Access { path, source })?;
    sync_directory(&directory, &directory_path)
}

pub(crate) fn clear_rotation_key(rotation_key: &str) -> Result<(), ConfigurationError> {
    let pairing_path = pairing_path()?;
    let directory_path = pairing_path.parent().expect("pairing path has a parent");
    let directory = lock_directory(directory_path)?;
    let (path, mut pairing) = read_pairing_file()?;
    if pairing.get("rotation_key").and_then(Value::as_str) != Some(rotation_key) {
        return Ok(());
    }
    pairing
        .as_object_mut()
        .expect("pairing is a JSON object")
        .remove("rotation_key");
    write_pairing_file(&path, &pairing)?;
    sync_directory(&directory, directory_path)
}

pub(crate) fn lock_pairing_for_rotation(path: &Path) -> Result<LockedPairing, ConfigurationError> {
    let pairing = lock_pairing(path)?;
    if pairing.pairing.rotation_key.is_some() {
        return Err(ConfigurationError::RotationPending {
            path: path.to_owned(),
        });
    }

    Ok(pairing)
}

pub(crate) fn lock_pairing_if_rotated_before(
    path: &Path,
    timestamp: u64,
) -> Result<Option<LockedPairing>, ConfigurationError> {
    let pairing = lock_pairing(path)?;
    if pairing.pairing.rotation_key.is_some() {
        return Ok(None);
    }
    if !pairing.pairing.rotated_before(timestamp) {
        return Ok(None);
    }

    Ok(Some(pairing))
}

fn lock_pairing(path: &Path) -> Result<LockedPairing, ConfigurationError> {
    let directory_path = path.parent().expect("pairing path has a parent");
    let directory = lock_directory(directory_path)?;
    let contents = read_pairing_value(path)?;
    let pairing = parse_pairing(path, contents.clone())?;

    Ok(LockedPairing {
        path: path.to_owned(),
        directory_path: directory_path.to_owned(),
        directory,
        contents,
        pairing,
    })
}

impl LockedPairing {
    pub(crate) fn pairing(&self) -> &Pairing {
        &self.pairing
    }

    pub(crate) fn write_rotation(
        mut self,
        client_psk: &[u8],
        rotation_key: &str,
        rotated_at: u64,
    ) -> Result<(), ConfigurationError> {
        let pairing = self
            .contents
            .as_object_mut()
            .expect("pairing configuration is a JSON object");
        pairing.insert(
            "client_psk".into(),
            BASE64_STANDARD.encode(client_psk).into(),
        );
        pairing.insert("rotation_key".into(), rotation_key.into());
        pairing.insert("rotated_at".into(), rotated_at.into());
        write_pairing_file(&self.path, &self.contents)?;
        sync_directory(&self.directory, &self.directory_path)
    }
}

pub(crate) fn finish_pending_pairing() -> Result<(), ConfigurationError> {
    let pairing_path = pairing_path()?;
    let directory_path = pairing_path.parent().expect("pairing path has a parent");
    let directory = lock_directory(directory_path)?;
    let (path, mut pairing) = read_pending_pairing_file()?;
    pairing
        .as_object_mut()
        .expect("pending pairing is a JSON object")
        .remove("pending");
    write_pairing_file(&path, &pairing)?;
    sync_directory(&directory, directory_path)
}

pub(crate) fn abort_pending_pairing() -> Result<(), ConfigurationError> {
    let pairing_path = pairing_path()?;
    let directory_path = pairing_path.parent().expect("pairing path has a parent");
    let directory = lock_directory(directory_path)?;
    let (path, _) = read_pending_pairing_file()?;
    fs::remove_file(&path).map_err(|source| ConfigurationError::Access { path, source })?;
    sync_directory(&directory, directory_path)
}

pub(crate) fn remove_pairing() -> Result<(), ConfigurationError> {
    let pairing_path = pairing_path()?;
    let directory_path = pairing_path.parent().expect("pairing path has a parent");
    match pairing_path.try_exists() {
        Ok(true) => {}
        Ok(false) => return Err(ConfigurationError::NoPairing { path: pairing_path }),
        Err(source) => {
            return Err(ConfigurationError::Access {
                path: pairing_path,
                source,
            });
        }
    }

    let directory = lock_directory(directory_path)?;
    match fs::remove_file(&pairing_path) {
        Ok(()) => sync_directory(&directory, directory_path),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(ConfigurationError::NoPairing { path: pairing_path })
        }
        Err(source) => Err(ConfigurationError::Access {
            path: pairing_path,
            source,
        }),
    }
}

pub(crate) fn remove_active_pairing(
    expected_device_id: [u8; 16],
    expected_client_id: [u8; 16],
) -> Result<(), ConfigurationError> {
    let pairing_path = pairing_path()?;
    let directory_path = pairing_path.parent().expect("pairing path has a parent");
    let directory = lock_directory(directory_path)?;
    let (path, contents) = match read_pairing_file() {
        Ok(pairing) => pairing,
        Err(ConfigurationError::NoPairing { .. }) => return Ok(()),
        Err(error) => return Err(error),
    };
    let pairing: Pairing =
        serde_json::from_value(contents).map_err(|source| ConfigurationError::Invalid {
            path: path.clone(),
            source,
        })?;
    if pairing.pending
        || pairing.device_id_bytes() != expected_device_id
        || pairing.client_id_bytes() != expected_client_id
    {
        return Err(ConfigurationError::PairingChanged { path });
    }

    fs::remove_file(&path).map_err(|source| ConfigurationError::Access { path, source })?;
    sync_directory(&directory, directory_path)
}

pub(crate) fn pairing_path() -> Result<PathBuf, ConfigurationError> {
    let home = env::var_os("HOME").ok_or(ConfigurationError::HomeNotSet)?;
    Ok(PathBuf::from(home).join(".agentknock/pairing.json"))
}

fn read_pending_pairing_file() -> Result<(PathBuf, Value), ConfigurationError> {
    let (path, pairing) = read_pairing_file()?;
    if pairing.get("pending") != Some(&Value::Bool(true)) {
        return Err(ConfigurationError::PairingNotPending { path });
    }

    Ok((path, pairing))
}

fn read_pairing_file() -> Result<(PathBuf, Value), ConfigurationError> {
    let path = pairing_path()?;
    let pairing = read_pairing_value(&path)?;
    Ok((path, pairing))
}

fn read_pairing_value(path: &Path) -> Result<Value, ConfigurationError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(ConfigurationError::NoPairing {
                path: path.to_owned(),
            });
        }
        Err(source) => {
            return Err(ConfigurationError::Access {
                path: path.to_owned(),
                source,
            });
        }
    };
    validate_permissions(&file, path)?;
    let pairing: Value =
        serde_json::from_reader(file).map_err(|source| ConfigurationError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    Ok(pairing)
}

fn write_pairing_file(path: &Path, pairing: &Value) -> Result<(), ConfigurationError> {
    let contents =
        serde_json::to_vec_pretty(pairing).map_err(|source| ConfigurationError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    let mut options = AtomicWriteFile::options();
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|source| ConfigurationError::Access {
            path: path.to_owned(),
            source,
        })?;
    file.write_all(&contents)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| ConfigurationError::Access {
            path: path.to_owned(),
            source,
        })?;
    file.commit().map_err(|source| ConfigurationError::Access {
        path: path.to_owned(),
        source,
    })
}

fn lock_directory(path: &Path) -> Result<File, ConfigurationError> {
    let directory = File::open(path).map_err(|source| ConfigurationError::Access {
        path: path.to_owned(),
        source,
    })?;
    directory
        .lock()
        .map_err(|source| ConfigurationError::Access {
            path: path.to_owned(),
            source,
        })?;
    Ok(directory)
}

fn sync_directory(directory: &File, path: &Path) -> Result<(), ConfigurationError> {
    directory
        .sync_all()
        .map_err(|source| ConfigurationError::Access {
            path: path.to_owned(),
            source,
        })
}

pub(crate) fn read_pairing_from(path: &Path) -> Result<Pairing, ConfigurationError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(ConfigurationError::NoPairing {
                path: path.to_owned(),
            });
        }
        Err(source) => {
            return Err(ConfigurationError::Access {
                path: path.to_owned(),
                source,
            });
        }
    };

    validate_permissions(&file, path)?;

    let pairing = serde_json::from_reader(file).map_err(|source| ConfigurationError::Invalid {
        path: path.to_owned(),
        source,
    })?;
    validate_pairing(path, pairing)
}

fn parse_pairing(path: &Path, contents: Value) -> Result<Pairing, ConfigurationError> {
    let pairing =
        serde_json::from_value(contents).map_err(|source| ConfigurationError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    validate_pairing(path, pairing)
}

fn validate_pairing(path: &Path, pairing: Pairing) -> Result<Pairing, ConfigurationError> {
    if pairing.pending {
        return Err(ConfigurationError::PairingPending {
            path: path.to_owned(),
        });
    }
    if pairing.client_psk.is_empty() {
        return Err(ConfigurationError::EmptyPsk {
            path: path.to_owned(),
        });
    }

    Ok(pairing)
}

fn validate_permissions(file: &File, path: &Path) -> Result<(), ConfigurationError> {
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

    Ok(())
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

fn deserialize_client_token<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let token = BASE64_URL_SAFE
        .decode(&encoded)
        .map_err(serde::de::Error::custom)?;
    if token.len() != 32 || BASE64_URL_SAFE.encode(token) != encoded {
        return Err(serde::de::Error::custom(
            "expected a canonical unpadded base64url-encoded 32-byte client token",
        ));
    }
    Ok(encoded)
}

#[derive(Serialize)]
struct PendingPairingFile<'a> {
    pending: bool,
    device_id: RelayId,
    client_id: RelayId,
    client_token: &'a str,
    #[serde(serialize_with = "serialize_base64")]
    client_psk: &'a [u8],
    #[serde(serialize_with = "serialize_base64")]
    device_key: &'a [u8],
    rotated_at: u64,
}

pub(crate) fn current_timestamp() -> Result<u64, ConfigurationError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn serialize_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
}
