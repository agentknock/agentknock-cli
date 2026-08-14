use std::{
    env, fmt,
    fs::{self, File},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Deserialize)]
pub(crate) struct Pairing {
    #[serde(default)]
    pending: bool,
    route_id: Identifier,
    pairing_id: Identifier,
    #[serde(deserialize_with = "deserialize_base64")]
    pairing_psk: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    route_key: Vec<u8>,
    #[serde(default)]
    rotation: Option<Rotation>,
}

#[derive(Clone, Copy)]
pub(crate) struct Identifier(u128);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Rotation {
    key: String,
    ciphertext: String,
}

pub(crate) struct PendingPairing {
    route_id: Identifier,
    pairing_id: Identifier,
    pairing_psk: Vec<u8>,
    route_key: Vec<u8>,
}

impl Pairing {
    pub(crate) fn route_id(&self) -> String {
        self.route_id.to_string()
    }

    pub(crate) fn route_id_bytes(&self) -> [u8; 16] {
        self.route_id.0.to_be_bytes()
    }

    pub(crate) fn pairing_id(&self) -> String {
        self.pairing_id.to_string()
    }

    pub(crate) fn pairing_id_bytes(&self) -> [u8; 16] {
        self.pairing_id.0.to_be_bytes()
    }

    pub(crate) fn pairing_psk(&self) -> &[u8] {
        &self.pairing_psk
    }

    pub(crate) fn route_key(&self) -> &[u8] {
        &self.route_key
    }

    pub(crate) fn rotation(&self) -> Option<&Rotation> {
        self.rotation.as_ref()
    }
}

impl Identifier {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    pub(crate) fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl PendingPairing {
    pub(crate) fn new(
        route_id: Identifier,
        pairing_id: Identifier,
        pairing_psk: Vec<u8>,
        route_key: Vec<u8>,
    ) -> Self {
        Self {
            route_id,
            pairing_id,
            pairing_psk,
            route_key,
        }
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

impl Serialize for Identifier {
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

    #[error("{path} contains an empty pairing PSK")]
    EmptyPsk { path: PathBuf },

    #[error("pairing in {path} is still pending")]
    PairingPending { path: PathBuf },

    #[error("pairing configuration {path} already exists")]
    PairingExists { path: PathBuf },

    #[error("no pending pairing exists in {path}")]
    NoPendingPairing { path: PathBuf },
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
    if pairing.pairing_psk.is_empty() {
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
        Ok(true) => Err(ConfigurationError::PairingExists {
            path: path.to_owned(),
        }),
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
    let contents = serde_json::to_vec_pretty(&PendingPairingFile {
        pending: true,
        route_id: pairing.route_id,
        pairing_id: pairing.pairing_id,
        pairing_psk: &pairing.pairing_psk,
        route_key: &pairing.route_key,
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

pub(crate) fn clear_rotation(rotation: &Rotation) -> Result<(), ConfigurationError> {
    let pairing_path = pairing_path()?;
    let directory_path = pairing_path.parent().expect("pairing path has a parent");
    let directory = lock_directory(directory_path)?;
    let (path, mut pairing) = read_pairing_file()?;
    let expected =
        serde_json::to_value(rotation).map_err(|source| ConfigurationError::Invalid {
            path: path.clone(),
            source,
        })?;
    if pairing.get("rotation") != Some(&expected) {
        return Ok(());
    }
    pairing
        .as_object_mut()
        .expect("pairing is a JSON object")
        .remove("rotation");
    write_pairing_file(&path, &pairing)?;
    sync_directory(&directory, directory_path)
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

fn pairing_path() -> Result<PathBuf, ConfigurationError> {
    let home = env::var_os("HOME").ok_or(ConfigurationError::HomeNotSet)?;
    Ok(PathBuf::from(home).join(".agentknock/pairing.json"))
}

fn read_pending_pairing_file() -> Result<(PathBuf, Value), ConfigurationError> {
    let (path, pairing) = read_pairing_file()?;
    if pairing.get("pending") != Some(&Value::Bool(true)) {
        return Err(ConfigurationError::NoPendingPairing { path });
    }

    Ok((path, pairing))
}

fn read_pairing_file() -> Result<(PathBuf, Value), ConfigurationError> {
    let path = pairing_path()?;
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(ConfigurationError::NoPendingPairing { path });
        }
        Err(source) => return Err(ConfigurationError::Access { path, source }),
    };
    validate_permissions(&file, &path)?;
    let pairing: Value =
        serde_json::from_reader(file).map_err(|source| ConfigurationError::Invalid {
            path: path.clone(),
            source,
        })?;
    Ok((path, pairing))
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

fn read_pairing_from(path: &Path) -> Result<Pairing, ConfigurationError> {
    let file = File::open(path).map_err(|source| ConfigurationError::Access {
        path: path.to_owned(),
        source,
    })?;

    validate_permissions(&file, path)?;

    let pairing: Pairing =
        serde_json::from_reader(file).map_err(|source| ConfigurationError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    if pairing.pending {
        return Err(ConfigurationError::PairingPending {
            path: path.to_owned(),
        });
    }
    if pairing.pairing_psk.is_empty() {
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

#[derive(Serialize)]
struct PendingPairingFile<'a> {
    pending: bool,
    route_id: Identifier,
    pairing_id: Identifier,
    #[serde(serialize_with = "serialize_base64")]
    pairing_psk: &'a [u8],
    #[serde(serialize_with = "serialize_base64")]
    route_key: &'a [u8],
}

fn serialize_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
}
