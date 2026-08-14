use std::{
    env, fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

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
}

#[derive(Clone, Copy)]
pub(crate) struct Identifier(u128);

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
    let path = pairing_path()?;
    match path.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err(ConfigurationError::PairingExists { path }),
        Err(source) => Err(ConfigurationError::Access { path, source }),
    }
}

pub(crate) fn write_pending_pairing(pairing: &PendingPairing) -> Result<(), ConfigurationError> {
    let path = pairing_path()?;
    let directory = path.parent().expect("pairing path has a parent").to_owned();
    fs::create_dir_all(&directory).map_err(|source| ConfigurationError::Access {
        path: directory.clone(),
        source,
    })?;
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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            ConfigurationError::PairingExists { path: path.clone() }
        } else {
            ConfigurationError::Access {
                path: path.clone(),
                source,
            }
        }
    })?;
    file.write_all(&contents)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| ConfigurationError::Access { path, source })
}

pub(crate) fn finish_pending_pairing() -> Result<(), ConfigurationError> {
    let (path, mut pairing) = read_pending_pairing_file()?;
    pairing
        .as_object_mut()
        .expect("pending pairing is a JSON object")
        .remove("pending");
    let contents =
        serde_json::to_vec_pretty(&pairing).map_err(|source| ConfigurationError::Invalid {
            path: path.clone(),
            source,
        })?;
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|source| ConfigurationError::Access {
            path: path.clone(),
            source,
        })?;
    file.write_all(&contents)
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| ConfigurationError::Access { path, source })
}

pub(crate) fn abort_pending_pairing() -> Result<(), ConfigurationError> {
    let (path, _) = read_pending_pairing_file()?;
    fs::remove_file(&path).map_err(|source| ConfigurationError::Access { path, source })
}

fn pairing_path() -> Result<PathBuf, ConfigurationError> {
    let home = env::var_os("HOME").ok_or(ConfigurationError::HomeNotSet)?;
    Ok(PathBuf::from(home).join(".agentknock/pairing.json"))
}

fn read_pending_pairing_file() -> Result<(PathBuf, Value), ConfigurationError> {
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
    if pairing.get("pending") != Some(&Value::Bool(true)) {
        return Err(ConfigurationError::NoPendingPairing { path });
    }

    Ok((path, pairing))
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
