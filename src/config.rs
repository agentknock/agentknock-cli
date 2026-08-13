use std::{
    env, fmt,
    fs::File,
    io,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Deserialize)]
pub(crate) struct Pairing {
    route_id: Identifier,
    pairing_id: Identifier,
    #[serde(deserialize_with = "deserialize_base64")]
    pairing_psk: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    route_key: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Identifier(u128);

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
}

pub(crate) fn read_pairing() -> Result<Pairing, ConfigurationError> {
    let home = env::var_os("HOME").ok_or(ConfigurationError::HomeNotSet)?;
    read_pairing_from(&PathBuf::from(home).join(".agentknock/pairing.json"))
}

fn read_pairing_from(path: &Path) -> Result<Pairing, ConfigurationError> {
    let file = File::open(path).map_err(|source| ConfigurationError::Access {
        path: path.to_owned(),
        source,
    })?;

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

    let pairing: Pairing =
        serde_json::from_reader(file).map_err(|source| ConfigurationError::Invalid {
            path: path.to_owned(),
            source,
        })?;
    if pairing.pairing_psk.is_empty() {
        return Err(ConfigurationError::EmptyPsk {
            path: path.to_owned(),
        });
    }

    Ok(pairing)
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
