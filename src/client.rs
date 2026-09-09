use std::{
    env,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::config::{ConfigurationError, StoredPairingStatus, read_pairing_status};

/// Identifies the application that uses the Agentknock library.
///
/// Agentknock includes this identity in protected messages sent to the device.
/// The application name identifies the embedding program, while its version
/// identifies that program's release. The library reports its own name and
/// version separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationInfo {
    name: String,
    version: String,
}

/// Performs Agentknock operations using one local pairing.
///
/// A client stores only application identity and the location of its local
/// state. It can be cloned and reused for concurrent operations; pairing-file
/// updates are synchronized between clients and processes.
#[derive(Clone, Debug)]
pub struct Client {
    application_info: ApplicationInfo,
    home: PathBuf,
}

/// A stage reported while an operation exchanges messages with the device.
///
/// Updates proceed from preparation through delivery, response processing,
/// and completion. Delivery updates can repeat. `Completed` means the exchange
/// has finished, not that the device approved the request; the return value
/// reports the operation's outcome. Failures can stop updates at any stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestProgress {
    /// Agentknock is reading local state and preparing the request.
    Preparing,

    /// The request is waiting to be delivered to the device.
    WaitingForDelivery,

    /// The device has received the request but hasn't returned a response.
    WaitingForResponse,

    /// Agentknock is processing the response and handing off the completion.
    Completing,

    /// The exchange has finished.
    Completed,
}

/// The state of the pairing stored on this client.
///
/// This status describes local state only. It doesn't confirm that the relay
/// can reach the device or that the device still accepts the pairing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PairingStatus {
    /// This client has no pairing.
    NotPaired,

    /// This client has started pairing but hasn't activated the pairing.
    Pending,

    /// This client has an active local pairing.
    Active,
}

impl ApplicationInfo {
    /// Creates an application identity from the values reported to the device.
    ///
    /// Agentknock sends both values unchanged. They should identify the
    /// embedding application and its release, not the Agentknock library.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn version(&self) -> &str {
        &self.version
    }
}

impl Client {
    /// Creates a client that uses the user's shared Agentknock state.
    ///
    /// Uses `AGENTKNOCK_HOME` when set, or `$HOME/.agentknock` otherwise.
    /// `AGENTKNOCK_HOME` must be a nonempty absolute path. The directory is
    /// selected at construction and doesn't need to exist yet.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::HomeNotSet`] if neither environment
    /// variable is set, or [`ConfigurationError::InvalidHome`] if the selected
    /// path is invalid or can't be resolved.
    pub fn new(application_info: ApplicationInfo) -> Result<Self, ConfigurationError> {
        let home = default_home(env::var_os("AGENTKNOCK_HOME"), env::var_os("HOME"))?;
        Self::new_in(application_info, home)
    }

    /// Creates a client that uses `home` for configuration and pairing state.
    ///
    /// This overrides `AGENTKNOCK_HOME` and `HOME`. Relative paths are resolved
    /// against the current working directory at construction. The directory
    /// doesn't need to exist yet. Agentknock stores the pairing in
    /// `pairing.json` inside it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::InvalidHome`] if the path is empty or
    /// can't be resolved.
    pub fn new_in(
        application_info: ApplicationInfo,
        home: impl Into<PathBuf>,
    ) -> Result<Self, ConfigurationError> {
        let home = home.into();
        let home = std::path::absolute(&home)
            .map_err(|source| ConfigurationError::InvalidHome { path: home, source })?;
        Ok(Self {
            application_info,
            home,
        })
    }

    /// Returns the absolute directory selected for configuration and pairing state.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the state of the pairing stored on this client.
    ///
    /// This method reads only local state. It doesn't contact the relay or
    /// device, so [`PairingStatus::Active`] doesn't confirm that the device
    /// still accepts the pairing. A missing pairing file returns
    /// [`PairingStatus::NotPaired`]; an unreadable, insecure, or malformed file
    /// returns a [`ConfigurationError`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if the pairing file can't be read and
    /// validated safely.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use agentknock::{ApplicationInfo, Client, PairingStatus};
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let client = Client::new(ApplicationInfo::new("my-application", "1.0.0"))?;
    ///
    ///     match client.pairing_status()? {
    ///         PairingStatus::NotPaired => println!("not paired"),
    ///         PairingStatus::Pending => println!("pairing is pending"),
    ///         PairingStatus::Active => println!("pairing is active"),
    ///         _ => println!("pairing has an unknown status"),
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn pairing_status(&self) -> Result<PairingStatus, ConfigurationError> {
        Ok(match read_pairing_status(&self.pairing_path())? {
            None => PairingStatus::NotPaired,
            Some(StoredPairingStatus::Pending) => PairingStatus::Pending,
            Some(StoredPairingStatus::Active) => PairingStatus::Active,
        })
    }

    pub(crate) fn application_info(&self) -> &ApplicationInfo {
        &self.application_info
    }

    pub(crate) fn pairing_path(&self) -> PathBuf {
        self.home.join("pairing.json")
    }

    pub(crate) fn encode<T>(&self, contents: &T) -> Result<Vec<u8>, serde_json::Error>
    where
        T: Serialize,
    {
        crate::protocol::encode(&self.application_info, contents)
    }
}

fn default_home(
    agentknock_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, ConfigurationError> {
    if let Some(home) = agentknock_home {
        let path = PathBuf::from(home);
        if !path.is_absolute() {
            return Err(ConfigurationError::InvalidHome {
                path,
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "AGENTKNOCK_HOME must be a nonempty absolute path",
                ),
            });
        }
        Ok(path)
    } else {
        let home = home.ok_or(ConfigurationError::HomeNotSet)?;
        if home.is_empty() {
            return Err(ConfigurationError::InvalidHome {
                path: home.into(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "HOME must not be empty"),
            });
        }
        Ok(PathBuf::from(home).join(".agentknock"))
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationInfo, Client, ConfigurationError, PairingStatus, default_home};

    #[test]
    fn default_home_uses_the_override_without_requiring_home() {
        for home in [None, Some("/user-home".into()), Some("".into())] {
            assert_eq!(
                default_home(Some("/agentknock-home".into()), home).unwrap(),
                std::path::Path::new("/agentknock-home")
            );
        }
        assert_eq!(
            default_home(None, Some("/user-home".into())).unwrap(),
            std::path::Path::new("/user-home/.agentknock")
        );
        assert!(matches!(
            default_home(None, None),
            Err(ConfigurationError::HomeNotSet)
        ));
    }

    #[test]
    fn invalid_home_environment_does_not_fall_back() {
        for path in ["", "relative"] {
            assert!(matches!(
                default_home(Some(path.into()), Some("/user-home".into())),
                Err(ConfigurationError::InvalidHome { .. })
            ));
        }
        assert!(matches!(
            default_home(None, Some("".into())),
            Err(ConfigurationError::InvalidHome { .. })
        ));
    }

    #[test]
    fn explicit_home_resolves_relative_paths_and_rejects_empty_paths() {
        let application = ApplicationInfo::new("test-application", "1.0.0");
        let client = Client::new_in(application.clone(), "relative-agentknock-home").unwrap();
        assert_eq!(
            client.home(),
            std::env::current_dir()
                .unwrap()
                .join("relative-agentknock-home")
        );
        assert!(matches!(
            Client::new_in(application, ""),
            Err(ConfigurationError::InvalidHome { .. })
        ));
    }

    #[test]
    fn custom_state_directory_contains_pairing_file() {
        let client = Client::new_in(
            ApplicationInfo::new("test-application", "1.0.0"),
            "/tmp/agentknock-test-state",
        )
        .unwrap();

        assert_eq!(
            client.pairing_path(),
            std::path::Path::new("/tmp/agentknock-test-state/pairing.json")
        );
    }

    #[test]
    fn missing_pairing_has_not_paired_status() {
        let client = Client::new_in(
            ApplicationInfo::new("test-application", "1.0.0"),
            std::env::temp_dir().join(format!(
                "agentknock-missing-test-state-{}",
                ulid::Ulid::generate()
            )),
        )
        .unwrap();

        assert_eq!(client.pairing_status().unwrap(), PairingStatus::NotPaired);
    }
}
