use std::{
    env,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::ConfigurationError;

/// Identifies the application that embeds Agentknock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationInfo {
    name: String,
    version: String,
}

/// An Agentknock client that shares pairing state across operations.
#[derive(Clone, Debug)]
pub struct Client {
    application_info: ApplicationInfo,
    state_directory: Option<PathBuf>,
}

impl ApplicationInfo {
    /// Creates the name and version reported for the embedding application.
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
    /// Creates a client that uses the machine user's shared Agentknock state.
    pub fn new(application_info: ApplicationInfo) -> Self {
        Self {
            application_info,
            state_directory: env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".agentknock")),
        }
    }

    /// Creates a client that stores its state in `state_directory`.
    ///
    /// Use this constructor when an application needs state isolated from the
    /// machine user's default Agentknock pairing.
    pub fn new_in(application_info: ApplicationInfo, state_directory: impl Into<PathBuf>) -> Self {
        Self {
            application_info,
            state_directory: Some(state_directory.into()),
        }
    }

    pub(crate) fn state_directory(&self) -> Result<&Path, ConfigurationError> {
        self.state_directory
            .as_deref()
            .ok_or(ConfigurationError::HomeNotSet)
    }

    pub(crate) fn pairing_path(&self) -> Result<PathBuf, ConfigurationError> {
        Ok(self.state_directory()?.join("pairing.json"))
    }

    pub(crate) fn encode<T>(&self, contents: &T) -> Result<Vec<u8>, serde_json::Error>
    where
        T: Serialize,
    {
        crate::protocol::encode(&self.application_info, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::{ApplicationInfo, Client};

    #[test]
    fn custom_state_directory_contains_pairing_file() {
        let client = Client::new_in(
            ApplicationInfo::new("test-application", "1.0.0"),
            "/tmp/agentknock-test-state",
        );

        assert_eq!(
            client.pairing_path().unwrap(),
            std::path::Path::new("/tmp/agentknock-test-state/pairing.json")
        );
    }
}
