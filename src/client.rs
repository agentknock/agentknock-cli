use std::{
    env,
    path::{Path, PathBuf},
};

use crate::ConfigurationError;

/// An Agentknock client that shares pairing state across operations.
#[derive(Clone, Debug)]
pub struct Client {
    state_directory: Option<PathBuf>,
}

impl Client {
    /// Creates a client that uses the machine user's shared Agentknock state.
    pub fn new() -> Self {
        Self {
            state_directory: env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".agentknock")),
        }
    }

    /// Creates a client that stores its state in `state_directory`.
    ///
    /// Use this constructor when an application needs state isolated from the
    /// machine user's default Agentknock pairing.
    pub fn new_in(state_directory: impl Into<PathBuf>) -> Self {
        Self {
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
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Client;

    #[test]
    fn custom_state_directory_contains_pairing_file() {
        let client = Client::new_in("/tmp/agentknock-test-state");

        assert_eq!(
            client.pairing_path().unwrap(),
            std::path::Path::new("/tmp/agentknock-test-state/pairing.json")
        );
    }
}
