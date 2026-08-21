//! TODO: Document the Agentknock project.

mod client;
mod config;
mod crypto;
mod pairing;
mod protocol;
mod secret_use;
mod secrets;
mod websocket;

pub use client::{ApplicationInfo, Client, PairingStatus};
pub use config::ConfigurationError;
pub use pairing::{PairingProgress, PairingRemoveError, PairingSas};
pub use secret_use::{
    ExecutableMode, RequestError, SecretUseDenialReason, SecretUseOperation, SecretUseOutput,
    SecretUseProgress, SecretUseRequest, StreamKind,
};
pub use secrets::{
    EnvironmentSecret, Secret, SecretListProgress, SecretUploadError, SecretUploadMode,
    SecretUploadProgress, Secrets,
};
