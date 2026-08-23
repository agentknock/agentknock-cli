//! Agentknock is primarily a command-line application.
//!
//! Start with the [Agentknock README] for installation, usage, and project
//! documentation.
//!
//! The public items below form the unstable Agentknock embedding API. Direct
//! use of this API is not currently recommended.
//!
//! [Agentknock README]: https://docs.rs/crate/agentknock/latest

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
