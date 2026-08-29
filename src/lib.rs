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
mod git_sign;
mod pairing;
mod protocol;
mod proxy;
mod secret_use;
mod secrets;
mod ssh_authentication;
mod websocket;

pub use client::{ApplicationInfo, Client, PairingStatus};
pub use config::ConfigurationError;
pub use git_sign::{
    GitSignChangeStatus, GitSignChangedPath, GitSignHead, GitSignProgress, GitSignRepository,
    GitSignRequest,
};
pub use pairing::{PairingProgress, PairingRemoveError, PairingSas};
pub use secret_use::{
    DenialReason, EnvironmentVariableOptions, ExecutableMode, RequestError, SecretUseInvocation,
    SecretUseOperation, SecretUseOptions, SecretUseOutput, SecretUseProgress, SecretUseRequest,
    SshSecretUse, StreamKind,
};
pub use secrets::{
    Secret, SecretListProgress, SecretUpload, SecretUploadError, SecretUploadMode,
    SecretUploadProgress, Secrets,
};
pub use ssh_authentication::{
    SshAuthenticationProgress, SshAuthenticationRequest, SshSignatureAlgorithm,
};
