use std::{fmt, io};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{config::ConfigurationError, crypto, protocol::DeviceError, websocket};

/// An error during an operation that communicates with the relay or device.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RequestError {
    /// Local pairing state couldn't be read or updated safely.
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),

    /// Consecutive transport or relay failures exhausted the retry policy.
    ///
    /// Valid relay traffic resets the consecutive-failure count.
    #[error("relay remained unavailable after {failures} consecutive failures")]
    RelayUnavailable {
        /// The number of consecutive failures observed.
        failures: usize,
    },

    /// An error report wasn't authenticated by the device.
    ///
    /// Callers must not treat this as a trusted device decision or use it to
    /// change cryptographic state.
    #[error("received unauthenticated error {code}: {message:?}")]
    Unauthenticated {
        /// A machine-readable error code supplied by the relay.
        code: String,
        /// Human-readable diagnostic text supplied by the relay.
        message: String,
    },

    /// The relay reports that the paired client is inactive.
    #[error("paired client is inactive: {message}")]
    ClientInactive {
        /// Human-readable context supplied by the relay.
        message: String,
    },

    /// The device returned an authenticated protocol error.
    #[error("device rejected the request with {code}: {message}")]
    DeviceRejected {
        /// A machine-readable error code supplied by the device.
        code: String,
        /// Human-readable diagnostic text supplied by the device.
        message: String,
    },

    /// The operation failed without a more specific public error category.
    #[error(transparent)]
    Other(#[from] io::Error),

    /// The device denied an authorization request.
    #[error("request denied ({reason}): {message}")]
    Denied {
        /// The device's denial category.
        reason: DenialReason,
        /// Human-readable context supplied by the device.
        message: String,
    },

    /// The device rejected a pending pairing during activation.
    #[error("pairing was rejected")]
    PairingRejected,

    /// The cancellation future resolved before the operation returned its result.
    #[error("request was interrupted")]
    Interrupted,
}

impl RequestError {
    pub(crate) fn other<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Other(io::Error::other(error))
    }
}

/// The reason that the device denied an authorization request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialReason {
    /// A user explicitly denied the request.
    UserDenied,

    /// Device policy denied the request.
    PolicyDenied,

    /// The device considered the request malformed or unsupported.
    InvalidRequest,

    /// The device denied the request for another reason.
    Other,
}

impl fmt::Display for DenialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UserDenied => "USER_DENIED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::Other => "OTHER",
        })
    }
}

impl From<websocket::Error> for RequestError {
    fn from(error: websocket::Error) -> Self {
        match error {
            websocket::Error::RetriesExhausted { failures, .. } => {
                Self::RelayUnavailable { failures }
            }
            websocket::Error::Unauthenticated { code, message } => {
                Self::Unauthenticated { code, message }
            }
            websocket::Error::RelayRejected { code, message } if code == "CLIENT_INACTIVE" => {
                Self::ClientInactive { message }
            }
            websocket::Error::ClientInactive { reason, .. } => {
                Self::ClientInactive { message: reason }
            }
            error => Self::other(error),
        }
    }
}

impl From<crypto::Error> for RequestError {
    fn from(error: crypto::Error) -> Self {
        Self::other(error)
    }
}

impl From<DeviceError> for RequestError {
    fn from(error: DeviceError) -> Self {
        Self::DeviceRejected {
            code: error.code,
            message: error.message,
        }
    }
}
