use std::{future::Future, io};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Client, RequestError, RequestProgress, protocol::Method};

/// Describes one SSH authentication requested by a command invocation.
pub struct SshAuthenticationRequest<'a> {
    /// The request identifier of the initial invocation.
    pub invocation_id: &'a str,

    /// The authorization token created for the invocation.
    pub invocation_token: &'a [u8; 32],

    /// The name of the SSH secret selected for the invocation.
    pub secret: &'a str,

    /// The signature algorithm requested by the SSH client.
    ///
    /// This value must match the algorithm encoded in [`Self::message`].
    pub algorithm: SshSignatureAlgorithm,

    /// The exact message bytes supplied by the SSH client.
    ///
    /// The message must be a valid SSH user-authentication request for the
    /// selected secret's public key.
    pub message: &'a [u8],
}

/// An SSH signature algorithm supported by Agentknock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SshSignatureAlgorithm {
    /// Ed25519 as defined for SSH.
    Ed25519,

    /// RSA with SHA-256 as defined by RFC 8332.
    RsaSha256,

    /// RSA with SHA-512 as defined by RFC 8332.
    RsaSha512,
}

impl SshSignatureAlgorithm {
    /// Returns the SSH protocol name of the signature algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::RsaSha256 => "rsa-sha2-256",
            Self::RsaSha512 => "rsa-sha2-512",
        }
    }
}

impl Client {
    /// Requests an SSH authentication signature from a selected secret.
    ///
    /// The device makes a separate decision for each authentication. The
    /// request includes the exact SSH user-authentication bytes supplied by
    /// the SSH client.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] if local pairing state isn't active, the relay
    /// exchange fails, the device denies the signature, the response is
    /// invalid, or the operation is canceled.
    pub async fn request_ssh_authentication<P>(
        &self,
        request: SshAuthenticationRequest<'_>,
        cancellation: impl Future<Output = ()>,
        mut progress: P,
    ) -> Result<Vec<u8>, RequestError>
    where
        P: FnMut(RequestProgress),
    {
        progress(RequestProgress::Preparing);
        request
            .invocation_id
            .parse::<Ulid>()
            .map_err(RequestError::other)?;
        if request.secret.is_empty() {
            return Err(RequestError::other("SSH secret name is empty"));
        }
        let request_id = Ulid::generate();
        let payload = SshAuthenticationRequestPayload {
            method: Method::SshAuthenticate,
            invocation_id: request.invocation_id,
            invocation_token: BASE64_STANDARD.encode(request.invocation_token),
            secret: request.secret,
            message: BASE64_STANDARD.encode(request.message),
        };
        self.approval_exchange(
            request_id,
            &payload,
            cancellation,
            progress,
            |response: ApprovedSignature| {
                let signature = response.signature.ok_or_else(|| {
                    io::Error::other("approved response doesn't contain an SSH signature")
                })?;
                match BASE64_STANDARD.decode(signature) {
                    Ok(signature) if valid_signature(&signature, request.algorithm) => {
                        Ok(signature)
                    }
                    _ => Err(io::Error::other(
                        "approved response doesn't contain a valid SSH signature",
                    )),
                }
            },
        )
        .await
    }
}

fn valid_signature(signature: &[u8], expected: SshSignatureAlgorithm) -> bool {
    let Some((algorithm, remainder)) = take_string(signature) else {
        return false;
    };
    let Some((value, remainder)) = take_string(remainder) else {
        return false;
    };
    remainder.is_empty()
        && !value.is_empty()
        && algorithm == expected.as_str().as_bytes()
        && (expected != SshSignatureAlgorithm::Ed25519 || value.len() == 64)
}

fn take_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4_usize.checked_add(length)?)?;
    Some((value, &input[4 + length..]))
}

#[derive(Serialize)]
struct SshAuthenticationRequestPayload<'a> {
    method: Method,
    invocation_id: &'a str,
    invocation_token: String,
    secret: &'a str,
    message: String,
}

#[derive(Deserialize)]
struct ApprovedSignature {
    signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_the_requested_signature_algorithm() {
        let signature = signature("ssh-ed25519", &[7; 64]);
        assert!(valid_signature(&signature, SshSignatureAlgorithm::Ed25519));
        assert!(!valid_signature(
            &signature,
            SshSignatureAlgorithm::RsaSha512
        ));
    }

    #[test]
    fn rejects_malformed_signatures() {
        assert!(!valid_signature(&[], SshSignatureAlgorithm::Ed25519));
        assert!(!valid_signature(
            &signature("ssh-ed25519", &[7; 63]),
            SshSignatureAlgorithm::Ed25519
        ));
        let mut trailing = signature("ssh-ed25519", &[7; 64]);
        trailing.push(0);
        assert!(!valid_signature(&trailing, SshSignatureAlgorithm::Ed25519));
    }

    fn signature(algorithm: &str, value: &[u8]) -> Vec<u8> {
        let mut signature = Vec::new();
        put_string(&mut signature, algorithm.as_bytes());
        put_string(&mut signature, value);
        signature
    }

    fn put_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }
}
