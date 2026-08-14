use std::{fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Serialize;
use ulid::Ulid;

use crate::{
    ConfigurationError, ProtocolError, RequestError,
    config::{
        abort_pending_pairing, ensure_pairing_absent, finish_pending_pairing, write_pending_pairing,
    },
    crypto::{
        PairingResponse, derive_pairing_commitment, derive_route_id, generate_client_random,
        seal_pairing,
    },
    rest::Relay,
};

pub async fn start_pairing(address: &str) -> Result<(), RequestError> {
    ensure_pairing_absent()?;
    let client_random = generate_client_random().map_err(ProtocolError::from)?;
    let commitment = derive_pairing_commitment(address).map_err(ProtocolError::from)?;
    let request_id = Ulid::generate();
    let route_id = derive_route_id(address).map_err(ProtocolError::from)?;
    let relay = Relay::new(&route_id.to_string(), &request_id.to_string())?;
    let request = PairingRequest {
        version: 1,
        commitment: BASE64_STANDARD.encode(commitment),
    };
    let response: PairingResponse = relay.request(&request).await?;
    let contents = PairingContents {
        client_random: BASE64_STANDARD.encode(&client_random),
        hostname: read_trimmed("/etc/hostname"),
        machine_id: read_trimmed("/etc/machine-id"),
        os_version: os_version(),
    };
    let plaintext = serde_json::to_vec(&contents).map_err(ProtocolError::from)?;
    let (completion, pairing, sas) =
        seal_pairing(route_id, &request_id, response, &client_random, &plaintext)
            .map_err(ProtocolError::from)?;
    write_pending_pairing(&pairing)?;

    relay.complete(&request, &completion).await?;
    println!("{}", format_sas(sas));

    Ok(())
}

pub fn finish_pairing() -> Result<(), ConfigurationError> {
    finish_pending_pairing()
}

pub fn abort_pairing() -> Result<(), ConfigurationError> {
    abort_pending_pairing()
}

fn format_sas(sas: u64) -> String {
    format!(
        "{:04} {:04} {:04}",
        sas / 100_000_000,
        sas / 10_000 % 10_000,
        sas % 10_000,
    )
}

#[derive(Serialize)]
struct PairingRequest {
    version: u8,
    commitment: String,
}

#[derive(Serialize)]
struct PairingContents {
    client_random: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_version: Option<String>,
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let contents = contents.trim();
    (!contents.is_empty()).then(|| contents.to_owned())
}

fn os_version() -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"'))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::format_sas;

    #[test]
    fn formats_sas_as_three_groups() {
        assert_eq!(format_sas(123_456_789), "0001 2345 6789");
    }
}
