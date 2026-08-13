use std::{
    env,
    error::Error,
    fmt,
    fs::File,
    io,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::aead::{Aead as _, Key as AeadKey, KeyInit as _, Nonce as AeadNonce};
use clap::{ArgAction, ArgGroup, Parser, builder::NonEmptyStringValueParser};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, PskBundle, Serializable,
    aead::{Aead as HpkeAeadTrait, AeadCtxS, ChaCha20Poly1305},
    hybrid_array::Array,
    kdf::{HkdfSha256, Kdf as HpkeKdfTrait},
    kem::X25519HkdfSha256,
    setup_sender,
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use ulid::Ulid;

#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt, process::CommandExt};

const RELAY_URL: &str = "https://relay.agentknock.dev/";
const RESPONSE_EXPORTER_CONTEXT: &[u8] = b"agentknock-v1 response";
const TEST_RELAY_URL_ENV: &str = "AGENTKNOCK_TEST_RELAY_URL";

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kem = X25519HkdfSha256;
type ResponseAead = <Aead as HpkeAeadTrait>::AeadImpl;
type ResponseSecret = Array<u8, <Kdf as HpkeKdfTrait>::Nh>;
type ResponseKey = AeadKey<ResponseAead>;
type ResponseNonce = AeadNonce<ResponseAead>;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "agentknock",
    version,
    about = "AgentKnock command-line client",
    arg_required_else_help = true,
    group(
        ArgGroup::new("command")
            .required(true)
            .multiple(false)
            .args(["exec", "start_pairing", "finish_pairing"])
    )
)]
struct Cli {
    /// Run a command with credentials supplied by AgentKnock.
    #[arg(
        long,
        action = ArgAction::Set,
        value_delimiter = ',',
        value_name = "CREDENTIAL",
        value_parser = NonEmptyStringValueParser::new(),
        requires = "command_to_run"
    )]
    exec: Option<Vec<String>>,

    /// Start pairing with an AgentKnock service.
    #[arg(
        long,
        value_name = "PAIRING_ADDRESS_NAME",
        value_parser = NonEmptyStringValueParser::new()
    )]
    start_pairing: Option<String>,

    /// Finish pairing with an AgentKnock service.
    #[arg(long)]
    finish_pairing: bool,

    /// Command and arguments to run.
    #[arg(
        last = true,
        num_args = 1..,
        value_name = "COMMAND",
        requires = "exec"
    )]
    command_to_run: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Operation {
    Exec {
        names: Vec<String>,
        command: Vec<String>,
    },
    StartPairing(String),
    FinishPairing,
}

impl Cli {
    fn into_operation(self) -> Operation {
        if let Some(names) = self.exec {
            return Operation::Exec {
                names,
                command: self.command_to_run,
            };
        }

        if let Some(address_name) = self.start_pairing {
            return Operation::StartPairing(address_name);
        }

        if self.finish_pairing {
            return Operation::FinishPairing;
        }

        unreachable!("clap requires exactly one operation")
    }
}

#[derive(Deserialize)]
struct Pairing {
    route_id: Identifier,
    pairing_id: Identifier,
    #[serde(deserialize_with = "deserialize_base64")]
    pairing_psk: Vec<u8>,
    #[serde(deserialize_with = "deserialize_route_key")]
    route_key: <Kem as KemTrait>::PublicKey,
}

#[derive(Deserialize, Serialize)]
struct Placeholder {}

#[derive(Serialize)]
struct Request {
    version: &'static str,
    pairing_id: String,
    key: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct Completion {
    pairing_id: String,
    key: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct RequestMessage<'a> {
    request: &'a Request,
}

#[derive(Deserialize)]
struct RequestResponse {
    state: MessageState,
    response: Option<Response>,
}

#[derive(Deserialize)]
struct Response {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct CompletionMessage<'a> {
    request: &'a Request,
    completion: Completion,
}

#[derive(Clone, Copy)]
struct Identifier(u128);

impl Identifier {
    fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
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

#[derive(Deserialize)]
struct CompletionResponse {
    state: MessageState,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MessageState {
    RequestPending,
    RequestDelivered,
    ResponsePending,
    ResponseDelivered,
    CompletionPending,
    CompletionDelivered,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().into_operation() {
        Operation::Exec { names: _, command } => {
            let pairing = read_pairing()?;
            message_exchange(&relay_url()?, &pairing).await?;
            exec(command)?;
        }
        Operation::StartPairing(_) | Operation::FinishPairing => {}
    }

    Ok(())
}

fn read_pairing() -> Result<Pairing, Box<dyn Error>> {
    let home = env::var_os("HOME")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    read_pairing_from(&PathBuf::from(home).join(".agentknock/pairing.json"))
}

fn read_pairing_from(path: &Path) -> Result<Pairing, Box<dyn Error>> {
    let file = File::open(path)?;

    #[cfg(unix)]
    {
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} must have mode 0600, found {mode:04o}", path.display()),
            )
            .into());
        }
    }

    let pairing: Pairing = serde_json::from_reader(file)?;
    if pairing.pairing_psk.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} contains an empty field", path.display()),
        )
        .into());
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

fn deserialize_route_key<'de, D>(deserializer: D) -> Result<<Kem as KemTrait>::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_base64(deserializer)?;
    <Kem as KemTrait>::PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
}

fn relay_url() -> Result<String, env::VarError> {
    match env::var(TEST_RELAY_URL_ENV) {
        Err(env::VarError::NotPresent) => Ok(RELAY_URL.to_owned()),
        relay_url => relay_url,
    }
}

async fn message_exchange(relay_url: &str, pairing: &Pairing) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let request_id = Ulid::generate();
    let message_url = format!(
        "{}/v1/route/{}/msg/{request_id}",
        relay_url.trim_end_matches('/'),
        pairing.route_id,
    );
    let info = [
        pairing.route_id.to_bytes(),
        pairing.pairing_id.to_bytes(),
        request_id.to_bytes(),
    ]
    .concat();
    let pairing_id = pairing.pairing_id.to_bytes();
    let psk = PskBundle::new(&pairing.pairing_psk, &pairing_id)?;
    let (encapped_key, mut sender_context) =
        setup_sender::<Aead, Kdf, Kem>(&OpModeS::Psk(psk), &pairing.route_key, &info)?;
    let ciphertext = sender_context.seal(&serde_json::to_vec(&Placeholder {})?, b"")?;
    let encapped_key = encapped_key.to_bytes();
    let request = Request {
        version: "1",
        pairing_id: pairing.pairing_id.to_string(),
        key: BASE64_STANDARD.encode(encapped_key),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };

    let request_response: RequestResponse = post_message(
        &client,
        &format!("{message_url}/request"),
        &RequestMessage { request: &request },
    )
    .await?;
    let _request_state = request_response.state;
    if let Some(response) = request_response.response {
        let _response = decrypt_response(&sender_context, &encapped_key, response)?;
    }

    let completion = Completion {
        pairing_id: pairing.pairing_id.to_string(),
        key: request.key.clone(),
        ciphertext: BASE64_STANDARD
            .encode(sender_context.seal(&serde_json::to_vec(&Placeholder {})?, b"")?),
    };
    let completion_response: CompletionResponse = post_message(
        &client,
        &format!("{message_url}/complete"),
        &CompletionMessage {
            request: &request,
            completion,
        },
    )
    .await?;
    let _completion_state = completion_response.state;

    Ok(())
}

fn decrypt_response(
    sender_context: &AeadCtxS<Aead, Kdf, Kem>,
    encapped_key: &[u8],
    response: Response,
) -> Result<Placeholder, Box<dyn Error>> {
    let nonce = BASE64_STANDARD.decode(response.nonce)?;
    let ciphertext = BASE64_STANDARD.decode(response.ciphertext)?;
    let mut salt = Vec::with_capacity(encapped_key.len() + nonce.len());
    salt.extend_from_slice(encapped_key);
    salt.extend_from_slice(&nonce);

    let mut exported_secret = ResponseSecret::default();
    sender_context.export(RESPONSE_EXPORTER_CONTEXT, &mut exported_secret)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &exported_secret);
    let mut key = ResponseKey::default();
    hkdf.expand(b"key", &mut key)?;
    let mut nonce = ResponseNonce::default();
    hkdf.expand(b"nonce", &mut nonce)?;
    let cipher = ResponseAead::new(&key);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    Ok(serde_json::from_slice(&plaintext)?)
}

async fn post_message<B, R>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<R, reqwest::Error>
where
    B: Serialize + ?Sized,
    R: DeserializeOwned,
{
    client
        .post(url)
        .json(body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

#[cfg(unix)]
fn exec(command: Vec<String>) -> io::Result<()> {
    let (program, arguments) = command.split_first().expect("command is required");
    Err(ProcessCommand::new(program).args(arguments).exec())
}

#[cfg(not(unix))]
fn exec(_command: Vec<String>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "exec is only supported on Unix",
    ))
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::{Cli, Operation};

    #[test]
    fn parses_exec_command() {
        let cli = Cli::try_parse_from([
            "agentknock",
            "--exec",
            "gh-token,cf-wrangler",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$TOKEN\"",
        ])
        .unwrap();

        assert_eq!(
            cli.into_operation(),
            Operation::Exec {
                names: vec!["gh-token".into(), "cf-wrangler".into()],
                command: ["sh", "-c", "printf '%s' \"$TOKEN\""]
                    .map(String::from)
                    .to_vec(),
            }
        );
    }

    #[test]
    fn parses_start_pairing_command() {
        let cli =
            Cli::try_parse_from(["agentknock", "--start-pairing", "pairing-address-name"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            Operation::StartPairing("pairing-address-name".into())
        );
    }

    #[test]
    fn parses_finish_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "--finish-pairing"]).unwrap();

        assert_eq!(cli.into_operation(), Operation::FinishPairing);
    }

    #[test]
    fn rejects_finish_pairing_argument() {
        let error =
            Cli::try_parse_from(["agentknock", "--finish-pairing", "unexpected"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn shows_help_without_a_command() {
        let error = Cli::try_parse_from(["agentknock"]).unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn rejects_repeated_exec_options() {
        let error = Cli::try_parse_from([
            "agentknock",
            "--exec",
            "gh-token",
            "--exec",
            "cf-wrangler",
            "--",
            "echo",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn rejects_space_separated_exec_values() {
        let error = Cli::try_parse_from([
            "agentknock",
            "--exec",
            "gh-token",
            "cf-wrangler",
            "--",
            "echo",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn rejects_command_without_delimiter() {
        let error = Cli::try_parse_from(["agentknock", "--exec", "gh-token", "echo"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn rejects_empty_command_after_delimiter() {
        let error = Cli::try_parse_from(["agentknock", "--exec", "gh-token", "--"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn rejects_empty_exec_value() {
        let error =
            Cli::try_parse_from(["agentknock", "--exec", "gh-token,", "--", "echo"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_arguments() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let invalid_utf8 = OsString::from_vec(vec![0xff]);
        let cases = [
            vec![
                "agentknock".into(),
                "--exec".into(),
                invalid_utf8.clone(),
                "--".into(),
                "echo".into(),
            ],
            vec![
                "agentknock".into(),
                "--exec".into(),
                "gh-token".into(),
                "--".into(),
                invalid_utf8.clone(),
            ],
            vec![
                "agentknock".into(),
                "--exec".into(),
                "gh-token".into(),
                "--".into(),
                "echo".into(),
                invalid_utf8,
            ],
        ];

        for arguments in cases {
            let error = Cli::try_parse_from(arguments).unwrap_err();

            assert_eq!(error.kind(), ErrorKind::InvalidUtf8);
        }
    }
}
