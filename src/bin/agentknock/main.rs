use std::{env, error::Error, io, process::Command as ProcessCommand};

use clap::{ArgAction, ArgGroup, Parser, builder::NonEmptyStringValueParser};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const RELAY_URL: &str = "https://relay.agentknock.dev/";
const TEST_RELAY_URL_ENV: &str = "AGENTKNOCK_TEST_RELAY_URL";
const ROUTE_ID: &str = "placeholder-route";

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

#[derive(Deserialize, Serialize)]
struct EmptyMessage {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().into_operation() {
        Operation::Exec { names: _, command } => {
            message_exchange(&relay_url()?).await?;
            exec(command)?;
        }
        Operation::StartPairing(_) | Operation::FinishPairing => {}
    }

    Ok(())
}

fn relay_url() -> Result<String, env::VarError> {
    match env::var(TEST_RELAY_URL_ENV) {
        Err(env::VarError::NotPresent) => Ok(RELAY_URL.to_owned()),
        relay_url => relay_url,
    }
}

async fn message_exchange(relay_url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let message_url = format!(
        "{}/v1/route/{ROUTE_ID}/msg/{}",
        relay_url.trim_end_matches('/'),
        Ulid::generate()
    );

    post_empty_message(&client, &format!("{message_url}/request")).await?;
    post_empty_message(&client, &format!("{message_url}/complete")).await?;

    Ok(())
}

async fn post_empty_message(client: &reqwest::Client, url: &str) -> Result<(), reqwest::Error> {
    client
        .post(url)
        .json(&EmptyMessage {})
        .send()
        .await?
        .error_for_status()?
        .json::<EmptyMessage>()
        .await?;

    Ok(())
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
