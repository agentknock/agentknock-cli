use std::{error::Error, io, process::Command as ProcessCommand};

use clap::{ArgAction, ArgGroup, Parser, builder::NonEmptyStringValueParser};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

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
            .args(["exec", "post", "start_pairing", "finish_pairing"])
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

    /// Send a JSON message to an HTTP endpoint.
    #[arg(
        long,
        action = ArgAction::Set,
        num_args = 2,
        value_names = ["URL", "MESSAGE"]
    )]
    post: Option<Vec<String>>,

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
struct PostArgs {
    url: String,
    message: String,
}

#[derive(Serialize)]
struct PostRequest<'a> {
    message: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PostResponse {
    echoed_message: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match (cli.exec, cli.post, cli.start_pairing, cli.finish_pairing) {
        (Some(_), None, None, false) => exec(cli.command_to_run)?,
        (None, Some(post_args), None, false) => {
            let [url, message] = post_args
                .try_into()
                .expect("clap requires exactly two arguments for --post");
            post(PostArgs { url, message }).await?;
        }
        (None, None, Some(_), false) | (None, None, None, true) => {}
        _ => unreachable!("clap requires exactly one command"),
    }

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

async fn post(args: PostArgs) -> Result<(), Box<dyn Error>> {
    let response = reqwest::Client::new()
        .post(args.url)
        .json(&PostRequest {
            message: &args.message,
        })
        .send()
        .await?
        .error_for_status()?
        .json::<PostResponse>()
        .await?;

    println!("{}", serde_json::to_string(&response)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::Cli;

    #[test]
    fn parses_post_command() {
        let cli =
            Cli::try_parse_from(["agentknock", "--post", "http://127.0.0.1/message", "hello"])
                .unwrap();

        assert_eq!(
            cli.post,
            Some(vec!["http://127.0.0.1/message".into(), "hello".into()])
        );
    }

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
            cli.exec,
            Some(vec!["gh-token".into(), "cf-wrangler".into()])
        );
        assert_eq!(
            cli.command_to_run,
            ["sh", "-c", "printf '%s' \"$TOKEN\""]
                .map(String::from)
                .to_vec()
        );
    }

    #[test]
    fn parses_start_pairing_command() {
        let cli =
            Cli::try_parse_from(["agentknock", "--start-pairing", "pairing-address-name"]).unwrap();

        assert_eq!(cli.start_pairing.as_deref(), Some("pairing-address-name"));
    }

    #[test]
    fn parses_finish_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "--finish-pairing"]).unwrap();

        assert!(cli.finish_pairing);
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
