use std::error::Error;

use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "agentknock",
    version,
    about = "AgentKnock command-line client",
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Command {
    /// Send a JSON message to an HTTP endpoint.
    Post(PostArgs),

    /// Run a command with credentials supplied by AgentKnock.
    Run(RunArgs),
}

#[derive(Debug, Args, PartialEq, Eq)]
struct PostArgs {
    /// HTTP endpoint that receives the message.
    url: String,

    /// Message to send.
    message: String,
}

#[derive(Debug, Args, PartialEq, Eq)]
struct RunArgs {
    /// Command and arguments to run.
    #[arg(last = true, required = true, num_args = 1.., value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Serialize)]
struct PostRequest<'a> {
    message: &'a str,
}

#[derive(Deserialize, Serialize)]
struct PostResponse {
    echoed_message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Post(args) => post(args).await,
        Command::Run(_) => Ok(()),
    }
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

    use super::{Cli, Command};

    #[test]
    fn parses_post_command() {
        let cli = Cli::try_parse_from(["agentknock", "post", "http://127.0.0.1/message", "hello"])
            .unwrap();

        let Command::Post(post) = cli.command else {
            panic!("expected post command");
        };
        assert_eq!(post.url, "http://127.0.0.1/message");
        assert_eq!(post.message, "hello");
    }

    #[test]
    fn parses_command_and_arguments_after_delimiter() {
        let cli = Cli::try_parse_from([
            "agentknock",
            "run",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$TOKEN\"",
        ])
        .unwrap();

        let Command::Run(run) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(
            run.command,
            ["sh", "-c", "printf '%s' \"$TOKEN\""]
                .map(String::from)
                .to_vec()
        );
    }

    #[test]
    fn rejects_command_without_delimiter() {
        let error = Cli::try_parse_from(["agentknock", "run", "echo"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn rejects_empty_command_after_delimiter() {
        let error = Cli::try_parse_from(["agentknock", "run", "--"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_program_and_arguments() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let invalid_utf8 = OsString::from_vec(vec![0xff]);
        let cases = [
            vec![
                "agentknock".into(),
                "run".into(),
                "--".into(),
                invalid_utf8.clone(),
            ],
            vec![
                "agentknock".into(),
                "run".into(),
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
