use std::{
    cell::Cell,
    error::Error,
    io,
    process::{Command as ProcessCommand, ExitCode},
    rc::Rc,
    time::Duration,
};

use agentknock::{
    CredentialRequest, CredentialRequestProgress, Credentials, RequestOperation, abort_pairing,
    finish_pairing, start_pairing,
};
use clap::{ArgAction, ArgGroup, Parser, builder::NonEmptyStringValueParser};

#[cfg(not(unix))]
use agentknock::request_credentials;
#[cfg(unix)]
use agentknock::request_credentials_with_progress;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const REQUEST_STATUS_INTERVAL: Duration = Duration::from_secs(30);

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
            .args(["exec", "start_pairing", "finish_pairing", "abort_pairing"])
    )
)]
struct Cli {
    /// Suppress all AgentKnock runtime output.
    #[arg(long, conflicts_with = "verbose", requires = "exec")]
    quiet: bool,

    /// Report credential request state changes immediately.
    #[arg(long, conflicts_with = "quiet", requires = "exec")]
    verbose: bool,

    /// Run a command with profiles supplied by AgentKnock.
    #[arg(
        long,
        action = ArgAction::Set,
        value_delimiter = ',',
        value_name = "PROFILE",
        value_parser = NonEmptyStringValueParser::new(),
        requires = "command_to_run"
    )]
    exec: Option<Vec<String>>,

    /// Explain why the requested profiles are needed.
    #[arg(
        long,
        value_name = "REASON",
        value_parser = NonEmptyStringValueParser::new(),
        requires = "exec"
    )]
    reason: Option<String>,

    /// Start pairing with an AgentKnock service.
    #[arg(
        long,
        value_name = "PAIRING_ADDRESS_NAME",
        value_parser = parse_pairing_address
    )]
    start_pairing: Option<String>,

    /// Finish pairing with an AgentKnock service.
    #[arg(long)]
    finish_pairing: bool,

    /// Abort a pending AgentKnock pairing.
    #[arg(long)]
    abort_pairing: bool,

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
        profiles: Vec<String>,
        reason: Option<String>,
        command: Vec<String>,
    },
    StartPairing(String),
    FinishPairing,
    AbortPairing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Normal,
    Quiet,
    Verbose,
}

fn parse_pairing_address(address: &str) -> Result<String, &'static str> {
    if !address.is_empty()
        && address
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        Ok(address.to_owned())
    } else {
        Err("pairing address must contain only lowercase ASCII letters and dashes")
    }
}

impl Cli {
    fn output_mode(&self) -> OutputMode {
        if self.quiet {
            OutputMode::Quiet
        } else if self.verbose {
            OutputMode::Verbose
        } else {
            OutputMode::Normal
        }
    }

    fn into_operation(self) -> Operation {
        if let Some(profiles) = self.exec {
            return Operation::Exec {
                profiles,
                reason: self.reason,
                command: self.command_to_run,
            };
        }

        if let Some(address_name) = self.start_pairing {
            return Operation::StartPairing(address_name);
        }

        if self.finish_pairing {
            return Operation::FinishPairing;
        }

        if self.abort_pairing {
            return Operation::AbortPairing;
        }

        unreachable!("clap requires exactly one operation")
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let output = cli.output_mode();
    match run(cli.into_operation(), output).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if output != OutputMode::Quiet {
                print_message(&error);
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(operation: Operation, output: OutputMode) -> Result<(), Box<dyn Error>> {
    match operation {
        Operation::Exec {
            profiles,
            reason,
            command,
        } => {
            let (program, arguments) = command.split_first().expect("command is required");
            let request = CredentialRequest {
                profiles: &profiles,
                operation: RequestOperation::Exec {
                    command: program,
                    arguments,
                },
                reason: reason.as_deref(),
            };
            #[cfg(unix)]
            let credentials = request_exec_credentials(request, output).await?;
            #[cfg(not(unix))]
            let credentials = request_credentials(request).await?;
            if output == OutputMode::Verbose {
                print_received_environment(&credentials);
                print_message(format_args!("Executing command: {program}."));
            }
            exec(command, credentials)?;
        }
        Operation::StartPairing(address) => start_pairing(&address).await?,
        Operation::FinishPairing => finish_pairing().await?,
        Operation::AbortPairing => abort_pairing()?,
    }

    Ok(())
}

#[cfg(unix)]
async fn request_exec_credentials(
    request: CredentialRequest<'_>,
    output: OutputMode,
) -> Result<Credentials, Box<dyn Error>> {
    use tokio::{
        signal::unix::{SignalKind, signal},
        time::{Instant, sleep},
    };

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let current_progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&current_progress);
    let request = request_credentials_with_progress(
        request,
        async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        },
        move |progress| {
            let changed = observed_progress.replace(Some(progress)) != Some(progress);
            if changed && output == OutputMode::Verbose {
                print_progress(progress);
            }
        },
    );
    tokio::pin!(request);
    let heartbeat = sleep(REQUEST_STATUS_INTERVAL);
    tokio::pin!(heartbeat);

    loop {
        tokio::select! {
            biased;
            result = request.as_mut() => return result.map_err(Into::into),
            _ = heartbeat.as_mut(), if output != OutputMode::Quiet => {
                if let Some(progress) = current_progress.get() {
                    print_progress(progress);
                }
                heartbeat.as_mut().reset(Instant::now() + REQUEST_STATUS_INTERVAL);
            }
        }
    }
}

fn print_progress(progress: CredentialRequestProgress) {
    print_message(progress_message(progress));
}

fn print_received_environment(credentials: &Credentials) {
    let mut names = credentials.environment_variable_names().peekable();
    if names.peek().is_none() {
        print_message("No environment variables received.");
        return;
    }

    print_message("Environment variables received:");
    for name in names {
        print_message(format_args!("- {name}"));
    }
}

fn progress_message(progress: CredentialRequestProgress) -> &'static str {
    match progress {
        CredentialRequestProgress::Preparing => "Preparing credentials request.",
        CredentialRequestProgress::WaitingForDelivery => {
            "Credentials request waiting for delivery to phone."
        }
        CredentialRequestProgress::WaitingForResponse => {
            "Credentials request delivered; waiting for response from phone."
        }
        CredentialRequestProgress::Completing => {
            "Credentials response received; completing request."
        }
        CredentialRequestProgress::Completed => "Credentials request completed.",
    }
}

fn print_message(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        eprintln!("AGENTKNOCK: {line}");
    }
}

#[cfg(unix)]
fn exec(command: Vec<String>, credentials: Credentials) -> io::Result<()> {
    let (program, arguments) = command.split_first().expect("command is required");
    Err(ProcessCommand::new(program)
        .args(arguments)
        .envs(credentials.into_environment())
        .exec())
}

#[cfg(not(unix))]
fn exec(_command: Vec<String>, _credentials: Credentials) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "exec is only supported on Unix",
    ))
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::{Cli, Operation, OutputMode, progress_message};

    #[test]
    fn parses_exec_command() {
        let cli = Cli::try_parse_from([
            "agentknock",
            "--exec",
            "gh-token,cf-wrangler",
            "--reason",
            "needed by the deployment agent",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$TOKEN\"",
        ])
        .unwrap();

        assert_eq!(
            cli.into_operation(),
            Operation::Exec {
                profiles: vec!["gh-token".into(), "cf-wrangler".into()],
                reason: Some("needed by the deployment agent".into()),
                command: ["sh", "-c", "printf '%s' \"$TOKEN\""]
                    .map(String::from)
                    .to_vec(),
            }
        );
    }

    #[test]
    fn parses_output_modes() {
        let normal =
            Cli::try_parse_from(["agentknock", "--exec", "profile", "--", "true"]).unwrap();
        let quiet =
            Cli::try_parse_from(["agentknock", "--quiet", "--exec", "profile", "--", "true"])
                .unwrap();
        let verbose =
            Cli::try_parse_from(["agentknock", "--verbose", "--exec", "profile", "--", "true"])
                .unwrap();

        assert_eq!(normal.output_mode(), OutputMode::Normal);
        assert_eq!(quiet.output_mode(), OutputMode::Quiet);
        assert_eq!(verbose.output_mode(), OutputMode::Verbose);
    }

    #[test]
    fn rejects_quiet_and_verbose_together() {
        let error = Cli::try_parse_from([
            "agentknock",
            "--quiet",
            "--verbose",
            "--exec",
            "profile",
            "--",
            "true",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn describes_credential_request_progress() {
        use agentknock::CredentialRequestProgress::*;

        assert_eq!(
            progress_message(WaitingForDelivery),
            "Credentials request waiting for delivery to phone."
        );
        assert_eq!(
            progress_message(WaitingForResponse),
            "Credentials request delivered; waiting for response from phone."
        );
        assert_eq!(
            progress_message(Completing),
            "Credentials response received; completing request."
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
    fn rejects_invalid_pairing_address() {
        for address in ["Yup-its-free", "yup_its_free", "yup-its-frée"] {
            let error =
                Cli::try_parse_from(["agentknock", "--start-pairing", address]).unwrap_err();

            assert_eq!(error.kind(), ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn parses_finish_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "--finish-pairing"]).unwrap();

        assert_eq!(cli.into_operation(), Operation::FinishPairing);
    }

    #[test]
    fn parses_abort_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "--abort-pairing"]).unwrap();

        assert_eq!(cli.into_operation(), Operation::AbortPairing);
    }

    #[test]
    fn rejects_finish_pairing_argument() {
        let error =
            Cli::try_parse_from(["agentknock", "--finish-pairing", "unexpected"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn rejects_abort_pairing_argument() {
        let error =
            Cli::try_parse_from(["agentknock", "--abort-pairing", "unexpected"]).unwrap_err();

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
