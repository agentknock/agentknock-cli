use std::{
    cell::Cell,
    env,
    future::Future,
    io::{self, IsTerminal as _},
    path::Path,
    process::{Command as ProcessCommand, ExitCode},
    rc::Rc,
    time::Duration,
};

use agentknock::{
    ConfigurationError, CredentialRequest, CredentialRequestProgress, Credentials, DenialReason,
    PairingProgress, PairingSas, ProfileListProgress, Profiles, RequestError, RequestOperation,
    StreamKind, UnpairError, ValueSource, abort_pairing, finish_pairing_with_progress,
    force_unpair, list_profiles_with_progress, start_pairing_with_progress, unpair_with_progress,
};
use clap::{ArgAction, ArgGroup, Parser, builder::NonEmptyStringValueParser};

#[cfg(not(unix))]
use agentknock::request_credentials;
#[cfg(unix)]
use agentknock::request_credentials_with_progress;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt as _, process::CommandExt};

const REQUEST_STATUS_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const MAX_LAUNCHER_DEPTH: usize = 4;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "agentknock",
    version,
    about = "AgentKnock requests credentials and runs commands.",
    arg_required_else_help = true,
    group(
        ArgGroup::new("command")
            .required(true)
            .multiple(false)
            .args([
                "exec",
                "start_pairing",
                "finish_pairing",
                "abort_pairing",
                "unpair",
                "list",
            ])
    )
)]
struct Cli {
    /// Do not show AgentKnock runtime output.
    #[arg(long, conflicts_with = "verbose", requires = "exec")]
    quiet: bool,

    /// Show each credentials-request state change immediately.
    #[arg(long, conflicts_with = "quiet", requires = "exec")]
    verbose: bool,

    /// Run a command with credentials from the specified profiles.
    #[arg(
        long,
        action = ArgAction::Set,
        value_delimiter = ',',
        value_name = "PROFILE",
        value_parser = NonEmptyStringValueParser::new(),
        requires = "command_to_run"
    )]
    exec: Option<Vec<String>>,

    /// Give the reason for the credentials request.
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

    /// Finish a pending pairing with an AgentKnock service.
    #[arg(long)]
    finish_pairing: bool,

    /// Abort a pending AgentKnock pairing.
    #[arg(long)]
    abort_pairing: bool,

    /// Remove an active AgentKnock pairing.
    #[arg(long)]
    unpair: bool,

    /// Remove only the local pairing, without contacting the phone.
    #[arg(long, requires = "unpair")]
    force: bool,

    /// List the profiles available from the paired phone.
    #[arg(long)]
    list: bool,

    /// Command and arguments that AgentKnock runs.
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
    Unpair {
        force: bool,
    },
    List,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Normal,
    Quiet,
    Verbose,
}

#[derive(Clone, Copy)]
enum PairingOperation {
    Start,
    Finish,
    Unpair,
}

#[derive(Debug)]
enum CommandError {
    ExecRequest(RequestError),
    ExecContext(io::Error),
    ExecSignal(io::Error),
    ExecProcess { program: String, source: io::Error },
    StartPairing(RequestError),
    FinishPairing(RequestError),
    AbortPairing(ConfigurationError),
    ForceUnpair(ConfigurationError),
    Unpair(UnpairError),
    List(RequestError),
}

fn parse_pairing_address(address: &str) -> Result<String, &'static str> {
    if !address.is_empty()
        && address
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        Ok(address.to_owned())
    } else {
        Err("the pairing address must contain only lowercase ASCII letters and hyphens")
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

        if self.unpair {
            return Operation::Unpair { force: self.force };
        }

        if self.list {
            return Operation::List;
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
            print_command_error(&error, output);
            ExitCode::FAILURE
        }
    }
}

async fn run(operation: Operation, output: OutputMode) -> Result<(), CommandError> {
    match operation {
        Operation::Exec {
            profiles,
            reason,
            command,
        } => {
            let (program, arguments) = command.split_first().expect("command is required");
            let working_directory = working_directory().map_err(CommandError::ExecContext)?;
            let resolved_path = resolve_command_path(program, Path::new(&working_directory));
            let launcher_chain = launcher_chain();
            let request = CredentialRequest {
                profiles: &profiles,
                operation: RequestOperation::Exec {
                    command: program,
                    arguments,
                    working_directory: &working_directory,
                    resolved_path: resolved_path.as_deref(),
                    stdin: standard_stream_kind(0, io::stdin().is_terminal()),
                    stdout: standard_stream_kind(1, io::stdout().is_terminal()),
                    stderr: standard_stream_kind(2, io::stderr().is_terminal()),
                },
                reason: reason.as_deref(),
                launcher_chain: &launcher_chain,
            };
            #[cfg(unix)]
            let credentials = request_exec_credentials(request, output).await?;
            #[cfg(not(unix))]
            let credentials = request_credentials(request)
                .await
                .map_err(CommandError::ExecRequest)?;
            if output == OutputMode::Verbose {
                print_received_environment(&credentials);
                print_message(format_args!("AgentKnock executes the command: {program}."));
            }
            let program = program.clone();
            exec(command, credentials)
                .map_err(|source| CommandError::ExecProcess { program, source })?;
        }
        Operation::StartPairing(address) => {
            let sas = start_pairing_for_cli(&address)
                .await
                .map_err(CommandError::StartPairing)?;
            print_start_pairing_success(&sas);
        }
        Operation::FinishPairing => {
            finish_pairing_for_cli()
                .await
                .map_err(CommandError::FinishPairing)?;
            println!("AgentKnock finished pairing. AgentKnock is ready to provide credentials.");
        }
        Operation::AbortPairing => {
            abort_pairing().map_err(CommandError::AbortPairing)?;
            println!("AgentKnock aborted the pending pairing. AgentKnock is not paired.");
        }
        Operation::Unpair { force } => {
            if force {
                force_unpair().map_err(CommandError::ForceUnpair)?;
                println!(
                    "AgentKnock removed the local pairing. The phone-side pairing was not changed."
                );
            } else {
                unpair_for_cli().await.map_err(CommandError::Unpair)?;
                println!("AgentKnock unpaired this installation.");
            }
        }
        Operation::List => {
            let profiles = list_profiles_for_cli().await.map_err(CommandError::List)?;
            print_profiles(&profiles);
        }
    }

    Ok(())
}

async fn start_pairing_for_cli(address: &str) -> Result<PairingSas, RequestError> {
    let progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&progress);
    let request = start_pairing_with_progress(address, move |current| {
        observed_progress.set(Some(current));
    });
    monitor_operation(request, progress, move |progress| {
        pairing_progress_message(PairingOperation::Start, progress)
    })
    .await
}

async fn finish_pairing_for_cli() -> Result<(), RequestError> {
    let progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&progress);
    let request = finish_pairing_with_progress(move |current| {
        observed_progress.set(Some(current));
    });
    monitor_operation(request, progress, move |progress| {
        pairing_progress_message(PairingOperation::Finish, progress)
    })
    .await
}

async fn unpair_for_cli() -> Result<(), UnpairError> {
    let progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&progress);
    let request = unpair_with_progress(move |current| {
        observed_progress.set(Some(current));
    });
    monitor_operation(request, progress, move |progress| {
        pairing_progress_message(PairingOperation::Unpair, progress)
    })
    .await
}

async fn list_profiles_for_cli() -> Result<Profiles, RequestError> {
    let progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&progress);
    let request = list_profiles_with_progress(move |current| {
        observed_progress.set(Some(current));
    });
    monitor_operation(request, progress, profile_list_progress_message).await
}

async fn monitor_operation<T, E, F, P, M>(
    request: F,
    progress: Rc<Cell<Option<P>>>,
    progress_message: M,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    P: Copy,
    M: Fn(P) -> &'static str,
{
    use tokio::time::{Instant, sleep};

    tokio::pin!(request);
    let heartbeat = sleep(REQUEST_STATUS_INTERVAL);
    tokio::pin!(heartbeat);
    loop {
        tokio::select! {
            biased;
            result = request.as_mut() => return result,
            _ = heartbeat.as_mut() => {
                if let Some(progress) = progress.get() {
                    eprintln!("{}", progress_message(progress));
                }
                heartbeat.as_mut().reset(Instant::now() + REQUEST_STATUS_INTERVAL);
            }
        }
    }
}

fn profile_list_progress_message(progress: ProfileListProgress) -> &'static str {
    match progress {
        ProfileListProgress::Preparing => "AgentKnock prepares the profile list request.",
        ProfileListProgress::WaitingForDelivery => {
            "AgentKnock waits for the phone to receive the profile list request."
        }
        ProfileListProgress::WaitingForResponse => {
            "The phone received the profile list request. AgentKnock waits for a response from the phone."
        }
        ProfileListProgress::Completing => {
            "AgentKnock received the profile list. AgentKnock confirms receipt."
        }
        ProfileListProgress::Completed => "AgentKnock completed the profile list request.",
    }
}

fn pairing_progress_message(
    operation: PairingOperation,
    progress: PairingProgress,
) -> &'static str {
    match (operation, progress) {
        (PairingOperation::Start, PairingProgress::Preparing) => {
            "AgentKnock prepares the pairing request."
        }
        (PairingOperation::Start, PairingProgress::WaitingForDelivery) => {
            "AgentKnock waits for the phone to receive the pairing request."
        }
        (PairingOperation::Start, PairingProgress::WaitingForResponse) => {
            "The phone received the pairing request. AgentKnock waits for a response from the phone."
        }
        (PairingOperation::Start, PairingProgress::Completing) => {
            "AgentKnock received the pairing response. AgentKnock saves the pending pairing."
        }
        (PairingOperation::Start, PairingProgress::Completed) => {
            "AgentKnock completed the pairing request."
        }
        (PairingOperation::Finish, PairingProgress::Preparing) => {
            "AgentKnock prepares the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::WaitingForDelivery) => {
            "AgentKnock waits for the phone to receive the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::WaitingForResponse) => {
            "The phone received the pairing confirmation. AgentKnock waits for a response from the phone."
        }
        (PairingOperation::Finish, PairingProgress::Completing) => {
            "The phone accepted the pairing. AgentKnock saves the active pairing."
        }
        (PairingOperation::Finish, PairingProgress::Completed) => {
            "AgentKnock completed the pairing confirmation."
        }
        (PairingOperation::Unpair, PairingProgress::Preparing) => {
            "AgentKnock prepares the unpair request."
        }
        (PairingOperation::Unpair, PairingProgress::WaitingForDelivery) => {
            "AgentKnock waits for the phone to receive the unpair request."
        }
        (PairingOperation::Unpair, PairingProgress::WaitingForResponse) => {
            "The phone received the unpair request. AgentKnock waits for a response from the phone."
        }
        (PairingOperation::Unpair, PairingProgress::Completing) => {
            "The phone accepted the unpair request. AgentKnock removes the local pairing."
        }
        (PairingOperation::Unpair, PairingProgress::Completed) => {
            "AgentKnock completed the unpair request."
        }
    }
}

#[cfg(unix)]
async fn request_exec_credentials(
    request: CredentialRequest<'_>,
    output: OutputMode,
) -> Result<Credentials, CommandError> {
    use tokio::{
        signal::unix::{SignalKind, signal},
        time::{Instant, sleep},
    };

    let mut interrupt = signal(SignalKind::interrupt()).map_err(CommandError::ExecSignal)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(CommandError::ExecSignal)?;
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
            result = request.as_mut() => return result.map_err(CommandError::ExecRequest),
            _ = heartbeat.as_mut(), if output != OutputMode::Quiet => {
                if let Some(progress) = current_progress.get() {
                    print_progress(progress);
                }
                heartbeat.as_mut().reset(Instant::now() + REQUEST_STATUS_INTERVAL);
            }
        }
    }
}

fn print_start_pairing_success(sas: &PairingSas) {
    println!("AgentKnock started the pairing process.");
    println!("Verification code:");
    println!("{sas}");
    println!("Suggested action: Compare the verification code with the code on the phone.");
    println!("Suggested action: If the codes match, approve the pairing on the phone.");
    println!("Suggested action: After approval, run this command:");
    println!("agentknock --finish-pairing");
}

fn print_command_error(error: &CommandError, output: OutputMode) {
    match error {
        CommandError::ExecRequest(error) if output != OutputMode::Quiet => {
            print_exec_request_error(error);
        }
        CommandError::ExecContext(source) if output != OutputMode::Quiet => {
            print_message(format_args!(
                "AgentKnock could not inspect the invocation context: {source}."
            ));
            print_message("The credentials request did not start.");
            print_message("Suggested action: Correct the local system error.");
            print_message("Suggested action: Run the original command again.");
        }
        CommandError::ExecSignal(source) if output != OutputMode::Quiet => {
            print_message(format_args!(
                "A signal-handling error stopped the credentials request: {source}."
            ));
            print_message("The command did not start.");
            print_message("Suggested action: Correct the local system error.");
            print_message("Suggested action: Run the original command again.");
        }
        CommandError::ExecProcess { program, source } if output != OutputMode::Quiet => {
            print_message(format_args!(
                "The phone approved the credentials request. AgentKnock did not execute the command {program:?}: {source}."
            ));
            print_message("Suggested action: Make sure that the command exists and is executable.");
            print_message("Suggested action: Run the original command again.");
        }
        CommandError::ExecRequest(_)
        | CommandError::ExecContext(_)
        | CommandError::ExecSignal(_)
        | CommandError::ExecProcess { .. } => {}
        CommandError::StartPairing(error) => print_start_pairing_error(error),
        CommandError::FinishPairing(error) => print_finish_pairing_error(error),
        CommandError::AbortPairing(error) => print_abort_pairing_error(error),
        CommandError::ForceUnpair(error) => print_force_unpair_error(error),
        CommandError::Unpair(error) => print_unpair_error(error),
        CommandError::List(error) => print_list_error(error),
    }
}

fn print_list_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("AgentKnock is not paired. It cannot list profiles.");
            print_plain_error("Suggested action: Get a pairing address.");
            print_plain_error("Suggested action: Run this command:");
            print_plain_error("agentknock --start-pairing <PAIRING_ADDRESS>");
        }
        RequestError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error("Pairing is in progress. AgentKnock cannot list profiles yet.");
            print_plain_error("Suggested action: Approve the pairing on the phone.");
            print_plain_error("Suggested action: After approval, run this command:");
            print_plain_error("agentknock --finish-pairing");
            print_plain_error("Suggested action: Run this command again:");
            print_plain_error("agentknock --list");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("AgentKnock did not list profiles: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::Relay(_) | RequestError::RelayUnavailable { .. } => {
            print_plain_error(format_args!("AgentKnock did not list profiles: {error}."));
            print_plain_error("Suggested action: Make sure that the network connection works.");
            print_plain_error("Suggested action: Run this command again:");
            print_plain_error("agentknock --list");
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_plain_error("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
            print_plain_error("Suggested action: Run this command again:");
            print_plain_error("agentknock --list");
        }
        _ => {
            print_plain_error(format_args!("AgentKnock did not list profiles: {error}."));
            print_plain_error("Suggested action: Run this command again:");
            print_plain_error("agentknock --list");
        }
    }
}

fn print_exec_request_error(error: &RequestError) {
    match error {
        RequestError::Configuration(error) => print_exec_configuration_error(error),
        RequestError::Denied {
            reason: DenialReason::UserDenied,
            message,
        } => {
            print_message(format_args!(
                "The credentials request was denied on the phone: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Denied {
            reason: DenialReason::PolicyDenied,
            message,
        } => {
            print_message(format_args!(
                "The policy denied the credentials request: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Denied {
            reason: DenialReason::InvalidRequest,
            message,
        } => {
            print_message(format_args!(
                "The credentials request was invalid: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Denied {
            reason: DenialReason::Other,
            message,
        } => {
            print_message(format_args!(
                "The credentials request was denied: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Interrupted => {
            print_message(
                "A signal interrupted the credentials request. The command did not start.",
            );
            print_message(
                "Suggested action: If you still need the credentials, run the original command again.",
            );
        }
        RequestError::RelayUnavailable { failures } => {
            print_message(format_args!(
                "AgentKnock did not receive a relay response after {failures} consecutive errors."
            ));
            print_message("The command did not start.");
            print_message("Suggested action: Make sure that the network connection works.");
            print_message("Suggested action: Run the original command again.");
        }
        RequestError::Relay(source) => {
            print_message(format_args!(
                "The relay rejected the credentials request: {source}."
            ));
            print_message("The command did not start.");
            print_message(
                "Suggested action: Make sure that the network connection and pairing state are correct.",
            );
            print_message("Suggested action: Run the original command again.");
        }
        RequestError::Protocol(source) => {
            print_message(format_args!(
                "A protocol error stopped the credentials request: {source}."
            ));
            print_message("The command did not start.");
            print_message("Suggested action: Run the original command again.");
            print_message(
                "Suggested action: If the error occurs again, report the protocol error.",
            );
        }
        RequestError::UnexpectedRelayStatus(status) => {
            print_message(format_args!(
                "The relay returned HTTP status {status}. AgentKnock did not expect this status."
            ));
            print_message("The command did not start.");
            print_message("Suggested action: Run the original command again.");
            print_message(
                "Suggested action: If the status occurs again, report a relay compatibility problem.",
            );
        }
        RequestError::PairingRejected => {
            print_message("The paired phone rejected the client pairing.");
            print_message("The command did not start.");
            print_message("Suggested action: Repair or remove the pairing configuration.");
            print_message("Suggested action: Start pairing again.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_message("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_message("The command did not start.");
            print_message("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
            print_message("Suggested action: Run the original command again.");
        }
    }
}

fn print_exec_configuration_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_message("AgentKnock is not paired. The command did not start.");
            print_message("Suggested action: Get a pairing address.");
            print_message("Suggested action: Run this command:");
            print_message("agentknock --start-pairing <PAIRING_ADDRESS>");
            print_message("Suggested action: Complete pairing.");
            print_message("Suggested action: Run the original command again.");
        }
        ConfigurationError::PairingPending { .. } => {
            print_message("Pairing is in progress. The command did not start.");
            print_message("Suggested action: Approve the pairing on the phone.");
            print_message("Suggested action: After approval, run this command:");
            print_message("agentknock --finish-pairing");
            print_message("Suggested action: Run the original command again.");
        }
        ConfigurationError::InsecurePermissions { path, mode } => {
            print_message(format_args!(
                "Pairing configuration {path:?} has mode {mode:04o}. Mode 0600 is required."
            ));
            print_message("The command did not start.");
            print_message("Suggested action: Run this command:");
            print_message(format_args!("chmod 600 {path:?}"));
            print_message("Suggested action: Run the original command again.");
        }
        ConfigurationError::HomeNotSet => {
            print_message("HOME is not set. AgentKnock cannot find the pairing configuration.");
            print_message("The command did not start.");
            print_message("Suggested action: Set HOME to the correct home directory.");
            print_message("Suggested action: Run the original command again.");
        }
        ConfigurationError::Invalid { path, source } => {
            print_message(format_args!(
                "The pairing configuration at {path:?} contains invalid JSON: {source}."
            ));
            print_message("The command did not start.");
            print_message(
                "Suggested action: Repair the file, or remove it and start pairing again.",
            );
        }
        ConfigurationError::EmptyPsk { path } => {
            print_message(format_args!("The pairing PSK in {path:?} is empty."));
            print_message("The command did not start.");
            print_message(
                "Suggested action: Repair the file, or remove it and start pairing again.",
            );
        }
        ConfigurationError::InvalidSystemTime(_) => {
            print_message(format_args!("The system clock is invalid: {error}."));
            print_message("The command did not start.");
            print_message("Suggested action: Correct the system clock.");
            print_message("Suggested action: Run the original command again.");
        }
        _ => {
            print_message(format_args!(
                "A pairing configuration error stopped the command: {error}."
            ));
            print_message("Suggested action: Correct the pairing configuration error.");
            print_message("Suggested action: Run the original command again.");
        }
    }
}

fn print_start_pairing_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error("Pairing is already in progress.");
            print_plain_error("Suggested action: Approve the pairing on the phone.");
            print_plain_error("Suggested action: After approval, run this command:");
            print_plain_error("agentknock --finish-pairing");
            print_plain_error("Suggested action: To abort the pending pairing, run this command:");
            print_plain_error("agentknock --abort-pairing");
        }
        RequestError::Configuration(ConfigurationError::PairingExists { .. }) => {
            print_plain_error("AgentKnock is already paired and ready to provide credentials.");
            print_plain_error("AgentKnock did not change the existing pairing.");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("AgentKnock did not start pairing: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::Relay(_) | RequestError::RelayUnavailable { .. } => {
            print_plain_error(format_args!("AgentKnock did not start pairing: {error}."));
            print_plain_error("Suggested action: Make sure that the network connection works.");
            print_plain_error("Suggested action: Run the original command again.");
            print_plain_error(
                "Suggested action: If pairing is in progress after another error, run this command:",
            );
            print_plain_error("agentknock --abort-pairing");
        }
        _ => {
            print_plain_error(format_args!("AgentKnock did not start pairing: {error}."));
            print_plain_error("Suggested action: Run the original command again.");
            print_plain_error(
                "Suggested action: If pairing is in progress after another error, run this command:",
            );
            print_plain_error("agentknock --abort-pairing");
        }
    }
}

fn print_finish_pairing_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("No pairing is in progress.");
            print_plain_error("Suggested action: Get a pairing address.");
            print_plain_error("Suggested action: Run this command:");
            print_plain_error("agentknock --start-pairing <PAIRING_ADDRESS>");
        }
        RequestError::Configuration(ConfigurationError::PairingNotPending { .. }) => {
            print_plain_error("Pairing is complete. AgentKnock is ready to provide credentials.");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("AgentKnock did not finish pairing: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::PairingRejected => {
            print_plain_error(
                "The phone rejected the pairing. AgentKnock kept the pending pairing.",
            );
            print_plain_error("Suggested action: Review the pairing request on the phone.");
            print_plain_error(
                "Suggested action: To send the finish request again, run this command:",
            );
            print_plain_error("agentknock --finish-pairing");
            print_plain_error("Suggested action: To abort the pending pairing, run this command:");
            print_plain_error("agentknock --abort-pairing");
        }
        _ => {
            print_plain_error(format_args!("AgentKnock did not finish pairing: {error}."));
            print_plain_error("Suggested action: Make sure that the network connection works.");
            print_plain_error("Suggested action: Run this command again:");
            print_plain_error("agentknock --finish-pairing");
            print_plain_error(
                "If AgentKnock reports that pairing is complete, no action is necessary.",
            );
        }
    }
}

fn print_abort_pairing_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_plain_error("AgentKnock has no pairing to abort.");
        }
        ConfigurationError::PairingNotPending { .. } => {
            print_plain_error(
                "Pairing is active. The --abort-pairing option does not remove the active pairing.",
            );
            print_plain_error("AgentKnock did not change the active pairing.");
        }
        _ => {
            print_plain_error(format_args!(
                "AgentKnock did not abort the pending pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_unpair_error(error: &UnpairError) {
    match error {
        UnpairError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("AgentKnock is not paired. There is no active pairing to remove.");
        }
        UnpairError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error(
                "Pairing is in progress. AgentKnock did not remove the pending pairing.",
            );
            print_plain_error("Suggested action: To abort the pending pairing, run this command:");
            print_plain_error("agentknock --abort-pairing");
        }
        UnpairError::Configuration(error) => {
            print_plain_error(format_args!("AgentKnock did not start unpairing: {error}."));
            print_plain_configuration_action(error);
        }
        UnpairError::Request(error) => {
            print_plain_error(format_args!(
                "AgentKnock did not receive a valid unpair response: {error}."
            ));
            print_plain_error("The local pairing is unchanged. The phone-side result is unknown.");
            print_plain_error("Suggested action: Run this command again:");
            print_plain_error("agentknock --unpair");
        }
        UnpairError::LocalState(ConfigurationError::PairingChanged { .. }) => {
            print_plain_error(
                "The phone accepted the unpair request, but the local pairing changed.",
            );
            print_plain_error("AgentKnock did not remove the current local pairing.");
            print_plain_error("Suggested action: To remove the current pairing, run this command:");
            print_plain_error("agentknock --unpair");
        }
        UnpairError::LocalState(error) => {
            print_plain_error(format_args!(
                "The phone accepted the unpair request, but AgentKnock did not remove the local pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_force_unpair_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_plain_error("AgentKnock is not paired. There is no local pairing to remove.");
        }
        _ => {
            print_plain_error(format_args!(
                "AgentKnock did not remove the local pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_plain_configuration_action(error: &ConfigurationError) {
    match error {
        ConfigurationError::InsecurePermissions { path, .. } => {
            print_plain_error("Suggested action: Run this command:");
            print_plain_error(format_args!("chmod 600 {path:?}"));
            print_plain_error("Suggested action: Run the original command again.");
        }
        ConfigurationError::HomeNotSet => {
            print_plain_error("Suggested action: Set HOME to the correct home directory.");
            print_plain_error("Suggested action: Run the original command again.");
        }
        ConfigurationError::Invalid { path, .. } | ConfigurationError::EmptyPsk { path } => {
            print_plain_error(format_args!("Suggested action: Repair or remove {path:?}."));
            print_plain_error("Suggested action: Run the original command again.");
        }
        ConfigurationError::InvalidSystemTime(_) => {
            print_plain_error("Suggested action: Correct the system clock.");
            print_plain_error("Suggested action: Run the original command again.");
        }
        _ => {
            print_plain_error("Suggested action: Correct the configuration error.");
            print_plain_error("Suggested action: Run the original command again.");
        }
    }
}

fn print_plain_error(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        eprintln!("{line}");
    }
}

fn print_progress(progress: CredentialRequestProgress) {
    print_message(progress_message(progress));
}

fn print_received_environment(credentials: &Credentials) {
    let mut names = credentials.environment_variable_names().peekable();
    if names.peek().is_none() {
        print_message("AgentKnock received no environment variables.");
        return;
    }

    print_message("AgentKnock received these environment variables:");
    for name in names {
        print_message(format_args!("- {name}"));
    }
}

fn print_profiles(profiles: &Profiles) {
    let profiles = profiles
        .iter()
        .map(|(name, profile)| {
            let environment = profile
                .environment
                .iter()
                .map(|(name, source)| {
                    (
                        name,
                        match source {
                            ValueSource::Stored => "STORED",
                            ValueSource::Issued => "ISSUED",
                        },
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            (
                name,
                serde_json::json!({
                    "description": profile.description,
                    "environment": environment,
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let output = serde_json::json!({"profiles": profiles});
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("profile metadata is valid JSON")
    );
}

fn working_directory() -> io::Result<String> {
    env::current_dir()?
        .into_os_string()
        .into_string()
        .map_err(|path| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("working directory is not valid UTF-8: {path:?}"),
            )
        })
}

#[cfg(target_os = "linux")]
fn standard_stream_kind(file_descriptor: u8, terminal: bool) -> StreamKind {
    if terminal {
        return StreamKind::Terminal;
    }

    let Ok(metadata) = std::fs::metadata(format!("/proc/self/fd/{file_descriptor}")) else {
        return StreamKind::Unknown;
    };
    let file_type = metadata.file_type();

    if file_type.is_fifo() {
        StreamKind::Pipe
    } else if file_type.is_socket() {
        StreamKind::Socket
    } else if file_type.is_file() {
        StreamKind::RegularFile
    } else if file_type.is_char_device()
        && std::fs::metadata("/dev/null")
            .is_ok_and(|null_device| metadata.rdev() == null_device.rdev())
    {
        StreamKind::NullDevice
    } else {
        StreamKind::Unknown
    }
}

#[cfg(not(target_os = "linux"))]
fn standard_stream_kind(_file_descriptor: u8, terminal: bool) -> StreamKind {
    if terminal {
        StreamKind::Terminal
    } else {
        StreamKind::Unknown
    }
}

#[cfg(unix)]
fn resolve_command_path(command: &str, working_directory: &Path) -> Option<String> {
    if command.contains('/') {
        let command = Path::new(command);
        let candidate = if command.is_absolute() {
            command.to_owned()
        } else {
            working_directory.join(command)
        };
        return resolve_executable(&candidate);
    }

    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            working_directory.join(directory)
        };
        let candidate = directory.join(command);
        if is_executable(&candidate) {
            return std::fs::canonicalize(candidate)
                .ok()?
                .into_os_string()
                .into_string()
                .ok();
        }
    }

    None
}

#[cfg(unix)]
fn resolve_executable(path: &Path) -> Option<String> {
    if !is_executable(path) {
        return None;
    }

    std::fs::canonicalize(path)
        .ok()?
        .into_os_string()
        .into_string()
        .ok()
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn resolve_command_path(_command: &str, _working_directory: &Path) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn launcher_chain() -> Vec<String> {
    let mut launchers = Vec::new();
    let mut process_id = std::process::id();

    for _ in 0..MAX_LAUNCHER_DEPTH {
        let status = match std::fs::read_to_string(format!("/proc/{process_id}/status")) {
            Ok(status) => status,
            Err(_) => break,
        };
        let Some(parent_id) = parent_id(&status) else {
            break;
        };
        if parent_id <= 1 || parent_id == process_id {
            break;
        }
        let executable = match std::fs::read_link(format!("/proc/{parent_id}/exe")) {
            Ok(executable) => executable,
            Err(_) => break,
        };
        let Some(executable) = executable.to_str() else {
            break;
        };
        launchers.push(executable.to_owned());
        process_id = parent_id;
    }

    launchers.reverse();
    launchers
}

#[cfg(target_os = "linux")]
fn parent_id(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
fn launcher_chain() -> Vec<String> {
    Vec::new()
}

fn progress_message(progress: CredentialRequestProgress) -> &'static str {
    match progress {
        CredentialRequestProgress::Preparing => "AgentKnock prepares the credentials request.",
        CredentialRequestProgress::WaitingForDelivery => {
            "AgentKnock waits for the phone to receive the credentials request."
        }
        CredentialRequestProgress::WaitingForResponse => {
            "The phone received the credentials request. AgentKnock waits for a response from the phone."
        }
        CredentialRequestProgress::Completing => {
            "AgentKnock received the credentials response. AgentKnock completes the request."
        }
        CredentialRequestProgress::Completed => "AgentKnock completed the credentials request.",
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

    #[cfg(target_os = "linux")]
    use super::parent_id;

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

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_parent_id_from_proc_status() {
        assert_eq!(parent_id("Name:\tbash\nPPid:\t1234\n"), Some(1234));
        assert_eq!(parent_id("Name:\tbash\n"), None);
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
            "AgentKnock waits for the phone to receive the credentials request."
        );
        assert_eq!(
            progress_message(WaitingForResponse),
            "The phone received the credentials request. AgentKnock waits for a response from the phone."
        );
        assert_eq!(
            progress_message(Completing),
            "AgentKnock received the credentials response. AgentKnock completes the request."
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
    fn parses_unpair_command() {
        let cli = Cli::try_parse_from(["agentknock", "--unpair"]).unwrap();

        assert_eq!(cli.into_operation(), Operation::Unpair { force: false });
    }

    #[test]
    fn parses_forced_unpair_command() {
        let cli = Cli::try_parse_from(["agentknock", "--unpair", "--force"]).unwrap();

        assert_eq!(cli.into_operation(), Operation::Unpair { force: true });
    }

    #[test]
    fn parses_list_command() {
        let cli = Cli::try_parse_from(["agentknock", "--list"]).unwrap();

        assert_eq!(cli.into_operation(), Operation::List);
    }

    #[test]
    fn rejects_force_without_unpair() {
        let error = Cli::try_parse_from(["agentknock", "--force"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
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
    fn rejects_unpair_argument() {
        let error = Cli::try_parse_from(["agentknock", "--unpair", "unexpected"]).unwrap_err();

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
