#[cfg(not(target_os = "linux"))]
compile_error!("the agentknock CLI currently supports Linux only");

mod executable;

use std::{
    cell::Cell,
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs,
    future::Future,
    io::{self, IsTerminal as _, Read as _},
    path::{Path, PathBuf},
    process::ExitCode,
    rc::Rc,
    str::FromStr,
    time::Duration,
};

use agentknock::{
    ConfigurationError, CredentialRequest, CredentialRequestProgress, Credentials, DenialReason,
    EnvironmentProfile, PairingProgress, PairingRemoveError, PairingSas, Profile,
    ProfileListProgress, ProfileUploadError, ProfileUploadMode, ProfileUploadProgress, Profiles,
    RequestError, RequestOperation, StreamKind, abort_pairing, finish_pairing_with_progress,
    force_remove_pairing, list_profiles_with_progress, remove_pairing_with_progress,
    start_pairing_with_progress, upload_profile_with_progress,
};
use clap::{ArgAction, Args, Parser, Subcommand, builder::NonEmptyStringValueParser};
use executable::{SelectedExecutable, SignalState};
use futures_util::FutureExt as _;
use thiserror::Error;

use agentknock::request_credentials_with_progress;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

const REQUEST_STATUS_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const MAX_LAUNCHER_DEPTH: usize = 4;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "agentknock",
    version,
    about = "Agentknock requests profile access and runs commands.",
    arg_required_else_help = true,
    subcommand_required = true,
    disable_help_subcommand = true,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Command {
    /// Run a command with access provided by one or more profiles.
    #[command(visible_alias = "x")]
    Exec(ExecCommand),

    /// Manage the pairing with an Agentknock device.
    #[command(
        arg_required_else_help = true,
        subcommand_required = true,
        disable_help_subcommand = true
    )]
    Pairing {
        #[command(subcommand)]
        command: PairingCommand,
    },

    /// Manage profiles from the paired device.
    #[command(
        arg_required_else_help = true,
        subcommand_required = true,
        disable_help_subcommand = true
    )]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
}

#[derive(Debug, Args, PartialEq, Eq)]
struct ExecCommand {
    /// Request access from this profile. Repeat for each profile.
    #[arg(
        short = 'p',
        long = "profile",
        action = ArgAction::Append,
        required = true,
        value_name = "PROFILE",
        value_parser = parse_profile
    )]
    profiles: Vec<String>,

    /// Give the reason for the profile access request.
    #[arg(
        long,
        value_name = "REASON",
        value_parser = NonEmptyStringValueParser::new()
    )]
    reason: Option<String>,

    /// Do not show Agentknock runtime output.
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,

    /// Show each profile access request state change immediately.
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,

    /// Command and arguments to run. The `--` separator is required.
    #[arg(last = true, num_args = 1.., required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum PairingCommand {
    /// Start pairing with an Agentknock device.
    Start {
        /// Pairing address shown by the device.
        #[arg(value_name = "PAIRING_ADDRESS", value_parser = parse_pairing_address)]
        address: String,
    },

    /// Finish a pending pairing after approval on the device.
    Finish,

    /// Abort a pending pairing.
    Abort,

    /// Remove an active pairing.
    Remove {
        /// Remove only the local pairing, without contacting the device.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum ProfileCommand {
    /// List the profiles available from the paired device.
    List,

    /// Upload a profile to the paired device.
    Upload(ProfileUploadCommand),
}

#[derive(Debug, Args, PartialEq, Eq)]
struct ProfileUploadCommand {
    /// New profile name, or existing profile name with --replace or --update.
    ///
    /// The device can rename a new profile before it accepts the profile.
    #[arg(value_name = "NAME", value_parser = parse_profile)]
    name: String,

    /// Profile description to send to the device.
    #[arg(long, value_name = "DESCRIPTION")]
    description: Option<String>,

    /// Replace the complete existing profile with this name.
    #[arg(long, conflicts_with = "update")]
    replace: bool,

    /// Update only the supplied fields in the existing profile with this name.
    #[arg(long, conflicts_with = "replace")]
    update: bool,

    #[command(flatten, next_help_heading = "Environment profile input")]
    environment: EnvironmentProfileInput,
}

#[derive(Debug, Args, PartialEq, Eq)]
#[group(required = true, multiple = true)]
struct EnvironmentProfileInput {
    /// Add environment variable NAME from the current environment.
    #[arg(long, action = ArgAction::Append, value_name = "NAME", value_parser = parse_environment_name)]
    from_env: Vec<String>,

    /// Add environment variable NAME from the contents of PATH. Use NAME=- for standard input.
    #[arg(long, action = ArgAction::Append, value_name = "NAME=PATH")]
    from_file: Vec<VariableFile>,

    /// Prompt for environment variable NAME without showing its value.
    #[arg(long, action = ArgAction::Append, value_name = "NAME", value_parser = parse_environment_name)]
    from_prompt: Vec<String>,

    /// Add environment variables from a dotenv file. Use - for standard input.
    #[arg(long, action = ArgAction::Append, value_name = "PATH", value_parser = parse_path)]
    from_env_file: Vec<PathBuf>,
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
    RemovePairing {
        force: bool,
    },
    ListProfiles,
    UploadProfile(ProfileUploadCommand),
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
    Remove,
}

#[derive(Debug)]
enum CommandError {
    ExecRequest(RequestError),
    ExecSelection { program: String, source: io::Error },
    ExecSignal(io::Error),
    ExecInterrupted,
    ExecProcess { program: String, source: io::Error },
    StartPairing(RequestError),
    FinishPairing(RequestError),
    AbortPairing(ConfigurationError),
    ForceRemovePairing(ConfigurationError),
    RemovePairing(PairingRemoveError),
    ListProfiles(RequestError),
    ProfileInput(ProfileInputError),
    UploadProfile(ProfileUploadError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VariableFile {
    name: String,
    path: PathBuf,
}

#[derive(Debug, Error)]
enum ProfileInputError {
    #[error("standard input can be used by only one profile source")]
    MultipleStdinSources,

    #[error("environment variable {name:?} is not set")]
    MissingEnvironmentVariable { name: String },

    #[error("environment variable {name:?} is not valid UTF-8")]
    NonUtf8EnvironmentVariable { name: String },

    #[error("could not read {source_name}: {source}")]
    Read {
        source_name: String,
        #[source]
        source: io::Error,
    },

    #[error("environment file {source_name} is invalid")]
    EnvironmentFile {
        source_name: String,
        #[source]
        source: dotenvy::Error,
    },

    #[error("environment variable name {name:?} is not a portable shell identifier")]
    InvalidEnvironmentVariableName { name: String },

    #[error("environment variable {name:?} was provided more than once")]
    DuplicateEnvironmentVariable { name: String },

    #[error("environment variable {name:?} contains a null byte")]
    NullEnvironmentVariable { name: String },

    #[error("the environment profile contains no variables")]
    NoEnvironmentVariables,

    #[error("could not read environment variable {name:?} from the terminal: {source}")]
    Prompt {
        name: String,
        #[source]
        source: io::Error,
    },
}

fn parse_profile(profile: &str) -> Result<String, &'static str> {
    if profile.is_empty() {
        Err("the profile name must not be empty")
    } else if profile.contains(',') {
        Err(
            "a profile name must not contain a comma; use a separate -p or --profile option for each profile",
        )
    } else {
        Ok(profile.to_owned())
    }
}

fn parse_environment_name(name: &str) -> Result<String, &'static str> {
    if valid_environment_name(name) {
        Ok(name.to_owned())
    } else {
        Err("the environment variable name must be a portable shell identifier")
    }
}

fn parse_path(path: &str) -> Result<PathBuf, &'static str> {
    if path.is_empty() {
        Err("the path must not be empty")
    } else {
        Ok(path.into())
    }
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl FromStr for VariableFile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, path) = value
            .split_once('=')
            .ok_or_else(|| "expected NAME=PATH".to_owned())?;
        parse_environment_name(name).map_err(str::to_owned)?;
        if path.is_empty() {
            return Err("the value path must not be empty".into());
        }
        Ok(Self {
            name: name.to_owned(),
            path: path.into(),
        })
    }
}

fn parse_pairing_address(address: &str) -> Result<String, &'static str> {
    if address
        .split('-')
        .all(|word| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase()))
    {
        Ok(address.to_owned())
    } else {
        Err("the pairing address must contain lowercase ASCII words separated by single hyphens")
    }
}

impl Cli {
    fn into_operation(self) -> (Operation, OutputMode) {
        match self.command {
            Command::Exec(command) => {
                let output = command.output_mode();
                (
                    Operation::Exec {
                        profiles: command.profiles,
                        reason: command.reason,
                        command: command.command,
                    },
                    output,
                )
            }
            Command::Pairing {
                command: PairingCommand::Start { address },
            } => (Operation::StartPairing(address), OutputMode::Normal),
            Command::Pairing {
                command: PairingCommand::Finish,
            } => (Operation::FinishPairing, OutputMode::Normal),
            Command::Pairing {
                command: PairingCommand::Abort,
            } => (Operation::AbortPairing, OutputMode::Normal),
            Command::Pairing {
                command: PairingCommand::Remove { force },
            } => (Operation::RemovePairing { force }, OutputMode::Normal),
            Command::Profile {
                command: ProfileCommand::List,
            } => (Operation::ListProfiles, OutputMode::Normal),
            Command::Profile {
                command: ProfileCommand::Upload(command),
            } => (Operation::UploadProfile(command), OutputMode::Normal),
        }
    }
}

impl ExecCommand {
    fn output_mode(&self) -> OutputMode {
        if self.quiet {
            OutputMode::Quiet
        } else if self.verbose {
            OutputMode::Verbose
        } else {
            OutputMode::Normal
        }
    }
}

fn exec_is_missing_separator(arguments: &[OsString]) -> bool {
    let Some(command) = arguments.get(1).and_then(|argument| argument.to_str()) else {
        return false;
    };
    if command != "exec" && command != "x" {
        return false;
    }

    let arguments = &arguments[2..];
    !arguments
        .iter()
        .any(|argument| argument == OsStr::new("--"))
        && !arguments.iter().any(|argument| {
            matches!(
                argument.to_str(),
                Some("-h" | "--help" | "-V" | "--version")
            )
        })
}

fn print_missing_exec_separator() {
    eprintln!("error: `--` is required before the command to execute");
    eprintln!();
    eprintln!("Usage: agentknock exec -p <PROFILE>... -- <COMMAND> [ARGUMENT]...");
    eprintln!();
    eprintln!("For more information, try '--help'.");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if exec_is_missing_separator(&arguments) {
        print_missing_exec_separator();
        return ExitCode::from(2);
    }

    let (operation, output) = Cli::parse_from(arguments).into_operation();
    match run(operation, output).await {
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
            let selected = SelectedExecutable::select(program).map_err(|source| {
                CommandError::ExecSelection {
                    program: program.clone(),
                    source,
                }
            })?;
            let signal_state = SignalState::capture().map_err(CommandError::ExecSignal)?;
            let launcher_chain = launcher_chain();
            let request = CredentialRequest {
                profiles: &profiles,
                operation: RequestOperation::Exec {
                    command: program,
                    arguments,
                    working_directory: selected.working_directory(),
                    executable_path: selected.path(),
                    executable_hash: selected.hash(),
                    executable_mode: selected.mode(),
                    stdin: standard_stream_kind(0, io::stdin().is_terminal()),
                    stdout: standard_stream_kind(1, io::stdout().is_terminal()),
                    stderr: standard_stream_kind(2, io::stderr().is_terminal()),
                },
                reason: reason.as_deref(),
                launcher_chain: &launcher_chain,
            };
            let mut signals = ExecSignals::new().map_err(CommandError::ExecSignal)?;
            let credentials = request_exec_credentials(request, output, &mut signals).await?;
            let blocked_signals = signal_state
                .block_interrupts()
                .map_err(CommandError::ExecSignal)?;
            if signals.received()
                || blocked_signals
                    .interrupted()
                    .map_err(CommandError::ExecSignal)?
            {
                return Err(CommandError::ExecInterrupted);
            }
            if output == OutputMode::Verbose {
                print_received_environment(&credentials);
                print_message(format_args!("Agentknock executes the command: {program}."));
            }
            let program = program.clone();
            selected
                .execute(arguments, credentials, &signal_state, blocked_signals)
                .map_err(|source| {
                    if source.kind() == io::ErrorKind::Interrupted {
                        CommandError::ExecInterrupted
                    } else {
                        CommandError::ExecProcess { program, source }
                    }
                })?;
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
            println!("Agentknock finished pairing. Agentknock is ready for use.");
        }
        Operation::AbortPairing => {
            abort_pairing().map_err(CommandError::AbortPairing)?;
            println!("Agentknock aborted the pending pairing. Agentknock is not paired.");
        }
        Operation::RemovePairing { force } => {
            if force {
                force_remove_pairing().map_err(CommandError::ForceRemovePairing)?;
                println!(
                    "Agentknock removed the local pairing. The device-side pairing was not changed."
                );
            } else {
                remove_pairing_for_cli()
                    .await
                    .map_err(CommandError::RemovePairing)?;
                println!("Agentknock removed this pairing.");
            }
        }
        Operation::ListProfiles => {
            let profiles = list_profiles_for_cli()
                .await
                .map_err(CommandError::ListProfiles)?;
            print_profiles(&profiles);
        }
        Operation::UploadProfile(command) => {
            let (profile, mode) = read_profile(command).map_err(CommandError::ProfileInput)?;
            upload_profile_for_cli(&profile, mode)
                .await
                .map_err(CommandError::UploadProfile)?;
            println!(
                "Agentknock delivered profile proposal {:?} to the device.",
                profile.name
            );
            println!("The profile proposal has not been accepted on the device.");
            println!("Suggested action: Review the profile proposal on the device.");
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

async fn remove_pairing_for_cli() -> Result<(), PairingRemoveError> {
    let progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&progress);
    let request = remove_pairing_with_progress(move |current| {
        observed_progress.set(Some(current));
    });
    monitor_operation(request, progress, move |progress| {
        pairing_progress_message(PairingOperation::Remove, progress)
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

async fn upload_profile_for_cli(
    profile: &EnvironmentProfile,
    mode: ProfileUploadMode,
) -> Result<(), ProfileUploadError> {
    let progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&progress);
    let request = upload_profile_with_progress(profile, mode, move |current| {
        observed_progress.set(Some(current));
    });
    monitor_operation(request, progress, profile_upload_progress_message).await
}

fn read_profile(
    command: ProfileUploadCommand,
) -> Result<(EnvironmentProfile, ProfileUploadMode), ProfileInputError> {
    let stdin_sources = command
        .environment
        .from_file
        .iter()
        .filter(|source| source.path == Path::new("-"))
        .count()
        + command
            .environment
            .from_env_file
            .iter()
            .filter(|path| path.as_path() == Path::new("-"))
            .count();
    if stdin_sources > 1 {
        return Err(ProfileInputError::MultipleStdinSources);
    }

    let mut variables = BTreeMap::new();
    for name in command.environment.from_env {
        let value = match env::var(&name) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => {
                return Err(ProfileInputError::MissingEnvironmentVariable { name });
            }
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ProfileInputError::NonUtf8EnvironmentVariable { name });
            }
        };
        insert_environment_variable(&mut variables, name, value)?;
    }
    for source in command.environment.from_file {
        let value = read_profile_source(&source.path)?;
        insert_environment_variable(&mut variables, source.name, value)?;
    }
    for path in command.environment.from_env_file {
        let source_name = profile_source_name(&path);
        let contents = read_profile_source(&path)?;
        for entry in dotenvy::from_read_iter(contents.as_bytes()) {
            let (name, value) = entry.map_err(|source| ProfileInputError::EnvironmentFile {
                source_name: source_name.clone(),
                source,
            })?;
            if !valid_environment_name(&name) {
                return Err(ProfileInputError::InvalidEnvironmentVariableName { name });
            }
            insert_environment_variable(&mut variables, name, value)?;
        }
    }
    for name in command.environment.from_prompt {
        if variables.contains_key(&name) {
            return Err(ProfileInputError::DuplicateEnvironmentVariable { name });
        }
        let value =
            rpassword::prompt_password(format!("Value for {name}: ")).map_err(|source| {
                ProfileInputError::Prompt {
                    name: name.clone(),
                    source,
                }
            })?;
        insert_environment_variable(&mut variables, name, value)?;
    }
    if variables.is_empty() {
        return Err(ProfileInputError::NoEnvironmentVariables);
    }

    let mode = if command.replace {
        ProfileUploadMode::Replace
    } else if command.update {
        ProfileUploadMode::Update
    } else {
        ProfileUploadMode::Create
    };
    Ok((
        EnvironmentProfile {
            name: command.name,
            description: command.description,
            variables,
        },
        mode,
    ))
}

fn read_profile_source(path: &Path) -> Result<String, ProfileInputError> {
    let source_name = profile_source_name(path);
    if path == Path::new("-") {
        let mut contents = String::new();
        io::stdin()
            .read_to_string(&mut contents)
            .map_err(|source| ProfileInputError::Read {
                source_name,
                source,
            })?;
        Ok(contents)
    } else {
        fs::read_to_string(path).map_err(|source| ProfileInputError::Read {
            source_name,
            source,
        })
    }
}

fn profile_source_name(path: &Path) -> String {
    if path == Path::new("-") {
        "standard input".into()
    } else {
        format!("{path:?}")
    }
}

fn insert_environment_variable(
    variables: &mut BTreeMap<String, String>,
    name: String,
    value: String,
) -> Result<(), ProfileInputError> {
    if value.contains('\0') {
        return Err(ProfileInputError::NullEnvironmentVariable { name });
    }
    if variables.insert(name.clone(), value).is_some() {
        return Err(ProfileInputError::DuplicateEnvironmentVariable { name });
    }
    Ok(())
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
        ProfileListProgress::Preparing => "Agentknock prepares the profile list request.",
        ProfileListProgress::WaitingForDelivery => {
            "Agentknock waits for the device to receive the profile list request."
        }
        ProfileListProgress::WaitingForResponse => {
            "The device received the profile list request. Agentknock waits for a response from the device."
        }
        ProfileListProgress::Completing => {
            "Agentknock received the profile list. Agentknock confirms receipt."
        }
        ProfileListProgress::Completed => "Agentknock completed the profile list request.",
    }
}

fn profile_upload_progress_message(progress: ProfileUploadProgress) -> &'static str {
    match progress {
        ProfileUploadProgress::Preparing => "Agentknock prepares the profile proposal.",
        ProfileUploadProgress::WaitingForDelivery => {
            "Agentknock waits for the device to receive the profile proposal."
        }
        ProfileUploadProgress::WaitingForResponse => {
            "The device received the profile proposal. Agentknock waits for durable receipt confirmation."
        }
        ProfileUploadProgress::Completing => {
            "The device stored the profile proposal. Agentknock confirms receipt."
        }
        ProfileUploadProgress::Completed => {
            "Agentknock completed delivery of the profile proposal."
        }
    }
}

fn pairing_progress_message(
    operation: PairingOperation,
    progress: PairingProgress,
) -> &'static str {
    match (operation, progress) {
        (PairingOperation::Start, PairingProgress::Preparing) => {
            "Agentknock prepares the pairing request."
        }
        (PairingOperation::Start, PairingProgress::WaitingForDelivery) => {
            "Agentknock waits for the device to receive the pairing request."
        }
        (PairingOperation::Start, PairingProgress::WaitingForResponse) => {
            "The device received the pairing request. Agentknock waits for a response from the device."
        }
        (PairingOperation::Start, PairingProgress::Completing) => {
            "Agentknock received the pairing response. Agentknock saves the pending pairing."
        }
        (PairingOperation::Start, PairingProgress::Completed) => {
            "Agentknock completed the pairing request."
        }
        (PairingOperation::Finish, PairingProgress::Preparing) => {
            "Agentknock prepares the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::WaitingForDelivery) => {
            "Agentknock waits for the device to receive the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::WaitingForResponse) => {
            "The device received the pairing confirmation. Agentknock waits for a response from the device."
        }
        (PairingOperation::Finish, PairingProgress::Completing) => {
            "The device accepted the pairing. Agentknock saves the active pairing."
        }
        (PairingOperation::Finish, PairingProgress::Completed) => {
            "Agentknock completed the pairing confirmation."
        }
        (PairingOperation::Remove, PairingProgress::Preparing) => {
            "Agentknock prepares the pairing removal request."
        }
        (PairingOperation::Remove, PairingProgress::WaitingForDelivery) => {
            "Agentknock waits for the device to receive the pairing removal request."
        }
        (PairingOperation::Remove, PairingProgress::WaitingForResponse) => {
            "The device received the pairing removal request. Agentknock waits for a response from the device."
        }
        (PairingOperation::Remove, PairingProgress::Completing) => {
            "The device accepted the pairing removal request. Agentknock removes the local pairing."
        }
        (PairingOperation::Remove, PairingProgress::Completed) => {
            "Agentknock completed the pairing removal request."
        }
    }
}

struct ExecSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl ExecSignals {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    fn received(&mut self) -> bool {
        self.interrupt.recv().now_or_never().flatten().is_some()
            || self.terminate.recv().now_or_never().flatten().is_some()
    }
}

async fn request_exec_credentials(
    request: CredentialRequest<'_>,
    output: OutputMode,
    signals: &mut ExecSignals,
) -> Result<Credentials, CommandError> {
    use tokio::time::{Instant, sleep};

    let current_progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&current_progress);
    let interrupt = &mut signals.interrupt;
    let terminate = &mut signals.terminate;
    let request = request_credentials_with_progress(
        request,
        async {
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
    println!("Agentknock started the pairing process.");
    println!("Verification code:");
    println!("{sas}");
    println!("Suggested action: Compare the verification code with the code on the device.");
    println!("Suggested action: If the codes match, approve the pairing on the device.");
    println!("Suggested action: After approval, run this command:");
    println!("agentknock pairing finish");
}

fn print_command_error(error: &CommandError, output: OutputMode) {
    match error {
        CommandError::ExecRequest(error) if output != OutputMode::Quiet => {
            print_exec_request_error(error);
        }
        CommandError::ExecSelection { program, source } if output != OutputMode::Quiet => {
            print_message(format_args!(
                "Agentknock could not select the command {program:?}: {source}."
            ));
            print_message("The profile access request did not start.");
            match source.kind() {
                io::ErrorKind::NotFound => {
                    print_message("Suggested action: Correct the command name or path.");
                }
                io::ErrorKind::PermissionDenied => {
                    print_message(
                        "Suggested action: Make the command executable or correct its access permissions.",
                    );
                }
                _ => {}
            }
        }
        CommandError::ExecSignal(source) if output != OutputMode::Quiet => {
            print_message(format_args!(
                "A signal-handling error stopped the profile access request: {source}."
            ));
            print_message("The command did not start.");
        }
        CommandError::ExecInterrupted if output != OutputMode::Quiet => {
            print_message("A signal interrupted Agentknock. The command did not start.");
        }
        CommandError::ExecProcess { program, source } if output != OutputMode::Quiet => {
            print_message(format_args!(
                "The device approved the profile access request. Agentknock did not execute the command {program:?}: {source}."
            ));
            match source.kind() {
                io::ErrorKind::NotFound => {
                    print_message(
                        "Suggested action: Check the selected script path or executable interpreter.",
                    );
                }
                io::ErrorKind::PermissionDenied => {
                    print_message(
                        "Suggested action: Make the command executable or correct its access permissions.",
                    );
                }
                _ => {}
            }
        }
        CommandError::ExecRequest(_)
        | CommandError::ExecSelection { .. }
        | CommandError::ExecSignal(_)
        | CommandError::ExecInterrupted
        | CommandError::ExecProcess { .. } => {}
        CommandError::StartPairing(error) => print_start_pairing_error(error),
        CommandError::FinishPairing(error) => print_finish_pairing_error(error),
        CommandError::AbortPairing(error) => print_abort_pairing_error(error),
        CommandError::ForceRemovePairing(error) => print_force_remove_pairing_error(error),
        CommandError::RemovePairing(error) => print_remove_pairing_error(error),
        CommandError::ListProfiles(error) => print_list_error(error),
        CommandError::ProfileInput(error) => {
            print_plain_error(format_args!(
                "Agentknock could not read the profile proposal: {error}."
            ));
        }
        CommandError::UploadProfile(error) => print_upload_error(error),
    }
}

fn print_upload_error(error: &ProfileUploadError) {
    match error {
        ProfileUploadError::Rejected { message } => {
            print_plain_error(format_args!(
                "The device rejected the profile proposal: {message}"
            ));
            print_plain_error("Agentknock did not deliver the profile proposal.");
        }
        ProfileUploadError::Request(RequestError::Configuration(
            ConfigurationError::NoPairing { .. },
        )) => {
            print_plain_error("Agentknock is not paired. It cannot upload a profile.");
            print_plain_error("Suggested action: Get a pairing address.");
            print_plain_error("Suggested action: Run this command:");
            print_plain_error("agentknock pairing start <PAIRING_ADDRESS>");
        }
        ProfileUploadError::Request(RequestError::Configuration(
            ConfigurationError::PairingPending { .. },
        )) => {
            print_plain_error("Pairing is in progress. Agentknock cannot upload a profile yet.");
        }
        ProfileUploadError::Request(RequestError::Configuration(error)) => {
            print_plain_error(format_args!(
                "Agentknock did not deliver the profile proposal: {error}."
            ));
            print_plain_configuration_action(error);
        }
        ProfileUploadError::Request(RequestError::RelayUnavailable { .. }) => {
            print_plain_error(format_args!(
                "Agentknock did not deliver the profile proposal: {error}."
            ));
            print_plain_error(
                "Suggested action: After relay connectivity is restored, run the original command again.",
            );
        }
        ProfileUploadError::Request(RequestError::Unauthenticated { code, message }) => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error("Agentknock did not deliver the profile proposal.");
            print_plain_unauthenticated_action(code);
        }
        ProfileUploadError::Request(RequestError::ClientInactive { message }) => {
            print_plain_error(format_args!(
                "The relay reports that this paired client is not active: {message}"
            ));
            print_plain_error("Agentknock did not deliver the profile proposal.");
        }
        ProfileUploadError::Request(RequestError::InvalidTestRelayUrl) => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_plain_error("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
        }
        ProfileUploadError::Request(error) => {
            print_plain_error(format_args!(
                "Agentknock did not deliver the profile proposal: {error}."
            ));
        }
    }
}

fn print_list_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("Agentknock is not paired. It cannot list profiles.");
            print_plain_error("Suggested action: Get a pairing address.");
            print_plain_error("Suggested action: Run this command:");
            print_plain_error("agentknock pairing start <PAIRING_ADDRESS>");
        }
        RequestError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error("Pairing is in progress. Agentknock cannot list profiles yet.");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("Agentknock did not list profiles: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::RelayUnavailable { .. } => {
            print_plain_error(format_args!("Agentknock did not list profiles: {error}."));
            print_plain_error("Suggested action: After relay connectivity is restored, run:");
            print_plain_error("agentknock profile list");
        }
        RequestError::Relay(_) => {
            print_plain_error(format_args!("Agentknock did not list profiles: {error}."));
        }
        RequestError::Unauthenticated { code, message } => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error("Agentknock did not list profiles.");
            print_plain_error(
                "Agentknock did not change the local pairing because of this report.",
            );
            print_plain_unauthenticated_action(code);
        }
        RequestError::ClientInactive { message } => {
            print_plain_error(format_args!(
                "The relay reports that this paired client is not active: {message}"
            ));
            print_plain_error("Agentknock did not list profiles.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_plain_error("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
        }
        _ => {
            print_plain_error(format_args!("Agentknock did not list profiles: {error}."));
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
                "The profile access request was denied on the device: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Denied {
            reason: DenialReason::PolicyDenied,
            message,
        } => {
            print_message(format_args!(
                "The policy denied the profile access request: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Denied {
            reason: DenialReason::InvalidRequest,
            message,
        } => {
            print_message(format_args!(
                "The profile access request was invalid: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Denied {
            reason: DenialReason::Other,
            message,
        } => {
            print_message(format_args!(
                "The profile access request was denied: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Interrupted => {
            print_message(
                "A signal interrupted the profile access request. The command did not start.",
            );
        }
        RequestError::RelayUnavailable { failures } => {
            print_message(format_args!(
                "Agentknock did not receive a relay response after {failures} consecutive errors."
            ));
            print_message("The command did not start.");
            print_message(
                "Suggested action: After relay connectivity is restored, run the original command again.",
            );
        }
        RequestError::Relay(source) => {
            print_message(format_args!("The profile access request failed: {source}."));
            print_message("The command did not start.");
        }
        RequestError::Unauthenticated { code, message } => {
            print_unauthenticated_report(code, message);
            print_message("The command did not start.");
            print_message("Agentknock did not change the local pairing because of this report.");
            print_unauthenticated_action(code);
        }
        RequestError::ClientInactive { message } => {
            print_message(format_args!(
                "The relay reports that this paired client is not active: {message}"
            ));
            print_message("The command did not start.");
        }
        RequestError::Protocol(source) => {
            print_message(format_args!(
                "A protocol error stopped the profile access request: {source}."
            ));
            print_message("The command did not start.");
        }
        RequestError::UnexpectedRelayStatus(status) => {
            print_message(format_args!(
                "The relay returned HTTP status {status}. Agentknock did not expect this status."
            ));
            print_message("The command did not start.");
        }
        RequestError::PairingRejected => {
            print_message("The paired device rejected the client pairing.");
            print_message("The command did not start.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_message("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_message("The command did not start.");
            print_message("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
        }
    }
}

fn print_exec_configuration_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_message("Agentknock is not paired. The command did not start.");
            print_message("Suggested action: Get a pairing address.");
            print_message("Suggested action: Run this command:");
            print_message("agentknock pairing start <PAIRING_ADDRESS>");
            print_message("Suggested action: Complete pairing.");
            print_message("Suggested action: Run the original command again.");
        }
        ConfigurationError::PairingPending { .. } => {
            print_message("Pairing is in progress. The command did not start.");
        }
        ConfigurationError::InsecurePermissions { path, mode } => {
            print_message(format_args!(
                "Pairing configuration {path:?} has mode {mode:04o}. Mode 0600 is required."
            ));
            print_message("The command did not start.");
            print_message("Suggested action: Run this command:");
            print_message(format_args!("chmod 600 {path:?}"));
        }
        ConfigurationError::HomeNotSet => {
            print_message("HOME is not set. Agentknock cannot find the pairing configuration.");
            print_message("The command did not start.");
            print_message("Suggested action: Set HOME to the correct home directory.");
        }
        ConfigurationError::Invalid { path, source } => {
            print_message(format_args!(
                "The pairing configuration at {path:?} is invalid: {source}."
            ));
            print_message("The command did not start.");
        }
        ConfigurationError::InvalidSystemTime(_) => {
            print_message(format_args!("The system clock is invalid: {error}."));
            print_message("The command did not start.");
            print_message("Suggested action: Correct the system clock.");
        }
        _ => {
            print_message(format_args!(
                "A pairing configuration error stopped the command: {error}."
            ));
        }
    }
}

fn print_start_pairing_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error("Pairing is already in progress.");
        }
        RequestError::Configuration(ConfigurationError::PairingExists { .. }) => {
            print_plain_error("Agentknock is already paired and ready for use.");
            print_plain_error("Agentknock did not change the existing pairing.");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("Agentknock did not start pairing: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::RelayUnavailable { .. } => {
            print_plain_error(format_args!("Agentknock did not start pairing: {error}."));
            print_plain_error(
                "Suggested action: After relay connectivity is restored, run the original command again.",
            );
        }
        RequestError::Relay(_) => {
            print_plain_error(format_args!("Agentknock did not start pairing: {error}."));
        }
        RequestError::Unauthenticated { code, message } => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error(
                "Agentknock did not change the pairing state because of this report.",
            );
            print_plain_unauthenticated_action(code);
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_plain_error("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
        }
        _ => {
            print_plain_error(format_args!("Agentknock did not start pairing: {error}."));
        }
    }
}

fn print_finish_pairing_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("No pairing is in progress.");
            print_plain_error("Suggested action: Get a pairing address.");
            print_plain_error("Suggested action: Run this command:");
            print_plain_error("agentknock pairing start <PAIRING_ADDRESS>");
        }
        RequestError::Configuration(ConfigurationError::PairingNotPending { .. }) => {
            print_plain_error("Pairing is complete. Agentknock is ready for use.");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("Agentknock did not finish pairing: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::PairingRejected => {
            print_plain_error(
                "The device rejected the pairing. Agentknock kept the pending pairing.",
            );
        }
        RequestError::Unauthenticated { code, message } => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error(
                "Agentknock did not change the pairing state because of this report.",
            );
            print_plain_unauthenticated_action(code);
        }
        RequestError::ClientInactive { message } => {
            print_plain_error(format_args!(
                "The relay reports that the pending client is not active: {message}"
            ));
            print_plain_error("Agentknock kept the pending pairing.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL is not valid UTF-8.");
            print_plain_error("Suggested action: Correct or unset AGENTKNOCK_TEST_RELAY_URL.");
        }
        _ => {
            print_plain_error(format_args!("Agentknock did not finish pairing: {error}."));
        }
    }
}

fn print_abort_pairing_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_plain_error("Agentknock has no pairing to abort.");
        }
        ConfigurationError::PairingNotPending { .. } => {
            print_plain_error("Pairing is active. Agentknock can abort only a pending pairing.");
            print_plain_error("Agentknock did not change the active pairing.");
        }
        _ => {
            print_plain_error(format_args!(
                "Agentknock did not abort the pending pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_remove_pairing_error(error: &PairingRemoveError) {
    match error {
        PairingRemoveError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("Agentknock is not paired. There is no active pairing to remove.");
        }
        PairingRemoveError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error(
                "Pairing is in progress. Agentknock did not remove the pending pairing.",
            );
            print_plain_error("Suggested action: To abort the pending pairing, run this command:");
            print_plain_error("agentknock pairing abort");
        }
        PairingRemoveError::Configuration(error) => {
            print_plain_error(format_args!(
                "Agentknock did not start pairing removal: {error}."
            ));
            print_plain_configuration_action(error);
        }
        PairingRemoveError::Request(error) => {
            match error {
                RequestError::Unauthenticated { code, message } => {
                    print_plain_unauthenticated_report(code, message);
                    print_plain_unauthenticated_action(code);
                }
                RequestError::ClientInactive { message } => {
                    print_plain_error(format_args!(
                        "The relay reports that this paired client is not active: {message}"
                    ));
                }
                _ => {
                    print_plain_error(format_args!(
                        "Agentknock did not receive a valid pairing removal response: {error}."
                    ));
                }
            }
            print_plain_error("The local pairing is unchanged. The device-side result is unknown.");
        }
        PairingRemoveError::LocalState(ConfigurationError::PairingChanged { .. }) => {
            print_plain_error(
                "The device accepted the pairing removal request, but the local pairing changed.",
            );
            print_plain_error("Agentknock did not remove the current local pairing.");
        }
        PairingRemoveError::LocalState(error) => {
            print_plain_error(format_args!(
                "The device accepted the pairing removal request, but Agentknock did not remove the local pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_unauthenticated_report(code: &str, message: &str) {
    print_message(format_args!(
        "Agentknock received this error report: {code:?}: {message:?}."
    ));
    print_message(
        "Agentknock could not authenticate the report. The device or relay could have sent it.",
    );
}

fn print_plain_unauthenticated_report(code: &str, message: &str) {
    print_plain_error(format_args!(
        "Agentknock received this error report: {code:?}: {message:?}."
    ));
    print_plain_error(
        "Agentknock could not authenticate the report. The device or relay could have sent it.",
    );
}

fn print_unauthenticated_action(code: &str) {
    if code == "UNSUPPORTED_PROTOCOL_VERSION" {
        print_message(
            "Suggested action: Make sure that Agentknock and the device support the same protocol version.",
        );
    }
}

fn print_plain_unauthenticated_action(code: &str) {
    if code == "UNSUPPORTED_PROTOCOL_VERSION" {
        print_plain_error(
            "Suggested action: Make sure that Agentknock and the device support the same protocol version.",
        );
    }
}

fn print_force_remove_pairing_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_plain_error("Agentknock is not paired. There is no local pairing to remove.");
        }
        _ => {
            print_plain_error(format_args!(
                "Agentknock did not remove the local pairing: {error}."
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
        }
        ConfigurationError::HomeNotSet => {
            print_plain_error("Suggested action: Set HOME to the correct home directory.");
        }
        ConfigurationError::InvalidSystemTime(_) => {
            print_plain_error("Suggested action: Correct the system clock.");
        }
        _ => {}
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
        print_message("Agentknock received no environment variables.");
        return;
    }

    print_message("Agentknock received these environment variables:");
    for name in names {
        print_message(format_args!("- {name}"));
    }
}

fn print_profiles(profiles: &Profiles) {
    let profiles = profiles
        .iter()
        .map(|(name, profile)| {
            let output = match profile {
                Profile::Environment {
                    description,
                    variables,
                } => serde_json::json!({
                    "description": description,
                    "type": "environment",
                    "variables": variables,
                }),
            };
            (name, output)
        })
        .collect::<BTreeMap<_, _>>();
    let output = serde_json::json!({"profiles": profiles});
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("profile metadata is valid JSON")
    );
}

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

fn parent_id(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

fn progress_message(progress: CredentialRequestProgress) -> &'static str {
    match progress {
        CredentialRequestProgress::Preparing => "Agentknock prepares the profile access request.",
        CredentialRequestProgress::WaitingForDelivery => {
            "Agentknock waits for the device to receive the profile access request."
        }
        CredentialRequestProgress::WaitingForResponse => {
            "The device received the profile access request. Agentknock waits for a response from the device."
        }
        CredentialRequestProgress::Completing => {
            "Agentknock received a response to the profile access request. Agentknock completes the request."
        }
        CredentialRequestProgress::Completed => "Agentknock completed the profile access request.",
    }
}

fn print_message(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        eprintln!("AGENTKNOCK: {line}");
    }
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::{
        Cli, EnvironmentProfileInput, Operation, OutputMode, ProfileUploadCommand, VariableFile,
        exec_is_missing_separator, progress_message,
    };

    #[cfg(target_os = "linux")]
    use super::parent_id;

    #[test]
    fn parses_exec_command() {
        let cli = Cli::try_parse_from([
            "agentknock",
            "exec",
            "-p",
            "gh-token",
            "--profile",
            "cf-wrangler",
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
            (
                Operation::Exec {
                    profiles: vec!["gh-token".into(), "cf-wrangler".into()],
                    reason: Some("needed by the deployment agent".into()),
                    command: ["sh", "-c", "printf '%s' \"$TOKEN\""]
                        .map(String::from)
                        .to_vec(),
                },
                OutputMode::Normal,
            )
        );
    }

    #[test]
    fn parses_exec_alias() {
        let cli = Cli::try_parse_from(["agentknock", "x", "-p", "github", "--", "true"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (
                Operation::Exec {
                    profiles: vec!["github".into()],
                    reason: None,
                    command: vec!["true".into()],
                },
                OutputMode::Normal,
            )
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
            Cli::try_parse_from(["agentknock", "exec", "-p", "profile", "--", "true"]).unwrap();
        let quiet = Cli::try_parse_from([
            "agentknock",
            "exec",
            "--quiet",
            "-p",
            "profile",
            "--",
            "true",
        ])
        .unwrap();
        let verbose = Cli::try_parse_from([
            "agentknock",
            "exec",
            "--verbose",
            "-p",
            "profile",
            "--",
            "true",
        ])
        .unwrap();

        assert_eq!(normal.into_operation().1, OutputMode::Normal);
        assert_eq!(quiet.into_operation().1, OutputMode::Quiet);
        assert_eq!(verbose.into_operation().1, OutputMode::Verbose);
    }

    #[test]
    fn rejects_quiet_and_verbose_together() {
        let error = Cli::try_parse_from([
            "agentknock",
            "exec",
            "--quiet",
            "--verbose",
            "-p",
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
            "Agentknock waits for the device to receive the profile access request."
        );
        assert_eq!(
            progress_message(WaitingForResponse),
            "The device received the profile access request. Agentknock waits for a response from the device."
        );
        assert_eq!(
            progress_message(Completing),
            "Agentknock received a response to the profile access request. Agentknock completes the request."
        );
    }

    #[test]
    fn parses_start_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "pairing", "start", "pairing-address-name"])
            .unwrap();

        assert_eq!(
            cli.into_operation(),
            (
                Operation::StartPairing("pairing-address-name".into()),
                OutputMode::Normal,
            )
        );
    }

    #[test]
    fn rejects_invalid_pairing_address() {
        for address in [
            "yup-its-free-",
            "yup--its-free",
            "Yup-its-free",
            "yup_its_free",
            "yup-its-frée",
        ] {
            let error =
                Cli::try_parse_from(["agentknock", "pairing", "start", address]).unwrap_err();

            assert_eq!(error.kind(), ErrorKind::ValueValidation);
        }

        for address in ["-", "--", "-yup-its-free", "--help"] {
            let error =
                Cli::try_parse_from(["agentknock", "pairing", "start", "--", address]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn parses_finish_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "pairing", "finish"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (Operation::FinishPairing, OutputMode::Normal)
        );
    }

    #[test]
    fn parses_abort_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "pairing", "abort"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (Operation::AbortPairing, OutputMode::Normal)
        );
    }

    #[test]
    fn parses_remove_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "pairing", "remove"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (
                Operation::RemovePairing { force: false },
                OutputMode::Normal
            )
        );
    }

    #[test]
    fn parses_forced_remove_pairing_command() {
        let cli = Cli::try_parse_from(["agentknock", "pairing", "remove", "--force"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (Operation::RemovePairing { force: true }, OutputMode::Normal)
        );
    }

    #[test]
    fn parses_profile_list_command() {
        let cli = Cli::try_parse_from(["agentknock", "profile", "list"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (Operation::ListProfiles, OutputMode::Normal)
        );
    }

    #[test]
    fn parses_profile_upload_command() {
        let cli = Cli::try_parse_from([
            "agentknock",
            "profile",
            "upload",
            "github",
            "--description",
            "GitHub API access",
            "--update",
            "--from-env",
            "GH_TOKEN",
            "--from-file",
            "GH_HOST=host",
            "--from-env-file",
            "shared.env",
            "--from-prompt",
            "GH_SECRET",
        ])
        .unwrap();

        assert_eq!(
            cli.into_operation(),
            (
                Operation::UploadProfile(ProfileUploadCommand {
                    name: "github".into(),
                    description: Some("GitHub API access".into()),
                    replace: false,
                    update: true,
                    environment: EnvironmentProfileInput {
                        from_env: vec!["GH_TOKEN".into()],
                        from_file: vec![VariableFile {
                            name: "GH_HOST".into(),
                            path: "host".into(),
                        }],
                        from_prompt: vec!["GH_SECRET".into()],
                        from_env_file: vec!["shared.env".into()],
                    },
                }),
                OutputMode::Normal,
            )
        );
    }

    #[test]
    fn describes_profile_upload_without_assuming_an_environment_profile() {
        let help = Cli::try_parse_from(["agentknock", "profile", "upload", "--help"]).unwrap_err();

        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        let help = help.to_string();
        assert!(help.contains("Upload a profile to the paired device"));
        assert!(help.contains("Environment profile input:"));
        assert!(
            help.contains("New profile name, or existing profile name with --replace or --update.")
        );
        assert!(!help.contains("Suggested profile name"));
    }

    #[test]
    fn requires_a_profile_upload_source() {
        let error = Cli::try_parse_from(["agentknock", "profile", "upload", "github"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn rejects_multiple_profile_upload_modes() {
        let error = Cli::try_parse_from([
            "agentknock",
            "profile",
            "upload",
            "github",
            "--replace",
            "--update",
            "--from-env",
            "GH_TOKEN",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn rejects_finish_pairing_argument() {
        let error =
            Cli::try_parse_from(["agentknock", "pairing", "finish", "unexpected"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn rejects_abort_pairing_argument() {
        let error =
            Cli::try_parse_from(["agentknock", "pairing", "abort", "unexpected"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn rejects_remove_pairing_argument() {
        let error =
            Cli::try_parse_from(["agentknock", "pairing", "remove", "unexpected"]).unwrap_err();

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
    fn shows_help_without_a_pairing_command() {
        let error = Cli::try_parse_from(["agentknock", "pairing"]).unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn shows_help_without_a_profile_command() {
        let error = Cli::try_parse_from(["agentknock", "profile"]).unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn does_not_define_help_subcommands() {
        let root_error = Cli::try_parse_from(["agentknock", "help"]).unwrap_err();
        let pairing_error = Cli::try_parse_from(["agentknock", "pairing", "help"]).unwrap_err();
        let profile_error = Cli::try_parse_from(["agentknock", "profile", "help"]).unwrap_err();

        assert_eq!(root_error.kind(), ErrorKind::InvalidSubcommand);
        assert_eq!(pairing_error.kind(), ErrorKind::InvalidSubcommand);
        assert_eq!(profile_error.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn accepts_help_as_a_pairing_address() {
        let cli = Cli::try_parse_from(["agentknock", "pairing", "start", "help"]).unwrap();

        assert_eq!(
            cli.into_operation(),
            (Operation::StartPairing("help".into()), OutputMode::Normal,)
        );
    }

    #[test]
    fn rejects_space_separated_profiles() {
        let error = Cli::try_parse_from([
            "agentknock",
            "exec",
            "-p",
            "gh-token",
            "cf-wrangler",
            "--",
            "echo",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn identifies_exec_without_separator() {
        assert!(exec_is_missing_separator(&[
            "agentknock".into(),
            "exec".into(),
            "-p".into(),
            "gh-token".into(),
            "echo".into(),
        ]));
        assert!(exec_is_missing_separator(&[
            "agentknock".into(),
            "x".into(),
            "-p".into(),
            "gh-token".into(),
            "echo".into(),
        ]));
        assert!(!exec_is_missing_separator(&[
            "agentknock".into(),
            "exec".into(),
            "--help".into(),
        ]));
    }

    #[test]
    fn rejects_empty_command_after_delimiter() {
        let error =
            Cli::try_parse_from(["agentknock", "exec", "-p", "gh-token", "--"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn rejects_comma_separated_profiles() {
        let error = Cli::try_parse_from([
            "agentknock",
            "exec",
            "-p",
            "gh-token,cf-wrangler",
            "--",
            "echo",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_arguments() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let invalid_utf8 = OsString::from_vec(vec![0xff]);
        let cases = [
            vec![
                "agentknock".into(),
                "exec".into(),
                "-p".into(),
                invalid_utf8.clone(),
                "--".into(),
                "echo".into(),
            ],
            vec![
                "agentknock".into(),
                "exec".into(),
                "-p".into(),
                "gh-token".into(),
                "--".into(),
                invalid_utf8.clone(),
            ],
            vec![
                "agentknock".into(),
                "exec".into(),
                "-p".into(),
                "gh-token".into(),
                "--".into(),
                "echo".into(),
                invalid_utf8,
            ],
            vec![
                "agentknock".into(),
                "profile".into(),
                "upload".into(),
                "test".into(),
                "--from-env-file".into(),
                OsString::from_vec(vec![0xff]),
            ],
        ];

        for arguments in cases {
            let error = Cli::try_parse_from(arguments).unwrap_err();

            assert_eq!(error.kind(), ErrorKind::InvalidUtf8);
        }
    }
}
