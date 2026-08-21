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

const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const MAX_LAUNCHER_DEPTH: usize = 4;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "agentknock",
    version,
    about = "Request profile access, manage profiles, and pair with a device.",
    long_about = "Pair this client with a device, request access to profiles stored on the device, and send profile proposals to the device.\n\nBefore you request or manage profiles, use `agentknock pairing start` and `agentknock pairing finish` to pair this client. Commands that wait for the device report their progress every 30 seconds. All command-line arguments must be valid UTF-8.",
    max_term_width = 120,
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
    /// Request access to profiles, then run a command.
    ///
    /// The request includes the profile names, optional reason, command, and arguments. It also
    /// includes the working directory, selected executable path, SHA-256 hash when available,
    /// paths of the programs that launched Agentknock, and how standard input, output, and error
    /// are connected. If the device approves the request, Agentknock adds the returned variables to
    /// the command's environment. Returned values replace existing values with the same names.
    /// Agentknock then replaces itself with the command.
    ///
    /// Specify each profile with a separate `--profile` option. The `--` separator is required;
    /// Agentknock treats everything after it as the command and its arguments. Agentknock doesn't
    /// invoke a shell or interpret those arguments.
    ///
    /// If multiple profiles provide the same environment variable, their values must match.
    /// Otherwise, Agentknock doesn't run the command.
    ///
    /// Agentknock writes its messages to standard error. The command inherits standard input,
    /// standard output, and standard error. While the request waits for the device, Agentknock
    /// reports progress and total elapsed time every 30 seconds unless you use `--quiet`.
    /// Interrupting Agentknock prevents the command from running.
    ///
    /// You can use `agentknock x` as a shorter alias for `agentknock exec`.
    #[command(
        visible_alias = "x",
        after_long_help = "Examples:\n  Request one profile:\n    agentknock exec -p github -- gh issue list\n\n  Request multiple profiles and explain why:\n    agentknock exec -p github -p cloudflare --reason \"Deploy the release\" -- wrangler deploy"
    )]
    Exec(ExecCommand),

    /// Pair this client with a device or remove its pairing.
    ///
    /// Pairing creates an encrypted relationship between this client and one device. Start with
    /// the pairing address displayed on the device, confirm the full verification code, approve
    /// the pairing on the device, and then finish the pairing on this client.
    ///
    /// This client can have only one pairing, either pending or active. Abort a pending pairing if
    /// you don't complete it. Remove an active pairing when this client must no longer access the
    /// device.
    #[command(
        arg_required_else_help = true,
        subcommand_required = true,
        disable_help_subcommand = true
    )]
    Pairing {
        #[command(subcommand)]
        command: PairingCommand,
    },

    /// List profiles or send a profile proposal to the paired device.
    ///
    /// A profile defines data or operations that the paired device can provide. This version of
    /// Agentknock can request environment profiles and send environment profile proposals.
    ///
    /// Profile commands require an active pairing. Listing returns profile metadata without
    /// secret values. Uploading sends secret values to the device in an encrypted proposal.
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
    /// Name of a profile to request from the device.
    ///
    /// Repeat this option to request more than one profile. A profile name can't be empty or
    /// contain a comma. To find available names, use `agentknock profile list`.
    #[arg(
        short = 'p',
        long = "profile",
        action = ArgAction::Append,
        required = true,
        value_name = "PROFILE",
        value_parser = parse_profile
    )]
    profiles: Vec<String>,

    /// Explanation for why the command needs profile access.
    ///
    /// Agentknock sends this text unchanged to the device as part of the access request.
    #[arg(
        long,
        value_name = "REASON",
        value_parser = NonEmptyStringValueParser::new()
    )]
    reason: Option<String>,

    /// Suppress Agentknock request and command-launch messages.
    ///
    /// This option doesn't suppress output from the command.
    #[arg(long, conflicts_with = "verbose")]
    quiet: bool,

    /// Show each profile access request state change.
    ///
    /// Before Agentknock runs the command, it lists the names of the environment variables that
    /// it received. It never displays their values.
    #[arg(long, conflicts_with = "quiet")]
    verbose: bool,

    /// Executable name or path, followed by its arguments.
    ///
    /// Put the command after the required `--` separator. If the executable name doesn't contain
    /// a slash, Agentknock searches `PATH`, or the system default search path if `PATH` isn't set.
    /// Agentknock passes each argument unchanged.
    #[arg(last = true, num_args = 1.., required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum PairingCommand {
    /// Start pairing with a device.
    ///
    /// Use the pairing address displayed on the device to create a pending pairing. Agentknock
    /// displays a 12-digit verification code. Confirm the full code on the device before you
    /// approve the pairing.
    ///
    /// If the codes match, approve the pairing on the device and then use `agentknock pairing
    /// finish`. If they don't match, reject the pairing on the device and use `agentknock pairing
    /// abort`.
    ///
    /// This command doesn't replace an existing pending or active pairing.
    ///
    /// While the request waits for the device, Agentknock reports progress and total elapsed time
    /// every 30 seconds.
    Start {
        /// Exact pairing address displayed on the device.
        ///
        /// The address contains lowercase ASCII words separated by single hyphens, such as
        /// `calm-river-lantern`.
        #[arg(value_name = "PAIRING_ADDRESS", value_parser = parse_pairing_address)]
        address: String,
    },

    /// Activate a pairing that you approved on the device.
    ///
    /// Use this command after `agentknock pairing start`, but only after you confirm that the full
    /// verification code matches and approve the pairing on the device. Agentknock asks the device
    /// to confirm the pairing and then marks the local pairing as active.
    ///
    /// If the verification codes don't match, use `agentknock pairing abort` instead.
    ///
    /// While the request waits for the device, Agentknock reports progress and total elapsed time
    /// every 30 seconds.
    Finish,

    /// Discard a pending pairing.
    ///
    /// Use this command if you reject or abandon a pairing, including when the verification codes
    /// don't match. Agentknock deletes the pending pairing from this client without contacting the
    /// device.
    ///
    /// This command doesn't remove an active pairing. To remove one, use `agentknock pairing
    /// remove`.
    Abort,

    /// Remove an active pairing from this client and the device.
    ///
    /// By default, Agentknock asks the device to remove the pairing and waits for an authenticated
    /// response before it deletes the local pairing. After removal, this client can no longer
    /// request profiles from the device.
    ///
    /// If the device can't be contacted, use `--force` to delete only the local pairing.
    /// Without `--force`, Agentknock reports progress and total elapsed time every 30 seconds while
    /// it waits for the device.
    Remove {
        /// Delete only the local pairing without contacting the device.
        ///
        /// The device retains its pairing record. Use this option only when normal removal can't
        /// complete, such as when the device is no longer available.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum ProfileCommand {
    /// List profiles available from the paired device.
    ///
    /// Request metadata for the profiles that this client can access. Agentknock writes a JSON
    /// object to standard output. Each profile includes its type, optional description, and the
    /// environment variable names that it provides. The output never includes secret values.
    ///
    /// Agentknock writes progress and error messages to standard error, so you can redirect or
    /// process the JSON output separately.
    ///
    /// While the request waits for the device, Agentknock reports progress and total elapsed time
    /// every 30 seconds.
    #[command(
        after_long_help = "Example output:\n  {\n    \"profiles\": {\n      \"github\": {\n        \"description\": \"GitHub API access\",\n        \"type\": \"environment\",\n        \"variables\": [\"GH_TOKEN\"]\n      }\n    }\n  }"
    )]
    List,

    /// Send a profile proposal to the paired device.
    ///
    /// Build an environment profile from one or more local sources and send it to the paired
    /// device in an encrypted proposal. The command completes after the device confirms that it
    /// stored the proposal. The device doesn't apply the proposed changes until you accept them;
    /// Agentknock doesn't wait for that decision.
    ///
    /// Without `--replace` or `--update`, the proposal creates a profile when accepted. Use
    /// `--replace` to propose replacing an existing profile completely. Use `--update` to propose
    /// changing supplied variables while retaining variables that you don't supply.
    ///
    /// You can combine and repeat input options, but each environment variable name can occur only
    /// once. At most one input can read from standard input. Names must be portable shell variable
    /// names, and all names and values must be valid UTF-8.
    ///
    /// While the proposal waits for the device, Agentknock reports progress and total elapsed time
    /// every 30 seconds.
    #[command(
        after_long_help = "Examples:\n  Create a profile from the current environment:\n    agentknock profile upload github --description \"GitHub API access\" --from-env GH_TOKEN\n\n  Create a profile from a dotenv file:\n    agentknock profile upload development --from-env-file .env\n\n  Update one variable in an existing profile:\n    agentknock profile upload github --update --from-prompt GH_TOKEN"
    )]
    Upload(ProfileUploadCommand),
}

#[derive(Debug, Args, PartialEq, Eq)]
struct ProfileUploadCommand {
    /// Name of the new or existing profile.
    ///
    /// Without `--replace` or `--update`, this value is the proposed name for a new profile. You
    /// can rename the profile when you accept it on the device.
    ///
    /// With `--replace` or `--update`, use the exact name of the existing profile. The device
    /// doesn't rename an existing profile. A profile name can't be empty or contain a comma.
    #[arg(value_name = "NAME", value_parser = parse_profile)]
    name: String,

    /// Description for the profile.
    ///
    /// With `--update`, omit this option to retain the existing description. Specify an empty
    /// string to remove the description.
    #[arg(long, value_name = "DESCRIPTION")]
    description: Option<String>,

    /// Propose replacing an existing profile with the supplied profile.
    ///
    /// Existing environment variables that you don't supply are removed.
    #[arg(long, conflicts_with = "update")]
    replace: bool,

    /// Propose updating the supplied fields in an existing profile.
    ///
    /// Existing environment variables that you don't supply are retained.
    #[arg(long, conflicts_with = "replace")]
    update: bool,

    #[command(flatten, next_help_heading = "Environment variable sources")]
    environment: EnvironmentProfileInput,
}

#[derive(Debug, Args, PartialEq, Eq)]
#[group(required = true, multiple = true)]
struct EnvironmentProfileInput {
    /// Read an environment variable from the current process environment.
    ///
    /// NAME is both the source and destination variable name. Repeat this option to read more
    /// variables.
    #[arg(long, action = ArgAction::Append, value_name = "NAME", value_parser = parse_environment_name)]
    from_env: Vec<String>,

    /// Read an environment variable value from a file.
    ///
    /// Use `NAME=PATH`, where NAME is the destination variable name. Agentknock reads the complete
    /// file without trimming whitespace. Use `NAME=-` to read the value from standard input.
    /// Repeat this option to read more variables.
    #[arg(long, action = ArgAction::Append, value_name = "NAME=PATH")]
    from_file: Vec<VariableFile>,

    /// Prompt for an environment variable without displaying its value.
    ///
    /// NAME is the destination variable name. Repeat this option to prompt for more variables.
    #[arg(long, action = ArgAction::Append, value_name = "NAME", value_parser = parse_environment_name)]
    from_prompt: Vec<String>,

    /// Read environment variables from a dotenv file.
    ///
    /// Agentknock uses the names and values defined in the file. Use `-` to read dotenv data from
    /// standard input. Repeat this option to read more files.
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
    #[error("only one profile source can read from standard input")]
    MultipleStdinSources,

    #[error("environment variable {name:?} isn't set")]
    MissingEnvironmentVariable { name: String },

    #[error("environment variable {name:?} isn't valid UTF-8")]
    NonUtf8EnvironmentVariable { name: String },

    #[error("couldn't read {source_name}: {source}")]
    Read {
        source_name: String,
        #[source]
        source: io::Error,
    },

    #[error("environment file {source_name} isn't valid")]
    EnvironmentFile {
        source_name: String,
        #[source]
        source: dotenvy::Error,
    },

    #[error("environment variable name {name:?} isn't a portable shell identifier")]
    InvalidEnvironmentVariableName { name: String },

    #[error("environment variable {name:?} was provided more than once")]
    DuplicateEnvironmentVariable { name: String },

    #[error("environment variable {name:?} contains a null byte")]
    NullEnvironmentVariable { name: String },

    #[error("the environment profile doesn't contain any variables")]
    NoEnvironmentVariables,

    #[error("couldn't read environment variable {name:?} from the terminal: {source}")]
    Prompt {
        name: String,
        #[source]
        source: io::Error,
    },
}

fn parse_profile(profile: &str) -> Result<String, &'static str> {
    if profile.is_empty() {
        Err("the profile name can't be empty")
    } else if profile.contains(',') {
        Err("a profile name can't contain a comma. Repeat -p or --profile for each profile")
    } else {
        Ok(profile.to_owned())
    }
}

fn parse_environment_name(name: &str) -> Result<String, &'static str> {
    if valid_environment_name(name) {
        Ok(name.to_owned())
    } else {
        Err("the environment variable name isn't a portable shell identifier")
    }
}

fn parse_path(path: &str) -> Result<PathBuf, &'static str> {
    if path.is_empty() {
        Err("the path can't be empty")
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
            .ok_or_else(|| "use NAME=PATH".to_owned())?;
        parse_environment_name(name).map_err(str::to_owned)?;
        if path.is_empty() {
            return Err("PATH can't be empty".into());
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
        Err("use lowercase ASCII words separated by single hyphens")
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
    eprintln!("error: add `--` before the command to run");
    eprintln!();
    eprintln!("Usage: agentknock exec -p <PROFILE>... -- <COMMAND> [ARGUMENT]...");
    eprintln!();
    eprintln!("For more information, run 'agentknock exec --help'.");
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
                print_message(format_args!("Running command {program:?}."));
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
            println!("Pairing complete. Agentknock is ready to request profile access.");
        }
        Operation::AbortPairing => {
            abort_pairing().map_err(CommandError::AbortPairing)?;
            println!("Pending pairing discarded.");
        }
        Operation::RemovePairing { force } => {
            if force {
                force_remove_pairing().map_err(CommandError::ForceRemovePairing)?;
                println!("Local pairing removed. The pairing on the device is unchanged.");
            } else {
                remove_pairing_for_cli()
                    .await
                    .map_err(CommandError::RemovePairing)?;
                println!("Pairing removed from this client and the device.");
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
                "Profile proposal {:?} delivered to the device.",
                profile.name
            );
            println!("The profile isn't available until you accept the proposal on the device.");
            println!("Suggested action: Review the proposal on the device.");
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
    let started = Instant::now();
    let heartbeat = sleep(PROGRESS_INTERVAL);
    tokio::pin!(heartbeat);
    loop {
        tokio::select! {
            biased;
            result = request.as_mut() => return result,
            _ = heartbeat.as_mut() => {
                if let Some(progress) = progress.get() {
                    eprintln!("{}", progress_report(progress_message(progress), started.elapsed()));
                }
                heartbeat.as_mut().reset(Instant::now() + PROGRESS_INTERVAL);
            }
        }
    }
}

fn progress_report(message: &str, elapsed: Duration) -> String {
    format!("{message} Elapsed time: {}.", format_elapsed_time(elapsed))
}

fn format_elapsed_time(elapsed: Duration) -> String {
    let total_seconds = elapsed.as_secs();
    let units = [
        ("day", total_seconds / 86_400),
        ("hour", total_seconds % 86_400 / 3_600),
        ("minute", total_seconds % 3_600 / 60),
        ("second", total_seconds % 60),
    ];
    let parts = units
        .into_iter()
        .filter(|(_, value)| *value != 0)
        .map(|(unit, value)| {
            let suffix = if value == 1 { "" } else { "s" };
            format!("{value} {unit}{suffix}")
        })
        .collect::<Vec<_>>();

    if parts.is_empty() {
        "0 seconds".into()
    } else {
        parts.join(" ")
    }
}

fn profile_list_progress_message(progress: ProfileListProgress) -> &'static str {
    match progress {
        ProfileListProgress::Preparing => "Preparing the profile list request.",
        ProfileListProgress::WaitingForDelivery => {
            "Waiting for the device to receive the profile list request."
        }
        ProfileListProgress::WaitingForResponse => {
            "The device received the profile list request. Waiting for its response."
        }
        ProfileListProgress::Completing => {
            "Profile list received. Confirming receipt with the device."
        }
        ProfileListProgress::Completed => "Profile list request complete.",
    }
}

fn profile_upload_progress_message(progress: ProfileUploadProgress) -> &'static str {
    match progress {
        ProfileUploadProgress::Preparing => "Preparing the profile proposal.",
        ProfileUploadProgress::WaitingForDelivery => {
            "Waiting for the device to receive the profile proposal."
        }
        ProfileUploadProgress::WaitingForResponse => {
            "The device received the profile proposal. Waiting for confirmation that it saved the proposal."
        }
        ProfileUploadProgress::Completing => "Device response received. Confirming receipt.",
        ProfileUploadProgress::Completed => "Profile proposal request complete.",
    }
}

fn pairing_progress_message(
    operation: PairingOperation,
    progress: PairingProgress,
) -> &'static str {
    match (operation, progress) {
        (PairingOperation::Start, PairingProgress::Preparing) => "Preparing the pairing request.",
        (PairingOperation::Start, PairingProgress::WaitingForDelivery) => {
            "Waiting for the device to receive the pairing request."
        }
        (PairingOperation::Start, PairingProgress::WaitingForResponse) => {
            "The device received the pairing request. Waiting for its response."
        }
        (PairingOperation::Start, PairingProgress::Completing) => {
            "Pairing response received. Saving the pending pairing."
        }
        (PairingOperation::Start, PairingProgress::Completed) => "Pairing request complete.",
        (PairingOperation::Finish, PairingProgress::Preparing) => {
            "Preparing the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::WaitingForDelivery) => {
            "Waiting for the device to receive the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::WaitingForResponse) => {
            "The device received the pairing confirmation. Waiting for its response."
        }
        (PairingOperation::Finish, PairingProgress::Completing) => {
            "Device response received. Processing the pairing confirmation."
        }
        (PairingOperation::Finish, PairingProgress::Completed) => "Pairing activated.",
        (PairingOperation::Remove, PairingProgress::Preparing) => {
            "Preparing the pairing removal request."
        }
        (PairingOperation::Remove, PairingProgress::WaitingForDelivery) => {
            "Waiting for the device to receive the pairing removal request."
        }
        (PairingOperation::Remove, PairingProgress::WaitingForResponse) => {
            "The device received the pairing removal request. Waiting for its response."
        }
        (PairingOperation::Remove, PairingProgress::Completing) => {
            "Device response received. Processing the pairing removal."
        }
        (PairingOperation::Remove, PairingProgress::Completed) => "Pairing removal complete.",
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
    let started = Instant::now();
    let heartbeat = sleep(PROGRESS_INTERVAL);
    tokio::pin!(heartbeat);

    loop {
        tokio::select! {
            biased;
            result = request.as_mut() => return result.map_err(CommandError::ExecRequest),
            _ = heartbeat.as_mut(), if output != OutputMode::Quiet => {
                if let Some(progress) = current_progress.get() {
                    print_message(progress_report(progress_message(progress), started.elapsed()));
                }
                heartbeat.as_mut().reset(Instant::now() + PROGRESS_INTERVAL);
            }
        }
    }
}

fn print_start_pairing_success(sas: &PairingSas) {
    println!("Pairing started.");
    println!("Verification code:");
    println!("{sas}");
    println!("Compare the full verification code with the code on the device.");
    println!("If the codes match, approve the pairing on the device. Then run:");
    println!("agentknock pairing finish");
    println!("If the codes don't match, reject the pairing on the device. Then run:");
    println!("agentknock pairing abort");
}

fn print_command_error(error: &CommandError, output: OutputMode) {
    match error {
        CommandError::ExecRequest(error) if output != OutputMode::Quiet => {
            print_exec_request_error(error);
        }
        CommandError::ExecSelection { program, source } if output != OutputMode::Quiet => {
            match source.kind() {
                io::ErrorKind::NotFound => {
                    print_message(format_args!("Command {program:?} wasn't found."));
                }
                io::ErrorKind::PermissionDenied => {
                    print_message(format_args!(
                        "Agentknock can't run command {program:?}: {source}."
                    ));
                }
                _ => {
                    print_message(format_args!(
                        "Agentknock couldn't prepare command {program:?}: {source}."
                    ));
                }
            }
            print_message("No profile access request was sent.");
            match source.kind() {
                io::ErrorKind::NotFound => {
                    print_message("Suggested action: Check the command name or path.");
                }
                io::ErrorKind::PermissionDenied => {
                    print_message("Suggested action: Check the command's execute permissions.");
                }
                _ => {}
            }
        }
        CommandError::ExecSignal(source) if output != OutputMode::Quiet => {
            print_message(format_args!(
                "Agentknock couldn't configure signal handling: {source}."
            ));
            print_message("The command didn't run.");
        }
        CommandError::ExecInterrupted if output != OutputMode::Quiet => {
            print_message(
                "Agentknock received an interrupt or termination signal. The command didn't run.",
            );
        }
        CommandError::ExecProcess { program, source } if output != OutputMode::Quiet => {
            print_message(format_args!(
                "Profile access was approved, but Agentknock couldn't run command {program:?}: {source}."
            ));
            match source.kind() {
                io::ErrorKind::NotFound => {
                    print_message(
                        "Suggested action: Check that the command and its interpreter still exist.",
                    );
                }
                io::ErrorKind::PermissionDenied => {
                    print_message("Suggested action: Check the command's execute permissions.");
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
                "Couldn't create the profile proposal: {error}."
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
        }
        ProfileUploadError::Request(RequestError::Configuration(
            ConfigurationError::NoPairing { .. },
        )) => {
            print_plain_error("Agentknock isn't paired, so it can't send the profile proposal.");
            print_plain_error("Suggested action: Get a pairing address, then run:");
            print_plain_error("agentknock pairing start <PAIRING_ADDRESS>");
        }
        ProfileUploadError::Request(RequestError::Configuration(
            ConfigurationError::PairingPending { .. },
        )) => {
            print_plain_error(
                "Pairing is waiting for confirmation, so Agentknock can't send the profile proposal.",
            );
            print_plain_error("Suggested action: After you approve the pairing, run:");
            print_plain_error("agentknock pairing finish");
        }
        ProfileUploadError::Request(RequestError::Configuration(error)) => {
            print_plain_error(format_args!(
                "Agentknock couldn't send the profile proposal: {error}."
            ));
            print_plain_configuration_action(error);
        }
        ProfileUploadError::Request(RequestError::RelayUnavailable { failures }) => {
            print_plain_error(format_args!(
                "Agentknock couldn't confirm delivery after {failures} consecutive relay errors."
            ));
            print_plain_error(
                "Suggested action: Check whether the proposal reached the device before you try again.",
            );
        }
        ProfileUploadError::Request(RequestError::Unauthenticated { code, message }) => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error(
                "Agentknock didn't receive authenticated confirmation that the device saved the proposal.",
            );
            print_plain_unauthenticated_action(code);
        }
        ProfileUploadError::Request(RequestError::ClientInactive { message }) => {
            print_plain_error(format_args!(
                "The relay reports that this paired client is inactive: {message}"
            ));
            print_plain_error("The profile proposal wasn't delivered.");
        }
        ProfileUploadError::Request(RequestError::InvalidTestRelayUrl) => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL isn't valid UTF-8.");
            print_plain_error(
                "Suggested action: Set AGENTKNOCK_TEST_RELAY_URL to valid UTF-8 or unset it.",
            );
        }
        ProfileUploadError::Request(error) => {
            print_plain_error(format_args!(
                "Agentknock couldn't send the profile proposal: {error}."
            ));
        }
    }
}

fn print_list_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("Agentknock isn't paired, so it can't list profiles.");
            print_plain_error("Suggested action: Get a pairing address, then run:");
            print_plain_error("agentknock pairing start <PAIRING_ADDRESS>");
        }
        RequestError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error(
                "Pairing is waiting for confirmation, so Agentknock can't list profiles.",
            );
            print_plain_error("Suggested action: After you approve the pairing, run:");
            print_plain_error("agentknock pairing finish");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("Agentknock couldn't list profiles: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::RelayUnavailable { .. } => {
            print_plain_error(format_args!("Agentknock couldn't list profiles: {error}."));
            print_plain_error("Suggested action: Check relay connectivity, then run:");
            print_plain_error("agentknock profile list");
        }
        RequestError::Relay(_) => {
            print_plain_error(format_args!("Agentknock couldn't list profiles: {error}."));
        }
        RequestError::Unauthenticated { code, message } => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error("Agentknock didn't receive a profile list.");
            print_plain_error("The unauthenticated report didn't change the local pairing.");
            print_plain_unauthenticated_action(code);
        }
        RequestError::ClientInactive { message } => {
            print_plain_error(format_args!(
                "The relay reports that this paired client is inactive: {message}"
            ));
            print_plain_error("Agentknock didn't receive a profile list.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL isn't valid UTF-8.");
            print_plain_error(
                "Suggested action: Set AGENTKNOCK_TEST_RELAY_URL to valid UTF-8 or unset it.",
            );
        }
        _ => {
            print_plain_error(format_args!("Agentknock couldn't list profiles: {error}."));
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
                "The device denied the profile access request: {message}"
            ));
            print_message("The command didn't run.");
        }
        RequestError::Denied {
            reason: DenialReason::PolicyDenied,
            message,
        } => {
            print_message(format_args!(
                "Device policy denied the profile access request: {message}"
            ));
            print_message("The command didn't run.");
        }
        RequestError::Denied {
            reason: DenialReason::InvalidRequest,
            message,
        } => {
            print_message(format_args!(
                "The device rejected the profile access request as invalid: {message}"
            ));
            print_message("The command didn't run.");
        }
        RequestError::Denied {
            reason: DenialReason::Other,
            message,
        } => {
            print_message(format_args!(
                "The profile access request was denied: {message}"
            ));
            print_message("The command didn't run.");
        }
        RequestError::Interrupted => {
            print_message(
                "Agentknock received a signal and canceled the profile access request. The command didn't run.",
            );
        }
        RequestError::RelayUnavailable { failures } => {
            print_message(format_args!(
                "Agentknock couldn't reach the relay after {failures} consecutive errors."
            ));
            print_message("The command didn't run.");
            print_message(
                "Suggested action: Check the network connection and relay status, then run the command again.",
            );
        }
        RequestError::Relay(source) => {
            print_message(format_args!(
                "The profile access request failed because of a relay error: {source}."
            ));
            print_message("The command didn't run.");
        }
        RequestError::Unauthenticated { code, message } => {
            print_unauthenticated_report(code, message);
            print_message("The command didn't run.");
            print_message("The unauthenticated report didn't change the local pairing.");
            print_unauthenticated_action(code);
        }
        RequestError::ClientInactive { message } => {
            print_message(format_args!(
                "The relay reports that this paired client is inactive: {message}"
            ));
            print_message("The command didn't run.");
        }
        RequestError::Protocol(source) => {
            print_message(format_args!(
                "The profile access request failed because of a protocol error: {source}."
            ));
            print_message("The command didn't run.");
        }
        RequestError::UnexpectedRelayStatus(status) => {
            print_message(format_args!(
                "The relay returned unexpected HTTP status {status}."
            ));
            print_message("The command didn't run.");
        }
        RequestError::PairingRejected => {
            print_message("The device rejected this client pairing.");
            print_message("The command didn't run.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_message("AGENTKNOCK_TEST_RELAY_URL isn't valid UTF-8.");
            print_message("The command didn't run.");
            print_message(
                "Suggested action: Set AGENTKNOCK_TEST_RELAY_URL to valid UTF-8 or unset it.",
            );
        }
    }
}

fn print_exec_configuration_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_message("Agentknock isn't paired, so the command didn't run.");
            print_message("Suggested action: Get a pairing address, then run:");
            print_message("agentknock pairing start <PAIRING_ADDRESS>");
        }
        ConfigurationError::PairingPending { .. } => {
            print_message("Pairing is waiting for confirmation, so the command didn't run.");
            print_message("Suggested action: After you approve the pairing, run:");
            print_message("agentknock pairing finish");
        }
        ConfigurationError::InsecurePermissions { path, mode } => {
            print_message(format_args!(
                "Pairing file {path:?} has permissions {mode:04o}. Agentknock requires 0600."
            ));
            print_message("The command didn't run.");
            print_message("Suggested action: Run:");
            print_message(format_args!("chmod 600 {path:?}"));
        }
        ConfigurationError::HomeNotSet => {
            print_message(
                "The HOME environment variable isn't set, so Agentknock can't find the pairing file.",
            );
            print_message("The command didn't run.");
            print_message("Suggested action: Set HOME to your home directory.");
        }
        ConfigurationError::Invalid { path, source } => {
            print_message(format_args!("Pairing file {path:?} isn't valid: {source}."));
            print_message("The command didn't run.");
        }
        ConfigurationError::InvalidSystemTime(_) => {
            print_message(format_args!("The system clock isn't valid: {error}."));
            print_message("The command didn't run.");
            print_message("Suggested action: Correct the system clock.");
        }
        _ => {
            print_message(format_args!(
                "The command didn't run because of a pairing error: {error}."
            ));
        }
    }
}

fn print_start_pairing_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error("A pairing is already waiting for confirmation.");
            print_plain_error("To activate it after approval, run:");
            print_plain_error("agentknock pairing finish");
            print_plain_error("To discard it, run:");
            print_plain_error("agentknock pairing abort");
        }
        RequestError::Configuration(ConfigurationError::PairingExists { .. }) => {
            print_plain_error("Agentknock is already paired. The existing pairing is unchanged.");
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("Agentknock couldn't start pairing: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::RelayUnavailable { failures } => {
            print_plain_error(format_args!(
                "Agentknock couldn't reach the relay after {failures} consecutive errors. Pairing didn't start."
            ));
            print_plain_error(
                "Suggested action: Check the network connection and relay status, then run this command again.",
            );
        }
        RequestError::Relay(source) => {
            print_plain_error(format_args!(
                "Pairing didn't start because of a relay error: {source}."
            ));
        }
        RequestError::Unauthenticated { code, message } => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error("Pairing didn't start. The local pairing state is unchanged.");
            print_plain_unauthenticated_action(code);
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL isn't valid UTF-8.");
            print_plain_error(
                "Suggested action: Set AGENTKNOCK_TEST_RELAY_URL to valid UTF-8 or unset it.",
            );
        }
        _ => {
            print_plain_error(format_args!("Agentknock couldn't start pairing: {error}."));
        }
    }
}

fn print_finish_pairing_error(error: &RequestError) {
    match error {
        RequestError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("No pairing is waiting for confirmation.");
            print_plain_error("Suggested action: Get a pairing address, then run:");
            print_plain_error("agentknock pairing start <PAIRING_ADDRESS>");
        }
        RequestError::Configuration(ConfigurationError::PairingNotPending { .. }) => {
            print_plain_error(
                "Pairing is already complete. Agentknock is ready to request profile access.",
            );
        }
        RequestError::Configuration(error) => {
            print_plain_error(format_args!("Agentknock couldn't finish pairing: {error}."));
            print_plain_configuration_action(error);
        }
        RequestError::PairingRejected => {
            print_plain_error(
                "The device rejected the pairing. The pending pairing remains saved.",
            );
            print_plain_error("Suggested action: To discard the pending pairing, run:");
            print_plain_error("agentknock pairing abort");
        }
        RequestError::Unauthenticated { code, message } => {
            print_plain_unauthenticated_report(code, message);
            print_plain_error("The unauthenticated report didn't change the local pairing.");
            print_plain_unauthenticated_action(code);
        }
        RequestError::ClientInactive { message } => {
            print_plain_error(format_args!(
                "The relay reports that the pending client is inactive: {message}"
            ));
            print_plain_error("The pending pairing remains saved.");
        }
        RequestError::InvalidTestRelayUrl => {
            print_plain_error("AGENTKNOCK_TEST_RELAY_URL isn't valid UTF-8.");
            print_plain_error(
                "Suggested action: Set AGENTKNOCK_TEST_RELAY_URL to valid UTF-8 or unset it.",
            );
        }
        _ => {
            print_plain_error(format_args!("Agentknock couldn't finish pairing: {error}."));
        }
    }
}

fn print_abort_pairing_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_plain_error("No pending pairing exists.");
        }
        ConfigurationError::PairingNotPending { .. } => {
            print_plain_error(
                "The pairing is active, so there isn't a pending pairing to discard.",
            );
            print_plain_error("The active pairing is unchanged.");
            print_plain_error("Suggested action: To remove the active pairing, run:");
            print_plain_error("agentknock pairing remove");
        }
        _ => {
            print_plain_error(format_args!(
                "Agentknock couldn't discard the pending pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_remove_pairing_error(error: &PairingRemoveError) {
    match error {
        PairingRemoveError::Configuration(ConfigurationError::NoPairing { .. }) => {
            print_plain_error("No active pairing exists.");
        }
        PairingRemoveError::Configuration(ConfigurationError::PairingPending { .. }) => {
            print_plain_error("A pairing is waiting for confirmation. It wasn't removed.");
            print_plain_error("Suggested action: To discard the pending pairing, run:");
            print_plain_error("agentknock pairing abort");
        }
        PairingRemoveError::Configuration(error) => {
            print_plain_error(format_args!(
                "Agentknock couldn't start pairing removal: {error}."
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
                        "The relay reports that this paired client is inactive: {message}"
                    ));
                }
                _ => {
                    print_plain_error(format_args!(
                        "Agentknock didn't receive a valid pairing removal response: {error}."
                    ));
                }
            }
            print_plain_error("The local pairing is unchanged. The device state is unknown.");
        }
        PairingRemoveError::LocalState(ConfigurationError::PairingChanged { .. }) => {
            print_plain_error(
                "The device removed the pairing, but the local pairing changed during the request.",
            );
            print_plain_error("Agentknock kept the current local pairing.");
        }
        PairingRemoveError::LocalState(error) => {
            print_plain_error(format_args!(
                "The device removed the pairing, but Agentknock couldn't remove the local pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_unauthenticated_report(code: &str, message: &str) {
    print_message(format_args!(
        "Received an unauthenticated error report ({code:?}): {message:?}."
    ));
    print_message("The report could have come from the relay instead of the device.");
}

fn print_plain_unauthenticated_report(code: &str, message: &str) {
    print_plain_error(format_args!(
        "Received an unauthenticated error report ({code:?}): {message:?}."
    ));
    print_plain_error("The report could have come from the relay instead of the device.");
}

fn print_unauthenticated_action(code: &str) {
    if code == "UNSUPPORTED_PROTOCOL_VERSION" {
        print_message(
            "Suggested action: Use Agentknock and device software that support the same protocol version.",
        );
    }
}

fn print_plain_unauthenticated_action(code: &str) {
    if code == "UNSUPPORTED_PROTOCOL_VERSION" {
        print_plain_error(
            "Suggested action: Use Agentknock and device software that support the same protocol version.",
        );
    }
}

fn print_force_remove_pairing_error(error: &ConfigurationError) {
    match error {
        ConfigurationError::NoPairing { .. } => {
            print_plain_error("No local pairing exists.");
        }
        _ => {
            print_plain_error(format_args!(
                "Agentknock couldn't remove the local pairing: {error}."
            ));
            print_plain_configuration_action(error);
        }
    }
}

fn print_plain_configuration_action(error: &ConfigurationError) {
    match error {
        ConfigurationError::InsecurePermissions { path, .. } => {
            print_plain_error("Suggested action: Run:");
            print_plain_error(format_args!("chmod 600 {path:?}"));
        }
        ConfigurationError::HomeNotSet => {
            print_plain_error("Suggested action: Set HOME to your home directory.");
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
        print_message(
            "Profile access approved, but the profiles provided no environment variables.",
        );
        return;
    }

    print_message("Profile access approved. Received these environment variables:");
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
        CredentialRequestProgress::Preparing => "Preparing the profile access request.",
        CredentialRequestProgress::WaitingForDelivery => {
            "Waiting for the device to receive the profile access request."
        }
        CredentialRequestProgress::WaitingForResponse => {
            "The device received the profile access request. Waiting for its response."
        }
        CredentialRequestProgress::Completing => "Device response received. Confirming receipt.",
        CredentialRequestProgress::Completed => "Profile access request complete.",
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
        exec_is_missing_separator, format_elapsed_time, progress_message, progress_report,
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
            "Waiting for the device to receive the profile access request."
        );
        assert_eq!(
            progress_message(WaitingForResponse),
            "The device received the profile access request. Waiting for its response."
        );
        assert_eq!(
            progress_message(Completing),
            "Device response received. Confirming receipt."
        );
    }

    #[test]
    fn formats_elapsed_time_for_progress_reports() {
        use std::time::Duration;

        assert_eq!(format_elapsed_time(Duration::ZERO), "0 seconds");
        assert_eq!(format_elapsed_time(Duration::from_secs(30)), "30 seconds");
        assert_eq!(format_elapsed_time(Duration::from_secs(60)), "1 minute");
        assert_eq!(
            format_elapsed_time(Duration::from_secs(90)),
            "1 minute 30 seconds"
        );
        assert_eq!(
            format_elapsed_time(Duration::from_secs(3_661)),
            "1 hour 1 minute 1 second"
        );
        assert_eq!(
            format_elapsed_time(Duration::from_secs(90_061)),
            "1 day 1 hour 1 minute 1 second"
        );
        assert_eq!(
            progress_report("Waiting for the device.", Duration::from_secs(90)),
            "Waiting for the device. Elapsed time: 1 minute 30 seconds."
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
    fn documents_every_command() {
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["--help"],
                &[
                    "Pair this client with a device",
                    "Before you request or manage profiles",
                ],
            ),
            (
                &["exec", "--help"],
                &[
                    "adds the returned variables",
                    "The `--` separator is required",
                    "doesn't invoke a shell",
                    "Repeat this option",
                    "doesn't suppress output from the command",
                ],
            ),
            (
                &["pairing", "--help"],
                &[
                    "Pairing creates an encrypted relationship",
                    "confirm the full verification code",
                ],
            ),
            (
                &["pairing", "start", "--help"],
                &[
                    "12-digit verification code",
                    "agentknock pairing finish",
                    "lowercase ASCII words separated by single hyphens",
                ],
            ),
            (
                &["pairing", "finish", "--help"],
                &[
                    "only after you confirm",
                    "marks the local pairing as active",
                ],
            ),
            (
                &["pairing", "abort", "--help"],
                &[
                    "without contacting the device",
                    "doesn't remove an active pairing",
                ],
            ),
            (
                &["pairing", "remove", "--help"],
                &[
                    "waits for an authenticated response",
                    "delete only the local pairing",
                    "device retains its pairing record",
                ],
            ),
            (
                &["profile", "--help"],
                &[
                    "Profile commands require an active pairing",
                    "without secret values",
                ],
            ),
            (
                &["profile", "list", "--help"],
                &[
                    "JSON object to standard output",
                    "never includes secret values",
                    "Example output:",
                ],
            ),
            (
                &["profile", "upload", "--help"],
                &[
                    "doesn't wait for that decision",
                    "Use `--replace`",
                    "At most one input can read from standard input",
                    "Environment variable sources:",
                    "without trimming whitespace",
                    "Examples:",
                ],
            ),
        ];

        for (arguments, expected) in cases {
            let help = help_text(arguments);
            let normalized_help = normalize_whitespace(&help);
            for text in *expected {
                assert!(
                    normalized_help.contains(&normalize_whitespace(text)),
                    "help for {arguments:?} doesn't contain {text:?}:\n{help}"
                );
            }
        }
    }

    fn help_text(arguments: &[&str]) -> String {
        let error =
            Cli::try_parse_from(std::iter::once("agentknock").chain(arguments.iter().copied()))
                .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        error.to_string()
    }

    fn normalize_whitespace(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
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
