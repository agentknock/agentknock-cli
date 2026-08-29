use std::{
    cell::Cell,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            fs::PermissionsExt as _,
            net::UnixStream,
            process::CommandExt as _,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    rc::Rc,
    time::Duration,
};

#[cfg(target_os = "macos")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt as _;

use agentknock::{
    ApplicationInfo, Client, GitSignProgress, GitSignRepository, GitSignRequest,
    SecretUseInvocation, SshAuthenticationProgress, SshAuthenticationRequest, SshSecretUse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures_util::{
    FutureExt as _, StreamExt as _, future::LocalBoxFuture, stream::FuturesUnordered,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    time::{Instant, sleep},
};

use crate::git_repository::Repository;
use crate::ssh_agent::{Action as AgentAction, AgentConnection, SelectedIdentity};

const INTERNAL_ARGUMENT: &str = "__invocation-service";
const GIT_SIGN_HELPER_NAME: &str = "git-sign";
const QUIET_GIT_SIGN_HELPER_NAME: &str = "git-sign-quiet";
const GIT_SIGNATURE_NAMESPACE: &str = "git";
const SOCKET_NAME: &str = "service.sock";
const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize, Serialize)]
struct StartupRequest {
    owner_pid: libc::pid_t,
    invocation_id: String,
    invocation_token: String,
    secret: String,
    public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream_agent_socket: Option<String>,
    ssh_passthrough: bool,
    quiet: bool,
    verbose: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum StartupResponse {
    Ready { runtime_directory: String },
    Error { message: String },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum HelperRequest {
    Configuration,
    Sign {
        public_key: String,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        repository: Option<Repository>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum HelperResponse {
    Configuration {
        public_key: String,
        ssh_passthrough: bool,
    },
    Signature {
        signature: String,
    },
    Error {
        message: String,
    },
}

struct ServiceContext {
    client: Client,
    owner_pid: libc::pid_t,
    invocation_id: String,
    invocation_token: [u8; 32],
    secret: String,
    public_key: String,
    upstream_agent_socket: Option<OsString>,
    ssh_passthrough: bool,
    selected_identity: SelectedIdentity,
    quiet: bool,
    verbose: bool,
}

struct PreparedService {
    owner: ProcessMonitor,
    _runtime_directory: tempfile::TempDir,
    listener: tokio::net::UnixListener,
    agent_listener: tokio::net::UnixListener,
    runtime_directory: String,
    context: ServiceContext,
}

#[cfg(target_os = "linux")]
type ProcessMonitor = tokio::io::unix::AsyncFd<OwnedFd>;

#[cfg(target_os = "macos")]
struct ProcessMonitor {
    exited: Arc<AtomicBool>,
    notification: Arc<tokio::sync::Notify>,
}

/// A running invocation service.
///
/// The service follows the owner process across `execve` and exits when that
/// process exits.
pub struct InvocationService {
    _process: Child,
    runtime_directory: PathBuf,
    helper_name: &'static str,
}

pub fn requested(arguments: &[OsString]) -> bool {
    arguments.len() == 2 && arguments[1] == OsStr::new(INTERNAL_ARGUMENT)
}

pub fn git_signing_helper_requested(arguments: &[OsString]) -> bool {
    matches!(
        arguments
        .first()
        .and_then(|argument| Path::new(argument).file_name()),
        Some(name)
            if name == OsStr::new(GIT_SIGN_HELPER_NAME)
                || name == OsStr::new(QUIET_GIT_SIGN_HELPER_NAME)
    )
}

pub fn run() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = write_response(&StartupResponse::Error {
                message: error.to_string(),
            });
            return ExitCode::FAILURE;
        }
    };
    let prepared = {
        let _runtime = runtime.enter();
        prepare()
    };
    let service = match prepared {
        Ok(service) => service,
        Err(error) => {
            let _ = write_response(&StartupResponse::Error {
                message: error.to_string(),
            });
            return ExitCode::FAILURE;
        }
    };
    if write_response(&StartupResponse::Ready {
        runtime_directory: service.runtime_directory.clone(),
    })
    .is_err()
    {
        return ExitCode::FAILURE;
    }

    match runtime.block_on(serve(service)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

pub fn run_git_signing_helper(arguments: &[OsString]) -> ExitCode {
    let quiet = arguments
        .first()
        .and_then(|argument| Path::new(argument).file_name())
        == Some(OsStr::new(QUIET_GIT_SIGN_HELPER_NAME));
    match git_signing_helper(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !quiet {
                eprintln!("AGENTKNOCK: Git signing failed: {error}.");
            }
            ExitCode::FAILURE
        }
    }
}

impl InvocationService {
    pub fn start(
        invocation: &SecretUseInvocation,
        ssh: &SshSecretUse,
        upstream_agent_socket: Option<&OsStr>,
        ssh_passthrough: bool,
        quiet: bool,
        verbose: bool,
    ) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let executable = "/proc/self/exe";
        #[cfg(target_os = "macos")]
        let executable = std::env::current_exe()?;
        let mut process = Command::new(executable)
            .arg(INTERNAL_ARGUMENT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()?;

        match initialize(
            &mut process,
            invocation,
            ssh,
            upstream_agent_socket,
            ssh_passthrough,
            quiet,
            verbose,
        ) {
            Ok(runtime_directory) => Ok(Self {
                _process: process,
                runtime_directory,
                helper_name: if quiet {
                    QUIET_GIT_SIGN_HELPER_NAME
                } else {
                    GIT_SIGN_HELPER_NAME
                },
            }),
            Err(error) => {
                let _ = process.kill();
                let _ = process.wait();
                Err(error)
            }
        }
    }

    pub fn environment(
        &self,
        existing_count: Option<&OsStr>,
    ) -> io::Result<BTreeMap<OsString, OsString>> {
        let helper = self.runtime_directory.join(self.helper_name);
        let helper = helper.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Git signing helper path isn't valid UTF-8",
            )
        })?;
        let default_key_command = shell_argument(helper);
        let count = match existing_count {
            Some(value) => value
                .to_str()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "GIT_CONFIG_COUNT isn't valid UTF-8",
                    )
                })?
                .parse::<usize>()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "GIT_CONFIG_COUNT isn't a nonnegative integer",
                    )
                })?,
            None => 0,
        };
        let final_count = count
            .checked_add(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "too many Git settings"))?;

        Ok(BTreeMap::from([
            (
                "SSH_AUTH_SOCK".into(),
                self.runtime_directory
                    .join(crate::ssh_agent::SOCKET_NAME)
                    .into_os_string(),
            ),
            ("GIT_CONFIG_COUNT".into(), final_count.to_string().into()),
            (
                format!("GIT_CONFIG_KEY_{count}").into(),
                "gpg.ssh.program".into(),
            ),
            (format!("GIT_CONFIG_VALUE_{count}").into(), helper.into()),
            (
                format!("GIT_CONFIG_KEY_{}", count + 1).into(),
                "gpg.ssh.defaultKeyCommand".into(),
            ),
            (
                format!("GIT_CONFIG_VALUE_{}", count + 1).into(),
                default_key_command.into(),
            ),
        ]))
    }
}

fn initialize(
    process: &mut Child,
    invocation: &SecretUseInvocation,
    ssh: &SshSecretUse,
    upstream_agent_socket: Option<&OsStr>,
    ssh_passthrough: bool,
    quiet: bool,
    verbose: bool,
) -> io::Result<PathBuf> {
    let request = StartupRequest {
        // SAFETY: getpid has no preconditions.
        owner_pid: unsafe { libc::getpid() },
        invocation_id: invocation.id().to_owned(),
        invocation_token: BASE64_STANDARD.encode(invocation.token()),
        secret: ssh.name().to_owned(),
        public_key: ssh.public_key().to_owned(),
        upstream_agent_socket: upstream_agent_socket
            .map(OsStr::as_bytes)
            .map(|path| BASE64_STANDARD.encode(path)),
        ssh_passthrough,
        quiet,
        verbose,
    };
    let mut input = process
        .stdin
        .take()
        .expect("the invocation service has piped standard input");
    serde_json::to_writer(&mut input, &request).map_err(io::Error::other)?;
    input.write_all(b"\n")?;
    drop(input);

    let response: StartupResponse = serde_json::from_reader(
        process
            .stdout
            .take()
            .expect("the invocation service has piped standard output"),
    )
    .map_err(io::Error::other)?;
    match response {
        StartupResponse::Ready { runtime_directory } => Ok(PathBuf::from(runtime_directory)),
        StartupResponse::Error { message } => Err(io::Error::other(message)),
    }
}

fn prepare() -> io::Result<PreparedService> {
    let request = read_request()?;
    let token = BASE64_STANDARD
        .decode(&request.invocation_token)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let invocation_token = token.try_into().map_err(|_: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invocation token isn't 32 bytes",
        )
    })?;
    let upstream_agent_socket = if request.ssh_passthrough {
        request
            .upstream_agent_socket
            .map(|socket| {
                BASE64_STANDARD
                    .decode(socket)
                    .map(OsString::from_vec)
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid upstream SSH agent socket: {error}"),
                        )
                    })
            })
            .transpose()?
    } else {
        None
    };
    let owner = open_process(request.owner_pid)?;
    let runtime_directory = runtime_directory()?;
    let socket_path = runtime_directory.path().join(SOCKET_NAME);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let agent_socket_path = runtime_directory.path().join(crate::ssh_agent::SOCKET_NAME);
    let agent_listener = std::os::unix::net::UnixListener::bind(&agent_socket_path)?;
    agent_listener.set_nonblocking(true)?;
    let agent_listener = tokio::net::UnixListener::from_std(agent_listener)?;
    let helper_path = runtime_directory.path().join(if request.quiet {
        QUIET_GIT_SIGN_HELPER_NAME
    } else {
        GIT_SIGN_HELPER_NAME
    });
    install_helper(&helper_path)?;
    let path = runtime_directory
        .path()
        .to_str()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invocation service runtime directory isn't valid UTF-8",
            )
        })?
        .to_owned();

    let selected_identity =
        SelectedIdentity::from_openssh(&request.public_key, request.secret.clone())?;
    Ok(PreparedService {
        owner,
        _runtime_directory: runtime_directory,
        listener,
        agent_listener,
        runtime_directory: path,
        context: ServiceContext {
            client: Client::new(ApplicationInfo::new(
                "agentknock",
                env!("CARGO_PKG_VERSION"),
            )),
            owner_pid: request.owner_pid,
            invocation_id: request.invocation_id,
            invocation_token,
            secret: request.secret,
            public_key: request.public_key,
            upstream_agent_socket,
            ssh_passthrough: request.ssh_passthrough,
            selected_identity,
            quiet: request.quiet,
            verbose: request.verbose,
        },
    })
}

fn runtime_directory() -> io::Result<tempfile::TempDir> {
    let mut directory = tempfile::Builder::new();
    directory
        .prefix("agentknock-invocation-")
        .permissions(fs::Permissions::from_mode(0o700));

    #[cfg(target_os = "linux")]
    {
        if let Some(path) = xdg_runtime_directory()
            && let Ok(runtime_directory) = directory.tempdir_in(path)
        {
            return Ok(runtime_directory);
        }
        directory.tempdir()
    }

    // macOS limits Unix socket paths to 104 bytes. Its per-user temporary
    // directory can already approach that limit before our directory and
    // socket names are appended.
    #[cfg(target_os = "macos")]
    directory.tempdir_in("/tmp")
}

#[cfg(target_os = "linux")]
fn xdg_runtime_directory() -> Option<PathBuf> {
    let configured_path = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !configured_path.is_absolute() {
        return None;
    }
    let path = fs::canonicalize(configured_path).ok()?;
    let metadata = fs::symlink_metadata(&path).ok()?;
    // SAFETY: geteuid has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return None;
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor).ok()?;
        let owner = metadata.uid();
        let mode = metadata.mode();
        if !metadata.is_dir()
            || (owner != 0 && owner != effective_uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return None;
        }
    }
    Some(path)
}

async fn serve(service: PreparedService) -> io::Result<()> {
    let PreparedService {
        owner,
        _runtime_directory,
        listener,
        agent_listener,
        runtime_directory: _,
        context,
    } = service;
    let owner = Rc::new(owner);
    let context = Rc::new(context);
    let mut connections = FuturesUnordered::<LocalBoxFuture<'static, ()>>::new();

    loop {
        enum Connection {
            Helper(tokio::net::UnixStream),
            Agent(tokio::net::UnixStream),
        }
        let connection = tokio::select! {
            result = listener.accept() => Some(Connection::Helper(result?.0)),
            result = agent_listener.accept() => Some(Connection::Agent(result?.0)),
            Some(()) = connections.next(), if !connections.is_empty() => None,
            result = wait_for_process(&owner) => return result,
        };
        let Some(connection) = connection else {
            continue;
        };
        let context = Rc::clone(&context);
        let owner = Rc::clone(&owner);
        let handler = match connection {
            Connection::Helper(connection) => async move {
                let _ = handle_connection(connection, &context, &owner).await;
            }
            .boxed_local(),
            Connection::Agent(connection) => async move {
                let _ = handle_agent_connection(connection, &context, &owner).await;
            }
            .boxed_local(),
        };
        connections.push(handler);
    }
}

async fn handle_agent_connection(
    mut connection: tokio::net::UnixStream,
    context: &ServiceContext,
    owner: &ProcessMonitor,
) -> io::Result<()> {
    let peer_pid = connection
        .peer_cred()?
        .pid()
        .ok_or_else(|| io::Error::other("SSH agent client has no process identifier"))?;
    require_descendant(peer_pid, context.owner_pid)?;
    let mut agent = AgentConnection::new(
        &context.selected_identity,
        context.upstream_agent_socket.as_deref(),
    );

    loop {
        let packet = tokio::select! {
            result = crate::ssh_agent::read_packet(&mut connection) => result?,
            result = wait_for_process(owner) => return result,
        };
        let Some(packet) = packet else {
            return Ok(());
        };
        let response = match agent.handle(&packet).await {
            AgentAction::Respond(response) => response,
            AgentAction::Authenticate { algorithm, message } => {
                match request_ssh_authentication(context, owner, algorithm, &message).await {
                    Ok(signature) => crate::ssh_agent::signature_response(&signature),
                    Err(error) => {
                        if !context.quiet {
                            print_message(format!("SSH authentication failed: {error}."));
                        }
                        crate::ssh_agent::failure_response().to_vec()
                    }
                }
            }
        };
        crate::ssh_agent::write_packet(&mut connection, &response).await?;
    }
}

async fn handle_connection(
    mut connection: tokio::net::UnixStream,
    context: &ServiceContext,
    owner: &ProcessMonitor,
) -> io::Result<()> {
    let peer_pid = connection
        .peer_cred()?
        .pid()
        .ok_or_else(|| io::Error::other("invocation helper has no process identifier"))?;
    require_descendant(peer_pid, context.owner_pid)?;
    let mut input = Vec::new();
    connection.read_to_end(&mut input).await?;
    let request: HelperRequest = serde_json::from_slice(&input).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid invocation helper request: {error}"),
        )
    })?;
    let response = match request {
        HelperRequest::Configuration => HelperResponse::Configuration {
            public_key: context.public_key.clone(),
            ssh_passthrough: context.ssh_passthrough,
        },
        HelperRequest::Sign {
            public_key,
            message,
            repository,
        } => {
            let result = validate_signing_key(&public_key, &context.public_key).and_then(|()| {
                BASE64_STANDARD
                    .decode(message)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            });
            let result = match result {
                Ok(data) => {
                    let repository = repository.map(GitSignRepository::from);
                    request_git_signature(context, owner, &data, repository.as_ref())
                        .await
                        .map(|signature| HelperResponse::Signature { signature })
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(response) => response,
                Err(error) => HelperResponse::Error {
                    message: error.to_string(),
                },
            }
        }
    };
    let encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
    connection.write_all(&encoded).await?;
    connection.shutdown().await
}

async fn request_git_signature(
    context: &ServiceContext,
    owner: &ProcessMonitor,
    data: &[u8],
    repository: Option<&GitSignRepository>,
) -> io::Result<String> {
    let current_progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&current_progress);
    let request = context.client.request_git_signature(
        GitSignRequest {
            invocation_id: &context.invocation_id,
            invocation_token: &context.invocation_token,
            secret: &context.secret,
            message: data,
            repository,
        },
        async {
            let _ = wait_for_process(owner).await;
        },
        |progress| {
            let changed = observed_progress.replace(Some(progress)) != Some(progress);
            if changed && context.verbose {
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
            result = request.as_mut() => return result.map_err(io::Error::other),
            _ = heartbeat.as_mut(), if !context.quiet => {
                if let Some(progress) = current_progress.get() {
                    print_message(format!(
                        "{} ({} elapsed).",
                        progress_message(progress),
                        human_duration(started.elapsed()),
                    ));
                }
                heartbeat.as_mut().reset(Instant::now() + PROGRESS_INTERVAL);
            }
        }
    }
}

async fn request_ssh_authentication(
    context: &ServiceContext,
    owner: &ProcessMonitor,
    algorithm: agentknock::SshSignatureAlgorithm,
    message: &[u8],
) -> io::Result<Vec<u8>> {
    let current_progress = Rc::new(Cell::new(None));
    let observed_progress = Rc::clone(&current_progress);
    let request = context.client.request_ssh_authentication(
        SshAuthenticationRequest {
            invocation_id: &context.invocation_id,
            invocation_token: &context.invocation_token,
            secret: &context.secret,
            algorithm,
            message,
        },
        async {
            let _ = wait_for_process(owner).await;
        },
        |progress| {
            let changed = observed_progress.replace(Some(progress)) != Some(progress);
            if changed && context.verbose {
                print_ssh_progress(progress);
            }
        },
    );
    tokio::pin!(request);
    let started = Instant::now();
    let heartbeat = sleep(PROGRESS_INTERVAL);
    tokio::pin!(heartbeat);

    loop {
        tokio::select! {
            result = request.as_mut() => return result.map_err(io::Error::other),
            _ = heartbeat.as_mut(), if !context.quiet => {
                if let Some(progress) = current_progress.get() {
                    print_message(format!(
                        "{} ({} elapsed).",
                        ssh_progress_message(progress),
                        human_duration(started.elapsed()),
                    ));
                }
                heartbeat.as_mut().reset(Instant::now() + PROGRESS_INTERVAL);
            }
        }
    }
}

fn read_request() -> io::Result<StartupRequest> {
    serde_json::from_reader(io::stdin().lock()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid invocation service startup request: {error}"),
        )
    })
}

fn write_response(response: &StartupResponse) -> io::Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, response).map_err(io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()?;
    drop(output);

    // The launcher treats EOF as the end of the one-shot startup channel.
    // SAFETY: This process owns its standard output and doesn't use it again.
    let _ = unsafe { libc::close(libc::STDOUT_FILENO) };
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_process(pid: libc::pid_t) -> io::Result<ProcessMonitor> {
    // SAFETY: pidfd_open doesn't retain any userspace pointers. A successful
    // call returns a newly owned close-on-exec descriptor.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pidfd_open returned a newly owned descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) };
    tokio::io::unix::AsyncFd::new(descriptor)
}

#[cfg(target_os = "macos")]
fn open_process(pid: libc::pid_t) -> io::Result<ProcessMonitor> {
    // SAFETY: kqueue has no preconditions and returns a newly owned descriptor.
    let descriptor = unsafe { libc::kqueue() };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: kqueue returned a newly owned descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let event = libc::kevent {
        ident: pid as libc::uintptr_t,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: event points to one initialized registration. No output is requested.
    if unsafe {
        libc::kevent(
            descriptor.as_raw_fd(),
            &event,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    let exited = Arc::new(AtomicBool::new(false));
    let notification = Arc::new(tokio::sync::Notify::new());
    let thread_exited = Arc::clone(&exited);
    let thread_notification = Arc::clone(&notification);
    std::thread::Builder::new()
        .name("agentknock-process-monitor".to_owned())
        .spawn(move || {
            let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
            loop {
                // SAFETY: event is writable for one returned event. A null timeout waits
                // until the registered process exits or the call is interrupted.
                let result = unsafe {
                    libc::kevent(
                        descriptor.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        event.as_mut_ptr(),
                        1,
                        std::ptr::null(),
                    )
                };
                if result == 1 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            thread_exited.store(true, Ordering::Release);
            thread_notification.notify_waiters();
        })?;
    Ok(ProcessMonitor {
        exited,
        notification,
    })
}

fn require_descendant(mut process: libc::pid_t, owner: libc::pid_t) -> io::Result<()> {
    loop {
        if process == owner {
            return Ok(());
        }
        let parent = crate::process_info::parent_id(process)?;
        if parent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invocation helper isn't a child of the approved command",
            ));
        }
        process = parent;
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_process(process: &ProcessMonitor) -> io::Result<()> {
    loop {
        let mut ready = process.readable().await?;
        let mut event = libc::pollfd {
            fd: process.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event points to one initialized pollfd for the duration of
        // the call. A zero timeout only checks current readiness.
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result > 0 {
            return Ok(());
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        ready.clear_ready();
    }
}

#[cfg(target_os = "macos")]
async fn wait_for_process(process: &ProcessMonitor) -> io::Result<()> {
    loop {
        if process.exited.load(Ordering::Acquire) {
            return Ok(());
        }
        let notified = process.notification.notified();
        if process.exited.load(Ordering::Acquire) {
            return Ok(());
        }
        notified.await;
    }
}

#[cfg(target_os = "linux")]
fn install_helper(path: &Path) -> io::Result<()> {
    let executable = format!("/proc/{}/exe", std::process::id());
    std::os::unix::fs::symlink(executable, path)
}

#[cfg(target_os = "macos")]
fn install_helper(path: &Path) -> io::Result<()> {
    fs::copy(std::env::current_exe()?, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn git_signing_helper(arguments: &[OsString]) -> io::Result<()> {
    let runtime_directory = Path::new(
        arguments
            .first()
            .ok_or_else(|| io::Error::other("Git signing helper has no program path"))?,
    )
    .parent()
    .ok_or_else(|| io::Error::other("Git signing helper has no runtime directory"))?;

    if arguments.len() == 1 {
        let (public_key, _) = helper_configuration(runtime_directory)?;
        println!("key::{public_key}");
        return Ok(());
    }

    if !is_ssh_signing_operation(&arguments[1..]) {
        return exec_ssh_keygen(runtime_directory, &arguments[1..]);
    }
    let (public_key, ssh_passthrough) = helper_configuration(runtime_directory)?;
    let signing = match parse_git_sign_arguments(&arguments[1..]) {
        Ok(signing) => signing,
        Err(error) if !ssh_passthrough => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SSH passthrough is disabled: {error}"),
            ));
        }
        Err(_) => return exec_ssh_keygen(runtime_directory, &arguments[1..]),
    };
    let requested_key = fs::read_to_string(&signing.key_file)?;
    if !signing_key_matches(&requested_key, &public_key)? {
        if !ssh_passthrough {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Git requested SSH signing with a key other than the selected Agentknock key, but SSH passthrough is disabled",
            ));
        }
        return exec_ssh_keygen(runtime_directory, &arguments[1..]);
    }
    let data = fs::read(&signing.data_file)?;
    let repository = Repository::collect(&data);
    let response = call_service(
        runtime_directory,
        &HelperRequest::Sign {
            public_key: requested_key,
            message: BASE64_STANDARD.encode(data),
            repository,
        },
    )?;
    let HelperResponse::Signature { signature } = response else {
        return Err(io::Error::other(
            "invocation service returned an unexpected signing response",
        ));
    };
    let mut signature_path = signing.data_file.as_os_str().to_owned();
    signature_path.push(".sig");
    fs::write(signature_path, signature)
}

fn is_ssh_signing_operation(arguments: &[OsString]) -> bool {
    arguments.first().is_some_and(|argument| argument == "-Y")
        && arguments.get(1).is_some_and(|argument| argument == "sign")
}

fn helper_configuration(runtime_directory: &Path) -> io::Result<(String, bool)> {
    let HelperResponse::Configuration {
        public_key,
        ssh_passthrough,
    } = call_service(runtime_directory, &HelperRequest::Configuration)?
    else {
        return Err(io::Error::other(
            "invocation service returned an unexpected configuration response",
        ));
    };
    Ok((public_key, ssh_passthrough))
}

struct GitSignArguments {
    key_file: PathBuf,
    data_file: PathBuf,
}

fn parse_git_sign_arguments(arguments: &[OsString]) -> io::Result<GitSignArguments> {
    let arguments = arguments
        .iter()
        .map(|argument| {
            argument.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Git signing argument isn't valid UTF-8",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let ["-Y", "sign", "-n", namespace, "-f", key_file, rest @ ..] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported Git SSH signing arguments",
        ));
    };
    let data_file = match rest {
        ["-U", data_file] | [data_file] => data_file,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported Git SSH signing arguments",
            ));
        }
    };
    if *namespace != GIT_SIGNATURE_NAMESPACE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unsupported Git SSH signing namespace {namespace:?}; expected {GIT_SIGNATURE_NAMESPACE:?}"
            ),
        ));
    }
    Ok(GitSignArguments {
        key_file: PathBuf::from(key_file),
        data_file: PathBuf::from(data_file),
    })
}

fn public_key_identity(public_key: &str) -> Option<(&str, &str)> {
    let mut fields = public_key.split_ascii_whitespace();
    Some((fields.next()?, fields.next()?))
}

fn shell_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn signing_key_matches(requested: &str, expected: &str) -> io::Result<bool> {
    let expected = public_key_identity(expected).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the device returned an invalid SSH public key",
        )
    })?;
    Ok(public_key_identity(requested) == Some(expected))
}

fn validate_signing_key(requested: &str, expected: &str) -> io::Result<()> {
    let requested = public_key_identity(requested).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Git requested an invalid SSH public key",
        )
    })?;
    let expected = public_key_identity(expected).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the device returned an invalid SSH public key",
        )
    })?;
    if requested != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Git requested a different SSH signing key",
        ));
    }
    Ok(())
}

fn exec_ssh_keygen(runtime_directory: &Path, arguments: &[OsString]) -> io::Result<()> {
    Err(Command::new("ssh-keygen")
        .args(arguments)
        .env(
            "SSH_AUTH_SOCK",
            runtime_directory.join(crate::ssh_agent::SOCKET_NAME),
        )
        .exec())
}

fn call_service(runtime_directory: &Path, request: &HelperRequest) -> io::Result<HelperResponse> {
    let mut connection = UnixStream::connect(runtime_directory.join(SOCKET_NAME))?;
    serde_json::to_writer(&mut connection, request).map_err(io::Error::other)?;
    connection.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    connection.read_to_end(&mut response)?;
    match serde_json::from_slice(&response).map_err(io::Error::other)? {
        HelperResponse::Error { message } => Err(io::Error::other(message)),
        response => Ok(response),
    }
}

fn print_progress(progress: GitSignProgress) {
    print_message(progress_message(progress));
}

fn print_ssh_progress(progress: SshAuthenticationProgress) {
    print_message(ssh_progress_message(progress));
}

fn ssh_progress_message(progress: SshAuthenticationProgress) -> &'static str {
    match progress {
        SshAuthenticationProgress::Preparing => "Preparing the SSH authentication request.",
        SshAuthenticationProgress::WaitingForDelivery => {
            "Waiting to deliver the SSH authentication request to the device."
        }
        SshAuthenticationProgress::WaitingForResponse => {
            "Waiting for the device to approve SSH authentication."
        }
        SshAuthenticationProgress::Completing => "The device approved SSH authentication.",
        SshAuthenticationProgress::Completed => "SSH authentication is approved.",
        _ => "Waiting for SSH authentication approval.",
    }
}

fn progress_message(progress: GitSignProgress) -> &'static str {
    match progress {
        GitSignProgress::Preparing => "Preparing the Git signing request.",
        GitSignProgress::WaitingForDelivery => {
            "Waiting to deliver the Git signing request to the device."
        }
        GitSignProgress::WaitingForResponse => {
            "Waiting for the device to approve the Git signature."
        }
        GitSignProgress::Completing => "The device approved the Git signature.",
        GitSignProgress::Completed => "Git signing is approved.",
        _ => "Waiting for Git signing approval.",
    }
}

fn print_message(message: impl std::fmt::Display) {
    for line in message.to_string().lines() {
        eprintln!("AGENTKNOCK: {line}");
    }
}

fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        return format!("{seconds} seconds");
    }
    let minutes = seconds / 60;
    let seconds = seconds % 60;
    if seconds == 0 {
        format!("{minutes} minutes")
    } else {
        format!("{minutes} minutes {seconds} seconds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_git_sshsig_namespace() {
        let arguments = |namespace: &str| {
            ["-Y", "sign", "-n", namespace, "-f", "key", "-U", "message"].map(OsString::from)
        };

        assert!(parse_git_sign_arguments(&arguments("git")).is_ok());
        assert!(parse_git_sign_arguments(&arguments("file")).is_err());
    }

    #[test]
    fn distinguishes_signing_from_other_ssh_keygen_operations() {
        assert!(is_ssh_signing_operation(&[
            "-Y".into(),
            "sign".into(),
            "message".into(),
        ]));
        assert!(!is_ssh_signing_operation(&["-Y".into(), "verify".into(),]));
    }

    #[test]
    fn matches_rsa_public_keys_independently_of_comments() {
        assert!(
            signing_key_matches(
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB example@client",
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB example@device",
            )
            .unwrap()
        );
    }
}
