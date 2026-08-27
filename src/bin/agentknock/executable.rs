use std::{
    collections::BTreeMap,
    env,
    ffi::{CString, OsStr, OsString},
    fs::File,
    io::{self, Read as _},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd},
        unix::ffi::{OsStrExt as _, OsStringExt as _},
    },
    path::{Path, PathBuf},
    ptr,
};

use agentknock::{ExecutableMode, SecretUseOutput};
use sha2::{Digest as _, Sha256};

const HASH_LENGTH: usize = 32;
const READ_BUFFER_LENGTH: usize = 64 * 1024;

pub struct SelectedExecutable {
    descriptor: OwnedFd,
    command: String,
    path: String,
    hash: Option<[u8; HASH_LENGTH]>,
    mode: ExecutableMode,
    script_path: Option<PathBuf>,
    working_directory: String,
}

pub struct SignalState {
    interrupt: libc::sigaction,
    terminate: libc::sigaction,
}

pub struct BlockedSignals {
    previous: libc::sigset_t,
    active: bool,
}

impl SelectedExecutable {
    pub fn select(command: &str) -> io::Result<Self> {
        if command.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command name is empty",
            ));
        }

        let current_directory = open_directory(Path::new("."))?;
        let working_directory = descriptor_path(&current_directory, "working directory")?;
        let search_path = match env::var_os("PATH") {
            Some(path) => path,
            None => default_search_path()?,
        };

        Self::select_from(command, current_directory, working_directory, &search_path)
    }

    fn select_from(
        command: &str,
        current_directory: OwnedFd,
        working_directory: String,
        search_path: &OsStr,
    ) -> io::Result<Self> {
        if command.contains('/') {
            let candidate = PathBuf::from(command);
            let directory = if candidate.is_absolute() {
                libc::AT_FDCWD
            } else {
                current_directory.as_raw_fd()
            };
            return Self::from_candidate(command, &candidate, directory, working_directory);
        }

        let mut access_denied = false;
        let mut final_error = io::Error::from_raw_os_error(libc::ENOENT);
        for directory in env::split_paths(search_path) {
            let candidate = directory.join(command);
            let directory_descriptor = if directory.is_absolute() {
                libc::AT_FDCWD
            } else {
                current_directory.as_raw_fd()
            };
            match Self::from_candidate(
                command,
                &candidate,
                directory_descriptor,
                working_directory.clone(),
            ) {
                Ok(executable) => return Ok(executable),
                Err(error) if error.raw_os_error() == Some(libc::EACCES) => {
                    access_denied = true;
                    final_error = error;
                }
                Err(error) if is_search_miss(&error) => final_error = error,
                Err(error) => return Err(error),
            }
        }

        if access_denied {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        } else {
            Err(final_error)
        }
    }

    fn from_candidate(
        command: &str,
        candidate: &Path,
        directory: RawFd,
        working_directory: String,
    ) -> io::Result<Self> {
        let descriptor = open_candidate(directory, candidate)?;
        require_regular_file(&descriptor)?;
        require_effective_execute_access(&descriptor)?;
        let path = descriptor_path(&descriptor, "selected executable")?;
        let (hash, shebang) = inspect_selected_file(&descriptor)?;
        let mode = if shebang {
            ExecutableMode::Script
        } else {
            ExecutableMode::Binary
        };

        Ok(Self {
            descriptor,
            command: command.to_owned(),
            path,
            hash,
            mode,
            script_path: shebang.then(|| candidate.to_owned()),
            working_directory,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn hash(&self) -> Option<&[u8; HASH_LENGTH]> {
        self.hash.as_ref()
    }

    pub fn mode(&self) -> ExecutableMode {
        self.mode
    }

    pub fn working_directory(&self) -> &str {
        &self.working_directory
    }

    pub fn execute(
        self,
        arguments: &[String],
        secret_use_output: SecretUseOutput,
        additional_environment: BTreeMap<OsString, OsString>,
        signal_state: &SignalState,
        blocked_signals: BlockedSignals,
    ) -> io::Result<()> {
        self.verify_hash()?;
        let arguments = c_arguments(&self.command, arguments)?;
        let environment = c_environment(secret_use_output, additional_environment)?;
        if blocked_signals.interrupted()? {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "SIGINT or SIGTERM was received after approval",
            ));
        }
        signal_state.restore_for_exec(blocked_signals)?;

        let argument_pointers = c_pointers(&arguments);
        let environment_pointers = c_pointers(&environment);
        let result = match self.mode {
            ExecutableMode::Binary => {
                let empty_path = c"";
                // SAFETY: The descriptor stays open for the call; all pointer arrays are
                // NUL-terminated and point to live C strings.
                unsafe {
                    libc::syscall(
                        libc::SYS_execveat,
                        self.descriptor.as_raw_fd(),
                        empty_path.as_ptr(),
                        argument_pointers.as_ptr(),
                        environment_pointers.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    )
                }
            }
            ExecutableMode::Script => {
                let path = path_c_string(
                    self.script_path
                        .as_deref()
                        .expect("a shebang script has a captured path"),
                )?;
                // SAFETY: The path and pointer arrays are NUL-terminated and remain live
                // for the call.
                unsafe {
                    libc::execve(
                        path.as_ptr(),
                        argument_pointers.as_ptr(),
                        environment_pointers.as_ptr(),
                    ) as libc::c_long
                }
            }
        };
        debug_assert_eq!(result, -1);
        Err(io::Error::last_os_error())
    }

    fn verify_hash(&self) -> io::Result<()> {
        let Some(expected) = self.hash else {
            return Ok(());
        };
        let actual = match self.mode {
            ExecutableMode::Binary => read_selected_file(&self.descriptor)?.map(|(hash, _)| hash),
            ExecutableMode::Script => Some(hash_path(
                self.script_path
                    .as_deref()
                    .expect("a shebang script has a captured path"),
            )?),
        };
        let Some(actual) = actual else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the selected command can no longer be read for hash verification",
            ));
        };
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the selected command changed while Agentknock waited for the device",
            ));
        }
        Ok(())
    }
}

impl SignalState {
    pub fn capture() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal_action(libc::SIGINT)?,
            terminate: signal_action(libc::SIGTERM)?,
        })
    }

    pub fn block_interrupts(&self) -> io::Result<BlockedSignals> {
        BlockedSignals::new()
    }

    fn restore_for_exec(&self, mut blocked: BlockedSignals) -> io::Result<()> {
        set_signal_action(libc::SIGINT, &self.interrupt)?;
        set_signal_action(libc::SIGTERM, &self.terminate)?;
        set_signal_action(libc::SIGPIPE, &default_signal_action()?)?;
        blocked.restore()
    }
}

impl BlockedSignals {
    fn new() -> io::Result<Self> {
        let mut blocked = empty_signal_set()?;
        add_signal(&mut blocked, libc::SIGINT)?;
        add_signal(&mut blocked, libc::SIGTERM)?;
        let mut previous = MaybeUninit::uninit();
        // SAFETY: Both signal-set pointers are valid for the duration of the call.
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        // SAFETY: pthread_sigmask initialized the previous set on success.
        let previous = unsafe { previous.assume_init() };
        Ok(Self {
            previous,
            active: true,
        })
    }

    pub fn interrupted(&self) -> io::Result<bool> {
        let mut pending = MaybeUninit::uninit();
        // SAFETY: The output pointer is valid and sigpending initializes it on success.
        if unsafe { libc::sigpending(pending.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: sigpending initialized the set on success.
        let pending = unsafe { pending.assume_init() };
        Ok(signal_is_member(&pending, libc::SIGINT)? || signal_is_member(&pending, libc::SIGTERM)?)
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: The saved signal set is initialized and remains live for the call.
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, ptr::null_mut()) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    open_at(
        libc::AT_FDCWD,
        path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
}

fn open_candidate(directory: RawFd, path: &Path) -> io::Result<OwnedFd> {
    open_at(directory, path, libc::O_PATH | libc::O_CLOEXEC)
}

fn open_at(directory: RawFd, path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let path = path_c_string(path)?;
    // SAFETY: path is a valid C string and openat does not retain its pointer.
    let descriptor = unsafe { libc::openat(directory, path.as_ptr(), flags) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn require_regular_file(descriptor: &OwnedFd) -> io::Result<()> {
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata is a valid output pointer and fstat initializes it on success.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), metadata.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat initialized metadata on success.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(())
}

fn require_effective_execute_access(descriptor: &OwnedFd) -> io::Result<()> {
    let empty_path = c"";
    // SAFETY: The descriptor and empty-path C string are valid for the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            descriptor.as_raw_fd(),
            empty_path.as_ptr(),
            libc::X_OK,
            libc::AT_EMPTY_PATH | libc::AT_EACCESS,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOSYS) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux 5.8 or newer is required for executable access checks",
        ));
    }
    Err(error)
}

fn inspect_selected_file(descriptor: &OwnedFd) -> io::Result<(Option<[u8; HASH_LENGTH]>, bool)> {
    match read_selected_file(descriptor)? {
        Some((hash, shebang)) => Ok((Some(hash), shebang)),
        None => Ok((None, false)),
    }
}

fn read_selected_file(descriptor: &OwnedFd) -> io::Result<Option<([u8; HASH_LENGTH], bool)>> {
    let path = descriptor_proc_path(descriptor);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(hash_file(file)?))
}

fn hash_path(path: &Path) -> io::Result<[u8; HASH_LENGTH]> {
    File::open(path).and_then(|file| hash_file(file).map(|(hash, _)| hash))
}

fn hash_file(mut file: File) -> io::Result<([u8; HASH_LENGTH], bool)> {
    let mut hash = Sha256::new();
    let mut prefix = [0_u8; 2];
    let mut prefix_length = 0;
    let mut buffer = [0_u8; READ_BUFFER_LENGTH];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        if prefix_length < prefix.len() {
            let copied = (prefix.len() - prefix_length).min(length);
            prefix[prefix_length..prefix_length + copied].copy_from_slice(&buffer[..copied]);
            prefix_length += copied;
        }
        hash.update(&buffer[..length]);
    }
    Ok((
        hash.finalize().into(),
        prefix_length == 2 && prefix == *b"#!",
    ))
}

fn descriptor_path(descriptor: &OwnedFd, description: &str) -> io::Result<String> {
    let path = std::fs::read_link(descriptor_proc_path(descriptor)).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("can't read {description} through /proc/self/fd: {error}"),
        )
    })?;
    path.into_os_string().into_string().map_err(|path| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} isn't valid UTF-8: {path:?}"),
        )
    })
}

fn descriptor_proc_path(descriptor: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
}

fn default_search_path() -> io::Result<OsString> {
    // SAFETY: A null buffer with length zero asks confstr for the required size.
    let length = unsafe { libc::confstr(libc::_CS_PATH, ptr::null_mut(), 0) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut value = vec![0_u8; length];
    // SAFETY: value has the size returned by the first confstr call.
    let actual = unsafe {
        libc::confstr(
            libc::_CS_PATH,
            value.as_mut_ptr().cast::<libc::c_char>(),
            value.len(),
        )
    };
    if actual == 0 {
        return Err(io::Error::last_os_error());
    }
    value.truncate(actual - 1);
    Ok(OsString::from_vec(value))
}

fn is_search_miss(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ESTALE | libc::ENOTDIR | libc::ENODEV | libc::ETIMEDOUT)
    )
}

fn c_arguments(command: &str, arguments: &[String]) -> io::Result<Vec<CString>> {
    std::iter::once(command)
        .chain(arguments.iter().map(String::as_str))
        .map(|argument| {
            CString::new(argument).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command argument contains a null byte",
                )
            })
        })
        .collect()
}

fn c_environment(
    secret_use_output: SecretUseOutput,
    additional_environment: BTreeMap<OsString, OsString>,
) -> io::Result<Vec<CString>> {
    let mut environment = env::vars_os().collect::<BTreeMap<_, _>>();
    for (name, value) in secret_use_output.into_environment() {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("secret response contains invalid environment variable name {name:?}"),
            ));
        }
        if value.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("returned environment variable {name:?} contains a null byte"),
            ));
        }
        environment.insert(OsString::from(name), OsString::from(value));
    }
    environment.extend(additional_environment);

    environment
        .into_iter()
        .map(|(name, value)| {
            let mut entry = Vec::with_capacity(name.len() + value.len() + 1);
            entry.extend_from_slice(name.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "inherited environment contains a null byte",
                )
            })
        })
        .collect()
}

fn c_pointers(values: &[CString]) -> Vec<*const libc::c_char> {
    values
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect()
}

fn path_c_string(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a null byte"))
}

fn signal_action(signal: libc::c_int) -> io::Result<libc::sigaction> {
    let mut action = MaybeUninit::uninit();
    // SAFETY: A null new action queries the current action into a valid pointer.
    if unsafe { libc::sigaction(signal, ptr::null(), action.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sigaction initialized the action on success.
    Ok(unsafe { action.assume_init() })
}

fn set_signal_action(signal: libc::c_int, action: &libc::sigaction) -> io::Result<()> {
    // SAFETY: action is initialized and sigaction does not retain its pointer.
    if unsafe { libc::sigaction(signal, action, ptr::null_mut()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn default_signal_action() -> io::Result<libc::sigaction> {
    // SAFETY: A zeroed sigaction is valid after its mask is initialized below.
    let mut action = unsafe { MaybeUninit::<libc::sigaction>::zeroed().assume_init() };
    action.sa_sigaction = libc::SIG_DFL;
    action.sa_flags = 0;
    // SAFETY: sa_mask is a valid output pointer.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(action)
}

fn empty_signal_set() -> io::Result<libc::sigset_t> {
    let mut set = MaybeUninit::uninit();
    // SAFETY: set is a valid output pointer.
    if unsafe { libc::sigemptyset(set.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sigemptyset initialized the set on success.
    Ok(unsafe { set.assume_init() })
}

fn add_signal(set: &mut libc::sigset_t, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: set is initialized and mutable.
    if unsafe { libc::sigaddset(set, signal) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn signal_is_member(set: &libc::sigset_t, signal: libc::c_int) -> io::Result<bool> {
    // SAFETY: set is initialized and remains live for the call.
    match unsafe { libc::sigismember(set, signal) } {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, fs, os::unix::fs::PermissionsExt as _};

    use sha2::{Digest as _, Sha256};

    use super::SelectedExecutable;
    use agentknock::ExecutableMode;

    #[test]
    fn selects_and_hashes_a_shebang_script() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("tool");
        fs::write(&script, b"#!/bin/sh\necho selected\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = super::open_directory(directory.path()).unwrap();

        let executable = SelectedExecutable::select_from(
            "tool",
            cwd,
            directory.path().to_str().unwrap().to_owned(),
            directory.path().as_os_str(),
        )
        .unwrap();

        assert_eq!(executable.mode(), ExecutableMode::Script);
        assert_eq!(
            executable.hash().copied(),
            Some(Sha256::digest(b"#!/bin/sh\necho selected\n").into())
        );
        assert_eq!(executable.path(), script.to_str().unwrap());
    }

    #[test]
    fn ignores_a_non_executable_path_candidate() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("tool"), b"not executable").unwrap();
        let cwd = super::open_directory(directory.path()).unwrap();

        let error = SelectedExecutable::select_from(
            "tool",
            cwd,
            directory.path().to_str().unwrap().to_owned(),
            directory.path().as_os_str(),
        )
        .err()
        .unwrap();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn continues_the_path_search_after_a_non_executable_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("tool"), b"not executable").unwrap();
        let selected = second.join("tool");
        fs::write(&selected, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
        let path = std::env::join_paths([&first, &second]).unwrap();
        let cwd = super::open_directory(directory.path()).unwrap();

        let executable = SelectedExecutable::select_from(
            "tool",
            cwd,
            directory.path().to_str().unwrap().to_owned(),
            &path,
        )
        .unwrap();

        assert_eq!(executable.path(), selected.to_str().unwrap());
    }

    #[test]
    fn an_empty_path_component_uses_the_captured_working_directory() {
        let directory = tempfile::tempdir().unwrap();
        let selected = directory.path().join("tool");
        fs::write(&selected, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = super::open_directory(directory.path()).unwrap();

        let executable = SelectedExecutable::select_from(
            "tool",
            cwd,
            directory.path().to_str().unwrap().to_owned(),
            OsStr::new(":"),
        )
        .unwrap();

        assert_eq!(executable.path(), selected.to_str().unwrap());
    }

    #[test]
    fn detects_an_in_place_change_after_selection() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("tool");
        fs::write(&script, b"#!/bin/sh\necho before\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = super::open_directory(directory.path()).unwrap();
        let executable = SelectedExecutable::select_from(
            "tool",
            cwd,
            directory.path().to_str().unwrap().to_owned(),
            directory.path().as_os_str(),
        )
        .unwrap();

        fs::write(&script, b"#!/bin/sh\necho after\n").unwrap();

        let error = executable.verify_hash().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("changed while Agentknock waited for the device")
        );
    }

    #[test]
    fn detects_a_script_path_replacement_after_selection() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("tool");
        let replacement = directory.path().join("replacement");
        fs::write(&script, b"#!/bin/sh\necho before\n").unwrap();
        fs::write(&replacement, b"#!/bin/sh\necho replacement\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = super::open_directory(directory.path()).unwrap();
        let executable = SelectedExecutable::select_from(
            "tool",
            cwd,
            directory.path().to_str().unwrap().to_owned(),
            directory.path().as_os_str(),
        )
        .unwrap();

        fs::rename(&replacement, &script).unwrap();

        let error = executable.verify_hash().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
