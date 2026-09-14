use std::{io, path::PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

#[cfg(target_os = "macos")]
use std::{
    ffi::{CStr, OsString},
    mem::MaybeUninit,
    os::unix::ffi::OsStringExt as _,
};

#[cfg(target_os = "linux")]
pub fn open(process: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open returns a new descriptor and retains no pointers.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, process, 0) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pidfd_open returned a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) })
}

#[cfg(target_os = "linux")]
pub fn parent_id(process: libc::pid_t) -> io::Result<libc::pid_t> {
    match std::fs::read_to_string(format!("/proc/{process}/status")) {
        Ok(status) => return parse_parent_id(&status),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let descriptor = open(process)?;
    // SAFETY: All fields of pidfd_info are integers; zero requests no optional fields.
    let mut information: libc::pidfd_info = unsafe { std::mem::zeroed() };
    // SAFETY: The descriptor is a pidfd and information is a writable buffer of
    // the size encoded in PIDFD_GET_INFO. ioctl does not retain the pointer.
    if unsafe {
        libc::ioctl(
            descriptor.as_raw_fd(),
            libc::PIDFD_GET_INFO,
            &mut information,
        )
    } == -1
    {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ENOTTY) {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Process ancestry requires readable procfs or Linux 6.13+ with PIDFD_GET_INFO support",
            )
        } else {
            error
        });
    }
    if information.mask & u64::from(libc::PIDFD_INFO_PID) == 0 {
        return Err(io::Error::other(
            "PIDFD_GET_INFO returned no process identifiers",
        ));
    }
    libc::pid_t::try_from(information.ppid).map_err(|_| {
        io::Error::other("PIDFD_GET_INFO returned an invalid parent process identifier")
    })
}

#[cfg(target_os = "linux")]
fn parse_parent_id(status: &str) -> io::Result<libc::pid_t> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| io::Error::other("process status has no valid parent identifier"))
}

#[cfg(target_os = "linux")]
pub fn executable_path(process: libc::pid_t) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{process}/exe"))
}

#[cfg(target_os = "macos")]
pub fn parent_id(process: libc::pid_t) -> io::Result<libc::pid_t> {
    let mut information = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: information points to a buffer of the size supplied to proc_pidinfo.
    let result = unsafe {
        libc::proc_pidinfo(
            process,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast(),
            size,
        )
    };
    if result <= 0 {
        return Err(io::Error::last_os_error());
    }
    if result != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("process {process} returned incomplete process information"),
        ));
    }
    // SAFETY: proc_pidinfo initialized the complete structure.
    let information = unsafe { information.assume_init() };
    Ok(information.pbi_ppid as libc::pid_t)
}

#[cfg(target_os = "macos")]
pub fn executable_path(process: libc::pid_t) -> io::Result<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer is writable for the size supplied to proc_pidpath.
    let result =
        unsafe { libc::proc_pidpath(process, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if result <= 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: proc_pidpath writes a NUL-terminated path on success.
    let path = unsafe { CStr::from_ptr(buffer.as_ptr().cast()) };
    Ok(PathBuf::from(OsString::from_vec(path.to_bytes().to_vec())))
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_current_process_information() {
        let process = std::process::id() as libc::pid_t;
        // SAFETY: getppid has no preconditions.
        let expected_parent = unsafe { libc::getppid() };
        assert_eq!(super::parent_id(process).unwrap(), expected_parent);

        if std::env::var_os("AGENTKNOCK_TEST_WITHOUT_PROCFS").is_some() {
            assert_eq!(
                super::executable_path(process).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
        } else {
            let executable = super::executable_path(process).unwrap();
            assert!(executable.is_absolute());
            assert!(executable.is_file());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_missing_or_invalid_parent_identifiers() {
        assert_eq!(
            super::parse_parent_id("Name:\ttool\nPPid:\t1234\n").unwrap(),
            1234
        );
        assert!(super::parse_parent_id("Name:\ttool\n").is_err());
        assert!(super::parse_parent_id("PPid:\tinvalid\n").is_err());
    }
}
