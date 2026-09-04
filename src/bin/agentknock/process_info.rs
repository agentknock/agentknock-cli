use std::{io, path::PathBuf};

#[cfg(target_os = "macos")]
use std::{
    ffi::{CStr, OsString},
    mem::MaybeUninit,
    os::unix::ffi::OsStringExt as _,
};

#[cfg(target_os = "linux")]
pub fn parent_id(process: libc::pid_t) -> io::Result<libc::pid_t> {
    let status = std::fs::read_to_string(format!("/proc/{process}/status"))?;
    parse_parent_id(&status)
        .ok_or_else(|| io::Error::other(format!("process {process} has no parent process")))
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

#[cfg(target_os = "linux")]
fn parse_parent_id(status: &str) -> Option<libc::pid_t> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_current_process_information() {
        let process = std::process::id() as libc::pid_t;
        // SAFETY: getppid has no preconditions.
        let expected_parent = unsafe { libc::getppid() };
        assert_eq!(super::parent_id(process).unwrap(), expected_parent);

        let executable = super::executable_path(process).unwrap();
        assert!(executable.is_absolute());
        assert!(executable.is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_parent_id_from_proc_status() {
        assert_eq!(
            super::parse_parent_id("Name:\tbash\nPPid:\t1234\n"),
            Some(1234)
        );
        assert_eq!(super::parse_parent_id("Name:\tbash\n"), None);
    }
}
