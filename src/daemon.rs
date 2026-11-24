//! Classic double-fork daemonization for systems without a service
//! manager (Stevens' recipe): fork → setsid → fork → chdir("/") → stdio
//! to /dev/null → pidfile.
//!
//! The parent process exits only after the daemon signals readiness over
//! a pipe, so startup failures (setsid, pidfile write) are reported on
//! the administrator's terminal with a non-zero exit code. Everything
//! fallible (host key, bind) happens in the caller *before* daemonizing,
//! and no threads exist yet at this point, so the forked children are
//! single-threaded and std is safe to use.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use crate::error::{Error, Result};

/// How long the parent waits for the daemon's readiness signal.
const READY_TIMEOUT_MS: libc::c_int = 15_000;

/// Detach the current process into the background and write `pidfile`
/// (if any). The calling (parent) process never returns: it exits 0 once
/// the daemon signals readiness, or 1 with an error message.
/// `keep_stderr` leaves fd 2 alone (used with `--log-file`, where stderr
/// was already redirected to the log).
pub fn daemonize(pidfile: Option<&Path>, keep_stderr: bool) -> Result<()> {
    // The pidfile is required to be an absolute path by the CLI parser, so
    // the post-fork chdir("/") cannot relocate it.
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let (rfd, wfd) = (fds[0], fds[1]);

    match unsafe { libc::fork() } {
        -1 => return Err(Error::Io(std::io::Error::last_os_error())),
        0 => {}
        _pid => parent_side(rfd, wfd),
    }

    // First child: become session leader, then fork again so the
    // grandchild can never reacquire a controlling terminal.
    unsafe { libc::close(rfd) };
    if unsafe { libc::setsid() } < 0 {
        child_fail(wfd, "setsid failed");
    }
    match unsafe { libc::fork() } {
        -1 => child_fail(wfd, "second fork failed"),
        pid if pid > 0 => unsafe { libc::_exit(0) },
        _ => {}
    }

    // Grandchild: the daemon itself.
    unsafe {
        libc::chdir(c"/".as_ptr());
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            if !keep_stderr {
                libc::dup2(devnull, 2);
            }
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }

    if let Some(path) = pidfile {
        let pid = format!("{}\n", unsafe { libc::getpid() });
        if let Err(e) = std::fs::write(path, pid) {
            child_fail(wfd, &format!("cannot write pidfile {}: {e}", path.display()));
        }
    }

    let mut w = unsafe { std::fs::File::from_raw_fd(wfd) };
    let _ = w.write_all(b"OK\n");
    let _ = w.flush();
    Ok(())
}

/// Parent: wait (bounded) for the daemon's readiness signal, then exit.
fn parent_side(rfd: libc::c_int, wfd: libc::c_int) -> ! {
    unsafe { libc::close(wfd) };
    let mut file = unsafe { std::fs::File::from_raw_fd(rfd) };
    let mut pfd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, READY_TIMEOUT_MS) };
    if n <= 0 {
        crate::logger::log(format_args!("daemon failed to signal readiness"));
        std::process::exit(1);
    }
    let mut msg = String::new();
    let _ = file.read_to_string(&mut msg);
    if msg.trim_start().starts_with("OK") {
        std::process::exit(0);
    }
    crate::logger::log(format_args!("daemon startup failed: {}", msg.trim()));
    std::process::exit(1);
}

/// Report a startup failure to the waiting parent, then die.
fn child_fail(wfd: libc::c_int, msg: &str) -> ! {
    let mut w = unsafe { std::fs::File::from_raw_fd(wfd) };
    let _ = writeln!(w, "ERR {msg}");
    let _ = w.flush();
    unsafe { libc::_exit(1) };
}
