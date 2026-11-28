//! PTY and terminal glue (spec §5.5, §5.7): raw mode, window size,
//! forkpty, passphrase prompts with echo disabled, fd pumping.

use std::ffi::c_int;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// RAII guard restoring a terminal's original termios.
pub struct RawMode {
    fd: c_int,
    saved: libc::termios,
    active: bool,
}

impl RawMode {
    /// Switch `fd` into raw mode (like `cfmakeraw` + `tcsetattr`).
    pub fn enter(fd: c_int) -> Result<RawMode> {
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 {
                return Err(Error::Pty(format!("tcgetattr failed: {}", io::Error::last_os_error())));
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                return Err(Error::Pty(format!("tcsetattr failed: {}", io::Error::last_os_error())));
            }
            Ok(RawMode { fd, saved, active: true })
        }
    }

    pub fn restore(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
            }
            self.active = false;
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn isatty(fd: c_int) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Current window size of `fd`, defaulting to 80x24.
pub fn get_winsize(fd: c_int) -> (u32, u32) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
            (ws.ws_row as u32, ws.ws_col as u32)
        } else {
            (24, 80)
        }
    }
}

/// Clamp untrusted size fields to sane limits.
pub fn clamp_size(rows: u32, cols: u32) -> (u16, u16) {
    (
        rows.clamp(1, 4096) as u16,
        cols.clamp(1, 16384) as u16,
    )
}

/// Set the window size on a pty master (TIOCSWINSZ).
pub fn set_winsize_fd(fd: c_int, rows: u16, cols: u16) -> Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let r = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if r != 0 {
        return Err(Error::Pty(format!("TIOCSWINSZ failed: {}", io::Error::last_os_error())));
    }
    Ok(())
}

/// A pseudo-terminal pair. Both ends are opened `O_CLOEXEC` atomically, so
/// no other session's child can ever inherit them across `exec` — even a
/// child forked concurrently by another connection thread. (`openpty` /
/// `forkpty` in both musl and glibc open the master *without*
/// close-on-exec, which leaked every live session's master into every
/// other session.)
pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// Open a new PTY pair with the given window size.
pub fn open_pty(rows: u16, cols: u16) -> Result<Pty> {
    let err = |what: &str| Error::Pty(format!("{what}: {}", io::Error::last_os_error()));
    unsafe {
        let m = libc::open(
            c"/dev/ptmx".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if m < 0 {
            return Err(err("cannot open /dev/ptmx"));
        }
        let master = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m) != 0 {
            return Err(err("grantpt failed"));
        }
        if libc::unlockpt(m) != 0 {
            return Err(err("unlockpt failed"));
        }
        let mut name = [0 as libc::c_char; 128];
        let r = libc::ptsname_r(m, name.as_mut_ptr(), name.len());
        if r != 0 {
            return Err(Error::Pty(format!(
                "ptsname_r failed: {}",
                io::Error::from_raw_os_error(r)
            )));
        }
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if s < 0 {
            return Err(err("cannot open pty slave"));
        }
        let slave = OwnedFd::from_raw_fd(s);
        set_winsize_fd(master.as_raw_fd(), rows, cols)?;
        Ok(Pty { master, slave })
    }
}

/// Write all bytes to an fd, retrying EINTR.
/// Returns false when the fd reports a closed/error condition (e.g. EIO on
/// a pty master whose slave is gone).
pub fn write_fd_all(fd: c_int, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
            continue;
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
        }
        return false;
    }
    true
}

/// Read a line from `fd` (echo-off passphrase prompt). Restores termios
/// even on failure and zeroizes the intermediate buffer.
fn read_line_noecho(fd: c_int, prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    unsafe {
        let mut saved: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut saved) == 0 {
            let mut noecho = saved;
            noecho.c_lflag &= !libc::ECHO;
            libc::tcsetattr(fd, libc::TCSANOW, &noecho);
            let _ = libc::write(fd, prompt.as_ptr() as *const libc::c_void, prompt.len());
            let mut buf: Vec<u8> = Vec::new();
            loop {
                let mut ch = 0u8;
                let n = libc::read(fd, &mut ch as *mut u8 as *mut libc::c_void, 1);
                if n <= 0 {
                    break;
                }
                if ch == b'\n' {
                    break;
                }
                if ch == 0x7f || ch == 0x08 {
                    // backspace: pop one char (best-effort line editing)
                    if !buf.is_empty() {
                        buf.pop();
                    }
                    continue;
                }
                buf.push(ch);
            }
            libc::tcsetattr(fd, libc::TCSANOW, &saved);
            let _ = libc::write(fd, b"\n".as_ptr() as *const libc::c_void, 1);
            let owned = String::from_utf8_lossy(&buf).into_owned();
            buf.zeroize();
            return Ok(zeroize::Zeroizing::new(owned));
        }
        // no termios: fall back to plain read
        let _ = libc::write(fd, prompt.as_ptr() as *const libc::c_void, prompt.len());
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let mut ch = 0u8;
            let n = libc::read(fd, &mut ch as *mut u8 as *mut libc::c_void, 1);
            if n <= 0 {
                break;
            }
            if ch == b'\n' {
                break;
            }
            buf.push(ch);
        }
        let owned = String::from_utf8_lossy(&buf).into_owned();
        buf.zeroize();
        Ok(zeroize::Zeroizing::new(owned))
    }
}

/// Prompt for a passphrase with echo disabled. Reads from `/dev/tty` when
/// available (so the prompt works even with piped stdin), else stdin.
pub fn read_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    let tty = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR) };
    if tty >= 0 {
        let r = read_line_noecho(tty, prompt);
        unsafe { libc::close(tty) };
        r
    } else {
        read_line_noecho(0, prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_pty_is_close_on_exec() {
        let p = open_pty(24, 80).unwrap();
        for fd in [p.master.as_raw_fd(), p.slave.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags & libc::FD_CLOEXEC != 0, "fd {fd} lacks FD_CLOEXEC");
        }
        assert_eq!(get_winsize(p.slave.as_raw_fd()), (24, 80));
    }

    #[test]
    fn clamp_size_is_sane() {
        assert_eq!(clamp_size(24, 80), (24, 80));
        assert_eq!(clamp_size(0, 0), (1, 1));
        assert_eq!(clamp_size(999_999, 999_999), (4096, 16384));
    }
}
