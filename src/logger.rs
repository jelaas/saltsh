//! Server logging.
//!
//! All server log output goes through [`log`] so that a single flag
//! (`--log-timestamps`) can prefix every line with a local timestamp.
//! Output always lands on stderr, which `--log-file` redirects to a file.

use std::sync::atomic::{AtomicBool, Ordering};

static TIMESTAMPS: AtomicBool = AtomicBool::new(false);

/// Enable timestamp prefixes (from `--log-timestamps`).
pub fn enable_timestamps() {
    TIMESTAMPS.store(true, Ordering::Relaxed);
}

/// Write one `saltsh: ...` log line to stderr, with a `[YYYY-MM-DD
/// HH:MM:SS]` local-time prefix when timestamps are enabled.
pub fn log(args: std::fmt::Arguments<'_>) {
    if TIMESTAMPS.load(Ordering::Relaxed) {
        eprintln!("{} saltsh: {args}", timestamp());
    } else {
        eprintln!("saltsh: {args}");
    }
}

/// `[YYYY-MM-DD HH:MM:SS]` in local time (like syslog). Returns `[?]` if
/// the clock or libc formatting fails.
pub fn timestamp() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return "[?]".to_string();
        }
        let mut buf = [0u8; 32];
        let n = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            c"%Y-%m-%d %H:%M:%S".as_ptr(),
            &tm,
        );
        if n == 0 {
            return "[?]".to_string();
        }
        format!("[{}]", String::from_utf8_lossy(&buf[..n]))
    }
}

/// `logline!("... {}", x)` — a `log(format_args!(...))` shorthand.
macro_rules! logline {
    ($($arg:tt)*) => {
        $crate::logger::log(format_args!($($arg)*))
    };
}
pub(crate) use logline;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_format() {
        let ts = timestamp();
        // "[YYYY-MM-DD HH:MM:SS]" — 21 bytes, digits in the right places
        assert_eq!(ts.len(), 21, "{ts}");
        assert!(ts.starts_with('[') && ts.ends_with(']'));
        assert_eq!(&ts.as_bytes()[5], &b'-');
        assert_eq!(&ts.as_bytes()[8], &b'-');
        assert_eq!(&ts.as_bytes()[14], &b':');
        assert_eq!(&ts.as_bytes()[17], &b':');
    }
}
