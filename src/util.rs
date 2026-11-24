//! Misc OS helpers: passwd lookups, defaults, environment.

use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::sync::Mutex;

/// Snapshot of the fields we need from `struct passwd`. `getpwnam` uses
/// static storage, so lookups are serialized behind a mutex and all fields
/// are copied out immediately (the server is thread-per-connection).
#[derive(Debug, Clone)]
pub struct Passwd {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

static PW_LOCK: Mutex<()> = Mutex::new(());

pub fn getpwnam(name: &str) -> Option<Passwd> {
    let _guard = PW_LOCK.lock().unwrap();
    let cname = CString::new(name).ok()?;
    unsafe {
        let p = libc::getpwnam(cname.as_ptr());
        if p.is_null() {
            return None;
        }
        Some(copy_passwd(&*p))
    }
}

pub fn getpwuid(uid: u32) -> Option<Passwd> {
    let _guard = PW_LOCK.lock().unwrap();
    unsafe {
        let p = libc::getpwuid(uid);
        if p.is_null() {
            return None;
        }
        Some(copy_passwd(&*p))
    }
}

unsafe fn copy_passwd(p: &libc::passwd) -> Passwd {
    Passwd {
        name: CStr::from_ptr(p.pw_name).to_string_lossy().into_owned(),
        uid: p.pw_uid,
        gid: p.pw_gid,
        home: CStr::from_ptr(p.pw_dir).to_string_lossy().into_owned(),
        shell: CStr::from_ptr(p.pw_shell).to_string_lossy().into_owned(),
    }
}

/// The current user's home directory (`$HOME`, else passwd).
pub fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        return Some(PathBuf::from(h));
    }
    let euid = unsafe { libc::geteuid() };
    getpwuid(euid).map(|p| PathBuf::from(p.home))
}

/// The saltsh state directory: `$HOME/.saltsh`. All of saltsh's user-level
/// files live here (identity keys, known_hosts, per-user authorized_keys,
/// and the non-root host key) — the ssh-style single-directory layout.
pub fn saltsh_dir() -> crate::error::Result<PathBuf> {
    home_dir()
        .map(|h| h.join(".saltsh"))
        .ok_or_else(|| crate::error::Error::usage("cannot determine home directory (no $HOME)"))
}

/// The username to present when none is given (`$USER`, else passwd).
pub fn default_username() -> String {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() {
            return u;
        }
    }
    let euid = unsafe { libc::geteuid() };
    getpwuid(euid).map(|p| p.name).unwrap_or_else(|| "user".into())
}

/// The local login shell: `$SHELL`, else the passwd entry, else `/bin/sh`.
/// (The server clears its environment, so the passwd fallback matters.)
pub fn default_shell() -> String {
    if let Ok(s) = std::env::var("SHELL") {
        if !s.is_empty() {
            return s;
        }
    }
    let euid = unsafe { libc::geteuid() };
    getpwuid(euid)
        .map(|p| p.shell)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into())
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Default host-key path: `/etc/saltsh/host_key` as root,
/// `~/.saltsh/host_key` otherwise.
pub fn default_host_key_path() -> PathBuf {
    if is_root() {
        PathBuf::from("/etc/saltsh/host_key")
    } else {
        saltsh_dir()
            .unwrap_or_else(|_| PathBuf::from(".saltsh"))
            .join("host_key")
    }
}
