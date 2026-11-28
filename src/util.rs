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

/// The complete supplementary group list of `name` (including `gid`),
/// sized dynamically. Computed in the parent before forking so the child
/// can install it with one checked `setgroups` call.
///
/// This replaces `initgroups(3)` in the child, whose failure was ignored:
/// musl's `initgroups` uses a fixed 32-entry buffer and fails *without
/// calling setgroups* for users in more groups, so the session silently
/// kept the server's (root's) supplementary groups.
pub fn supplementary_groups(name: &str, gid: u32) -> Option<Vec<libc::gid_t>> {
    let _guard = PW_LOCK.lock().unwrap();
    let cname = CString::new(name).ok()?;
    let mut cap: libc::c_int = 64;
    for _ in 0..8 {
        let mut buf = vec![0 as libc::gid_t; cap as usize];
        let mut count = cap;
        let r = unsafe { libc::getgrouplist(cname.as_ptr(), gid, buf.as_mut_ptr(), &mut count) };
        if r >= 0 && count >= 0 && count <= cap {
            buf.truncate(count as usize);
            return Some(buf);
        }
        // Too small: glibc and musl both report the required size.
        cap = if count > cap { count } else { cap.saturating_mul(2) };
        if cap > 65536 {
            return None; // more than the kernel's NGROUPS_MAX
        }
    }
    None
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
