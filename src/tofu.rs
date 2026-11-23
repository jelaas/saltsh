//! Host-key trust: TOFU pinning (spec §6).
//!
//! Store: `~/.config/saltsh/known_hosts` (or `$XDG_CONFIG_HOME`), one line
//! per host: `host:port base64(Ed25519 pubkey)`. First connect prompts with
//! the SHA-256 fingerprint (OpenSSH-style); a key change is a hard fail.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::util;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    /// `host:port`
    pub addr: String,
    pub key: [u8; 32],
}

/// Path to the known_hosts store.
pub fn known_hosts_path() -> Result<PathBuf> {
    Ok(util::config_dir()?.join("saltsh").join("known_hosts"))
}

/// Load the store, silently skipping malformed lines.
pub fn load(path: &Path) -> Vec<HostEntry> {
    let mut entries = Vec::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, ' ');
            let (Some(addr), Some(b64)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(key_bytes) = B64.decode(b64) else { continue };
            if key_bytes.len() != 32 {
                continue;
            }
            entries.push(HostEntry {
                addr: addr.to_string(),
                key: key_bytes.try_into().expect("32 bytes"),
            });
        }
    }
    entries
}

/// Find the pinned key for `host:port`, if any.
pub fn find<'a>(entries: &'a [HostEntry], host: &str, port: u16) -> Option<&'a [u8; 32]> {
    let addr = format!("{host}:{port}");
    entries.iter().find(|e| e.addr == addr).map(|e| &e.key)
}

/// Append (or refresh) a pin, creating the store and its directories.
///
/// Appends are serialized with `flock` because several client processes
/// may pin keys concurrently; a plain O_APPEND can still interleave
/// multi-part writes.
pub fn add(path: &Path, host: &str, port: u16, key: &[u8; 32]) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::HostKey(format!("cannot create {}: {e}", parent.display()))
        })?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::HostKey(format!("cannot open {}: {e}", path.display())))?;
    let fd = f.as_raw_fd();
    if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
        return Err(Error::HostKey(format!(
            "cannot lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let result = writeln!(f, "{host}:{port} {}", B64.encode(key))
        .map_err(|e| Error::HostKey(format!("cannot write {}: {e}", path.display())));
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
    }
    result
}

/// OpenSSH-style fingerprint: `SHA256:<base64(sha256(pubkey))>`, matching
/// `ssh-keygen -lf` output for the same Ed25519 key.
pub fn fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("SHA256:{}", B64.encode(digest).trim_end_matches('='))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_find_roundtrip() {
        let dir = std::env::temp_dir().join(format!("saltsh-tofu-{}", std::process::id()));
        let path = dir.join("known_hosts");
        let _ = std::fs::remove_dir_all(&dir);
        let key = [7u8; 32];
        add(&path, "example.com", 2222, &key).unwrap();
        let entries = load(&path);
        assert_eq!(find(&entries, "example.com", 2222), Some(&key));
        assert_eq!(find(&entries, "example.com", 22), None);
        assert_eq!(find(&entries, "other.com", 2222), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(&[0u8; 32]);
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), "SHA256:".len() + 43); // base64 of 32 bytes, no padding
    }
}
