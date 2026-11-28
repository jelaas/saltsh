//! OpenSSH key formats (spec §7).
//!
//! * public keys: `ssh-ed25519 AAAA... comment` (base64 of
//!   `string "ssh-ed25519" || string 32-byte pubkey`) — used for client
//!   keys and `authorized_keys` entries,
//! * private keys: `-----BEGIN OPENSSH PRIVATE KEY-----` with
//!   `cipher=none, kdf=none` or `kdf=bcrypt, cipher=aes256-ctr`
//!   (the default `ssh-keygen` output), unwrapped with `bcrypt-pbkdf`
//!   and AES-256-CTR.
//!
//! Interop goal: keys produced by `ssh-keygen -t ed25519` parse here, and
//! keys written here (unencrypted or bcrypt-encrypted) parse with
//! `ssh-keygen -y`.

use std::io::Read;
use std::path::{Path, PathBuf};

use aes::Aes256;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::rng;

pub const SSH_ED25519: &[u8] = b"ssh-ed25519";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const PRIV_CHECKINT: u32 = 0x5A5A_A5A5;
/// SSH's private-blob padding block size (8 for "none" and aes256-ctr).
const PRIV_BLOCK: usize = 8;
/// OpenSSH default bcrypt KDF rounds.
const BCRYPT_ROUNDS: u32 = 16;

type Aes256Ctr = Ctr128BE<Aes256>;

/// An Ed25519 keypair as a raw 32-byte seed + 32-byte public key.
#[derive(Clone)]
pub struct KeyPair {
    pub seed: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Options parsed from one `authorized_keys` line.
///
/// Parsing is fail-closed: option names are matched case-insensitively
/// (like OpenSSH), and a line carrying an option saltsh does not know — or
/// one it cannot honor — is refused as a whole, so a restriction can never
/// be silently dropped. See [`parse_key_options`] for the accepted set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizedKeyOptions {
    /// `from="..."` pattern list (at most one `from=` per line).
    pub from: Option<String>,
    /// Forced command from `command="..."` (at most one per line).
    pub command: Option<String>,
    /// `expiry-time="..."`: the key is refused after this Unix time (the
    /// earliest one wins if several are given, as in OpenSSH).
    pub expires_at: Option<i64>,
    /// Terminal permission from `pty` (true) / `no-pty` / `restrict`
    /// (false), processed in order, last one wins (OpenSSH semantics).
    /// `None` = not specified: a PTY is allowed for ordinary sessions and
    /// denied for forced commands.
    pub pty: Option<bool>,
}

/// One parsed `authorized_keys` entry: public key + its options.
#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub public: [u8; 32],
    pub options: AuthorizedKeyOptions,
}

/// Generate a fresh Ed25519 keypair.
pub fn generate_keypair() -> KeyPair {
    let mut rng = rng::os_rng();
    let sk = SigningKey::generate(&mut rng);
    let public = sk.verifying_key().to_bytes();
    let seed = sk.to_bytes();
    KeyPair { seed, public }
}

// ---------------------------------------------------------------------------
// Public keys

/// The OpenSSH blob for an Ed25519 public key:
/// `string "ssh-ed25519" || string 32-byte pubkey`.
pub fn ssh_ed25519_pubkey_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(51);
    push_string(&mut b, SSH_ED25519);
    push_string(&mut b, public);
    b
}

/// Parse the OpenSSH blob for an Ed25519 public key.
pub fn parse_pubkey_blob(blob: &[u8]) -> Result<[u8; 32]> {
    let mut c = Cursor::new(blob);
    let ktype = c.string()?;
    if ktype != SSH_ED25519 {
        return Err(Error::key("not an ssh-ed25519 key"));
    }
    let pk = c.string()?;
    if pk.len() != 32 {
        return Err(Error::key("malformed ed25519 public key"));
    }
    Ok(pk.try_into().expect("32 bytes"))
}

/// One `authorized_keys` / `.pub` line:
/// `[options] ssh-ed25519 AAAA... comment`.
///
/// Errors for anything that is not a usable `ssh-ed25519` entry; see
/// [`parse_authorized_keys_entry`] for the variant that tells blank,
/// comment, and other-key-type lines apart from malformed ones.
pub fn parse_authorized_keys_line(line: &str) -> Result<AuthorizedKey> {
    parse_authorized_keys_entry(line)?
        .ok_or_else(|| Error::key("no ssh-ed25519 key on this line"))
}

/// Parse one `authorized_keys` line.
///
/// * `Ok(None)` — nothing to use and nothing wrong: a blank line, a
///   `#` comment, or a key type saltsh does not support (`ssh-rsa`, ...).
/// * `Err(_)` — an `ssh-ed25519` entry that must be refused: malformed
///   options, an unknown option, an option saltsh cannot honor, or bad key
///   data. Refusing (instead of skipping just the option) is what keeps a
///   restriction from being dropped silently.
///
/// The options field follows OpenSSH's syntax: comma-separated, no
/// unquoted whitespace, option names case-insensitive, values in double
/// quotes with `\"` as the only escape.
pub fn parse_authorized_keys_entry(line: &str) -> Result<Option<AuthorizedKey>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let first_end = line.find(char::is_whitespace).unwrap_or(line.len());
    let (opts_field, rest) = if looks_like_key_type(&line[..first_end]) {
        ("", line)
    } else {
        let end = options_field_end(line)?;
        (&line[..end], line[end..].trim_start())
    };
    let mut fields = rest.split_whitespace();
    let ktype = fields.next().ok_or_else(|| Error::key("missing key type"))?;
    if ktype != "ssh-ed25519" {
        return Ok(None); // not usable by saltsh, but not an error either
    }
    let b64 = fields.next().ok_or_else(|| Error::key("missing key data"))?;
    let options = parse_key_options(opts_field)?;
    let der = B64
        .decode(b64)
        .map_err(|e| Error::key(format!("bad base64 in authorized_keys: {e}")))?;
    let public = parse_pubkey_blob(&der)?;
    Ok(Some(AuthorizedKey { public, options }))
}

/// A token that starts a line without options: an OpenSSH key type name.
fn looks_like_key_type(tok: &str) -> bool {
    (tok.starts_with("ssh-") || tok.starts_with("ecdsa-") || tok.starts_with("sk-"))
        && !tok.contains(['=', '"', ','])
}

/// Byte index where the options field ends: the first whitespace outside
/// double quotes.
fn options_field_end(line: &str) -> Result<usize> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_quotes = false;
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c.is_whitespace() {
            return Ok(i);
        }
    }
    if in_quotes {
        return Err(Error::key("unterminated quote in options"));
    }
    Ok(line.len())
}

/// Split the options field into `(name, value)` pairs.
fn split_options(field: &str) -> Result<Vec<(String, Option<String>)>> {
    let mut out = Vec::new();
    let mut chars = field.chars().peekable();
    loop {
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ',' {
                break;
            }
            name.push(c);
            chars.next();
        }
        if name.is_empty() {
            return Err(Error::key("empty option name"));
        }
        let value = if chars.peek() == Some(&'=') {
            chars.next();
            if chars.next() != Some('"') {
                return Err(Error::key(format!(
                    "value of option '{}' must be double-quoted",
                    option_display(&name)
                )));
            }
            let mut v = String::new();
            loop {
                match chars.next() {
                    None => return Err(Error::key("unterminated quote in options")),
                    Some('\\') if chars.peek() == Some(&'"') => {
                        v.push('"');
                        chars.next();
                    }
                    Some('"') => break,
                    Some(c) => v.push(c),
                }
            }
            Some(v)
        } else {
            None
        };
        out.push((name, value));
        match chars.next() {
            None => break,
            Some(',') if chars.peek().is_some() => continue,
            Some(',') => return Err(Error::key("trailing comma in options")),
            Some(_) => return Err(Error::key("junk after option value")),
        }
    }
    Ok(out)
}

/// Option names for error messages: sanitized and bounded (the per-user
/// file is user-controlled and these messages reach the server log).
fn option_display(name: &str) -> String {
    crate::wire::display_safe(name.as_bytes(), 40)
}

/// Interpret an options field (see [`parse_authorized_keys_entry`]).
///
/// | options | effect |
/// |---|---|
/// | `command="..."` | forced command (client argv is appended — see README) |
/// | `from="..."` | source-address restriction |
/// | `expiry-time="..."` | key refused after this time |
/// | `pty`, `no-pty`, `restrict` | terminal permission (last one wins); `restrict` denies a PTY unless a later `pty` re-allows it |
/// | `[no-]port-forwarding`, `[no-]agent-forwarding`, `[no-]x11-forwarding`, `[no-]user-rc`, `no-touch-required` | accepted; saltsh has no forwarding, agent, X11 or rc features |
/// | `environment=`, `permitopen=`, `permitlisten=`, `tunnel=` | accepted, no effect (saltsh never sets per-key variables and has no forwarding) |
/// | `cert-authority`, `principals=`, `verify-required` | **line refused**: saltsh cannot honor them |
/// | anything else, duplicates of `command`/`from` | **line refused** |
pub fn parse_key_options(field: &str) -> Result<AuthorizedKeyOptions> {
    let mut o = AuthorizedKeyOptions::default();
    if field.is_empty() {
        return Ok(o);
    }
    for (name, value) in split_options(field)? {
        let lname = name.to_ascii_lowercase();
        let shown = option_display(&lname);
        match (lname.as_str(), value) {
            ("command", Some(v)) => {
                if o.command.is_some() {
                    return Err(Error::key("multiple command options"));
                }
                o.command = Some(v);
            }
            ("from", Some(v)) => {
                if o.from.is_some() {
                    return Err(Error::key("multiple from options"));
                }
                validate_from_list(&v)?;
                o.from = Some(v);
            }
            ("expiry-time", Some(v)) => {
                let t = parse_expiry_time(&v)?;
                o.expires_at = Some(o.expires_at.map_or(t, |e| e.min(t)));
            }
            ("pty", None) => o.pty = Some(true),
            ("no-pty" | "restrict", None) => o.pty = Some(false),
            (
                "port-forwarding" | "no-port-forwarding" | "agent-forwarding"
                | "no-agent-forwarding" | "x11-forwarding" | "no-x11-forwarding" | "user-rc"
                | "no-user-rc" | "no-touch-required",
                None,
            ) => {}
            ("environment" | "permitopen" | "permitlisten" | "tunnel", Some(_)) => {}
            ("cert-authority" | "principals" | "verify-required", _) => {
                return Err(Error::key(format!(
                    "option '{shown}' is not supported by saltsh"
                )));
            }
            (
                "command" | "from" | "expiry-time" | "environment" | "permitopen"
                | "permitlisten" | "tunnel",
                None,
            ) => {
                return Err(Error::key(format!("option '{shown}' requires a value")));
            }
            (
                "restrict" | "pty" | "no-pty" | "port-forwarding" | "no-port-forwarding"
                | "agent-forwarding" | "no-agent-forwarding" | "x11-forwarding"
                | "no-x11-forwarding" | "user-rc" | "no-user-rc" | "no-touch-required",
                Some(_),
            ) => {
                return Err(Error::key(format!("option '{shown}' takes no value")));
            }
            _ => return Err(Error::key(format!("unknown option '{shown}'"))),
        }
    }
    Ok(o)
}

/// Every `from=` pattern containing `/` must be a well-formed CIDR block.
/// OpenSSH refuses the key on a malformed one; silently treating it as
/// "no match" would let a broken `!negation` admit the very host it was
/// meant to exclude.
fn validate_from_list(list: &str) -> Result<()> {
    for raw in list.split(',') {
        let pattern = raw.trim();
        let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
        if pattern.contains('/') && !is_valid_cidr(pattern) {
            return Err(Error::key(format!(
                "invalid CIDR block in from= ('{}')",
                crate::wire::display_safe(pattern.as_bytes(), 64)
            )));
        }
    }
    Ok(())
}

fn is_valid_cidr(pattern: &str) -> bool {
    let Some((net, prefix)) = pattern.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if let Ok(v4) = net.parse::<std::net::Ipv4Addr>() {
        if prefix > 32 {
            return false;
        }
        // host bits must be clear, as OpenSSH requires
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        return u32::from(v4) & !mask == 0;
    }
    // IPv6 blocks are valid syntax but never match (saltsh is IPv4-only)
    net.parse::<std::net::Ipv6Addr>().is_ok() && prefix <= 128
}

/// `expiry-time="YYYYMMDD[HHMM[SS]][Z]"`: local time, or UTC with a
/// trailing `Z` (OpenSSH syntax). Returns the Unix time.
fn parse_expiry_time(v: &str) -> Result<i64> {
    let bad = || Error::key(format!(
        "invalid expiry-time '{}'",
        crate::wire::display_safe(v.as_bytes(), 32)
    ));
    let (digits, utc) = match v.strip_suffix(['Z', 'z']) {
        Some(d) => (d, true),
        None => (v, false),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) || ![8, 12, 14].contains(&digits.len()) {
        return Err(bad());
    }
    let n = |a: usize, b: usize| digits.get(a..b).map_or(0, |s| s.parse::<i32>().unwrap_or(-1));
    let (year, mon, day) = (n(0, 4), n(4, 6), n(6, 8));
    let (hour, min, sec) = (n(8, 10), n(10, 12), n(12, 14));
    if !(1..=12).contains(&mon) || !(1..=31).contains(&day) || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min) || !(0..=60).contains(&sec) || year < 1970
    {
        return Err(bad());
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    tm.tm_isdst = -1;
    let t = unsafe { if utc { libc::timegm(&mut tm) } else { libc::mktime(&mut tm) } };
    // mktime/timegm normalize impossible dates (Feb 31 -> Mar 3): reject them
    if t == -1 || tm.tm_mday != day || tm.tm_mon != mon - 1 {
        return Err(bad());
    }
    Ok(t as i64)
}

/// Largest `authorized_keys` file the server will read.
pub const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1 << 20;

/// Who may own an `authorized_keys` file and its directories
/// (StrictModes-style checks, as in OpenSSH).
pub struct KeyFilePolicy<'a> {
    /// The file (and each checked directory) must be owned by root or by
    /// this uid, and must not be group- or world-writable.
    pub owner_uid: u32,
    /// Also check every parent directory of the (resolved) file, stopping
    /// after this one (the user's home); `None` checks only the file.
    pub check_dirs_up_to: Option<&'a Path>,
}

/// Why an `authorized_keys` file yielded no keys.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyFileError {
    /// The file does not exist (not worth a log line).
    Missing,
    /// The file exists but was refused; the reason is safe to log.
    Refused(String),
}

/// The usable entries of an `authorized_keys` file, plus one warning per
/// refused line (safe to log: line numbers and sanitized option names,
/// never file content).
#[derive(Debug, Default)]
pub struct AuthorizedKeysFile {
    pub keys: Vec<AuthorizedKey>,
    pub warnings: Vec<String>,
}

/// Load an `authorized_keys` file the way a root daemon must: without
/// trusting the path. The file is opened non-blocking (a FIFO cannot
/// stall the server), must be a regular file (no `/dev/zero`, devices or
/// sockets), must pass the ownership/mode policy, and is read up to
/// [`MAX_AUTHORIZED_KEYS_BYTES`] only.
pub fn load_authorized_keys(
    path: &Path,
    policy: &KeyFilePolicy<'_>,
) -> std::result::Result<AuthorizedKeysFile, KeyFileError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path);
    let f = match f {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(KeyFileError::Missing),
        Err(e) => return Err(KeyFileError::Refused(format!("cannot open: {e}"))),
    };
    let meta = f
        .metadata()
        .map_err(|e| KeyFileError::Refused(format!("cannot stat: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(KeyFileError::Refused("not a regular file".into()));
    }
    check_owner_and_mode(meta.uid(), meta.mode(), policy.owner_uid)
        .map_err(|why| KeyFileError::Refused(format!("bad ownership or modes: {why}")))?;
    if let Some(home) = policy.check_dirs_up_to {
        check_parent_dirs(path, home, policy.owner_uid).map_err(KeyFileError::Refused)?;
    }
    let mut buf = Vec::new();
    f.take(MAX_AUTHORIZED_KEYS_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| KeyFileError::Refused(format!("read error: {e}")))?;
    if buf.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
        return Err(KeyFileError::Refused(format!(
            "larger than {MAX_AUTHORIZED_KEYS_BYTES} bytes"
        )));
    }
    let mut out = AuthorizedKeysFile::default();
    for (i, raw) in buf.split(|&b| b == b'\n').enumerate() {
        let Ok(line) = std::str::from_utf8(raw) else {
            out.warnings.push(format!("line {}: not valid UTF-8; skipped", i + 1));
            continue;
        };
        match parse_authorized_keys_entry(line) {
            Ok(Some(k)) => out.keys.push(k),
            Ok(None) => {}
            Err(e) => out.warnings.push(format!("line {}: {e}; key refused", i + 1)),
        }
    }
    Ok(out)
}

/// Owned by root or `uid`, and not writable by group or others.
fn check_owner_and_mode(file_uid: u32, mode: u32, uid: u32) -> std::result::Result<(), String> {
    if file_uid != 0 && file_uid != uid {
        return Err(format!("owned by uid {file_uid}"));
    }
    if mode & 0o022 != 0 {
        return Err(format!("group/world-writable (mode {:o})", mode & 0o7777));
    }
    Ok(())
}

/// StrictModes for directories: every directory from the file's resolved
/// location up to (and including) `home` must satisfy
/// [`check_owner_and_mode`]. If the file resolves outside `home`, the walk
/// continues to `/`.
fn check_parent_dirs(path: &Path, home: &Path, uid: u32) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(path).map_err(|e| format!("cannot resolve: {e}"))?;
    let home_real = std::fs::canonicalize(home).ok();
    let mut dir = real.parent();
    while let Some(d) = dir {
        let m = std::fs::metadata(d).map_err(|e| format!("cannot stat {}: {e}", d.display()))?;
        check_owner_and_mode(m.uid(), m.mode(), uid)
            .map_err(|why| format!("bad ownership or modes for directory {}: {why}", d.display()))?;
        if home_real.as_deref() == Some(d) {
            break;
        }
        dir = d.parent();
    }
    Ok(())
}

/// Format an `authorized_keys` entry for `public`.
pub fn authorized_keys_entry(public: &[u8; 32], comment: &str) -> String {
    format!("ssh-ed25519 {} {comment}\n", B64.encode(ssh_ed25519_pubkey_blob(public)))
}

// ---------------------------------------------------------------------------
// Private keys

/// Header info about an OpenSSH private key file, used to decide whether a
/// passphrase is needed before full parsing.
pub struct PrivateKeyInfo {
    pub encrypted: bool,
    pub cipher: String,
    pub kdf: String,
}

/// Read only the armor + header of an OpenSSH private key file.
pub fn private_key_info(path: &Path) -> Result<PrivateKeyInfo> {
    let data = read_file(path)?;
    let der = pem_decode(&data)?;
    let mut c = Cursor::new(&der);
    if c.take(OPENSSH_MAGIC.len())? != OPENSSH_MAGIC {
        return Err(Error::key("not an OpenSSH private key"));
    }
    let cipher = String::from_utf8_lossy(c.string()?).into_owned();
    let kdf = String::from_utf8_lossy(c.string()?).into_owned();
    Ok(PrivateKeyInfo {
        encrypted: cipher != "none" || kdf != "none",
        cipher,
        kdf,
    })
}

/// Load an OpenSSH private key, decrypting with `passphrase` when the file
/// is encrypted.
pub fn load_private_key(path: &Path, passphrase: Option<&str>) -> Result<KeyPair> {
    let data = read_file(path)?;
    parse_openssh_private(&data, passphrase)
}

/// Parse an OpenSSH private key from the file contents.
pub fn parse_openssh_private(data: &[u8], passphrase: Option<&str>) -> Result<KeyPair> {
    let der = pem_decode(data)?;
    let mut c = Cursor::new(&der);
    if c.take(OPENSSH_MAGIC.len())? != OPENSSH_MAGIC {
        return Err(Error::key("not an OpenSSH private key"));
    }
    let ciphername = c.string()?;
    let kdfname = c.string()?;
    let kdfoptions = c.string()?;
    let nkeys = c.u32()?;
    if nkeys != 1 {
        return Err(Error::key(format!("unsupported number of keys: {nkeys}")));
    }
    let pub_blob = c.string()?;
    let public = parse_pubkey_blob(pub_blob)?;
    let encrypted = c.string()?;

    // Every buffer that holds private key material is zeroized on drop.
    let priv_blob: Zeroizing<Vec<u8>> = match (ciphername, kdfname) {
        (b"none", b"none") => Zeroizing::new(encrypted.to_vec()),
        (b"aes256-ctr", b"bcrypt") => {
            let passphrase = passphrase.ok_or_else(|| Error::key("encrypted key: a passphrase is required"))?;
            decrypt_priv_blob(encrypted, kdfoptions, passphrase)?
        }
        (cn, kd) => {
            return Err(Error::key(format!(
                "unsupported cipher/kdf: {}/{}",
                String::from_utf8_lossy(cn),
                String::from_utf8_lossy(kd)
            )))
        }
    };

    let (seed, public2) = decode_priv_blob(&priv_blob)?;
    if public2 != public {
        return Err(Error::key("public key does not match private key"));
    }
    // Final sanity check: the seed really is this public key's seed.
    let sk = SigningKey::from_bytes(&seed);
    if sk.verifying_key().to_bytes() != public {
        return Err(Error::key("private key seed is corrupt"));
    }
    Ok(KeyPair { seed: *seed, public })
}

fn decrypt_priv_blob(blob: &[u8], kdfoptions: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut c = Cursor::new(kdfoptions);
    let salt = c.string()?;
    let rounds = c.u32()?;
    if rounds == 0 || rounds > 1 << 20 {
        return Err(Error::key("invalid bcrypt rounds"));
    }
    let mut keyiv = Zeroizing::new([0u8; 48]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut *keyiv)
        .map_err(|e| Error::key(format!("bcrypt-pbkdf failed: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    let mut iv = Zeroizing::new([0u8; 16]);
    key.copy_from_slice(&keyiv[..32]);
    iv.copy_from_slice(&keyiv[32..48]);
    let mut out = Zeroizing::new(blob.to_vec());
    let mut ctr = Aes256Ctr::new(&(*key).into(), &(*iv).into());
    ctr.apply_keystream(&mut out);
    Ok(out)
}

/// Parse the inner (decrypted) private blob:
/// checkint || checkint || string "ssh-ed25519" || string pub || string priv || comment || padding
fn decode_priv_blob(blob: &[u8]) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let mut c = Cursor::new(blob);
    let check1 = c.u32()?;
    let check2 = c.u32()?;
    if check1 != check2 {
        return Err(Error::key("bad checkint (wrong passphrase or corrupt key)"));
    }
    let ktype = c.string()?;
    if ktype != SSH_ED25519 {
        return Err(Error::key("not an ssh-ed25519 private key"));
    }
    let public: [u8; 32] = c
        .string()?
        .try_into()
        .map_err(|_| Error::key("malformed public key in private blob"))?;
    let priv64 = c.string()?;
    if priv64.len() != 64 {
        return Err(Error::key("malformed ed25519 private key"));
    }
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&priv64[0..32]).expect("32 bytes"));
    let public2: [u8; 32] = priv64[32..64].try_into().expect("32 bytes");
    if public2 != public {
        return Err(Error::key("public key does not match private key material"));
    }
    Ok((seed, public))
}

// ---------------------------------------------------------------------------
// Private-key writing (host keys; also used by tests)

/// Serialize an OpenSSH private key. With `passphrase: None` the file uses
/// `cipher=none, kdf=none`; with `Some` it uses `kdf=bcrypt` +
/// `aes256-ctr` exactly like default `ssh-keygen` output.
pub fn write_openssh_private(
    seed: &[u8; 32],
    public: &[u8; 32],
    comment: &str,
    passphrase: Option<&str>,
) -> Zeroizing<Vec<u8>> {
    // Pre-sized so growth never leaves stale copies of the seed behind.
    let mut blob = Zeroizing::new(Vec::with_capacity(256 + comment.len()));
    push_u32(&mut blob, PRIV_CHECKINT);
    push_u32(&mut blob, PRIV_CHECKINT);
    push_string(&mut blob, SSH_ED25519);
    push_string(&mut blob, public);
    let mut priv64 = Zeroizing::new(Vec::with_capacity(64));
    priv64.extend_from_slice(seed);
    priv64.extend_from_slice(public);
    push_string(&mut blob, &priv64);
    push_string(&mut blob, comment.as_bytes());
    // padding to a multiple of PRIV_BLOCK, at least 4 bytes, counting 1..n
    let mut pad = PRIV_BLOCK - (blob.len() % PRIV_BLOCK);
    if pad < 4 {
        pad += PRIV_BLOCK;
    }
    for i in 1..=pad {
        blob.push(i as u8);
    }

    let (ciphername, kdfname, kdfoptions) = match passphrase {
        None => (b"none".to_vec(), b"none".to_vec(), Vec::new()),
        Some(pass) => {
            let salt = rng::random_bytes::<16>();
            let mut kdfopts = Vec::new();
            push_string(&mut kdfopts, &salt);
            push_u32(&mut kdfopts, BCRYPT_ROUNDS);
            let mut keyiv = Zeroizing::new([0u8; 48]);
            bcrypt_pbkdf::bcrypt_pbkdf(pass.as_bytes(), &salt, BCRYPT_ROUNDS, &mut *keyiv)
                .expect("bcrypt-pbkdf derivation");
            let mut key = Zeroizing::new([0u8; 32]);
            let mut iv = Zeroizing::new([0u8; 16]);
            key.copy_from_slice(&keyiv[..32]);
            iv.copy_from_slice(&keyiv[32..48]);
            let mut ctr = Aes256Ctr::new(&(*key).into(), &(*iv).into());
            ctr.apply_keystream(&mut blob);
            (b"aes256-ctr".to_vec(), b"bcrypt".to_vec(), kdfopts)
        }
    };

    let mut out = Zeroizing::new(Vec::with_capacity(256 + blob.len()));
    out.extend_from_slice(OPENSSH_MAGIC);
    push_string(&mut out, &ciphername);
    push_string(&mut out, &kdfname);
    push_string(&mut out, &kdfoptions);
    push_u32(&mut out, 1);
    push_string(&mut out, &ssh_ed25519_pubkey_blob(public));
    push_string(&mut out, &blob);
    pem_encode(&out, PEM_BEGIN, PEM_END)
}

/// Write an (unencrypted) OpenSSH private key to `path` with mode 0600.
pub fn write_private_key_file(path: &Path, key: &KeyPair, comment: &str) -> Result<()> {
    let pem = write_openssh_private(&key.seed, &key.public, comment, None);
    write_file_mode(path, &pem, 0o600)
}

/// `saltsh keygen`: generate a keypair, write it to `path` (mode 0600) plus
/// the `path.pub` public line, and return the keypair. `passphrase` (when
/// given) encrypts the private key with bcrypt+aes256-ctr.
pub fn keygen(path: &Path, passphrase: Option<&str>, comment: &str) -> Result<KeyPair> {
    if path.exists() {
        return Err(Error::key(format!(
            "{} already exists; refusing to overwrite (use -f to pick a different path)",
            path.display()
        )));
    }
    let kp = generate_keypair();
    let pem = write_openssh_private(&kp.seed, &kp.public, comment, passphrase);
    write_file_mode(path, &pem, 0o600)?;
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    write_file_mode(&pub_path, authorized_keys_entry(&kp.public, comment).as_bytes(), 0o644)?;
    Ok(kp)
}

/// Load the host key from `path`, generating and saving a fresh one if the
/// file does not exist.
pub fn load_or_create_host_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let kp = load_private_key(path, None)?;
        return Ok(kp.signing_key());
    }
    let kp = generate_keypair();
    write_private_key_file(path, &kp, &format!("saltsh host key {}", hostname()))?;
    crate::logger::log(format_args!("generated new host key at {}", path.display()));
    Ok(kp.signing_key())
}

// ---------------------------------------------------------------------------
// Small binary helpers

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() - self.pos < n {
            return Err(Error::key("truncated key data"));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > 1 << 20 {
            return Err(Error::key("oversized string in key data"));
        }
        self.take(n)
    }
}

fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn push_string(b: &mut Vec<u8>, s: &[u8]) {
    push_u32(b, s.len() as u32);
    b.extend_from_slice(s);
}

// ---------------------------------------------------------------------------
// `from=` pattern lists (OpenSSH match.c semantics, IP candidates only)

/// Match a comma-separated pattern list against `candidate` (an IP
/// address for `from="..."` restrictions, or a hostname for
/// `~/.saltsh/config` Host sections). Semantics follow OpenSSH's
/// `match_pattern_list`: a matching negated (`!`) pattern rejects
/// immediately; otherwise the list matches if any positive pattern
/// matches.
pub fn match_pattern_list(list: &str, candidate: &str) -> bool {
    let mut positive = false;
    for raw in list.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (negated, pattern) = match raw.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        if pattern_matches(pattern, candidate) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

/// One pattern: an IPv4 CIDR block (`addr/prefixlen`, matched numerically)
/// or a glob (`*` any run, `?` one character) against the literal candidate.
/// saltsh is IPv4-only; patterns containing '/' are treated as IPv4 CIDR
/// and never match IPv6 (or non-address) candidates — fail-closed.
fn pattern_matches(pattern: &str, candidate: &str) -> bool {
    if pattern.contains('/') {
        cidr_matches(pattern, candidate)
    } else {
        glob_matches(pattern, candidate)
    }
}

/// Numeric IPv4 CIDR comparison.
fn cidr_matches(pattern: &str, candidate: &str) -> bool {
    use std::net::Ipv4Addr;
    let Some((net, prefix_s)) = pattern.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix_s.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let (Ok(net4), Ok(cand4)) = (net.parse::<Ipv4Addr>(), candidate.parse::<Ipv4Addr>()) else {
        return false;
    };
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (u32::from(net4) & mask) == (u32::from(cand4) & mask)
}

/// Simple `*`/`?` glob with backtracking.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = pi;
            star_t = ti;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn pem_decode(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(data).map_err(|_| Error::key("key file is not UTF-8"))?;
    let mut b64 = Zeroizing::new(String::with_capacity(text.len()));
    let mut in_body = false;
    for line in text.lines() {
        let line = line.trim();
        if line == PEM_END {
            break;
        }
        if in_body && !line.is_empty() {
            b64.push_str(line);
        }
        if line == PEM_BEGIN {
            in_body = true;
        }
    }
    if !in_body {
        return Err(Error::key("missing PEM armor"));
    }
    B64.decode(b64.as_bytes())
        .map(Zeroizing::new)
        .map_err(|e| Error::key(format!("bad base64 in key file: {e}")))
}

fn pem_encode(der: &[u8], begin: &str, end: &str) -> Zeroizing<Vec<u8>> {
    let b64 = Zeroizing::new(B64.encode(der));
    let mut out = Zeroizing::new(String::with_capacity(
        begin.len() + end.len() + b64.len() + b64.len() / 70 + 4,
    ));
    out.push_str(begin);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).expect("ascii"));
        out.push('\n');
    }
    out.push_str(end);
    out.push('\n');
    Zeroizing::new(std::mem::take(&mut *out).into_bytes())
}

fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| Error::key(format!("cannot read {}: {e}", path.display())))
}

fn write_file_mode(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::key(format!("cannot create {}: {e}", parent.display())))?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(mode);
    use std::io::Write;
    let mut f = opts
        .open(path)
        .map_err(|e| Error::key(format!("cannot write {}: {e}", path.display())))?;
    f.write_all(data)
        .map_err(|e| Error::key(format!("cannot write {}: {e}", path.display())))?;
    Ok(())
}

pub(crate) fn hostname() -> String {
    // Use gethostname(2): $HOSTNAME is not set on all systems (e.g.
    // Ubuntu), which would label every generated key "localhost".
    let mut buf = [0u8; 256];
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if let Ok(s) = std::str::from_utf8(&buf[..end]) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into())
}

/// Default identity path: `~/.saltsh/id_ed25519`.
pub fn default_identity_path(home: Option<&Path>) -> PathBuf {
    match home {
        Some(h) => h.join(".saltsh/id_ed25519"),
        None => PathBuf::from(".saltsh/id_ed25519"),
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    fn roundtrip(pass: Option<&str>) {
        let kp = generate_keypair();
        let pem = write_openssh_private(&kp.seed, &kp.public, "test@host", pass);
        let kp2 = parse_openssh_private(&pem, pass).expect("parse");
        assert_eq!(kp2.seed, kp.seed);
        assert_eq!(kp2.public, kp.public);
    }

    #[test]
    fn unencrypted_private_roundtrip() {
        roundtrip(None);
    }

    #[test]
    fn bcrypt_private_roundtrip() {
        roundtrip(Some("correct horse battery staple"));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let kp = generate_keypair();
        let pem = write_openssh_private(&kp.seed, &kp.public, "test@host", Some("right"));
        assert!(parse_openssh_private(&pem, Some("wrong")).is_err());
        assert!(parse_openssh_private(&pem, None).is_err());
    }

    #[test]
    fn pubkey_blob_roundtrip() {
        let kp = generate_keypair();
        let blob = ssh_ed25519_pubkey_blob(&kp.public);
        assert_eq!(parse_pubkey_blob(&blob).unwrap(), kp.public);
    }

    #[test]
    fn authorized_keys_parsing() {
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "alice@host");
        assert_eq!(parse_authorized_keys_line(&entry).unwrap().public, kp.public);
        // with options, including a quoted option containing spaces
        let with_opts = format!("command=\"echo hi\",no-pty {entry}");
        let ak = parse_authorized_keys_line(&with_opts).unwrap();
        assert_eq!(ak.public, kp.public);
        assert_eq!(ak.options.command.as_deref(), Some("echo hi"));
        assert_eq!(ak.options.from, None);
        // garbage is rejected
        assert!(parse_authorized_keys_line("garbage").is_err());
        assert!(parse_authorized_keys_line("ssh-ed25519 !!!").is_err());
    }

    #[test]
    fn authorized_keys_option_parsing() {
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "c");
        let entry = entry.trim_end();
        // from= with quoted value, escaped quotes in command=
        let line = format!(
            "from=\"192.0.2.0/24,127.0.0.1\",command=\"/bin/echo \\\"hi\\\"\" {entry}"
        );
        let ak = parse_authorized_keys_line(&line).unwrap();
        assert_eq!(ak.public, kp.public);
        assert_eq!(ak.options.from.as_deref(), Some("192.0.2.0/24,127.0.0.1"));
        assert_eq!(ak.options.command.as_deref(), Some("/bin/echo \"hi\""));
        // duplicate from= / command= options refuse the line (fail-closed;
        // merging them could only widen access)
        let line = format!("from=\"10.0.0.0/8\",from=\"192.168.0.0/16\" {entry}");
        assert!(parse_authorized_keys_line(&line).is_err());
        let line = format!("command=\"/bin/a\",command=\"/bin/b\" {entry}");
        assert!(parse_authorized_keys_line(&line).is_err());
        // OpenSSH options saltsh has nothing to enforce for are accepted
        let line = format!("environment=\"LANG=C\",no-port-forwarding,no-user-rc {entry}");
        let ak = parse_authorized_keys_line(&line).unwrap();
        assert_eq!(ak.options, AuthorizedKeyOptions::default());
    }

    #[test]
    fn pty_permission_is_ordered() {
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "c");
        let entry = entry.trim_end();
        let pty = |opts: &str| parse_authorized_keys_line(&format!("{opts} {entry}")).unwrap().options.pty;
        assert_eq!(pty("no-agent-forwarding"), None);
        assert_eq!(pty("pty"), Some(true));
        assert_eq!(pty("no-pty"), Some(false));
        assert_eq!(pty("restrict"), Some(false));
        assert_eq!(pty("restrict,pty"), Some(true)); // re-enabled after restrict
        assert_eq!(pty("pty,restrict"), Some(false)); // last one wins
        assert_eq!(pty("PTY,No-Pty"), Some(false));
    }

    #[test]
    fn option_names_are_case_insensitive() {
        // OpenSSH matches option names case-insensitively; a restriction
        // written in upper case must not be dropped.
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "c");
        let entry = entry.trim_end();
        let ak = parse_authorized_keys_line(&format!("COMMAND=\"/bin/echo restricted\" {entry}"))
            .unwrap();
        assert_eq!(ak.options.command.as_deref(), Some("/bin/echo restricted"));
        let ak = parse_authorized_keys_line(&format!("From=\"10.0.0.0/8\",No-PTY {entry}")).unwrap();
        assert_eq!(ak.options.from.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn unknown_or_unsupported_options_refuse_the_line() {
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "c");
        let entry = entry.trim_end();
        for opts in [
            "frm=\"10.0.0.1\"",         // typo of a restriction
            "made-up-flag",
            "cert-authority",           // would turn a CA key into a login key
            "principals=\"alice\"",
            "verify-required",
            "command=/bin/true",        // unquoted value
            "command=\"/bin/true",      // unterminated quote
            "command",                  // value missing
            "no-pty=\"x\"",             // flag with a value
            "no-pty,",                  // trailing comma
            "from=\"10.0.0.1/33\"",     // malformed CIDR
            "from=\"!10.0.0.0/33,*\"",  // malformed negation must not admit
            "from=\"10.0.0.1/8\"",      // host bits set
            "expiry-time=\"2026\"",
            "expiry-time=\"20260231\"", // no such date
        ] {
            assert!(
                parse_authorized_keys_line(&format!("{opts} {entry}")).is_err(),
                "should refuse: {opts}"
            );
        }
    }

    #[test]
    fn blank_comment_and_foreign_key_lines_are_skipped_not_errors() {
        assert!(parse_authorized_keys_entry("").unwrap().is_none());
        assert!(parse_authorized_keys_entry("   # a comment").unwrap().is_none());
        assert!(parse_authorized_keys_entry("ssh-rsa AAAAB3NzaC1yc2E= rsa@host").unwrap().is_none());
        // options on a foreign key type are not even looked at
        assert!(parse_authorized_keys_entry("bogus ssh-rsa AAAA x").unwrap().is_none());
    }

    #[test]
    fn quoting_follows_openssh() {
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "c");
        let entry = entry.trim_end();
        // whitespace and commas inside quotes belong to the value
        let ak = parse_authorized_keys_line(&format!(
            "command=\"/bin/printf %s,%s a b\",from=\"127.0.0.1, 10.0.0.0/8\" {entry}"
        ))
        .unwrap();
        assert_eq!(ak.options.command.as_deref(), Some("/bin/printf %s,%s a b"));
        assert_eq!(ak.options.from.as_deref(), Some("127.0.0.1, 10.0.0.0/8"));
        // only \" is an escape; other backslashes are literal (OpenSSH)
        let ak = parse_authorized_keys_line(&format!("command=\"a\\\\b \\\"q\\\"\" {entry}")).unwrap();
        assert_eq!(ak.options.command.as_deref(), Some("a\\\\b \"q\""));
    }

    #[test]
    fn expiry_time_is_parsed() {
        let kp = generate_keypair();
        let entry = authorized_keys_entry(&kp.public, "c");
        let entry = entry.trim_end();
        let ak = parse_authorized_keys_line(&format!("expiry-time=\"20300101000000Z\" {entry}")).unwrap();
        assert_eq!(ak.options.expires_at, Some(1_893_456_000));
        // several: the earliest wins
        let ak = parse_authorized_keys_line(&format!(
            "expiry-time=\"20300101Z\",expiry-time=\"20200101Z\" {entry}"
        ))
        .unwrap();
        assert_eq!(ak.options.expires_at, Some(1_577_836_800));
        // local-time form parses too
        assert!(parse_authorized_keys_line(&format!("expiry-time=\"203001011200\" {entry}")).is_ok());
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saltsh-akf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_authorized_keys_policy() {
        use std::os::unix::fs::PermissionsExt;
        let me = unsafe { libc::geteuid() };
        let only_file = KeyFilePolicy { owner_uid: me, check_dirs_up_to: None };
        let dir = scratch_dir("policy");
        let kp = generate_keypair();
        let good = dir.join("ak");
        std::fs::write(&good, format!(
            "# comment\n{}bogus-option {}",
            authorized_keys_entry(&kp.public, "ok"),
            authorized_keys_entry(&kp.public, "refused"),
        ))
        .unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        let f = load_authorized_keys(&good, &only_file).unwrap();
        assert_eq!(f.keys.len(), 1);
        assert_eq!(f.warnings.len(), 1, "{:?}", f.warnings);
        assert!(f.warnings[0].starts_with("line 3:"), "{:?}", f.warnings);

        // missing file
        assert_eq!(
            load_authorized_keys(&dir.join("absent"), &only_file).unwrap_err(),
            KeyFileError::Missing
        );
        // group-writable file is refused (StrictModes)
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(load_authorized_keys(&good, &only_file), Err(KeyFileError::Refused(_))));
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        // ...and so is a world-writable directory on the way to home
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let with_dirs = KeyFilePolicy { owner_uid: me, check_dirs_up_to: Some(&dir) };
        assert!(matches!(load_authorized_keys(&good, &with_dirs), Err(KeyFileError::Refused(_))));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(load_authorized_keys(&good, &with_dirs).unwrap().keys.len(), 1);

        // a symlink to a device is refused without reading it
        let zero = dir.join("zero");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        assert!(matches!(load_authorized_keys(&zero, &only_file), Err(KeyFileError::Refused(_))));
        // a FIFO neither blocks the open nor gets read
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(load_authorized_keys(&fifo, &only_file), Err(KeyFileError::Refused(_))));
        // oversized files are refused
        let big = dir.join("big");
        std::fs::write(&big, vec![b'#'; MAX_AUTHORIZED_KEYS_BYTES as usize + 1]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load_authorized_keys(&big, &only_file), Err(KeyFileError::Refused(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn match_pattern_list_semantics() {
        use super::match_pattern_list as m;
        // exact
        assert!(m("127.0.0.1", "127.0.0.1"));
        assert!(!m("127.0.0.1", "127.0.0.2"));
        // IPv4 CIDR
        assert!(m("192.168.1.0/24", "192.168.1.5"));
        assert!(!m("192.168.1.0/24", "192.168.2.5"));
        assert!(m("0.0.0.0/0", "8.8.8.8"));
        // IPv6 patterns never match (saltsh is IPv4-only; fail-closed)
        assert!(!m("::1/128", "::1"));
        assert!(!m("fd00::/8", "fd12::1"));
        // wildcards
        assert!(m("10.0.*", "10.0.0.1"));
        assert!(m("10.*.0.?", "10.0.0.1"));
        assert!(!m("10.*.0.??", "10.0.0.1"));
        // negation: rejected immediately, even by a later positive match
        assert!(!m("!127.0.0.1,0.0.0.0/0", "127.0.0.1"));
        assert!(m("!127.0.0.1,0.0.0.0/0", "10.1.2.3"));
        // comma-separated positives
        assert!(m("192.168.0.0/16,10.0.0.0/8", "10.1.2.3"));
        assert!(!m("192.168.0.0/16,10.0.0.0/8", "172.16.0.1"));
        // empty list matches nothing
        assert!(!m("", "1.2.3.4"));
    }

    #[test]
    fn generated_key_signs_and_verifies() {
        let kp = generate_keypair();
        let sk = kp.signing_key();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"msg");
        vk.verify(b"msg", &sig).expect("verify");
    }

    #[test]
    fn private_key_info_detects_encryption() {
        let kp = generate_keypair();
        let plain = write_openssh_private(&kp.seed, &kp.public, "c", None);
        let enc = write_openssh_private(&kp.seed, &kp.public, "c", Some("pw"));
        // write to temp files so we exercise private_key_info()
        let dir = std::env::temp_dir().join(format!("saltsh-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p1 = dir.join("plain");
        let p2 = dir.join("enc");
        std::fs::write(&p1, &plain).unwrap();
        std::fs::write(&p2, &enc).unwrap();
        assert!(!private_key_info(&p1).unwrap().encrypted);
        assert!(private_key_info(&p2).unwrap().encrypted);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
