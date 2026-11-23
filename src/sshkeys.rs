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

use std::path::{Path, PathBuf};

use aes::Aes256;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

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

/// Options parsed from one `authorized_keys` line. Unknown OpenSSH options
/// (bare flags like `no-pty`, or `environment=` etc.) are ignored; only
/// `command=` and `from=` have meaning to saltsh.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizedKeyOptions {
    /// Comma-joined `from="..."` pattern lists (multiple `from=` options
    /// are concatenated, matching OpenSSH).
    pub from: Option<String>,
    /// Forced command from `command="..."` (last occurrence wins).
    pub command: Option<String>,
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
/// `[options...] ssh-ed25519 AAAA... comment`.
///
/// Recognized options: `command="..."` (forced command) and `from="..."`
/// (source-address restriction). Option values may be double-quoted with
/// `\"`/`\\` escapes and may contain spaces; unknown options are skipped.
pub fn parse_authorized_keys_line(line: &str) -> Result<AuthorizedKey> {
    let tokens = split_ssh_tokens(line);
    let mut it = tokens.iter().map(|s| s.as_str());
    let mut options = AuthorizedKeyOptions::default();
    let mut froms: Vec<String> = Vec::new();
    let b64 = loop {
        match it.next() {
            None => return Err(Error::key("no key type found")),
            Some("ssh-ed25519") => match it.next() {
                Some(b) => break b,
                None => return Err(Error::key("missing key data")),
            },
            Some(t) => {
                // option token: key="value" or a bare flag (no-pty, ...)
                if let Some((k, v)) = t.split_once('=') {
                    match k {
                        "command" => options.command = Some(v.to_string()),
                        "from" => froms.push(v.to_string()),
                        _ => {} // environment=, permitopen=, ... (ignored)
                    }
                }
            }
        }
    };
    if !froms.is_empty() {
        options.from = Some(froms.join(","));
    }
    let der = B64
        .decode(b64)
        .map_err(|e| Error::key(format!("bad base64 in authorized_keys: {e}")))?;
    let public = parse_pubkey_blob(&der)?;
    Ok(AuthorizedKey { public, options })
}

/// Parse a whole `authorized_keys` file, ignoring unparsable lines.
pub fn read_authorized_keys(path: &Path) -> Vec<AuthorizedKey> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .filter_map(|l| parse_authorized_keys_line(l).ok())
            .collect(),
        Err(_) => Vec::new(),
    }
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
    let kdfoptions = c.string()?.to_vec();
    let nkeys = c.u32()?;
    if nkeys != 1 {
        return Err(Error::key(format!("unsupported number of keys: {nkeys}")));
    }
    let pub_blob = c.string()?;
    let public = parse_pubkey_blob(pub_blob)?;
    let encrypted = c.string()?.to_vec();

    let priv_blob = match (ciphername, kdfname) {
        (b"none", b"none") => encrypted,
        (b"aes256-ctr", b"bcrypt") => {
            let passphrase = passphrase.ok_or_else(|| Error::key("encrypted key: a passphrase is required"))?;
            decrypt_priv_blob(&encrypted, &kdfoptions, passphrase)?
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
    Ok(KeyPair { seed, public })
}

fn decrypt_priv_blob(blob: &[u8], kdfoptions: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut c = Cursor::new(kdfoptions);
    let salt = c.string()?;
    let rounds = c.u32()?;
    if rounds == 0 || rounds > 1 << 20 {
        return Err(Error::key("invalid bcrypt rounds"));
    }
    let mut keyiv = Zeroizing::new([0u8; 48]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut *keyiv)
        .map_err(|e| Error::key(format!("bcrypt-pbkdf failed: {e}")))?;
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&keyiv[..32]);
    iv.copy_from_slice(&keyiv[32..48]);
    let mut out = blob.to_vec();
    let mut ctr = Aes256Ctr::new(&key.into(), &iv.into());
    ctr.apply_keystream(&mut out);
    Ok(out)
}

/// Parse the inner (decrypted) private blob:
/// checkint || checkint || string "ssh-ed25519" || string pub || string priv || comment || padding
fn decode_priv_blob(blob: &[u8]) -> Result<([u8; 32], [u8; 32])> {
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
    let seed: [u8; 32] = priv64[0..32].try_into().expect("32 bytes");
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
) -> Vec<u8> {
    let mut blob = Vec::new();
    push_u32(&mut blob, PRIV_CHECKINT);
    push_u32(&mut blob, PRIV_CHECKINT);
    push_string(&mut blob, SSH_ED25519);
    push_string(&mut blob, public);
    let mut priv64 = Vec::with_capacity(64);
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
            let mut key = [0u8; 32];
            let mut iv = [0u8; 16];
            key.copy_from_slice(&keyiv[..32]);
            iv.copy_from_slice(&keyiv[32..48]);
            let mut ctr = Aes256Ctr::new(&key.into(), &iv.into());
            ctr.apply_keystream(&mut blob);
            (b"aes256-ctr".to_vec(), b"bcrypt".to_vec(), kdfopts)
        }
    };

    let mut out = Vec::new();
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
            "{} already exists; refusing to overwrite",
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
    eprintln!("saltsh: generated new host key at {}", path.display());
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

/// Split an ssh-style line on whitespace, respecting double-quoted option
/// values (e.g. `command="echo \"a b\""`). Quotes are stripped and `\"` /
/// `\\` escapes inside quotes are processed.
fn split_ssh_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => match chars.peek() {
                Some(&next) if next == '"' || next == '\\' => {
                    cur.push(next);
                    chars.next();
                }
                _ => cur.push('\\'),
            },
            c if (c.is_whitespace() || c == ',') && !in_quotes => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

// ---------------------------------------------------------------------------
// `from=` pattern lists (OpenSSH match.c semantics, IP candidates only)

/// Match a comma-separated pattern list against `candidate` (an IPv4
/// address string). Semantics follow OpenSSH's `match_pattern_list`: a
/// matching negated (`!`) pattern rejects immediately; otherwise the list
/// matches if any positive pattern matches. saltsh is IPv4-only.
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

fn pem_decode(data: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(data).map_err(|_| Error::key("key file is not UTF-8"))?;
    let mut b64 = String::new();
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
    B64.decode(&b64)
        .map_err(|e| Error::key(format!("bad base64 in key file: {e}")))
}

fn pem_encode(der: &[u8], begin: &str, end: &str) -> Vec<u8> {
    let b64 = B64.encode(der);
    let mut out = format!("{begin}\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).expect("ascii"));
        out.push('\n');
    }
    out.push_str(end);
    out.push('\n');
    out.into_bytes()
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| Error::key(format!("cannot read {}: {e}", path.display())))
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

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into())
}

/// Default identity path: `~/.ssh/id_ed25519`.
pub fn default_identity_path(home: Option<&Path>) -> PathBuf {
    match home {
        Some(h) => h.join(".ssh/id_ed25519"),
        None => PathBuf::from("id_ed25519"),
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
        // multiple from= options are joined with a comma
        let line = format!("from=\"10.0.0.0/8\",from=\"192.168.0.0/16\" {entry}");
        let ak = parse_authorized_keys_line(&line).unwrap();
        assert_eq!(ak.options.from.as_deref(), Some("10.0.0.0/8,192.168.0.0/16"));
        // unknown options are ignored
        let line = format!("no-pty,environment=\"LANG=C\",restrict {entry}");
        let ak = parse_authorized_keys_line(&line).unwrap();
        assert_eq!(ak.options, AuthorizedKeyOptions::default());
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
