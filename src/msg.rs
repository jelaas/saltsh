//! Wire message codec (spec §5.4, §5.5, §5.7).
//!
//! One-byte tag + payload. All integers big-endian; all strings `u32`
//! length-prefixed. The decoder is bounds-checked and never panics on
//! malformed input.

use crate::crypto::USER_SIG_CONTEXT;
use crate::error::{Error, Result};

pub const AUTH_REQ: u8 = 0x01;
pub const AUTH_CHALLENGE: u8 = 0x02;
pub const AUTH_SIG: u8 = 0x03;
pub const AUTH_OK: u8 = 0x04;
pub const AUTH_FAIL: u8 = 0x05;
pub const EXEC: u8 = 0x10;
pub const PTY_DATA: u8 = 0x20;
pub const RESIZE: u8 = 0x21;
pub const EXIT_STATUS: u8 = 0x22;
pub const SIGNAL: u8 = 0x30;

/// Maximum username length (protects getpwnam lookups).
pub const MAX_USERNAME: usize = 255;
/// Maximum length of a single string field (argv/env/term).
pub const MAX_STR: usize = 64 * 1024;
/// Maximum number of argv elements.
pub const MAX_ARGV: usize = 256;
/// Maximum number of environment variables.
pub const MAX_ENV: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// c->s: username, OpenSSH-format public key blob.
    AuthReq { username: String, pubkey_blob: Vec<u8> },
    /// s->c: 32-byte challenge nonce.
    AuthChallenge { nonce: [u8; 32] },
    /// c->s: Ed25519 signature.
    AuthSig { signature: Vec<u8> },
    AuthOk,
    AuthFail,
    /// c->s: argv[], TERM, rows, cols, env[] (KEY=VALUE strings). An empty
    /// argv means "no command" — the server picks the login shell, or runs
    /// a forced command from authorized_keys. The env list is always empty
    /// from the saltsh client and is ignored by the server (clients cannot
    /// set environment variables in the remote session); it exists for wire
    /// compatibility only.
    Exec {
        argv: Vec<String>,
        term: String,
        rows: u32,
        cols: u32,
        env: Vec<String>,
    },
    /// both: raw PTY bytes.
    PtyData(Vec<u8>),
    /// c->s: new window size.
    Resize { rows: u32, cols: u32 },
    /// s->c: u32 exit code (128+signal if killed by a signal).
    ExitStatus(u32),
    /// c->s: signal number to forward (Ctrl-C / Ctrl-Z).
    Signal(u32),
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Wr::new();
        match self {
            Msg::AuthReq { username, pubkey_blob } => {
                w.u8(AUTH_REQ);
                w.str(username);
                w.bytes(pubkey_blob);
            }
            Msg::AuthChallenge { nonce } => {
                w.u8(AUTH_CHALLENGE);
                w.raw(nonce);
            }
            Msg::AuthSig { signature } => {
                w.u8(AUTH_SIG);
                w.bytes(signature);
            }
            Msg::AuthOk => w.u8(AUTH_OK),
            Msg::AuthFail => w.u8(AUTH_FAIL),
            Msg::Exec { argv, term, rows, cols, env } => {
                w.u8(EXEC);
                w.u32(argv.len() as u32);
                for a in argv {
                    w.str(a);
                }
                w.str(term);
                w.u32(*rows);
                w.u32(*cols);
                w.u32(env.len() as u32);
                for e in env {
                    w.str(e);
                }
            }
            Msg::PtyData(d) => {
                w.u8(PTY_DATA);
                w.raw(d);
            }
            Msg::Resize { rows, cols } => {
                w.u8(RESIZE);
                w.u32(*rows);
                w.u32(*cols);
            }
            Msg::ExitStatus(code) => {
                w.u8(EXIT_STATUS);
                w.u32(*code);
            }
            Msg::Signal(sig) => {
                w.u8(SIGNAL);
                w.u32(*sig);
            }
        }
        w.b
    }

    pub fn decode(buf: &[u8]) -> Result<Msg> {
        let mut r = Rd::new(buf);
        let tag = r.u8()?;
        let m = match tag {
            AUTH_REQ => {
                let username = r.str_utf8("username")?;
                if username.len() > MAX_USERNAME {
                    return Err(Error::proto("username too long"));
                }
                let pubkey_blob = r.bytes("pubkey_blob")?;
                Msg::AuthReq { username, pubkey_blob }
            }
            AUTH_CHALLENGE => {
                let nonce = r.array32("nonce")?;
                r.expect_done("AUTH_CHALLENGE")?;
                Msg::AuthChallenge { nonce }
            }
            AUTH_SIG => {
                let signature = r.bytes("signature")?;
                r.expect_done("AUTH_SIG")?;
                Msg::AuthSig { signature }
            }
            AUTH_OK => {
                r.expect_done("AUTH_OK")?;
                Msg::AuthOk
            }
            AUTH_FAIL => {
                r.expect_done("AUTH_FAIL")?;
                Msg::AuthFail
            }
            EXEC => {
                let argc = r.u32()? as usize;
                if argc > MAX_ARGV {
                    return Err(Error::proto("too many argv elements"));
                }
                let mut argv = Vec::with_capacity(argc);
                for _ in 0..argc {
                    argv.push(r.str_utf8("argv")?);
                }
                let term = r.str_utf8("term")?;
                let rows = r.u32()?;
                let cols = r.u32()?;
                let envc = r.u32()? as usize;
                if envc > MAX_ENV {
                    return Err(Error::proto("too many env entries"));
                }
                let mut env = Vec::with_capacity(envc);
                for _ in 0..envc {
                    env.push(r.str_utf8("env")?);
                }
                r.expect_done("EXEC")?;
                Msg::Exec { argv, term, rows, cols, env }
            }
            PTY_DATA => {
                let d = r.rest();
                if d.is_empty() {
                    return Err(Error::proto("empty PTY_DATA"));
                }
                Msg::PtyData(d.to_vec())
            }
            RESIZE => {
                let rows = r.u32()?;
                let cols = r.u32()?;
                r.expect_done("RESIZE")?;
                Msg::Resize { rows, cols }
            }
            EXIT_STATUS => {
                let code = r.u32()?;
                r.expect_done("EXIT_STATUS")?;
                Msg::ExitStatus(code)
            }
            SIGNAL => {
                let sig = r.u32()?;
                r.expect_done("SIGNAL")?;
                Msg::Signal(sig)
            }
            t => return Err(Error::proto(format!("unknown message tag 0x{t:02x}"))),
        };
        Ok(m)
    }
}

/// The exact byte string signed for user authentication (spec §5.4):
/// `"saltsh-user-auth-v1" || session_id || username || pubkey_blob || nonce`
/// where the two variable-length fields use the wire encoding (u32
/// length-prefix) so the message is unambiguously parseable.
pub fn user_auth_message(
    session_id: &[u8; 32],
    username: &str,
    pubkey_blob: &[u8],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut w = Wr::new();
    w.raw(USER_SIG_CONTEXT);
    w.raw(session_id);
    w.str(username);
    w.bytes(pubkey_blob);
    w.raw(nonce);
    w.b
}

/// The exact byte string signed for host authentication (spec §5.2):
/// `"saltsh-host-key-v1" || session_id`.
pub fn host_auth_message(session_id: &[u8; 32]) -> Vec<u8> {
    let mut w = Wr::new();
    w.raw(crate::crypto::HOST_SIG_CONTEXT);
    w.raw(session_id);
    w.b
}

// ---------------------------------------------------------------------------
// Bounded reader / writer primitives

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        if self.b.len() - self.pos < n {
            return Err(Error::proto(format!("truncated message ({what})")));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1, "tag")?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4, "u32")?;
        Ok(u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }

    fn bytes(&mut self, what: &str) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > MAX_STR {
            return Err(Error::proto(format!("{what} too long")));
        }
        Ok(self.take(n, what)?.to_vec())
    }

    fn str_utf8(&mut self, what: &str) -> Result<String> {
        let b = self.bytes(what)?;
        if b.contains(&0) {
            return Err(Error::proto(format!("{what} contains NUL")));
        }
        String::from_utf8(b).map_err(|_| Error::proto(format!("{what} is not valid UTF-8")))
    }

    fn array32(&mut self, what: &str) -> Result<[u8; 32]> {
        let b = self.take(32, what)?;
        Ok(b.try_into().expect("32 bytes"))
    }

    fn rest(&self) -> &'a [u8] {
        &self.b[self.pos..]
    }

    fn expect_done(&self, what: &str) -> Result<()> {
        if self.pos != self.b.len() {
            return Err(Error::proto(format!("trailing bytes after {what}")));
        }
        Ok(())
    }
}

struct Wr {
    b: Vec<u8>,
}

impl Wr {
    fn new() -> Self {
        Wr { b: Vec::new() }
    }

    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }

    fn raw(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }

    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.b.extend_from_slice(v);
    }

    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(m: &Msg) {
        let enc = m.encode();
        let dec = Msg::decode(&enc).expect("decode");
        assert_eq!(*m, dec);
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(&Msg::AuthReq { username: "alice".into(), pubkey_blob: vec![1, 2, 3] });
        roundtrip(&Msg::AuthChallenge { nonce: [7u8; 32] });
        roundtrip(&Msg::AuthSig { signature: vec![9u8; 64] });
        roundtrip(&Msg::AuthOk);
        roundtrip(&Msg::AuthFail);
        roundtrip(&Msg::Exec {
            argv: vec!["a".into(), "b c".into(), "d".into()],
            term: "xterm-256color".into(),
            rows: 24,
            cols: 80,
            env: vec!["LANG=C.UTF-8".into()],
        });
        roundtrip(&Msg::PtyData(b"hello world".to_vec()));
        roundtrip(&Msg::Resize { rows: 40, cols: 132 });
        roundtrip(&Msg::ExitStatus(0));
        roundtrip(&Msg::Signal(2));
    }

    #[test]
    fn exec_preserves_argv_shape() {
        let m = Msg::Exec {
            argv: vec!["a".into(), "b c".into(), "d".into()],
            term: "xterm".into(),
            rows: 24,
            cols: 80,
            env: vec![],
        };
        let dec = Msg::decode(&m.encode()).unwrap();
        match dec {
            Msg::Exec { argv, .. } => assert_eq!(argv, vec!["a", "b c", "d"]),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(Msg::decode(&[]).is_err());
        assert!(Msg::decode(&[0x99]).is_err());
        assert!(Msg::decode(&[AUTH_OK, 0x00]).is_err()); // trailing byte
        assert!(Msg::decode(&[AUTH_CHALLENGE]).is_err()); // truncated
        // username with NUL
        let mut w = Wr::new();
        w.u8(AUTH_REQ);
        w.bytes(b"a\0b");
        w.bytes(b"");
        assert!(Msg::decode(&w.b).is_err());
        // huge string length
        let mut w = Wr::new();
        w.u8(EXEC);
        w.u32(1);
        w.u32(u32::MAX);
        assert!(Msg::decode(&w.b).is_err());
    }

    #[test]
    fn user_auth_message_is_wire_formatted() {
        let sid = [1u8; 32];
        let nonce = [2u8; 32];
        let m = user_auth_message(&sid, "alice", b"blob", &nonce);
        // context(19) || sid(32) || u32(5) "alice" || u32(4) "blob" || nonce(32)
        assert_eq!(m.len(), 19 + 32 + 4 + 5 + 4 + 4 + 32);
        assert_eq!(&m[0..19], USER_SIG_CONTEXT);
        assert_eq!(&m[19..51], &sid);
        assert_eq!(&m[51..55], &5u32.to_be_bytes());
        assert_eq!(&m[55..60], b"alice");
    }
}
