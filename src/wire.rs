//! Byte-level I/O helpers and secretbox packet framing (spec §5.6).

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::crypto::{OpenBox, SealBox, TAG_LEN};
use crate::error::{Error, Result};

/// Read exactly `buf.len()` bytes, retrying on EINTR.
pub fn read_exact(r: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )))
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Write all of `buf`, retrying on EINTR.
/// Returns `Ok(true)` if fully written, `Ok(false)` if the peer closed.
pub fn write_all(w: &mut impl Write, buf: &[u8]) -> Result<bool> {
    let mut done = 0;
    while done < buf.len() {
        match w.write(&buf[done..]) {
            Ok(0) => return Ok(false),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(false)
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

/// Seal `plaintext` into one secretbox packet and write it to `w`.
/// Returns `Ok(true)` on success, `Ok(false)` if the peer closed.
/// Enforces the rekey threshold (spec §5.6): once 2^32 packets or 2^40
/// plaintext bytes have passed through one key, the connection is dropped
/// (v1 has no in-place rekey).
pub fn send_packet(w: &mut impl Write, sb: &mut SealBox, plaintext: &[u8]) -> Result<bool> {
    let ct = sb.seal(plaintext)?;
    if sb.needs_rekey() {
        return Err(Error::proto("rekey threshold reached; closing connection"));
    }
    write_all(w, &ct)
}

/// Read one packet and unseal it.
/// Returns `Ok(None)` on a clean EOF before any bytes of the next packet.
///
/// Wire layout produced by `SealBox::seal` (and the underlying
/// xsalsa20poly1305 crate): `tag(16) || ct(u32_be(len) || body)`.
pub fn recv_packet(r: &mut impl Read, ob: &mut OpenBox) -> Result<Option<Vec<u8>>> {
    let mut head = [0u8; TAG_LEN + 4];
    let mut got = 0;
    while got < head.len() {
        match r.read(&mut head[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(None);
                }
                return Err(Error::proto("truncated packet header"));
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let len_ct: [u8; 4] = head[TAG_LEN..].try_into().expect("4 bytes");
    let len = ob.peek_len(&len_ct)? as usize;
    let mut rest = vec![0u8; len];
    read_exact(r, &mut rest)?;
    let mut full = Vec::with_capacity(head.len() + len);
    full.extend_from_slice(&head);
    full.extend_from_slice(&rest);
    let pt = ob.open(&full)?;
    if ob.needs_rekey() {
        return Err(Error::proto("rekey threshold reached; closing connection"));
    }
    Ok(Some(pt))
}

/// Enable TCP_NODELAY: interactive PTY traffic is latency-sensitive and the
/// packets are already framed, so Nagle's coalescing only adds delay.
pub fn set_nodelay(stream: &TcpStream) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let fd = stream.as_raw_fd();
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Read a line (up to and including `\n`) of at most `max` bytes.
/// Returns `Ok(None)` if the peer closed before sending any byte,
/// `Ok(Some(partial))` on EOF or `max` bytes without a newline.
pub fn read_line(r: &mut impl Read, max: usize) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(16);
    let mut byte = [0u8; 1];
    while buf.len() < max {
        match r.read(&mut byte) {
            Ok(0) => {
                return if buf.is_empty() { Ok(None) } else { Ok(Some(buf)) };
            }
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(Some(buf));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(Some(buf))
}

/// Render untrusted bytes for log/error display: non-printable bytes are
/// replaced with `?` and the result is truncated to `max` characters, so
/// hostile input can neither forge log lines nor flood them.
pub fn display_safe(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '?' })
        .take(max)
        .collect()
}

/// Resolve `host` for an IPv4-only connection (saltsh does not support
/// IPv6): pick the first IPv4 address DNS returns.
pub fn resolve_v4(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no IPv4 address for '{host}' (saltsh is IPv4-only)"),
            )
        })
}

/// Socket timeout for the pre-session phase (version exchange, KEX, auth,
/// EXEC). Bound how long an unauthenticated peer can hold a thread by
/// dribbling bytes (slowloris). Cleared before the session pump: an
/// interactive shell must be allowed to sit idle indefinitely.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Apply the handshake timeout to both directions of a socket.
pub fn set_handshake_timeout(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
}

/// A reader that enforces one absolute deadline across *all* reads.
///
/// A plain socket read timeout restarts on every successful read, so a
/// peer trickling one byte per (timeout - 1) seconds could hold a server
/// thread for hours. Here each read gets only the time remaining until
/// `deadline`, and fails with `TimedOut` once it has passed.
pub struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: std::time::Instant,
}

impl<'a> DeadlineReader<'a> {
    pub fn new(stream: &'a TcpStream, deadline: std::time::Instant) -> Self {
        DeadlineReader { stream, deadline }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "login grace time exceeded")
            })?;
        self.stream.set_read_timeout(Some(left))?;
        let mut s = self.stream;
        s.read(buf)
    }
}

/// Remove the socket timeouts before the session phase.
pub fn clear_timeouts(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_line_parses_bounded_lines() {
        let mut r = Cursor::new(b"SALTSH/1\nrest".to_vec());
        let line = read_line(&mut r, 256).unwrap().unwrap();
        assert_eq!(line, b"SALTSH/1\n");

        // empty input -> None
        let mut r = Cursor::new(b"".to_vec());
        assert!(read_line(&mut r, 256).unwrap().is_none());

        // EOF without newline -> partial
        let mut r = Cursor::new(b"partial".to_vec());
        assert_eq!(read_line(&mut r, 256).unwrap().unwrap(), b"partial");

        // capped at max bytes (no newline seen)
        let mut r = Cursor::new(b"x".repeat(64).to_vec());
        let line = read_line(&mut r, 8).unwrap().unwrap();
        assert_eq!(line.len(), 8);
    }

    #[test]
    fn display_safe_sanitizes_and_truncates() {
        assert_eq!(display_safe(b"ok", 8), "ok");
        // control characters replaced, never longer than max
        assert_eq!(display_safe(b"a\nb\r\x1b[31m", 4), "a?b?");
        assert_eq!(display_safe(b"verylongline", 4), "very");
        assert_eq!(display_safe(b"\n\x00\xff", 8), "???");
    }
}
