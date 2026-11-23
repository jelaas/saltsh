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

/// Remove the socket timeouts before the session phase.
pub fn clear_timeouts(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)
}
