//! Client: connect, KEX, TOFU host-key verification, Ed25519 auth, then a
//! PTY byte pump with raw mode and signal forwarding (spec §5, §6).

use std::ffi::c_int;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::cli::ClientOpts;
use crate::crypto;
use crate::crypto::{derive_keys, session_id, OpenBox, SealBox};
use crate::error::{Error, Result};
use crate::msg::{self, Msg};
use crate::pty::{self, RawMode};
use crate::rng;
use crate::sshkeys;
use crate::tofu;
use crate::util;
use crate::wire;

/// Connect and run a session. Returns the remote exit code.
pub fn run(opts: ClientOpts) -> Result<u32> {
    // 1. Load the identity, prompting for a passphrase if the file is encrypted.
    let key = load_identity(&opts)?;

    // Resolve the protocol identifier: --protocol wins, else the
    // ssh_config-style ~/.saltsh/config Host section for this host, else
    // the default. The config-derived value is validated just like the
    // flag.
    let protocol = match opts.protocol.as_deref() {
        Some(p) => p.to_string(),
        None => {
            let configured = util::saltsh_dir()
                .ok()
                .map(|d| d.join("config"))
                .and_then(|p| crate::config::load(&p).ok().flatten())
                .and_then(|c| c.protocol_for(&opts.host).map(String::from));
            configured.unwrap_or_else(|| crypto::DEFAULT_VERSION.to_string())
        }
    };
    let protocol = crate::cli::parse_protocol(&protocol)?;

    // 2. Connect + version exchange (IPv4 only). A handshake timeout bounds
    // how long an unauthenticated peer can hold this process (cleared for
    // the session). The client speaks first, then expects the server's
    // identical line.
    let addr = wire::resolve_v4(&opts.host, opts.port).map_err(Error::Io)?;
    let stream = TcpStream::connect(addr).map_err(Error::Io)?;
    wire::set_nodelay(&stream);
    wire::set_handshake_timeout(&stream)?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let vline = crypto::version_line(&protocol);
    writer.write_all(&vline)?;
    let line = wire::read_line(&mut reader, crypto::MAX_VERSION_LINE)?
        .ok_or_else(|| Error::proto("connection closed during version exchange"))?;
    if line != vline {
        return Err(Error::proto(format!(
            "server speaks a different protocol version: {:?}",
            wire::display_safe(&line, protocol.len())
        )));
    }

    // 3. Key exchange (client eph -> server eph || host_pk || host_sig).
    let mut rng = rng::os_rng();
    let eph = EphemeralSecret::random_from_rng(&mut rng);
    let eph_pub = PublicKey::from(&eph);
    writer.write_all(&eph_pub.to_bytes())?;
    let mut kex = [0u8; 32 + 32 + 64];
    wire::read_exact(&mut reader, &mut kex)?;
    let server_eph: [u8; 32] = kex[0..32].try_into().expect("32");
    let host_pk: [u8; 32] = kex[32..64].try_into().expect("32");
    let host_sig: [u8; 64] = kex[64..128].try_into().expect("64");
    let shared = eph.diffie_hellman(&PublicKey::from(server_eph));
    // Reject a low-order peer public key: X25519 would yield an all-zero
    // shared secret, making every derived session key a known constant
    // (RFC 7748 §7).
    if !shared.was_contributory() {
        return Err(Error::proto("low-order public key in key exchange"));
    }
    let mut shared_bytes = shared.to_bytes();
    let sid = session_id(
        &vline,
        &vline,
        &eph_pub.to_bytes(),
        &server_eph,
        &shared_bytes,
    );

    // 4. Verify the host signature against the pinned key (TOFU).
    verify_host_key(&opts, &host_pk, &sid, &host_sig)?;

    // 5. Derive directional keys; everything after this is secretbox-framed.
    let (mut c2s, mut s2c) = derive_keys(&sid, &shared_bytes)?;
    let mut sb = SealBox::new(&c2s);
    let mut ob = OpenBox::new(&s2c);
    // Scrub the stack copies; the boxes own the live key material (zeroized
    // by the xsalsa20poly1305 crate on drop).
    c2s.zeroize();
    s2c.zeroize();
    shared_bytes.zeroize();

    // 6. Authenticate (single challenge/response).
    let pubkey_blob = sshkeys::ssh_ed25519_pubkey_blob(&key.public);
    send_msg(&mut writer, &mut sb, &Msg::AuthReq { username: opts.username.clone(), pubkey_blob: pubkey_blob.clone() })?;
    let nonce = match recv_msg(&mut reader, &mut ob)? {
        Msg::AuthChallenge { nonce } => nonce,
        Msg::AuthFail => return Err(Error::Auth("server has no matching key".into())),
        _ => return Err(Error::proto("expected AUTH_CHALLENGE")),
    };
    let sig: Signature = key
        .signing_key()
        .sign(&msg::user_auth_message(&sid, &opts.username, &pubkey_blob, &nonce));
    send_msg(&mut writer, &mut sb, &Msg::AuthSig { signature: sig.to_bytes().to_vec() })?;
    match recv_msg(&mut reader, &mut ob)? {
        Msg::AuthOk => {}
        Msg::AuthFail => return Err(Error::Auth("authentication rejected".into())),
        _ => return Err(Error::proto("expected AUTH_OK/AUTH_FAIL")),
    }

    // 7. Exec request: exact argv, terminal request, TERM, window size
    // (spec §5.5). An empty argv means "no command" — the server then picks
    // the login shell, or runs a forced command from authorized_keys.
    // Like ssh, a terminal is requested only for an interactive login on a
    // terminal, unless -t / -T say otherwise; the server may still refuse
    // (key options, forced commands) and EXEC_OK tells what we got.
    // No environment variables are ever sent: the env list in the wire
    // format is always empty and the server ignores it regardless (the
    // client must not be able to set variables in the remote session).
    // TERM is the only client-supplied value the server applies, and it is
    // a dedicated terminal-type field, not an environment mechanism.
    let want_pty = opts.pty.unwrap_or(opts.argv.is_empty() && pty::isatty(0));
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let (rows, cols) = pty::get_winsize(0);
    send_msg(
        &mut writer,
        &mut sb,
        &Msg::Exec { argv: opts.argv, term, rows, cols, pty: want_pty, env: Vec::new() },
    )?;
    let got_pty = match recv_msg(&mut reader, &mut ob)? {
        Msg::ExecOk { pty } => pty,
        _ => return Err(Error::proto("expected EXEC_OK")),
    };
    if want_pty && !got_pty {
        eprintln!("saltsh: the server did not allocate a terminal for this session");
    }

    // 8. Session pump: input + signal forwarding on the stdin side,
    //    socket->stdout on this side. Timeouts come off — idle interactive
    //    sessions must survive. The local terminal goes raw only for a
    //    remote terminal; otherwise it stays cooked, so line editing and
    //    echo stay local, ^D ends the input (sent as EOF), and ^C/^Z are
    //    forwarded as signals.
    wire::clear_timeouts(&reader)?;
    let _raw = if got_pty && pty::isatty(0) { Some(RawMode::enter(0)?) } else { None };
    install_signal_handlers();
    let stdin_thread = thread::spawn(move || stdin_pump(writer, sb, got_pty));
    let code = session_recv_loop(reader, &mut ob);
    STOP_PUMP.store(true, Ordering::Relaxed);
    let _ = stdin_thread.join(); // exits within the 200 ms poll cadence
    code
}

/// Load the client identity; if the file is encrypted and no passphrase was
/// given, prompt for one on the terminal.
fn load_identity(opts: &ClientOpts) -> Result<sshkeys::KeyPair> {
    use std::os::unix::fs::MetadataExt;
    let path = opts
        .identity
        .clone()
        .unwrap_or_else(|| sshkeys::default_identity_path(util::home_dir().as_deref()));
    // Warn (like ssh) when the private key is readable by group/others.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.mode() & 0o077 != 0 {
            eprintln!(
                "saltsh: warning: {} is accessible by group/others (mode {:o}); consider chmod 600",
                path.display(),
                meta.mode() & 0o777
            );
        }
    }
    if !path.exists() {
        return Err(Error::key(format!(
            "no private key at {} — run 'saltsh keygen' to create one",
            path.display()
        )));
    }
    if let Some(pass) = &opts.passphrase {
        return sshkeys::load_private_key(&path, Some(pass)).map_err(|e| {
            if matches!(e, Error::Key(_)) {
                Error::Key(format!("failed to load {} (wrong passphrase?)", path.display()))
            } else {
                e
            }
        });
    }
    match sshkeys::private_key_info(&path) {
        Ok(info) if info.encrypted => {
            let pass = pty::read_passphrase(&format!("Enter passphrase for {}: ", path.display()))?;
            sshkeys::load_private_key(&path, Some(&pass)).map_err(|e| {
                if matches!(e, Error::Key(_)) {
                    Error::Key(format!("failed to decrypt {} (wrong passphrase?)", path.display()))
                } else {
                    e
                }
            })
        }
        Ok(_) => sshkeys::load_private_key(&path, None),
        Err(e) => Err(e),
    }
}

/// TOFU: verify the host signature; on first contact show the fingerprint
/// and (unless `--accept-new`) ask for confirmation; on key change, fail.
///
/// A key is only ever pinned after the server has proven it holds the
/// matching private key (valid signature over this session), and the
/// confirmation is read from the controlling terminal — never from stdin,
/// which may carry session input (`... | saltsh host -- cmd`).
fn verify_host_key(opts: &ClientOpts, host_pk: &[u8; 32], sid: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    let path = tofu::known_hosts_path()?;
    let entries = tofu::load(&path);
    let pinned = tofu::find(&entries, &opts.host, opts.port).copied();

    if pinned.is_some_and(|p| p != *host_pk) {
        return Err(Error::HostKey(format!(
            "REMOTE HOST IDENTIFICATION HAS CHANGED for '{}:{}'!\n\
             The server presented a different key than the pinned one. This could\n\
             mean a man-in-the-middle attack, or the host key was legitimately\n\
             rotated. Refusing to connect.",
            opts.host, opts.port
        )));
    }

    // verify_strict: also rejects small-order R and weak public keys.
    let vk = VerifyingKey::from_bytes(host_pk)
        .map_err(|e| Error::HostKey(format!("server sent an invalid host key: {e}")))?;
    vk.verify_strict(&msg::host_auth_message(sid), &Signature::from_bytes(sig))
        .map_err(|_| Error::HostKey("host key signature verification failed".into()))?;

    if pinned.is_none() {
        eprintln!(
            "The authenticity of host '{}:{}' can't be established.",
            opts.host, opts.port
        );
        eprintln!("Ed25519 key fingerprint is {}.", tofu::fingerprint(host_pk));
        if opts.accept_new {
            eprintln!(
                "Warning: Permanently added '{}:{}' to the list of known hosts.",
                opts.host, opts.port
            );
        } else if !confirm_on_tty("Are you sure you want to continue connecting (yes/no)? ")? {
            return Err(Error::HostKey("host key not accepted — aborting".into()));
        }
        tofu::add(&path, &opts.host, opts.port, host_pk)?;
    }
    Ok(())
}

/// Ask a yes/no question on the controlling terminal (like ssh). Without a
/// terminal the answer is "no": non-interactive use must pin keys
/// explicitly (`--accept-new`, or `saltsh hostkey` pre-seeding).
fn confirm_on_tty(question: &str) -> Result<bool> {
    use std::io::{BufRead, BufReader, Read};
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            Error::HostKey(
                "no terminal to confirm the new host key; use --accept-new or \
                 pre-seed ~/.saltsh/known_hosts (see 'saltsh hostkey')"
                    .into(),
            )
        })?;
    let mut w = &tty;
    w.write_all(question.as_bytes())
        .and_then(|_| w.flush())
        .map_err(|e| Error::HostKey(format!("cannot prompt: {e}")))?;
    let mut line = String::new();
    BufReader::new(&tty)
        .take(256)
        .read_line(&mut line)
        .map_err(|e| Error::HostKey(format!("cannot read confirmation: {e}")))?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

// ---------------------------------------------------------------------------
// Session pump

const FLAG_WINCH: u8 = 1;
const FLAG_INT: u8 = 2;
const FLAG_TSTP: u8 = 4;
static SIGNAL_FLAGS: AtomicU8 = AtomicU8::new(0);
/// Set by the main thread when the session ends; the stdin pump polls it and
/// exits (stdin may be a pipe that stays open without data forever).
static STOP_PUMP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_winch(_sig: c_int) {
    SIGNAL_FLAGS.fetch_or(FLAG_WINCH, Ordering::Relaxed);
}
extern "C" fn on_sigint(_sig: c_int) {
    SIGNAL_FLAGS.fetch_or(FLAG_INT, Ordering::Relaxed);
}
extern "C" fn on_sigtstp(_sig: c_int) {
    SIGNAL_FLAGS.fetch_or(FLAG_TSTP, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_winch as extern "C" fn(c_int) as usize as libc::sighandler_t;
        sa.sa_flags = 0; // no SA_RESTART: interrupted syscalls wake the pumps
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
        sa.sa_sigaction = on_sigint as extern "C" fn(c_int) as usize as libc::sighandler_t;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        sa.sa_sigaction = on_sigtstp as extern "C" fn(c_int) as usize as libc::sighandler_t;
        libc::sigaction(libc::SIGTSTP, &sa, std::ptr::null_mut());
    }
}

/// Pump stdin -> socket, plus signal forwarding. Runs on its own thread so a
/// backpressured direction can't deadlock the other. At end of input it
/// sends EOF once and keeps forwarding signals until the session ends.
fn stdin_pump(mut writer: TcpStream, mut sb: SealBox, remote_pty: bool) {
    let mut buf = [0u8; 16384];
    let mut stdin_open = true;
    loop {
        if STOP_PUMP.load(Ordering::Relaxed) {
            break;
        }
        let f = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);
        if f & FLAG_WINCH != 0 && remote_pty {
            let (rows, cols) = pty::get_winsize(0);
            if !send_msg_quiet(&mut writer, &mut sb, &Msg::Resize { rows, cols }) {
                break;
            }
        }
        if f & FLAG_INT != 0 && !send_msg_quiet(&mut writer, &mut sb, &Msg::Signal(libc::SIGINT as u32)) {
            break;
        }
        if f & FLAG_TSTP != 0 && !send_msg_quiet(&mut writer, &mut sb, &Msg::Signal(libc::SIGTSTP as u32)) {
            break;
        }

        if !stdin_open {
            // nothing to read any more; just wait for signals / the end
            unsafe { libc::poll(std::ptr::null_mut(), 0, 200) };
            continue;
        }
        let mut pfd = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, 200) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            continue;
        }
        if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let r = unsafe { libc::read(0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if r > 0 {
                let data = buf[..r as usize].to_vec();
                if !send_msg_quiet(&mut writer, &mut sb, &Msg::PtyData(data)) {
                    break;
                }
            } else if r < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue; // a forwarded signal interrupted the read: not EOF
            } else {
                // EOF (or a read error): tell the server the input is over
                stdin_open = false;
                if !send_msg_quiet(&mut writer, &mut sb, &Msg::Eof) {
                    break;
                }
            }
        }
    }
}

/// Pump socket -> stdout until EXIT_STATUS or EOF.
fn session_recv_loop(mut reader: TcpStream, ob: &mut OpenBox) -> Result<u32> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        match wire::recv_packet(&mut reader, ob)? {
            None => return Ok(255), // peer closed without an exit status
            Some(pkt) => match Msg::decode(&pkt)? {
                Msg::PtyData(d) => {
                    if !wire::write_all(&mut out, &d)? {
                        return Ok(255);
                    }
                    let _ = out.flush();
                }
                Msg::ExitStatus(code) => {
                    let _ = out.flush();
                    return Ok(code);
                }
                _ => return Err(Error::proto("unexpected message during session")),
            },
        }
    }
}

// ---------------------------------------------------------------------------

fn send_msg(w: &mut TcpStream, sb: &mut SealBox, m: &Msg) -> Result<()> {
    if !wire::send_packet(w, sb, &m.encode())? {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "peer closed the connection",
        )));
    }
    Ok(())
}

fn send_msg_quiet(w: &mut TcpStream, sb: &mut SealBox, m: &Msg) -> bool {
    matches!(send_msg(w, sb, m), Ok(()))
}

fn recv_msg(r: &mut TcpStream, ob: &mut OpenBox) -> Result<Msg> {
    let pkt = wire::recv_packet(r, ob)?
        .ok_or_else(|| Error::proto("connection closed unexpectedly"))?;
    Msg::decode(&pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_opts_defaults() {
        let o = ClientOpts {
            host: "h".into(),
            port: 2222,
            username: String::new(),
            identity: None,
            passphrase: None,
            accept_new: false,
            protocol: None,
            argv: vec![],
            pty: None,
        };
        assert_eq!(o.host, "h");
    }
}
