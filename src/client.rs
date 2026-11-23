//! Client: connect, KEX, TOFU host-key verification, Ed25519 auth, then a
//! PTY byte pump with raw mode and signal forwarding (spec §5, §6).

use std::ffi::c_int;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::cli::ClientOpts;
use crate::crypto::{
    derive_keys, session_id, OpenBox, SealBox, HOST_SIG_CONTEXT, VERSION_LINE,
};
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

    // 2. Connect + version exchange (IPv4 only). A handshake timeout bounds
    // how long an unauthenticated peer can hold this process (cleared for
    // the session).
    let addr = wire::resolve_v4(&opts.host, opts.port).map_err(Error::Io)?;
    let stream = TcpStream::connect(addr).map_err(Error::Io)?;
    wire::set_nodelay(&stream);
    wire::set_handshake_timeout(&stream)?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    writer.write_all(VERSION_LINE)?;
    let mut ver = [0u8; VERSION_LINE.len()];
    wire::read_exact(&mut reader, &mut ver)?;
    if ver != VERSION_LINE {
        return Err(Error::proto(format!(
            "server speaks a different protocol version: {:?}",
            String::from_utf8_lossy(&ver)
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
    let shared_bytes = shared.to_bytes();
    let sid = session_id(
        VERSION_LINE,
        VERSION_LINE,
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

    // 7. Exec request: exact argv, TERM, window size, env (spec §5.5).
    // An empty argv means "no command" — the server then picks the login
    // shell, or runs a forced command from authorized_keys.
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let (rows, cols) = pty::get_winsize(0);
    let mut env = opts.env.clone();
    for k in ["LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ"] {
        if let Ok(v) = std::env::var(k) {
            env.push(format!("{k}={v}"));
        }
    }
    send_msg(&mut writer, &mut sb, &Msg::Exec { argv: opts.argv, term, rows, cols, env })?;

    // 8. Session pump: raw mode + signal forwarding on the stdin side,
    //    socket->stdout on this side. Timeouts come off — idle interactive
    //    sessions must survive.
    wire::clear_timeouts(&reader)?;
    let _raw = if pty::isatty(0) { Some(RawMode::enter(0)?) } else { None };
    install_signal_handlers();
    let stdin_thread = thread::spawn(move || stdin_pump(writer, sb));
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
fn verify_host_key(opts: &ClientOpts, host_pk: &[u8; 32], sid: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    let path = tofu::known_hosts_path()?;
    let entries = tofu::load(&path);
    let mut pinned = tofu::find(&entries, &opts.host, opts.port).copied();

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
        } else {
            eprint!("Are you sure you want to continue connecting (yes/no)? ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| Error::HostKey(format!("cannot read confirmation: {e}")))?;
            if !line.trim().eq_ignore_ascii_case("yes") {
                return Err(Error::HostKey("host key not accepted — aborting".into()));
            }
        }
        tofu::add(&path, &opts.host, opts.port, host_pk)?;
        pinned = Some(*host_pk);
    }

    let pinned = pinned.expect("just set");
    if pinned != *host_pk {
        return Err(Error::HostKey(format!(
            "REMOTE HOST IDENTIFICATION HAS CHANGED for '{}:{}'!\n\
             The server presented a different key than the pinned one. This could\n\
             mean a man-in-the-middle attack, or the host key was legitimately\n\
             rotated. Refusing to connect.",
            opts.host, opts.port
        )));
    }

    let vk = VerifyingKey::from_bytes(&pinned)
        .map_err(|e| Error::Crypto(format!("bad pinned host key: {e}")))?;
    let msg = [HOST_SIG_CONTEXT, sid.as_ref()].concat();
    let signature = Signature::from_bytes(sig);
    vk.verify(&msg, &signature)
        .map_err(|_| Error::HostKey("host key signature verification failed".into()))?;
    Ok(())
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
/// backpressured direction can't deadlock the other.
fn stdin_pump(mut writer: TcpStream, mut sb: SealBox) {
    let mut buf = [0u8; 16384];
    loop {
        if STOP_PUMP.load(Ordering::Relaxed) {
            break;
        }
        let f = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);
        if f & FLAG_WINCH != 0 {
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
            } else {
                break; // EOF or error: nothing more to send
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
            env: vec![],
            argv: vec![],
        };
        assert_eq!(o.host, "h");
    }
}
