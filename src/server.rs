//! Server: listen, accept (thread-per-connection), KEX, Ed25519 auth
//! against `authorized_keys`, then forkpty + execvp the exact argv and pump
//! the PTY (spec §3, §5).

use std::ffi::{CString, c_char, c_int};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::cli::ServerOpts;
use crate::crypto;
use crate::crypto::{derive_keys, session_id, OpenBox, SealBox};
use crate::error::{Error, Result};
use crate::logger::logline;
use crate::msg::{self, Msg};
use crate::pty;
use crate::rng;
use crate::sshkeys;
use crate::tofu;
use crate::util;
use crate::util::Passwd;
use crate::wire;

/// Listen forever, spawning a thread per connection.
pub fn run(opts: ServerOpts) -> Result<()> {
    // --log-timestamps: applies to every server log line from here on.
    if opts.log_timestamps {
        crate::logger::enable_timestamps();
    }
    // --log-file: redirect stderr to the log file first, so ALL subsequent
    // logging (host key generation, startup, connections, errors) goes
    // there. Done before the host key load and before daemonizing; the
    // daemon then keeps fd 2 pointing at the file.
    let log_file = match &opts.log_file {
        Some(path) => {
            use std::os::fd::AsRawFd;
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    Error::Io(std::io::Error::new(
                        e.kind(),
                        format!("cannot open log file {}: {e}", path.display()),
                    ))
                })?;
            let fd = f.as_raw_fd();
            unsafe { libc::dup2(fd, 2) };
            Some(f)
        }
        None => None,
    };

    // Everything fallible happens BEFORE daemonizing, so errors reach the
    // administrator's terminal (or the log file): host key
    // load/generation, address resolution, and the bind itself. (Path
    // options are validated as absolute by the CLI parser, so the
    // post-daemonize chdir("/") cannot break them.)
    let host_key_path = opts
        .host_key_path
        .clone()
        .unwrap_or_else(util::default_host_key_path);
    let sk = sshkeys::load_or_create_host_key(&host_key_path)?;
    let addr = wire::resolve_v4(&opts.listen, opts.port)?;
    let listener = TcpListener::bind(addr).map_err(Error::Io)?;

    // Pidfile: an explicit --pidfile wins; daemonizing defaults to the
    // classic /var/run/saltsh.pid.
    let pidfile = opts
        .pidfile
        .clone()
        .or_else(|| opts.daemonize.then(|| PathBuf::from("/var/run/saltsh.pid")));
    if opts.daemonize {
        logline!(
            "daemonizing (host key fingerprint {}, listening on {})",
            tofu::fingerprint(&sk.verifying_key().to_bytes()),
            addr
        );
        // Keep stderr when logging to a file (fd 2 was redirected above).
        crate::daemon::daemonize(pidfile.as_deref(), log_file.is_some())?;
    } else if let Some(path) = &pidfile {
        std::fs::write(path, format!("{}\n", std::process::id())).map_err(Error::Io)?;
    }
    serve(listener, sk, opts)
}

/// Serve on an already-bound listener. Exposed for tests, where binding on
/// port 0 and keeping the listener bound avoids bind-port races between
/// concurrently started servers.
pub fn run_on(listener: TcpListener, opts: ServerOpts) -> Result<()> {
    let host_key_path = opts
        .host_key_path
        .clone()
        .unwrap_or_else(util::default_host_key_path);
    let sk = sshkeys::load_or_create_host_key(&host_key_path)?;
    serve(listener, sk, opts)
}

fn serve(listener: TcpListener, sk: SigningKey, opts: ServerOpts) -> Result<()> {
    let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
    logline!(
        "host key fingerprint {} ({}): {}",
        tofu::fingerprint(&sk.verifying_key().to_bytes()),
        opts.host_key_path
            .clone()
            .unwrap_or_else(util::default_host_key_path)
            .display(),
        if opts.authorized_keys_path.is_some() { "shared authorized_keys" } else { "per-user authorized_keys" }
    );
    logline!("listening on {local}");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let sk = sk.clone();
                let opts = opts.clone();
                // Note: the "connection from" line itself is logged inside
                // handle_conn, only AFTER the peer sends a valid protocol
                // line — silent scans produce no log spam.
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into());
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &sk, &opts) {
                        logline!("connection {peer} failed: {e}");
                    }
                });
            }
            Err(e) => logline!("accept error: {e}"),
        }
    }
    Ok(())
}

/// Where the session command should run.
enum RunAs {
    /// The server process's own identity (used with --authorized-keys).
    CurrentUser,
    /// Drop privileges to this user (per-user ~/.saltsh/authorized_keys).
    User(Passwd),
}

/// Sanitize wire-controlled strings before they reach the log: a malicious
/// client could otherwise inject fake log lines via control characters.
fn log_safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn handle_conn(stream: TcpStream, sk: &SigningKey, opts: &ServerOpts) -> Result<()> {
    wire::set_nodelay(&stream);
    // Bound the pre-auth phase (slowloris defense); cleared for the session.
    wire::set_handshake_timeout(&stream)?;
    // Used for `from="..."` authorized_keys restrictions (IPv4 listeners,
    // so peers are always plain IPv4 addresses).
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    // --- version exchange (spec §5.1). The server speaks second: it stays
    // silent until the client sends the correct `IDENT\n` line, so port
    // scanners get no banner. A mismatching or unsolicited line is closed
    // without a reply; the attempt is logged, but the untrusted bytes are
    // sanitized and truncated to the configured identifier's length.
    let vline = crypto::version_line(&opts.protocol);
    let client_line = match wire::read_line(&mut reader, crypto::MAX_VERSION_LINE)? {
        None => return Ok(()), // connected and left without speaking
        Some(l) => l,
    };
    if client_line != vline {
        logline!(
            "connection {peer_ip}: protocol mismatch (got {:?}, expected {:?})",
            wire::display_safe(&client_line, opts.protocol.len()),
            opts.protocol
        );
        return Ok(());
    }
    logline!("connection from {peer_ip}");
    writer.write_all(&vline)?;

    // --- key exchange (spec §5.2)
    let mut client_eph = [0u8; 32];
    wire::read_exact(&mut reader, &mut client_eph)?;
    let mut rng = rng::os_rng();
    let eph = EphemeralSecret::random_from_rng(&mut rng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(client_eph));
    // Reject a low-order peer public key: X25519 would yield an all-zero
    // shared secret, making every derived session key a known constant
    // (RFC 7748 §7).
    if !shared.was_contributory() {
        return Err(Error::proto("low-order public key in key exchange"));
    }
    let shared_bytes = shared.to_bytes();
    let sid = session_id(&client_line, &vline, &client_eph, &eph_pub.to_bytes(), &shared_bytes);
    let host_pk = sk.verifying_key().to_bytes();
    let host_sig: Signature = sk.sign(&msg::host_auth_message(&sid));
    // Note: the host public key is sent alongside the signature (not spelled
    // out in the spec's §5.2 listing) so that first-time clients can pin it
    // (TOFU, §6) — this mirrors how SSH transmits the host key in KEX.
    let mut reply = Vec::with_capacity(128);
    reply.extend_from_slice(&eph_pub.to_bytes());
    reply.extend_from_slice(&host_pk);
    reply.extend_from_slice(&host_sig.to_bytes());
    writer.write_all(&reply)?;

    // --- session keys (spec §5.3)
    let (mut c2s, mut s2c) = derive_keys(&sid, &shared_bytes)?;
    let mut ob = OpenBox::new(&c2s);
    let mut sb = SealBox::new(&s2c);
    // Scrub the stack copies; the boxes own the live key material (zeroized
    // by the xsalsa20poly1305 crate on drop).
    c2s.zeroize();
    s2c.zeroize();

    // --- authentication (spec §5.4): single challenge/response
    let (username, run_as, forced_command) =
        auth_exchange(&mut reader, &mut writer, &mut sb, &mut ob, &sid, opts, &peer_ip)?;

    // --- exec request (spec §5.5)
    let exec = recv_msg(&mut reader, &mut ob)?;
    // The env list is deliberately ignored: the client must never be able
    // to set environment variables in the remote session (the wire field
    // exists for protocol stability only). The only client-supplied value
    // the server applies is the TERM terminal-type field.
    let Msg::Exec { argv, term, rows, cols, .. } = exec else {
        return Err(Error::proto("expected EXEC"));
    };

    let shell = match &run_as {
        RunAs::User(pw) if !pw.shell.is_empty() => pw.shell.clone(),
        _ => util::default_shell(),
    };
    // A `command="..."` forced command overrides the requested argv: the
    // forced command is split into its base elements, and the client's argv
    // is appended *as-is* (each element one argument — no shell joining or
    // re-splitting). SSH_ORIGINAL_COMMAND gets the original request.
    let mut forced_tokens: Vec<String> = Vec::new();
    let mut ssh_original: Option<String> = None;
    if let Some(cmd) = &forced_command {
        forced_tokens = cmd.split_whitespace().map(String::from).collect();
        if forced_tokens.is_empty() {
            return Err(Error::Auth("authorized_keys entry has an empty forced command".into()));
        }
        ssh_original = Some(argv.join(" "));
    }
    let argv = if !forced_tokens.is_empty() {
        let mut merged = forced_tokens;
        merged.extend(argv);
        merged
    } else if argv.is_empty() {
        vec![shell.clone()]
    } else {
        argv
    };
    let orig_c = ssh_original
        .as_deref()
        .map(|s| CString::new(s).unwrap_or_default());
    let (rows, cols) = pty::clamp_size(rows, cols);
    // Pre-session phase done: remove the handshake timeout so an idle
    // interactive session is never killed.
    wire::clear_timeouts(&reader)?;

    // --- pre-build everything the forked child needs (no allocation, no
    // non-async-signal-safe calls between fork and exec)
    let arg_cs: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap_or_else(|_| CString::new("[invalid]").unwrap()))
        .collect();
    let mut arg_ptrs: Vec<*const c_char> = arg_cs.iter().map(|c| c.as_ptr()).collect();
    arg_ptrs.push(std::ptr::null());
    let term_c =
        CString::new(term.as_str()).unwrap_or_else(|_| CString::new("xterm").unwrap());
    let (pw_name_c, pw_home_c, pw_ids) = match &run_as {
        RunAs::User(pw) => (
            Some(CString::new(pw.name.clone()).unwrap_or_default()),
            Some(CString::new(pw.home.clone()).unwrap_or_default()),
            Some((pw.uid, pw.gid)),
        ),
        RunAs::CurrentUser => (None, None, None),
    };

    // --- forkpty: child is the session leader with the pty as controlling
    // terminal (login_tty semantics), parent pumps bytes (spec §5.7)
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    let mut master: c_int = 0;
    let pid = unsafe { libc::forkpty(&mut master, std::ptr::null_mut(), std::ptr::null(), &ws) };
    if pid < 0 {
        return Err(Error::Pty(format!(
            "forkpty failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        let params = ChildParams {
            arg_cs: &arg_cs,
            arg_ptrs: &arg_ptrs,
            term_c: &term_c,
            pw_name_c: &pw_name_c,
            pw_home_c: &pw_home_c,
            pw_ids,
            ssh_original: orig_c.as_ref(),
        };
        child_side(&params);
    }

    logline!(
        "user '{}' executing {:?} (pid {pid})",
        log_safe(&username),
        arg_cs
    );
    session_pump(reader, writer, ob, sb, master, pid)
}

/// Everything the forked child needs; built entirely before `forkpty` so
/// the child performs no allocation between fork and exec.
struct ChildParams<'a> {
    arg_cs: &'a [CString],
    arg_ptrs: &'a [*const c_char],
    term_c: &'a CString,
    pw_name_c: &'a Option<CString>,
    pw_home_c: &'a Option<CString>,
    pw_ids: Option<(u32, u32)>,
    ssh_original: Option<&'a CString>,
}

/// The child side of forkpty: set env, drop privileges, execvp. Never
/// returns; uses only async-signal-safe calls (everything is pre-built).
fn child_side(p: &ChildParams<'_>) -> ! {
    unsafe {
        // Only two environment variables are ever set, and neither takes
        // its value from client-controlled env input: TERM (dedicated
        // terminal-type protocol field) and SSH_ORIGINAL_COMMAND (the
        // requested argv, set only when the administrator's authorized_keys
        // entry carries a forced command).
        libc::setenv(c"TERM".as_ptr(), p.term_c.as_ptr(), 1);
        if let Some(orig) = p.ssh_original {
            libc::setenv(c"SSH_ORIGINAL_COMMAND".as_ptr(), orig.as_ptr(), 1);
        }
        if let Some((uid, gid)) = p.pw_ids {
            if libc::setgid(gid) != 0 {
                libc::write(2, c"saltsh: setgid failed\n".as_ptr() as *const libc::c_void, 25);
                libc::_exit(1);
            }
            if let Some(name) = p.pw_name_c {
                libc::initgroups(name.as_ptr(), gid);
            }
            if libc::setuid(uid) != 0 {
                libc::write(2, c"saltsh: setuid failed\n".as_ptr() as *const libc::c_void, 25);
                libc::_exit(1);
            }
            if let Some(home) = p.pw_home_c {
                libc::chdir(home.as_ptr());
            }
        }
        libc::execvp(p.arg_cs[0].as_ptr(), p.arg_ptrs.as_ptr());
        // exec failed
        libc::write(2, c"saltsh: exec failed\n".as_ptr() as *const libc::c_void, 20);
        libc::_exit(127);
    }
}

/// Authenticate the connection; returns the authenticated username, how to
/// run the session, and the forced command from the matched
/// `authorized_keys` entry (if any).
fn auth_exchange(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    sb: &mut SealBox,
    ob: &mut OpenBox,
    sid: &[u8; 32],
    opts: &ServerOpts,
    peer_ip: &str,
) -> Result<(String, RunAs, Option<String>)> {
    let req = recv_msg(reader, ob)?;
    let Msg::AuthReq { username, pubkey_blob } = req else {
        return Err(Error::proto("expected AUTH_REQ"));
    };
    if username.is_empty() || username.len() > msg::MAX_USERNAME {
        return Err(Error::Auth(format!("invalid username (len {})", username.len())));
    }
    let offered = sshkeys::parse_pubkey_blob(&pubkey_blob)
        .map_err(|e| Error::Auth(format!("unusable key offered: {e}")))?;

    let (allowed, run_as, forced_command) =
        lookup_allowed_keys(&username, &offered, opts, peer_ip)?;
    if !allowed {
        send_msg(writer, sb, &Msg::AuthFail)?;
        return Err(Error::Auth(format!(
            "no matching authorized key for '{}'",
            log_safe(&username)
        )));
    }

    let nonce = rng::random_bytes::<32>();
    send_msg(writer, sb, &Msg::AuthChallenge { nonce })?;

    let resp = recv_msg(reader, ob)?;
    let Msg::AuthSig { signature } = resp else {
        return Err(Error::proto("expected AUTH_SIG"));
    };
    let sig64: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::proto("signature is not 64 bytes"))?;
    let vk = VerifyingKey::from_bytes(&offered)
        .map_err(|e| Error::Auth(format!("bad key: {e}")))?;
    let auth_msg = msg::user_auth_message(sid, &username, &pubkey_blob, &nonce);
    match vk.verify(&auth_msg, &Signature::from_bytes(&sig64)) {
        Ok(()) => {
            send_msg(writer, sb, &Msg::AuthOk)?;
            Ok((username, run_as, forced_command))
        }
        Err(_) => {
            send_msg(writer, sb, &Msg::AuthFail)?;
            Err(Error::Auth(format!("bad signature for '{}'", log_safe(&username))))
        }
    }
}

/// Decide whether the offered public key is authorized, honoring per-entry
/// `from="..."` source restrictions, and return the matched entry's forced
/// command. Multiple entries with the same key are handled like OpenSSH:
/// the first entry whose key matches *and* whose `from=` list permits the
/// peer address wins.
fn lookup_allowed_keys(
    username: &str,
    offered: &[u8; 32],
    opts: &ServerOpts,
    peer_ip: &str,
) -> Result<(bool, RunAs, Option<String>)> {
    let find_allowed = |keys: Vec<sshkeys::AuthorizedKey>| {
        keys.into_iter().find_map(|ak| {
            if ak.public != *offered {
                return None;
            }
            if !allowed_from(&ak.options, peer_ip) {
                return None;
            }
            // outer Option = entry found, inner Option = forced command
            Some(ak.options.command.clone())
        })
    };
    if let Some(path) = &opts.authorized_keys_path {
        let found = find_allowed(sshkeys::read_authorized_keys(path));
        return Ok((found.is_some(), RunAs::CurrentUser, found.flatten()));
    }
    let pw = util::getpwnam(username)
        .ok_or_else(|| Error::Auth(format!("unknown user '{}'", log_safe(username))))?;
    // Per-user mode: resolve the user via /etc/passwd (getpwnam) and read
    // keys from ~<user>/.saltsh/authorized_keys. The session child then
    // drops privileges to that user (setgid + initgroups + setuid + chdir
    // home) — see child_side().
    let path = PathBuf::from(&pw.home).join(".saltsh/authorized_keys");
    if !path.exists() {
        return Ok((false, RunAs::User(pw), None));
    }
    let keys = sshkeys::read_authorized_keys(&path);
    if keys.is_empty() {
        logline!("warning: no usable keys in {}", path.display());
    }
    let found = find_allowed(keys);
    Ok((found.is_some(), RunAs::User(pw), found.flatten()))
}

/// `from="..."` check: no restriction means allowed; otherwise the pattern
/// list is matched against the peer's IP address (OpenSSH `from=` semantics).
fn allowed_from(options: &sshkeys::AuthorizedKeyOptions, peer_ip: &str) -> bool {
    match &options.from {
        None => true,
        Some(list) => sshkeys::match_pattern_list(list, peer_ip),
    }
}

/// Parent-side session pump: client bytes -> pty master; pty master ->
/// client (own thread); waitpid -> EXIT_STATUS (spec §5.7).
fn session_pump(
    mut reader: TcpStream,
    writer: TcpStream,
    mut ob: OpenBox,
    sb: SealBox,
    master: c_int,
    pid: libc::pid_t,
) -> Result<()> {
    let shared = Arc::new(Mutex::new((sb, writer)));
    let (tx, rx) = mpsc::channel::<()>();
    let pump_writer = Arc::clone(&shared);
    thread::spawn(move || master_pump(master, pump_writer, tx));

    let mut reaped = false;
    let mut exit_code: u32 = 255;
    let mut nudge_at: Option<Instant> = None;

    loop {
        // Did the child exit?
        if !reaped {
            let mut status: c_int = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                reaped = true;
                exit_code = decode_status(status);
                // Nudge stragglers holding the pty open (background jobs).
                unsafe { libc::kill(-pid, libc::SIGHUP) };
                nudge_at = Some(Instant::now());
                logline!("session pid {pid} exited ({exit_code})");
            }
        }

        // Master EOF (all slave fds closed)?
        if rx.try_recv().is_ok() {
            send_exit_status(&shared, exit_code);
            return Ok(());
        }
        // Or give up waiting for stragglers after a grace period.
        if reaped && nudge_at.is_some_and(|t| t.elapsed() > Duration::from_secs(2)) {
            send_exit_status(&shared, exit_code);
            return Ok(());
        }

        // Client traffic.
        let mut pfd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 100) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        if n == 0 {
            continue;
        }
        if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            continue;
        }
        match wire::recv_packet(&mut reader, &mut ob)? {
            None => {
                // Client hung up. Make sure the session dies with it, and
                // unblock the master pump by closing the pty.
                unsafe {
                    libc::kill(-pid, libc::SIGHUP);
                    libc::close(master);
                }
                return Ok(());
            }
            Some(pkt) => match Msg::decode(&pkt)? {
                Msg::PtyData(d) => {
                    pty::write_fd_all(master, &d); // false = slave gone; ignore
                }
                Msg::Resize { rows, cols } => {
                    let (r, c) = pty::clamp_size(rows, cols);
                    let _ = pty::set_winsize_fd(master, r, c);
                }
                Msg::Signal(sig) => {
                    if !reaped && (1..=64).contains(&sig) {
                        unsafe { libc::kill(pid, sig as c_int) };
                    }
                }
                _ => return Err(Error::proto("unexpected message during session")),
            },
        }
    }
}

fn decode_status(status: c_int) -> u32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status) as u32
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status) as u32
    } else {
        255
    }
}

fn send_exit_status(shared: &Arc<Mutex<(SealBox, TcpStream)>>, code: u32) {
    let mut g = shared.lock().unwrap();
    let (sb, w) = &mut *g;
    let _ = wire::send_packet(w, sb, &Msg::ExitStatus(code).encode());
}

/// Pump pty master -> client until EOF; then signal the main loop.
fn master_pump(master: c_int, writer: Arc<Mutex<(SealBox, TcpStream)>>, done: mpsc::Sender<()>) {
    let mut buf = [0u8; 16384];
    loop {
        let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            let mut g = writer.lock().unwrap();
            let (sb, w) = &mut *g;
            let data = buf[..n as usize].to_vec();
            if !matches!(wire::send_packet(w, sb, &Msg::PtyData(data).encode()), Ok(true)) {
                break;
            }
        } else if n == 0 {
            break;
        } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        } else {
            break; // EIO: slave side closed
        }
    }
    let _ = done.send(());
}

// ---------------------------------------------------------------------------

fn send_msg(w: &mut TcpStream, sb: &mut SealBox, m: &Msg) -> Result<()> {
    if !wire::send_packet(w, sb, &m.encode())? {
        return Err(Error::proto("peer closed the connection"));
    }
    Ok(())
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
    fn status_decoding() {
        assert_eq!(decode_status(0), 0);
        assert_eq!(decode_status(42 << 8), 42);
        assert_eq!(decode_status(9), 137); // WIFSIGNALED(9) -> 128 + 9
    }

    #[test]
    fn run_as_default_shell_fallback() {
        let argv: Vec<String> = vec![];
        let argv = if argv.is_empty() { vec![util::default_shell()] } else { argv };
        assert!(!argv.is_empty());
    }

    #[test]
    fn log_safe_strips_control_characters() {
        assert_eq!(log_safe("alice"), "alice");
        assert_eq!(log_safe("ali\nce\r"), "ali?ce?");
        assert_eq!(log_safe("x\u{1b}[31m"), "x?[31m");
        assert_eq!(log_safe("u\u{7f}ser"), "u?ser");
    }
}
