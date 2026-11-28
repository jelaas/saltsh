//! Server: listen, accept (thread-per-connection), KEX, Ed25519 auth
//! against `authorized_keys`, then fork + exec the session and pump it
//! (spec §3, §5). A session runs on a fresh PTY only when the client asks
//! for one (interactive logins by default) and the key permits it; all
//! other sessions — commands, forced commands — run on plain pipes
//! (binary-clean, no terminal, end of input via the EOF message).
//!
//! Hardening notes (see SECURITY.md for the full rationale):
//! * unauthenticated connections are capped globally and per source, and
//!   the whole pre-session phase runs under one absolute deadline;
//! * the PTY (or the pipes) are opened close-on-exec and the child closes
//!   every inherited descriptor, so no session can reach another
//!   session's terminal or streams;
//! * per-user sessions run through the account's login shell and get the
//!   account's full supplementary group list (checked `setgroups`);
//! * the session's descriptors are closed only after the pump thread has
//!   been joined, and every child is reaped, also when the client vanishes.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

/// How long stragglers (background jobs) may keep the PTY open after the
/// session's main process exited before the session is closed anyway.
const STRAGGLER_GRACE: Duration = Duration::from_secs(2);

/// Replace the server's inherited environment with a minimal one: PATH
/// only (with a sane default if it was absent). The server must never pass
/// its own environment — tokens, agent sockets, secrets — into client
/// sessions. Runs in `run()` (the real binary) only; `run_on` (tests)
/// deliberately leaves the process environment alone. (Sessions get an
/// explicitly built environment either way — see `prepare_session`.)
fn clear_environment() {
    use std::os::unix::ffi::OsStrExt;
    // vars_os(): a non-UTF-8 variable must not abort the server.
    let has_path = std::env::var_os("PATH").is_some();
    for (name, _) in std::env::vars_os() {
        if name.as_bytes() != b"PATH" {
            if let Ok(name_c) = CString::new(name.as_bytes()) {
                unsafe { libc::unsetenv(name_c.as_ptr()) };
            }
        }
    }
    if !has_path {
        unsafe {
            libc::setenv(
                c"PATH".as_ptr(),
                c"/usr/local/bin:/usr/bin:/bin".as_ptr(),
                1,
            );
        }
    }
}

/// Listen forever, spawning a thread per connection.
pub fn run(opts: ServerOpts) -> Result<()> {
    // Shed the inherited environment before anything else runs.
    clear_environment();
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
            use std::os::unix::fs::OpenOptionsExt;
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o640) // the log names users, peers and commands
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

    let limiter = Arc::new(StartupLimiter::new(opts.max_startups, opts.per_source_max_startups));
    let mut accept_log = RateLimitedLog::new();
    let mut refuse_log = RateLimitedLog::new();
    let mut spawn_log = RateLimitedLog::new();
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // EMFILE/ENFILE/ENOMEM/ENOBUFS leave the pending connection
                // in the backlog, so retrying at once would spin and flood
                // the log. Back off and rate-limit the message.
                accept_log.log(format_args!("accept error: {e}"));
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(slot) = limiter.try_acquire(peer.ip()) else {
            refuse_log.log(format_args!(
                "dropping connection from {}: too many unauthenticated connections",
                peer.ip()
            ));
            continue; // `stream` is dropped: closed without a reply
        };
        let sk = sk.clone();
        let opts = opts.clone();
        // Note: the "connection from" line itself is logged inside
        // handle_conn, only AFTER the peer sends a valid protocol line —
        // silent scans produce no log spam.
        let spawned = thread::Builder::new()
            .name("saltsh-conn".into())
            .spawn(move || {
                if let Err(e) = handle_conn(stream, &sk, &opts, slot) {
                    logline!("connection {peer} failed: {e}");
                }
            });
        if let Err(e) = spawned {
            // The closure (stream + slot) is dropped: the connection is
            // closed and its slot released. Never abort the server.
            spawn_log.log(format_args!("cannot start connection thread: {e}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Admission control (MaxStartups / PerSourceMaxStartups)

/// Counts unauthenticated connections, globally and per source address.
struct StartupLimiter {
    max_total: usize,
    max_per_source: usize,
    state: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

impl StartupLimiter {
    fn new(max_total: usize, max_per_source: usize) -> Self {
        StartupLimiter { max_total, max_per_source, state: Mutex::new((0, HashMap::new())) }
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<StartupSlot> {
        let mut g = self.state.lock().unwrap();
        let (total, per_source) = &mut *g;
        let from_ip = per_source.get(&ip).copied().unwrap_or(0);
        if *total >= self.max_total || from_ip >= self.max_per_source {
            return None;
        }
        *total += 1;
        *per_source.entry(ip).or_insert(0) += 1;
        Some(StartupSlot { limiter: Arc::clone(self), ip, held: true })
    }

    fn release(&self, ip: IpAddr) {
        let mut g = self.state.lock().unwrap();
        let (total, per_source) = &mut *g;
        *total = total.saturating_sub(1);
        if let Some(n) = per_source.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                per_source.remove(&ip);
            }
        }
    }
}

/// One unauthenticated connection's place in the [`StartupLimiter`];
/// released after authentication or when the connection ends.
struct StartupSlot {
    limiter: Arc<StartupLimiter>,
    ip: IpAddr,
    held: bool,
}

impl StartupSlot {
    fn release(&mut self) {
        if self.held {
            self.held = false;
            self.limiter.release(self.ip);
        }
    }
}

impl Drop for StartupSlot {
    fn drop(&mut self) {
        self.release();
    }
}

/// Log at most one line per interval, counting what was suppressed.
struct RateLimitedLog {
    last: Option<Instant>,
    suppressed: u64,
}

impl RateLimitedLog {
    const EVERY: Duration = Duration::from_secs(10);

    fn new() -> Self {
        RateLimitedLog { last: None, suppressed: 0 }
    }

    fn log(&mut self, args: std::fmt::Arguments<'_>) {
        let now = Instant::now();
        if self.last.is_some_and(|t| now.duration_since(t) < Self::EVERY) {
            self.suppressed += 1;
            return;
        }
        if self.suppressed > 0 {
            logline!("{args} ({} similar messages suppressed)", self.suppressed);
        } else {
            logline!("{args}");
        }
        self.suppressed = 0;
        self.last = Some(now);
    }
}

// ---------------------------------------------------------------------------
// Connection

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

fn handle_conn(
    stream: TcpStream,
    sk: &SigningKey,
    opts: &ServerOpts,
    mut slot: StartupSlot,
) -> Result<()> {
    wire::set_nodelay(&stream);
    // One absolute deadline covers the whole pre-session phase (version,
    // KEX, auth, EXEC); a per-read timeout would let a trickling peer hold
    // this thread indefinitely. Writes get the same bound.
    let deadline = Instant::now() + opts.login_grace_time;
    stream.set_write_timeout(Some(opts.login_grace_time))?;
    // Used for `from="..."` authorized_keys restrictions (IPv4 listeners,
    // so peers are always plain IPv4 addresses).
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let reader = stream.try_clone()?;
    let mut writer = stream;
    let mut hs = wire::DeadlineReader::new(&reader, deadline);

    // --- version exchange (spec §5.1). The server speaks second: it stays
    // silent until the client sends the correct `IDENT\n` line, so port
    // scanners get no banner. A mismatching or unsolicited line is closed
    // without a reply; the attempt is logged, but the untrusted bytes are
    // sanitized and truncated to the configured identifier's length.
    let vline = crypto::version_line(&opts.protocol);
    let client_line = match wire::read_line(&mut hs, crypto::MAX_VERSION_LINE)? {
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
    wire::read_exact(&mut hs, &mut client_eph)?;
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
    let mut shared_bytes = shared.to_bytes();
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
    shared_bytes.zeroize();

    // --- authentication (spec §5.4): single challenge/response
    let (username, grant) =
        auth_exchange(&mut hs, &mut writer, &mut sb, &mut ob, &sid, opts, &peer_ip)?;
    // Authenticated: no longer counts against the startup limits.
    slot.release();

    // --- exec request (spec §5.5), still under the login deadline
    let exec = recv_msg(&mut hs, &mut ob)?;
    // The env list is deliberately ignored: the client must never be able
    // to set environment variables in the remote session (the wire field
    // exists for protocol stability only). The only client-supplied value
    // the server applies is the TERM terminal-type field.
    let Msg::Exec { argv, term, rows, cols, pty: pty_requested, .. } = exec else {
        return Err(Error::proto("expected EXEC"));
    };
    // A PTY only when the client asks for one AND the key permits it. Key
    // options (`pty` / `no-pty` / `restrict`) decide when present;
    // otherwise ordinary sessions may have one and forced commands may not
    // (they are for automation: backups, rsync, git, ...). Without a PTY
    // the byte streams pass through unmodified — no line discipline
    // rewriting \n or interpreting ^C/^D/^Z, no echo.
    let Grant { run_as, forced_command, pty: pty_option } = grant;
    let with_tty = pty_requested && pty_option.unwrap_or(forced_command.is_none());
    let session = prepare_session(&run_as, argv, &term, forced_command.as_deref(), with_tty)?;
    let (rows, cols) = pty::clamp_size(rows, cols);
    // Pre-session phase done: remove the timeouts so an idle interactive
    // session is never killed.
    wire::clear_timeouts(&reader)?;

    let (io, child_fds) = if with_tty {
        let p = pty::open_pty(rows, cols)?;
        (SessionIo::Pty { master: p.master }, ChildFds::Pty { slave: p.slave })
    } else {
        // blocking (the child's stdio must be), close-on-exec
        let (stdin_r, stdin_w) = make_pipe(libc::O_CLOEXEC)?;
        let (out_r, out_w) = make_pipe(libc::O_CLOEXEC)?;
        (
            SessionIo::Pipes { stdin: Mutex::new(Some(stdin_w)), output: out_r },
            ChildFds::Pipes { stdin: stdin_r, output: out_w },
        )
    };
    let child_io = child_fds.child_io();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::Pty(format!("fork failed: {}", std::io::Error::last_os_error())));
    }
    if pid == 0 {
        child_side(&child_io, &session);
    }
    drop(child_fds); // the child holds its ends now
    // Tell the client how the session runs (raw local terminal or not)
    // before any session data can be sent.
    if let Err(e) = send_msg(&mut writer, &mut sb, &Msg::ExecOk { pty: with_tty }) {
        hang_up(pid);
        reaper::adopt(pid);
        return Err(e);
    }

    logline!(
        "user '{}' executing {:?} (pid {pid}, {})",
        log_safe(&username),
        session.argv,
        if with_tty { "pty" } else { "no pty" }
    );
    session_pump(reader, writer, ob, sb, io, pid)
}

/// The server's side of a session's stdio.
enum SessionIo {
    /// Terminal session: one PTY master carries input and output.
    Pty { master: OwnedFd },
    /// No terminal: client bytes go to `stdin` (closed on the client's
    /// EOF); stdout and stderr (merged into the one data stream) come back
    /// on `output`. Only the session loop touches `stdin`; the mutex just
    /// lets it be closed while the pump thread shares `&SessionIo`.
    Pipes { stdin: Mutex<Option<OwnedFd>>, output: OwnedFd },
}

impl SessionIo {
    /// Deliver client bytes to the session (dropped after EOF, or once
    /// the reader is gone: EIO / EPIPE).
    fn write_input(&self, data: &[u8]) {
        match self {
            SessionIo::Pty { master } => {
                pty::write_fd_all(master.as_raw_fd(), data);
            }
            SessionIo::Pipes { stdin, .. } => {
                if let Some(fd) = stdin.lock().unwrap().as_ref() {
                    pty::write_fd_all(fd.as_raw_fd(), data);
                }
            }
        }
    }

    /// The client's input ended: close the session's stdin so it reads EOF.
    /// On a terminal there is no such thing (the user types ^D), so it is
    /// ignored.
    fn close_input(&self) {
        if let SessionIo::Pipes { stdin, .. } = self {
            stdin.lock().unwrap().take();
        }
    }

    /// New window size (terminal sessions only).
    fn resize(&self, rows: u32, cols: u32) {
        if let SessionIo::Pty { master } = self {
            let (r, c) = pty::clamp_size(rows, cols);
            let _ = pty::set_winsize_fd(master.as_raw_fd(), r, c);
        }
    }

    /// What the pump reads and sends to the client.
    fn output_fd(&self) -> RawFd {
        match self {
            SessionIo::Pty { master } => master.as_raw_fd(),
            SessionIo::Pipes { output, .. } => output.as_raw_fd(),
        }
    }
}

/// The child's ends of the session's stdio, closed in the parent after
/// `fork`.
enum ChildFds {
    Pty { slave: OwnedFd },
    Pipes { stdin: OwnedFd, output: OwnedFd },
}

impl ChildFds {
    fn child_io(&self) -> ChildIo {
        match self {
            ChildFds::Pty { slave } => ChildIo {
                stdin: slave.as_raw_fd(),
                output: slave.as_raw_fd(),
                controlling_tty: true,
            },
            ChildFds::Pipes { stdin, output } => ChildIo {
                stdin: stdin.as_raw_fd(),
                output: output.as_raw_fd(),
                controlling_tty: false,
            },
        }
    }
}

/// Descriptors the child installs as 0 (`stdin`) and 1+2 (`output`).
struct ChildIo {
    stdin: RawFd,
    output: RawFd,
    /// Make `stdin` the controlling terminal (PTY sessions).
    controlling_tty: bool,
}

// ---------------------------------------------------------------------------
// Session preparation (parent side, before fork)

/// Everything the forked child needs, built before `fork` so the child
/// performs no allocation and makes only async-signal-safe calls.
struct SessionSpec {
    argv: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    /// Kept alive for `envp_ptrs`.
    _envp: Vec<CString>,
    envp_ptrs: Vec<*const c_char>,
    home: CString,
    ids: Option<UserIds>,
    /// Upper bound for the fallback close loop (no `close_range`).
    max_fd: c_int,
}

/// The identity a per-user session switches to.
struct UserIds {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

/// Login shells known to accept `-c 'exec "$0" "$@"' argv...` with POSIX
/// semantics (positional parameters after the command string), which lets
/// the shell gate the session without re-splitting the argv.
const POSIX_SHELLS: &[&str] = &[
    "sh", "bash", "dash", "ash", "ksh", "ksh93", "mksh", "lksh", "oksh", "pdksh", "zsh", "yash",
    "posh",
];

/// The command string handed to a POSIX login shell: exec the requested
/// argv exactly as received ($0 = argv[0], "$@" = the rest).
const POSIX_EXEC_ARGV: &str = "exec \"$0\" \"$@\"";

fn is_posix_shell(shell: &str) -> bool {
    Path::new(shell)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| POSIX_SHELLS.contains(&n))
}

/// Quote `argv` for a `-c` command string (OpenSSH-style): each element in
/// single quotes, embedded quotes as `'\''`.
fn shell_quote_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The argv that actually runs.
///
/// * No command: the login shell itself (interactive session).
/// * Shared-file mode (`enforce_login_shell = false`): the argv verbatim.
/// * Per-user mode: through the account's login shell, like sshd — so an
///   account whose shell is `nologin`, `false`, `git-shell`, `rbash` or any
///   other restricted shell cannot run arbitrary programs by naming them.
///   For POSIX shells the argv is passed as positional parameters and
///   exec'd unchanged (`sh -c 'exec "$0" "$@"' argv...`), preserving the
///   exact-argv guarantee. Any other shell receives the argv as one
///   OpenSSH-style quoted `-c` string and decides itself what to allow.
pub(crate) fn command_argv(shell: &str, argv: Vec<String>, enforce_login_shell: bool) -> Vec<String> {
    if argv.is_empty() {
        return vec![shell.to_string()];
    }
    if !enforce_login_shell {
        return argv;
    }
    if is_posix_shell(shell) {
        let mut v = vec![shell.to_string(), "-c".to_string(), POSIX_EXEC_ARGV.to_string()];
        v.extend(argv);
        v
    } else {
        vec![shell.to_string(), "-c".to_string(), shell_quote_join(&argv)]
    }
}

fn cstring(s: &str, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::proto(format!("{what} contains a NUL byte")))
}

fn prepare_session(
    run_as: &RunAs,
    argv: Vec<String>,
    term: &str,
    forced_command: Option<&str>,
    with_tty: bool,
) -> Result<SessionSpec> {
    // Session identity: HOME/USER/LOGNAME/SHELL for the logged-in user.
    // In per-user mode that's the passwd entry; in shared-file mode it's
    // the server's own identity.
    let (name, home, shell, ids) = match run_as {
        RunAs::User(pw) => {
            // An empty passwd shell means /bin/sh (login(1), sshd).
            let shell = if pw.shell.is_empty() { "/bin/sh".to_string() } else { pw.shell.clone() };
            let groups = util::supplementary_groups(&pw.name, pw.gid).ok_or_else(|| {
                Error::Auth(format!("cannot determine the groups of '{}'", log_safe(&pw.name)))
            })?;
            let ids = UserIds { uid: pw.uid, gid: pw.gid, groups };
            (pw.name.clone(), pw.home.clone(), shell, Some(ids))
        }
        RunAs::CurrentUser => {
            let (name, home) = match util::getpwuid(unsafe { libc::geteuid() }) {
                Some(pw) => (pw.name, pw.home),
                None => (util::default_username(), "/".to_string()),
            };
            (name, home, util::default_shell(), None)
        }
    };

    // A `command="..."` forced command overrides the requested argv: it is
    // split on whitespace, and the client's argv is APPENDED as extra
    // arguments (by design — see README "authorized_keys options"; forced
    // commands must treat extra arguments as untrusted input).
    // SSH_ORIGINAL_COMMAND gets the original request.
    let mut ssh_original: Option<String> = None;
    let requested = match forced_command {
        Some(cmd) => {
            let mut tokens: Vec<String> = cmd.split_whitespace().map(String::from).collect();
            if tokens.is_empty() {
                return Err(Error::Auth("authorized_keys entry has an empty forced command".into()));
            }
            ssh_original = Some(argv.join(" "));
            tokens.extend(argv);
            tokens
        }
        None => argv,
    };
    let final_argv = command_argv(&shell, requested, ids.is_some());

    let argv_c = final_argv
        .iter()
        .map(|a| cstring(a, "argument"))
        .collect::<Result<Vec<_>>>()?;
    let mut argv_ptrs: Vec<*const c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // The complete session environment — nothing inherited, nothing from
    // the client except TERM (a dedicated protocol field, and only when
    // there is a terminal, as with sshd).
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    let mut env = vec![
        format!("PATH={path}"),
        format!("HOME={home}"),
        format!("USER={name}"),
        format!("LOGNAME={name}"),
        format!("SHELL={shell}"),
    ];
    if with_tty {
        env.push(format!("TERM={term}"));
    }
    if let Some(orig) = ssh_original {
        env.push(format!("SSH_ORIGINAL_COMMAND={orig}"));
    }
    let envp = env
        .iter()
        .map(|e| cstring(e, "environment entry"))
        .collect::<Result<Vec<_>>>()?;
    let mut envp_ptrs: Vec<*const c_char> = envp.iter().map(|c| c.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let max_fd = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        rl.rlim_cur.min(1 << 20) as c_int
    } else {
        1024
    };

    Ok(SessionSpec {
        argv: argv_c,
        argv_ptrs,
        _envp: envp,
        envp_ptrs,
        home: cstring(&home, "home directory")?,
        ids,
        max_fd,
    })
}

// ---------------------------------------------------------------------------
// Child side (after fork, before exec): async-signal-safe calls only

/// Write a fixed message to the session's terminal and exit.
fn child_fail(msg: &CStr, code: c_int) -> ! {
    let b = msg.to_bytes();
    unsafe {
        libc::write(2, b.as_ptr() as *const libc::c_void, b.len());
        libc::_exit(code);
    }
}

/// The forked child: install the session's stdio (the PTY slave as
/// controlling terminal, or the pipes), close every other descriptor,
/// reset signal state, drop privileges (checked, irreversibly), and exec.
/// Never returns.
fn child_side(io: &ChildIo, s: &SessionSpec) -> ! {
    unsafe {
        // New session (and process group, so a hang-up reaches all of it);
        // with a PTY also login_tty(): the pty becomes the controlling
        // terminal. Pipe sessions have no controlling terminal at all.
        if libc::setsid() < 0 {
            child_fail(c"saltsh: setsid failed\n", 1);
        }
        if io.controlling_tty && libc::ioctl(io.stdin, libc::TIOCSCTTY, 0) != 0 {
            child_fail(c"saltsh: cannot acquire controlling terminal\n", 1);
        }
        if libc::dup2(io.stdin, 0) < 0 || libc::dup2(io.output, 1) < 0 || libc::dup2(io.output, 2) < 0 {
            child_fail(c"saltsh: dup2 failed\n", 1);
        }
        // Nothing from the server process may reach the session: other
        // sessions' PTYs, client sockets, the log. Everything is opened
        // close-on-exec already; this is the second line of defense.
        if libc::syscall(libc::SYS_close_range, 3 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) != 0 {
            let mut fd = 3;
            while fd < s.max_fd {
                libc::close(fd);
                fd += 1;
            }
        }
        // The server ignores SIGPIPE; sessions get default signal state.
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());

        if let Some(ids) = &s.ids {
            // Exactly the user's groups — a failure must never leave the
            // server's own supplementary groups in place.
            if libc::setgroups(ids.groups.len(), ids.groups.as_ptr()) != 0 {
                child_fail(c"saltsh: setgroups failed\n", 1);
            }
            if libc::setgid(ids.gid) != 0 {
                child_fail(c"saltsh: setgid failed\n", 1);
            }
            if libc::setuid(ids.uid) != 0 {
                child_fail(c"saltsh: setuid failed\n", 1);
            }
            // Paranoia (as sshd's permanently_set_uid): root must be gone.
            if ids.uid != 0 && (libc::setuid(0) == 0 || libc::seteuid(0) == 0) {
                child_fail(c"saltsh: privileges were not dropped\n", 1);
            }
        }
        if libc::chdir(s.home.as_ptr()) != 0 {
            libc::chdir(c"/".as_ptr());
        }
        libc::execvpe(s.argv_ptrs[0], s.argv_ptrs.as_ptr(), s.envp_ptrs.as_ptr());
        child_fail(c"saltsh: exec failed\n", 127);
    }
}

// ---------------------------------------------------------------------------
// Authentication

/// What a successful key lookup grants.
struct Grant {
    run_as: RunAs,
    forced_command: Option<String>,
    /// The entry's terminal permission (`pty` / `no-pty` / `restrict`).
    pty: Option<bool>,
}

/// Authenticate the connection; returns the authenticated username and
/// what the matched `authorized_keys` entry grants.
///
/// Every well-formed request gets a challenge, and every failure the same
/// AUTH_FAIL after the signature: a client learns nothing about whether a
/// user exists or whether a public key is authorized unless it holds the
/// private key *and* is authorized.
fn auth_exchange(
    reader: &mut impl Read,
    writer: &mut TcpStream,
    sb: &mut SealBox,
    ob: &mut OpenBox,
    sid: &[u8; 32],
    opts: &ServerOpts,
    peer_ip: &str,
) -> Result<(String, Grant)> {
    let req = recv_msg(reader, ob)?;
    let Msg::AuthReq { username, pubkey_blob } = req else {
        return Err(Error::proto("expected AUTH_REQ"));
    };
    let offered = sshkeys::parse_pubkey_blob(&pubkey_blob)
        .map_err(|e| Error::Auth(format!("unusable key offered: {e}")))?;

    let grant = if username.is_empty() || username.len() > msg::MAX_USERNAME {
        Err(format!("invalid username (len {})", username.len()))
    } else {
        lookup_grant(&username, &offered, opts, peer_ip)
    };

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
    let auth_msg = msg::user_auth_message(sid, &username, &pubkey_blob, &nonce);
    // verify_strict: also rejects small-order R and weak (small-order)
    // public keys, not just non-canonical S.
    let sig_ok = VerifyingKey::from_bytes(&offered)
        .map(|vk| vk.verify_strict(&auth_msg, &Signature::from_bytes(&sig64)).is_ok())
        .unwrap_or(false);
    match grant {
        Ok(g) if sig_ok => {
            send_msg(writer, sb, &Msg::AuthOk)?;
            Ok((username, g))
        }
        Ok(_) => {
            send_msg(writer, sb, &Msg::AuthFail)?;
            Err(Error::Auth(format!("bad signature for '{}'", log_safe(&username))))
        }
        Err(reason) => {
            send_msg(writer, sb, &Msg::AuthFail)?;
            Err(Error::Auth(format!("{reason} for '{}'", log_safe(&username))))
        }
    }
}

/// Decide whether the offered public key is authorized, honoring per-entry
/// `from="..."` restrictions and `expiry-time`, and return the matched
/// entry's forced command. Like OpenSSH, the first entry whose key matches
/// *and* whose restrictions permit this login wins. `Err` carries the
/// (server-side only) reason.
fn lookup_grant(
    username: &str,
    offered: &[u8; 32],
    opts: &ServerOpts,
    peer_ip: &str,
) -> std::result::Result<Grant, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let usable = |ak: &sshkeys::AuthorizedKey| {
        ak.public == *offered
            && allowed_from(&ak.options, peer_ip)
            && ak.options.expires_at.is_none_or(|t| now <= t)
    };
    if let Some(path) = &opts.authorized_keys_path {
        // Shared file: the administrator's; must be owned by root or the
        // server's own user and not group/world-writable.
        let policy = sshkeys::KeyFilePolicy {
            owner_uid: unsafe { libc::geteuid() },
            check_dirs_up_to: None,
        };
        let found = load_keys_logged(path, &policy).into_iter().find(|ak| usable(ak));
        return match found {
            Some(ak) => Ok(Grant {
                run_as: RunAs::CurrentUser,
                forced_command: ak.options.command.clone(),
                pty: ak.options.pty,
            }),
            None => Err("no matching authorized key".into()),
        };
    }
    // Per-user mode: resolve the user via /etc/passwd (getpwnam) and read
    // keys from ~<user>/.saltsh/authorized_keys (StrictModes-checked up to
    // the home directory). The session child then switches to that user —
    // see child_side().
    let pw = util::getpwnam(username).ok_or_else(|| "unknown user".to_string())?;
    let path = PathBuf::from(&pw.home).join(".saltsh/authorized_keys");
    let policy = sshkeys::KeyFilePolicy {
        owner_uid: pw.uid,
        check_dirs_up_to: Some(Path::new(&pw.home)),
    };
    let found = load_keys_logged(&path, &policy).into_iter().find(|ak| usable(ak));
    match found {
        Some(ak) => {
            let forced_command = ak.options.command.clone();
            Ok(Grant { run_as: RunAs::User(pw), forced_command, pty: ak.options.pty })
        }
        None => Err("no matching authorized key".into()),
    }
}

/// Load an authorized_keys file, logging refused files and lines.
fn load_keys_logged(path: &Path, policy: &sshkeys::KeyFilePolicy<'_>) -> Vec<sshkeys::AuthorizedKey> {
    match sshkeys::load_authorized_keys(path, policy) {
        Ok(f) => {
            for w in &f.warnings {
                logline!("warning: {}: {w}", path.display());
            }
            f.keys
        }
        Err(sshkeys::KeyFileError::Missing) => Vec::new(),
        Err(sshkeys::KeyFileError::Refused(why)) => {
            logline!("warning: refusing {}: {why}", path.display());
            Vec::new()
        }
    }
}

/// `from="..."` check: no restriction means allowed; otherwise the pattern
/// list is matched against the peer's IP address (OpenSSH `from=` semantics).
fn allowed_from(options: &sshkeys::AuthorizedKeyOptions, peer_ip: &str) -> bool {
    match &options.from {
        None => true,
        Some(list) => sshkeys::match_pattern_list(list, peer_ip),
    }
}

// ---------------------------------------------------------------------------
// Session pump

/// How the session loop ended.
enum SessionEnd {
    /// The session's main process exited (and was reaped) with this code.
    ChildExited(u32),
    /// The client closed the connection.
    ClientGone,
    /// The connection broke (decode/MAC/protocol/I/O error).
    Failed(Error),
}

/// Parent-side session pump: client bytes -> session input (this thread);
/// session output -> client (scoped pump thread); child exit ->
/// EXIT_STATUS.
///
/// Lifetimes are structural: the pump thread is scoped and woken through a
/// pipe, so the session's descriptors are closed only after the pump has
/// been joined (no use-after-close, no fd number reuse across sessions),
/// and the child is always reaped — here, or by the reaper when the client
/// vanished first.
fn session_pump(
    mut reader: TcpStream,
    writer: TcpStream,
    mut ob: OpenBox,
    sb: SealBox,
    io: SessionIo,
    pid: libc::pid_t,
) -> Result<()> {
    let out = Mutex::new((sb, writer));
    let (wake_r, wake_w) = match make_pipe(libc::O_CLOEXEC | libc::O_NONBLOCK) {
        Ok(p) => p,
        Err(e) => {
            hang_up(pid);
            reaper::adopt(pid);
            return Err(e);
        }
    };
    let (end, reaped) = thread::scope(|scope| {
        let pump = thread::Builder::new()
            .name("saltsh-pty".into())
            .spawn_scoped(scope, || output_pump(io.output_fd(), wake_r.as_raw_fd(), &out));
        let pump = match pump {
            Ok(p) => p,
            Err(e) => {
                hang_up(pid);
                return (SessionEnd::Failed(Error::Io(e)), false);
            }
        };
        let (end, reaped) = session_loop(&mut reader, &mut ob, &io, pid, &pump);
        if !matches!(end, SessionEnd::ChildExited(_)) {
            // Unblock a pump stuck writing to a client that stopped reading.
            let _ = reader.shutdown(Shutdown::Both);
        }
        // Stop the pump (stragglers may still hold the output open); the
        // scope joins it before `io` can be closed.
        let _ = unsafe { libc::write(wake_w.as_raw_fd(), b"x".as_ptr() as *const libc::c_void, 1) };
        (end, reaped)
    });
    drop(io); // safe: the pump thread has been joined
    if !reaped {
        reaper::adopt(pid);
    }
    match end {
        SessionEnd::ChildExited(code) => {
            // After the pump finished: the exit status is the last packet.
            send_exit_status(&out, code);
            Ok(())
        }
        SessionEnd::ClientGone => Ok(()),
        SessionEnd::Failed(e) => Err(e),
    }
}

/// The client-facing half of the session. Returns how it ended and whether
/// the child has been reaped.
fn session_loop(
    reader: &mut TcpStream,
    ob: &mut OpenBox,
    io: &SessionIo,
    pid: libc::pid_t,
    pump: &thread::ScopedJoinHandle<'_, ()>,
) -> (SessionEnd, bool) {
    let mut exited: Option<(u32, Instant)> = None;
    loop {
        if exited.is_none() {
            if let Some(code) = reap_if_exited(pid) {
                logline!("session pid {pid} exited ({code})");
                exited = Some((code, Instant::now()));
            }
        }
        if let Some((code, at)) = exited {
            // Done once all output is delivered (the pump saw EOF), or
            // when stragglers keep the pty open past the grace period.
            if pump.is_finished() || at.elapsed() > STRAGGLER_GRACE {
                return (SessionEnd::ChildExited(code), true);
            }
        }

        // Client traffic.
        let mut pfd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 100) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return finish_early(pid, exited.is_some(), SessionEnd::Failed(e.into()));
        }
        if n == 0 || pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            continue;
        }
        let msg = match wire::recv_packet(reader, ob) {
            Ok(Some(pkt)) => Msg::decode(&pkt),
            Ok(None) => return finish_early(pid, exited.is_some(), SessionEnd::ClientGone),
            Err(e) => return finish_early(pid, exited.is_some(), SessionEnd::Failed(e)),
        };
        match msg {
            Ok(Msg::PtyData(d)) => io.write_input(&d),
            Ok(Msg::Eof) => io.close_input(),
            Ok(Msg::Resize { rows, cols }) => io.resize(rows, cols),
            Ok(Msg::Signal(sig)) => {
                // Unreaped, so the pid cannot have been reused.
                if exited.is_none() && (1..=64).contains(&sig) {
                    unsafe { libc::kill(pid, sig as c_int) };
                }
            }
            Ok(_) => {
                let e = Error::proto("unexpected message during session");
                return finish_early(pid, exited.is_some(), SessionEnd::Failed(e));
            }
            Err(e) => return finish_early(pid, exited.is_some(), SessionEnd::Failed(e)),
        }
    }
}

/// The connection ended before the session did: hang up the session (if
/// its main process is still running) so it dies with the connection.
fn finish_early(pid: libc::pid_t, reaped: bool, end: SessionEnd) -> (SessionEnd, bool) {
    if !reaped {
        hang_up(pid);
    }
    (end, reaped)
}

/// SIGHUP the session's process group. Only called while the session
/// leader is unreaped, so `pid` (also the pgid) cannot have been recycled.
fn hang_up(pid: libc::pid_t) {
    unsafe { libc::kill(-pid, libc::SIGHUP) };
}

/// Non-blocking exit check without a PID-reuse window: detect the exit
/// with `WNOWAIT` (the zombie keeps the pid and pgid reserved), nudge
/// stragglers in the session's process group, then reap.
fn reap_if_exited(pid: libc::pid_t) -> Option<u32> {
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        if r != 0 {
            // ECHILD: nothing left to wait for (should not happen).
            return (std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
                .then_some(255);
        }
        if info.si_pid() == 0 {
            return None; // still running
        }
        // Background jobs still attached to the pty get a hangup while the
        // process group id is still guaranteed to be this session's.
        hang_up(pid);
        let mut status: c_int = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Some(255);
            }
        }
        Some(decode_status(status))
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

fn send_exit_status(out: &Mutex<(SealBox, TcpStream)>, code: u32) {
    let mut g = out.lock().unwrap();
    let (sb, w) = &mut *g;
    let _ = wire::send_packet(w, sb, &Msg::ExitStatus(code).encode());
}

/// Pump session output (pty master or output pipe) -> client until
/// EOF/EIO, a send failure, or a wake-up on `wake` (session over).
fn output_pump(output: RawFd, wake: RawFd, out: &Mutex<(SealBox, TcpStream)>) {
    let mut buf = [0u8; 16384];
    loop {
        let mut fds = [
            libc::pollfd { fd: output, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[1].revents != 0 {
            break;
        }
        if fds[0].revents == 0 {
            continue;
        }
        let n = unsafe { libc::read(output, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            let mut g = out.lock().unwrap();
            let (sb, w) = &mut *g;
            let data = buf[..n as usize].to_vec();
            if !matches!(wire::send_packet(w, sb, &Msg::PtyData(data).encode()), Ok(true)) {
                break;
            }
        } else if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        } else {
            break; // 0 (pipe EOF) or EIO (pty slave closed): all writers gone
        }
    }
}

/// A pipe (read end, write end) with `pipe2` flags (always pass
/// `O_CLOEXEC`).
fn make_pipe(flags: c_int) -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), flags) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Reaps session processes that outlive their connection (the client hung
/// up while the session — e.g. a `nohup`ed command — keeps running). One
/// shared thread, so a lingering session holds no connection thread or
/// startup slot.
mod reaper {
    use super::*;

    static PENDING: Mutex<Vec<libc::pid_t>> = Mutex::new(Vec::new());
    static WAKE: Condvar = Condvar::new();
    static START: Once = Once::new();

    pub(super) fn adopt(pid: libc::pid_t) {
        PENDING.lock().unwrap().push(pid);
        WAKE.notify_one();
        START.call_once(|| {
            if thread::Builder::new().name("saltsh-reaper".into()).spawn(run).is_err() {
                logline!("warning: cannot start the reaper thread; exited sessions may linger as zombies");
            }
        });
    }

    fn run() {
        loop {
            {
                let mut pending = PENDING.lock().unwrap();
                while pending.is_empty() {
                    pending = WAKE.wait(pending).unwrap();
                }
                // keep only the ones still running
                pending.retain(|&pid| {
                    let mut status: c_int = 0;
                    unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == 0 }
                });
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

// ---------------------------------------------------------------------------

fn send_msg(w: &mut TcpStream, sb: &mut SealBox, m: &Msg) -> Result<()> {
    if !wire::send_packet(w, sb, &m.encode())? {
        return Err(Error::proto("peer closed the connection"));
    }
    Ok(())
}

fn recv_msg(r: &mut impl Read, ob: &mut OpenBox) -> Result<Msg> {
    let pkt = wire::recv_packet(r, ob)?
        .ok_or_else(|| Error::proto("connection closed unexpectedly"))?;
    Msg::decode(&pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn status_decoding() {
        assert_eq!(decode_status(0), 0);
        assert_eq!(decode_status(42 << 8), 42);
        assert_eq!(decode_status(9), 137); // WIFSIGNALED(9) -> 128 + 9
    }

    #[test]
    fn log_safe_strips_control_characters() {
        assert_eq!(log_safe("alice"), "alice");
        assert_eq!(log_safe("ali\nce\r"), "ali?ce?");
        assert_eq!(log_safe("x\u{1b}[31m"), "x?[31m");
        assert_eq!(log_safe("u\u{7f}ser"), "u?ser");
    }

    #[test]
    fn command_argv_interactive_and_shared_mode() {
        // no command: the login shell itself, in both modes
        assert_eq!(command_argv("/bin/bash", vec![], true), v(&["/bin/bash"]));
        assert_eq!(command_argv("/usr/sbin/nologin", vec![], true), v(&["/usr/sbin/nologin"]));
        // shared-file mode: argv verbatim (server's own identity)
        assert_eq!(command_argv("/bin/bash", v(&["ls", "a b"]), false), v(&["ls", "a b"]));
    }

    #[test]
    fn command_argv_posix_shell_preserves_argv() {
        let got = command_argv("/bin/bash", v(&["echo", "a b", "c"]), true);
        assert_eq!(got, v(&["/bin/bash", "-c", "exec \"$0\" \"$@\"", "echo", "a b", "c"]));
        // busybox-style and other POSIX shells by basename
        assert!(is_posix_shell("/bin/ash"));
        assert!(is_posix_shell("/usr/bin/zsh"));
        // restricted variants are NOT treated as plain POSIX shells
        assert!(!is_posix_shell("/bin/rbash"));
        assert!(!is_posix_shell("/usr/bin/git-shell"));
    }

    #[test]
    fn command_argv_other_shells_get_a_quoted_string() {
        // nologin / false / git-shell decide for themselves
        let got = command_argv("/usr/sbin/nologin", v(&["/bin/sh", "-c", "id"]), true);
        assert_eq!(got, v(&["/usr/sbin/nologin", "-c", "'/bin/sh' '-c' 'id'"]));
        let got = command_argv("/usr/bin/git-shell", v(&["git-upload-pack", "it's"]), true);
        assert_eq!(got, v(&["/usr/bin/git-shell", "-c", "'git-upload-pack' 'it'\\''s'"]));
    }

    #[test]
    fn real_posix_shell_execs_argv_unchanged() {
        // The wrapper must hand every element through intact.
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", POSIX_EXEC_ARGV, "/bin/sh", "-c", "printf '%s|' \"$@\"", "x", "a b", "", "c'd"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "a b||c'd|");
    }

    #[test]
    fn startup_limiter_counts_and_releases() {
        let l = Arc::new(StartupLimiter::new(3, 2));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let s1 = l.try_acquire(a).unwrap();
        let _s2 = l.try_acquire(a).unwrap();
        assert!(l.try_acquire(a).is_none(), "per-source limit");
        let _s3 = l.try_acquire(b).unwrap();
        assert!(l.try_acquire(b).is_none(), "global limit");
        drop(s1);
        assert!(l.try_acquire(b).is_some(), "released on drop");
    }
}
