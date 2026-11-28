//! End-to-end tests: run `saltsh serve` in-process (on a background thread),
//! connect the real `saltsh` client binary, and verify the wire protocol —
//! including the spec's §2.6 argv correctness requirement
//! (`saltsh <host> -- a "b c" d` = 3 elements).
//!
//! The server runs in-process because some sandboxes deny `kill(2)`, which
//! makes it impossible to reap a spawned server process from a test
//! `Drop` impl. An in-process listener thread dies with the test harness.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use saltsh::cli::ServerOpts;
use saltsh::msg::Msg;
use saltsh::sshkeys::{self, KeyPair};
use saltsh::util;

const BIN: &str = env!("CARGO_BIN_EXE_saltsh");

/// Overridable in CI to test a specific artifact (e.g. the musl build):
/// `SALTSH_TEST_BIN=target/x86_64-unknown-linux-musl/release/saltsh cargo test`
fn bin() -> &'static str {
    if let Ok(p) = std::env::var("SALTSH_TEST_BIN") {
        Box::leak(p.into_boxed_str())
    } else {
        BIN
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "saltsh-it-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Guard for servers spawned as real processes: kills and reaps on drop
/// where the environment permits it. Some sandboxes deny `kill(2)`; there
/// the process is simply left running (the environment reclaims it).
struct ServerProc(Option<std::process::Child>);

impl Drop for ServerProc {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            if c.kill().is_ok() {
                let _ = c.wait();
            }
        }
    }
}

/// Allocate a bound listener on an OS-assigned free port; keeping it bound
/// (rather than closing and re-binding) makes the port race-free.
fn free_listener() -> (TcpListener, u16) {
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// `kill(2)` is denied in some sandboxes; skip signal-dependent tests there.
fn kill_works() -> bool {
    unsafe { libc::kill(libc::getpid(), 0) == 0 }
}

/// Start an in-process `saltsh serve` with a freshly generated host key and
/// the given `authorized_keys` file content. `shared_authorized_keys = false`
/// exercises the per-user `~user/.saltsh/authorized_keys` lookup path (requires
/// root; the test skips itself otherwise).
fn start_server_with(tag: &str, authorized_keys_content: &str, shared: bool) -> (u16, TempDir) {
    start_server_tweaked(tag, authorized_keys_content, shared, |_, _| {})
}

/// Like [`start_server_with`], with a hook to adjust the options (it also
/// gets the test directory, for creating custom files).
fn start_server_tweaked(
    tag: &str,
    authorized_keys_content: &str,
    shared: bool,
    tweak: impl FnOnce(&mut ServerOpts, &Path),
) -> (u16, TempDir) {
    let dir = TempDir::new(tag);
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");

    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "test host").unwrap();

    let (listener, port) = free_listener();
    let mut opts = ServerOpts {
        listen: "127.0.0.1".to_string(),
        port,
        host_key_path: Some(host_key),
        authorized_keys_path: None,
        ..ServerOpts::default()
    };
    if shared {
        std::fs::write(&authorized, authorized_keys_content).unwrap();
        opts.authorized_keys_path = Some(authorized);
    }
    tweak(&mut opts, &dir.0);
    std::thread::spawn(move || {
        let _ = saltsh::server::run_on(listener, opts);
    });
    assert!(
        wait_ready(port, Instant::now() + Duration::from_secs(10)),
        "server did not come up"
    );
    (port, dir)
}

/// Start an in-process server authorizing `client_key` (no options).
fn start_server(tag: &str, client_key: &KeyPair, shared_authorized_keys: bool) -> (u16, TempDir) {
    start_server_with(
        tag,
        &sshkeys::authorized_keys_entry(&client_key.public, "saltsh-test"),
        shared_authorized_keys,
    )
}

fn wait_ready(port: u16, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Run the client binary against `port`, returning (exit code, stdout).
/// `dir` provides an isolated `$HOME` so TOFU pins never leak
/// between tests (or runs — port numbers get reused by the OS, and a stale
/// pin for a reused port would correctly hard-fail as key rotation).
fn run_client(port: u16, identity: &Path, dir: &TempDir, argv: &[&str]) -> (i32, Vec<u8>) {
    let mut cmd = client_cmd(port, identity, dir, "127.0.0.1");
    cmd.arg("--").args(argv);
    let out = cmd.output().expect("spawn client");
    (out.status.code().unwrap_or(-1), out.stdout)
}

/// Base client command: pins the home directory to `dir` (isolating the
/// TOFU store at `$HOME/.saltsh/known_hosts` from other tests) and targets
/// `host`.
fn client_cmd(port: u16, identity: &Path, dir: &TempDir, host: &str) -> Command {
    let mut cmd = Command::new(bin());
    cmd.args(["--accept-new", "-p", &port.to_string(), "-i"])
        .arg(identity)
        .env("HOME", &dir.0)
        .arg(host);
    cmd
}

fn write_client_key(dir: &TempDir, kp: &KeyPair) -> PathBuf {
    let path = dir.0.join("id_ed25519");
    sshkeys::write_private_key_file(&path, kp, "test client").unwrap();
    path
}

/// A minimal protocol client assembled from the library, for tests that
/// need control the real client binary does not offer: inspect raw auth
/// replies, or vanish mid-session without a clean shutdown.
struct RawClient {
    stream: TcpStream,
    sb: saltsh::crypto::SealBox,
    ob: saltsh::crypto::OpenBox,
    sid: [u8; 32],
}

impl RawClient {
    fn connect(port: u16) -> RawClient {
        use x25519_dalek::{EphemeralSecret, PublicKey};
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let v = saltsh::crypto::version_line(saltsh::crypto::DEFAULT_VERSION);
        s.write_all(&v).unwrap();
        let mut ver = vec![0u8; v.len()];
        s.read_exact(&mut ver).unwrap();
        assert_eq!(ver, v);
        let eph = EphemeralSecret::random_from_rng(&mut saltsh::rng::os_rng());
        let eph_pub = PublicKey::from(&eph);
        s.write_all(eph_pub.as_bytes()).unwrap();
        let mut kex = [0u8; 128];
        s.read_exact(&mut kex).unwrap();
        let server_eph: [u8; 32] = kex[..32].try_into().unwrap();
        let shared = eph.diffie_hellman(&PublicKey::from(server_eph));
        let sid = saltsh::crypto::session_id(&v, &v, eph_pub.as_bytes(), &server_eph, shared.as_bytes());
        let (c2s, s2c) = saltsh::crypto::derive_keys(&sid, shared.as_bytes()).unwrap();
        RawClient {
            stream: s,
            sb: saltsh::crypto::SealBox::new(&c2s),
            ob: saltsh::crypto::OpenBox::new(&s2c),
            sid,
        }
    }

    fn send(&mut self, m: &Msg) {
        assert!(saltsh::wire::send_packet(&mut self.stream, &mut self.sb, &m.encode()).unwrap());
    }

    /// Next message, or None once the server closed the connection.
    fn recv(&mut self) -> Option<Msg> {
        saltsh::wire::recv_packet(&mut self.stream, &mut self.ob)
            .ok()
            .flatten()
            .map(|p| Msg::decode(&p).unwrap())
    }

    /// Full challenge/response as `user` with `kp`; returns the final reply
    /// (None if the server closed the connection at any point).
    fn login(&mut self, user: &str, kp: &KeyPair) -> Option<Msg> {
        use ed25519_dalek::Signer;
        let blob = sshkeys::ssh_ed25519_pubkey_blob(&kp.public);
        self.send(&Msg::AuthReq { username: user.into(), pubkey_blob: blob.clone() });
        let Msg::AuthChallenge { nonce } = self.recv()? else {
            return None;
        };
        let sig = kp
            .signing_key()
            .sign(&saltsh::msg::user_auth_message(&self.sid, user, &blob, &nonce));
        self.send(&Msg::AuthSig { signature: sig.to_bytes().to_vec() });
        self.recv()
    }
}

// ---------------------------------------------------------------------------

#[test]
fn argv_roundtrip_three_elements() {
    // spec §2.6: `saltsh <host> -- a "b c" d` yields 3 argv elements.
    // `printf "%s|" "$@"` proves the element boundaries: "b c" must arrive
    // as ONE element (no shell re-splitting anywhere in the chain).
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("argv", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, stdout) = run_client(
        port,
        &identity,
        &dir,
        &["/bin/sh", "-c", "printf '%s|' \"$0\" \"$@\"", "a", "b c", "d"],
    );
    assert_eq!(code, 0, "client exit code");
    assert_eq!(String::from_utf8_lossy(&stdout), "a|b c|d|");
}

#[test]
fn echo_preserves_arguments() {
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("echo", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, stdout) = run_client(port, &identity, &dir, &["/bin/echo", "a", "b c", "d"]);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "a b c d");
}

#[test]
fn exit_status_propagates() {
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("exit", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, _) = run_client(port, &identity, &dir, &["/bin/sh", "-c", "exit 7"]);
    assert_eq!(code, 7);
}

#[test]
fn signal_exit_status_is_128_plus_sig() {
    if !kill_works() {
        eprintln!("kill(2) denied in this environment; skipping");
        return;
    }
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("sig", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, _) = run_client(port, &identity, &dir, &["/bin/sh", "-c", "kill -TERM $$"]);
    if code == 1 {
        // Some sandboxes deny non-zero signal delivery; the shell reports
        // the failure and exits 1. Nothing to verify there.
        eprintln!("signal delivery restricted in this environment; skipping assertion");
        return;
    }
    assert_eq!(code, 128 + 15);
}

#[test]
fn unauthorized_key_is_rejected() {
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("authfail", &client_kp, true);
    // a *different* key must be refused
    let other = sshkeys::generate_keypair();
    let identity = write_client_key(&dir, &other);

    let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
    assert_ne!(code, 0);
}

#[test]
fn forced_command_overrides_and_appends_argv() {
    // command="..." runs instead of the requested argv; the client's argv
    // elements are appended verbatim (each element stays one argument).
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/sh -c\" {}", entry.trim_end());
    let (port, dir) = start_server_with("forced", &line, true);
    let identity = write_client_key(&dir, &client_kp);

    // forced = [sh, -c]; client argv = [script, a, "b c", d] -> $0=a, $1="b c", $2=d
    let (code, stdout) = run_client(
        port,
        &identity,
        &dir,
        &["printf '%s|' \"$0\" \"$@\"", "a", "b c", "d"],
    );
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout), "a|b c|d|");
}

#[test]
fn forced_command_with_no_client_args() {
    // No requested argv: the forced command runs by itself.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/echo forced\" {}", entry.trim_end());
    let (port, dir) = start_server_with("forced0", &line, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, stdout) = run_client(port, &identity, &dir, &[]);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "forced");
}

#[test]
fn from_restriction_allows_matching_ip() {
    // Client connects from 127.0.0.1; the pattern list must permit it.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("from=\"127.0.0.0/8,!127.0.0.2\" {}", entry.trim_end());
    let (port, dir) = start_server_with("fromok", &line, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, stdout) = run_client(port, &identity, &dir, &["/bin/echo", "from", "ok"]);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "from ok");
}

#[test]
fn from_restriction_rejects_other_ip() {
    // The key matches, but the peer's address is outside the allowed CIDR.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("from=\"192.0.2.0/24\" {}", entry.trim_end());
    let (port, dir) = start_server_with("fromdeny", &line, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
    assert_ne!(code, 0);
}

#[test]
fn from_restriction_negation() {
    // The peer is explicitly negated: `!127.0.0.1` wins over `0.0.0.0/0`.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("from=\"!127.0.0.1,0.0.0.0/0\" {}", entry.trim_end());
    let (port, dir) = start_server_with("fromneg", &line, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
    assert_ne!(code, 0);
}

#[test]
fn ssh_original_command_env() {
    // With a forced command, SSH_ORIGINAL_COMMAND carries the original
    // request (argv joined with single spaces, like sshd).
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/sh -c\" {}", entry.trim_end());
    let (port, dir) = start_server_with("origcmd", &line, true);
    let identity = write_client_key(&dir, &client_kp);

    let (code, stdout) = run_client(port, &identity, &dir, &["printf '%s' \"$SSH_ORIGINAL_COMMAND\""]);
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&stdout),
        "printf '%s' \"$SSH_ORIGINAL_COMMAND\""
    );
}

/// Both per-user tests edit the *real* user's `~/.saltsh/authorized_keys`,
/// so they must not run concurrently.
static PER_USER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn per_user_authorized_keys() {
    let _guard = PER_USER_LOCK.lock().unwrap();
    if !util::is_root() {
        eprintln!("per-user mode requires root; skipping");
        return;
    }
    // exercises the getpwnam + ~user/.saltsh/authorized_keys lookup path
    let client_kp = sshkeys::generate_keypair();
    let home = util::home_dir().expect("HOME");
    let saltsh_dir = home.join(".saltsh");
    let ak = saltsh_dir.join("authorized_keys");
    let original = std::fs::read(&ak).ok(); // may not exist
    std::fs::create_dir_all(&saltsh_dir).unwrap();
    std::fs::write(&ak, sshkeys::authorized_keys_entry(&client_kp.public, "saltsh-test"))
        .unwrap();

    let (port, dir) = start_server("peruser", &client_kp, false);
    let identity = write_client_key(&dir, &client_kp);

    let (code, stdout) = run_client(port, &identity, &dir, &["/bin/echo", "per", "user"]);
    // restore
    match original {
        Some(data) => std::fs::write(&ak, data).unwrap(),
        None => {
            let _ = std::fs::remove_file(&ak);
        }
    }
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "per user");
}

#[test]
fn user_at_host_logs_in_as_user() {
    let _guard = PER_USER_LOCK.lock().unwrap();
    if !util::is_root() {
        eprintln!("per-user mode requires root; skipping");
        return;
    }
    // `saltsh user@host` must authenticate as that user: the server resolves
    // them via /etc/passwd, reads ~user/.saltsh/authorized_keys, and drops
    // privileges. Poison $USER so the test only passes if the user@host
    // syntax really supplies the name.
    let me = util::default_username();
    let client_kp = sshkeys::generate_keypair();
    let home = util::home_dir().expect("HOME");
    let saltsh_dir = home.join(".saltsh");
    let ak = saltsh_dir.join("authorized_keys");
    let original = std::fs::read(&ak).ok();
    std::fs::create_dir_all(&saltsh_dir).unwrap();
    std::fs::write(&ak, sshkeys::authorized_keys_entry(&client_kp.public, "saltsh-test"))
        .unwrap();

    let (port, dir) = start_server("userathost", &client_kp, false);
    let identity = write_client_key(&dir, &client_kp);

    let mut cmd = client_cmd(port, &identity, &dir, &format!("{me}@127.0.0.1"));
    let out = cmd
        .env("USER", "definitely-not-a-real-user")
        .arg("--")
        .args(["/bin/echo", "login", "as", me.as_str()])
        .output()
        .unwrap();
    match original {
        Some(data) => std::fs::write(&ak, data).unwrap(),
        None => {
            let _ = std::fs::remove_file(&ak);
        }
    }
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("login as {me}")
    );
}

#[test]
fn user_at_host_unknown_user_rejected() {
    // A user@host name that /etc/passwd doesn't know (or that has no
    // ~user/.saltsh/authorized_keys) must be refused.
    let Some(ghost) = pick_unknown_user() else {
        eprintln!("no suitable unknown user; skipping");
        return;
    };
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("ghost", &client_kp, false);
    let identity = write_client_key(&dir, &client_kp);

    let mut cmd = client_cmd(port, &identity, &dir, &format!("{ghost}@127.0.0.1"));
    let out = cmd.arg("--").arg("/bin/true").output().unwrap();
    let code = out.status.code().unwrap_or(-1);
    assert_ne!(code, 0);
}

/// A user that exists in /etc/passwd but whose home has no
/// `.saltsh/authorized_keys` — or, failing that, a definitely-nonexistent
/// user (getpwnam fails).
fn pick_unknown_user() -> Option<String> {
    // prefer a real passwd entry with an empty/unwritable home
    for name in ["nobody", "daemon", "bin"] {
        if let Some(pw) = util::getpwnam(name) {
            let path = PathBuf::from(&pw.home).join(".saltsh/authorized_keys");
            if !path.exists() {
                return Some(name.to_string());
            }
        }
    }
    // otherwise a name that surely does not resolve
    Some("saltsh-no-such-user-98765".to_string())
}

#[test]
fn large_output_streams() {
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("large", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    // 100 KiB of 'y' through the PTY; no newlines, so the pty line
    // discipline cannot transform it.
    let mut cmd = client_cmd(port, &identity, &dir, "127.0.0.1");
    cmd.arg("--")
        .args(["/bin/sh", "-c", "head -c 102400 /dev/zero | tr '\\0' 'y'"]);
    let out = cmd.output().expect("spawn client");
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "client stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout.len(),
        102400,
        "client stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.iter().all(|&b| b == b'y'),
        "client stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn low_order_client_eph_is_rejected() {
    // RFC 7748 §7: a low-order peer public key yields an all-zero shared
    // secret. The server must abort the handshake instead of deriving
    // predictable session keys.
    let client_kp = sshkeys::generate_keypair();
    let (port, _dir) = start_server("loworder", &client_kp, true);

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"SALTSH/1\n").unwrap();
    let mut ver = [0u8; 9];
    s.read_exact(&mut ver).unwrap();
    assert_eq!(&ver, b"SALTSH/1\n");
    s.write_all(&[0u8; 32]).unwrap(); // u-coordinate 0 = low-order point
    let mut buf = [0u8; 128];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(n, 0, "server must close the connection without a KEX reply");
}

#[test]
fn low_order_server_eph_is_rejected() {
    // Mirror image: a malicious server presenting a low-order ephemeral
    // point must be rejected by the client before any key derivation.
    let (listener, port) = free_listener();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"SALTSH/1\n");
            let mut ver = [0u8; 9];
            let _ = s.read_exact(&mut ver);
            let mut eph = [0u8; 32];
            let _ = s.read_exact(&mut eph);
            // server eph = all zeros (low-order), host key + signature garbage
            let _ = s.write_all(&[0u8; 128]);
            std::thread::sleep(Duration::from_millis(300));
        }
    });
    let dir = TempDir::new("loworder-cli");
    let client_kp = sshkeys::generate_keypair();
    let identity = write_client_key(&dir, &client_kp);

    let mut cmd = client_cmd(port, &identity, &dir, "127.0.0.1");
    let out = cmd.arg("--").arg("/bin/true").output().unwrap();
    let code = out.status.code().unwrap_or(-1);
    assert_ne!(code, 0);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("low-order"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn client_cannot_set_server_env() {
    // The client must never be able to set environment variables in the
    // remote session. Give the client a distinctive LANG and a marker
    // variable; neither may appear in the server-side environment.
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("noenv", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    let mut cmd = client_cmd(port, &identity, &dir, "127.0.0.1");
    let out = cmd
        .env("LANG", "zz_ZZ.UTF-8")
        .env("SALTSH_MARKER", "should-not-appear")
        .arg("--")
        .args(["/usr/bin/env"])
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let env_out = String::from_utf8_lossy(&out.stdout);
    assert!(
        !env_out.contains("zz_ZZ.UTF-8"),
        "client LANG leaked into the remote environment: {env_out}"
    );
    assert!(
        !env_out.contains("SALTSH_MARKER"),
        "client env leaked into the remote environment: {env_out}"
    );
}

#[test]
fn daemonize_detaches_and_serves() {
    // `serve --daemonize` must exit 0 quickly, write the pidfile, and the
    // detached daemon must serve sessions.
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("daemon");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "test host").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let (listener, port) = free_listener();
    drop(listener); // free the port for the daemon to bind

    let pidfile = dir.0.join("saltsh.pid");
    let mut cmd = Command::new(bin());
    let st = cmd
        .args(["serve", "--listen", "127.0.0.1", "--port", &port.to_string(), "--host-key"])
        .arg(&host_key)
        .arg("--authorized-keys")
        .arg(&authorized)
        .arg("--daemonize")
        .arg("--pidfile")
        .arg(&pidfile)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "daemonize must exit 0; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .expect("pidfile written")
        .trim()
        .parse()
        .expect("numeric pid");
    assert!(pid > 1, "pidfile must hold the daemon's pid");

    // the daemon actually serves
    let identity = write_client_key(&dir, &client_kp);
    let (code, stdout) = run_client(port, &identity, &dir, &["/bin/echo", "daemon", "works"]);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "daemon works");
}

#[test]
fn daemonize_reports_bind_errors() {
    // Bind happens before detaching, so a busy port must fail the command
    // with a visible error instead of vanishing into the background.
    let dir = TempDir::new("daemon-bind");
    let host_key = dir.0.join("host_key");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    let (listener, port) = free_listener(); // keeps the port busy

    let out = Command::new(bin())
        .args(["serve", "--listen", "127.0.0.1", "--port", &port.to_string(), "--host-key"])
        .arg(&host_key)
        .arg("--authorized-keys")
        .arg("/dev/null")
        .arg("--daemonize")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("in use"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(listener);
}

#[test]
fn keygen_relative_path() {
    // keygen -f is the one path option that accepts a relative path:
    // the key and its .pub are written into the current directory.
    let dir = TempDir::new("keygen-rel");
    let out = Command::new(bin())
        .current_dir(&dir.0)
        .args(["keygen", "-N", "", "-f", "relkey"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.0.join("relkey").exists());
    assert!(dir.0.join("relkey.pub").exists());
    // the written files are real, parseable keys that match each other
    let kp = sshkeys::load_private_key(&dir.0.join("relkey"), None).expect("parse private");
    let pub_text = std::fs::read_to_string(dir.0.join("relkey.pub")).unwrap();
    let parsed = sshkeys::parse_authorized_keys_line(&pub_text).expect("parse .pub");
    assert_eq!(parsed.public, kp.public);
}

#[test]
fn keygen_prompts_for_passphrase_interactively() {
    // Default keygen (no -N) must ask for the passphrase twice over the
    // terminal (echo off) and encrypt the private key with the answer.
    use std::os::fd::{AsRawFd as _, FromRawFd};
    use std::os::unix::process::CommandExt as _;

    fn wait_for_prompts(mut f: &std::fs::File, buf: &mut Vec<u8>, want: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut pfd = libc::pollfd {
                fd: f.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, 200) };
            if n > 0 {
                let mut chunk = [0u8; 128];
                match f.read(&mut chunk) {
                    Ok(0) => return false,
                    Ok(r) => buf.extend_from_slice(&chunk[..r]),
                    Err(_) => return false,
                }
            } else if n < 0 {
                return false;
            }
            let seen = buf
                .windows(b"passphrase".len())
                .filter(|w| *w == b"passphrase")
                .count();
            if seen >= want {
                return true;
            }
        }
        false
    }

    let dir = TempDir::new("keygen-prompt");
    let mut master: libc::c_int = 0;
    let mut slave: libc::c_int = 0;
    let ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe {
        assert_eq!(
            libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws),
            0,
            "openpty"
        );
    }
    let out_path = dir.0.join("pk");
    let mut cmd = Command::new(bin());
    cmd.args(["keygen", "-f"])
        .arg(&out_path)
        .stdin(Stdio::from(unsafe { std::fs::File::from_raw_fd(slave) }))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Detach from any controlling terminal so /dev/tty is unavailable and
    // the prompt falls back to our pty slave (fd 0).
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();

    let mut master_f = unsafe { std::fs::File::from_raw_fd(master) };
    let mut seen = Vec::new();
    let ok1 = wait_for_prompts(&master_f, &mut seen, 1);
    assert!(
        ok1,
        "first prompt; got {:?} (child status: {:?})",
        String::from_utf8_lossy(&seen),
        child.try_wait().unwrap()
    );
    master_f.write_all(b"hunter22\n").unwrap();
    assert!(wait_for_prompts(&master_f, &mut seen, 2), "second prompt");
    master_f.write_all(b"hunter22\n").unwrap();

    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("passphrase-protected"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // the key is really encrypted with the typed passphrase
    assert!(sshkeys::load_private_key(&out_path, None).is_err());
    let kp = sshkeys::load_private_key(&out_path, Some("hunter22")).expect("decrypt");
    assert!(sshkeys::load_private_key(&out_path, Some("wrong")).is_err());
    let _ = kp;
}

#[test]
fn server_silent_until_valid_protocol() {
    // The server must not send anything before the client speaks, must
    // close silently on a wrong identifier, and must answer with the
    // version line once the correct one arrives.
    let client_kp = sshkeys::generate_keypair();
    let (port, _dir) = start_server("silent", &client_kp, true);

    // 1. no banner: connect and wait — nothing may arrive
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    let mut buf = [0u8; 16];
    assert!(
        s.read(&mut buf).is_err(),
        "server must stay silent until spoken to"
    );
    // 2. garbage (a scanner): closed without any reply
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let r = s.read(&mut buf);
    assert!(
        matches!(r, Ok(0) | Err(_)),
        "server must close silently on a bad identifier"
    );
    // 3. correct identifier: server replies with the identical line
    let mut s2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s2.write_all(b"SALTSH/1\n").unwrap();
    let mut line = [0u8; 9];
    s2.read_exact(&mut line).unwrap();
    assert_eq!(&line, b"SALTSH/1\n");
}

#[test]
fn custom_protocol_identifier() {
    // Both ends configured with the same identifier must interoperate; a
    // client with the default identifier is rejected (silently closed).
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("proto");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let (listener, port) = free_listener();
    let opts = ServerOpts {
        listen: "127.0.0.1".to_string(),
        port,
        host_key_path: Some(host_key),
        authorized_keys_path: Some(authorized),
        protocol: "MYSECRET/1".to_string(),
        ..ServerOpts::default()
    };
    std::thread::spawn(move || {
        let _ = saltsh::server::run_on(listener, opts);
    });
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));
    let identity = write_client_key(&dir, &client_kp);

    // default-identifier client is refused
    let out = client_cmd(port, &identity, &dir, "127.0.0.1")
        .arg("--")
        .arg("/bin/true")
        .output()
        .unwrap();
    assert_ne!(out.status.code().unwrap_or(0), 0);

    // matching client works end to end
    let out = Command::new(bin())
        .args(["--protocol", "MYSECRET/1", "--accept-new", "-p", &port.to_string(), "-i"])
        .arg(&identity)
        .env("HOME", &dir.0)
        .arg("127.0.0.1")
        .arg("--")
        .args(["/bin/echo", "secret", "handshake"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "secret handshake");
}

#[test]
fn server_logs_to_file() {
    // --log-file routes all server logging into the file (spawn the real
    // binary: run_on deliberately does not touch the process stderr).
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("logfile");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let log_path = dir.0.join("saltsh.log");
    let (listener, port) = free_listener();
    drop(listener);
    let mut cmd = Command::new(bin());
    let _srv = ServerProc(Some(
        cmd.args(["serve", "--listen", "127.0.0.1", "--port", &port.to_string(), "--host-key"])
            .arg(&host_key)
            .arg("--authorized-keys")
            .arg(&authorized)
            .arg("--log-file")
            .arg(&log_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));
    let identity = write_client_key(&dir, &client_kp);
    let (code, _) = run_client(port, &identity, &dir, &["/bin/echo", "logged"]);
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&log_path).expect("log file written");
    assert!(log.contains("executing"), "log contents: {log}");
    assert!(log.contains("connection from"), "log contents: {log}");
}

#[test]
fn server_log_timestamps() {
    // With --log-timestamps every server log line carries a
    // [YYYY-MM-DD HH:MM:SS] prefix; without the flag, none do.
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("logts");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let log_path = dir.0.join("saltsh.log");
    let (listener, port) = free_listener();
    drop(listener);
    let _srv = ServerProc(Some(
        Command::new(bin())
            .args(["serve", "--listen", "127.0.0.1", "--port", &port.to_string(), "--host-key"])
            .arg(&host_key)
            .arg("--authorized-keys")
            .arg(&authorized)
            .arg("--log-file")
            .arg(&log_path)
            .arg("--log-timestamps")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));
    let identity = write_client_key(&dir, &client_kp);
    let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
    assert_eq!(code, 0);
    let log = std::fs::read_to_string(&log_path).expect("log file written");
    assert!(!log.is_empty());
    for line in log.lines() {
        assert!(
            line.starts_with('[') && line.len() >= 21,
            "line missing timestamp: {line:?}"
        );
        // [YYYY-MM-DD HH:MM:SS] shape
        let b = line.as_bytes();
        assert_eq!(&b[5], &b'-');
        assert_eq!(&b[8], &b'-');
        assert_eq!(&b[11], &b' ');
        assert_eq!(&b[14], &b':');
        assert_eq!(&b[17], &b':');
        assert_eq!(&b[20], &b']');
        assert!(line[21..].starts_with(" saltsh:"), "line: {line:?}");
    }
}

#[test]
fn server_clears_env_and_sets_home() {
    // The server must shed its own inherited environment and give every
    // session an explicit identity: HOME/USER/LOGNAME/SHELL from passwd
    // plus PATH and TERM — and nothing else. Poison the server's
    // environment and verify none of it reaches the client shell.
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("envclear");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let (listener, port) = free_listener();
    drop(listener);
    let _srv = ServerProc(Some(
        Command::new(bin())
            .args(["serve", "--listen", "127.0.0.1", "--port", &port.to_string(), "--host-key"])
            .arg(&host_key)
            .arg("--authorized-keys")
            .arg(&authorized)
            .env("SECRET_TOKEN", "do-not-leak")
            .env("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")
            .env("AWS_ACCESS_KEY_ID", "AKIALEAK")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    ));
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));
    let identity = write_client_key(&dir, &client_kp);
    let me = util::getpwuid(unsafe { libc::geteuid() }).expect("passwd entry");

    let (code, stdout) = run_client(port, &identity, &dir, &["/usr/bin/env"]);
    assert_eq!(code, 0, "client failed");
    let env_out = String::from_utf8_lossy(&stdout);
    for leaked in ["SECRET_TOKEN", "SSH_AUTH_SOCK", "AWS_ACCESS_KEY_ID"] {
        assert!(!env_out.contains(leaked), "{leaked} leaked into session: {env_out}");
    }
    assert!(env_out.contains(&format!("HOME={}", me.home)), "env: {env_out}");
    assert!(env_out.contains(&format!("USER={}", me.name)), "env: {env_out}");
    assert!(env_out.contains(&format!("LOGNAME={}", me.name)), "env: {env_out}");
    assert!(env_out.contains("SHELL="), "env: {env_out}");
    assert!(env_out.contains("PATH="), "env: {env_out}");
    // a command runs without a terminal, so (like sshd) no TERM either —
    // see pty_only_when_requested for the terminal case
    assert!(!env_out.contains("TERM="), "env: {env_out}");
}

#[test]
fn hostkey_preseed_skips_tofu() {
    // `saltsh hostkey` on the server prints the known_hosts line; once the
    // client has it in ~/.saltsh/known_hosts, first connect succeeds
    // WITHOUT --accept-new and without any prompt (stdin is /dev/null, so
    // a prompt would read EOF and abort).
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("preseed");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();

    // start the server on a known port
    let (listener, port) = free_listener();
    let opts = ServerOpts {
        listen: "127.0.0.1".to_string(),
        port,
        host_key_path: Some(host_key.clone()),
        authorized_keys_path: Some(authorized),
        ..ServerOpts::default()
    };
    std::thread::spawn(move || {
        let _ = saltsh::server::run_on(listener, opts);
    });
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));

    // admin queries the line on the server side
    let out = Command::new(bin())
        .args(["hostkey", "--host-key"])
        .arg(&host_key)
        .arg("-p")
        .arg(port.to_string())
        .arg("127.0.0.1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8(out.stdout).unwrap();
    let line = line.trim_end();
    // the line is exactly the known_hosts format with the host key's blob
    assert_eq!(
        line,
        saltsh::tofu::known_hosts_line("127.0.0.1", port, &host_kp.public)
    );

    // seed the client's TOFU store with it
    let kh_dir = dir.0.join(".saltsh");
    std::fs::create_dir_all(&kh_dir).unwrap();
    std::fs::write(kh_dir.join("known_hosts"), format!("{line}\n")).unwrap();

    // connect WITHOUT --accept-new: the pin makes the prompt unnecessary
    let identity = write_client_key(&dir, &client_kp);
    let mut cmd = Command::new(bin());
    cmd.args(["-p", &port.to_string(), "-i"])
        .arg(&identity)
        .env("HOME", &dir.0)
        .arg("127.0.0.1")
        .arg("--")
        .args(["/bin/echo", "preseeded"]);
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "preseeded");
}

#[test]
fn client_config_protocol_per_host() {
    // The ssh_config-style ~/.saltsh/config supplies the protocol
    // identifier per Host; --protocol on the command line still wins.
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("cfgproto");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    let host_kp = sshkeys::generate_keypair();
    sshkeys::write_private_key_file(&host_key, &host_kp, "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let (listener, port) = free_listener();
    let opts = ServerOpts {
        listen: "127.0.0.1".to_string(),
        port,
        host_key_path: Some(host_key),
        authorized_keys_path: Some(authorized),
        protocol: "MYSECRET/1".to_string(),
        ..ServerOpts::default()
    };
    std::thread::spawn(move || {
        let _ = saltsh::server::run_on(listener, opts);
    });
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));
    let identity = write_client_key(&dir, &client_kp);
    let kh_dir = dir.0.join(".saltsh");
    std::fs::create_dir_all(&kh_dir).unwrap();
    let config = kh_dir.join("config");

    let run = |dir: &TempDir, extra: &[&str]| {
        let mut cmd = Command::new(bin());
        cmd.args(["--accept-new", "-p", &port.to_string(), "-i"])
            .arg(&identity)
            .env("HOME", &dir.0)
            .args(extra)
            .arg("127.0.0.1")
            .arg("--")
            .args(["/bin/echo", "cfg-ok"]);
        cmd.output().unwrap()
    };

    // 1. matching Host section: config alone is enough
    std::fs::write(&config, "Host 127.0.0.1\n    Protocol MYSECRET/1\n").unwrap();
    let out = run(&dir, &[]);
    assert_eq!(out.status.code().unwrap_or(-1), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "cfg-ok");

    // 2. non-matching Host section: falls back to the default identifier,
    //    which the server rejects
    std::fs::write(&config, "Host *.example.com\n    Protocol MYSECRET/1\n").unwrap();
    let out = run(&dir, &[]);
    assert_ne!(out.status.code().unwrap_or(0), 0);

    // 3. --protocol on the command line overrides the config (even a
    //    wrong config value)
    std::fs::write(&config, "Host 127.0.0.1\n    Protocol WRONG/1\n").unwrap();
    let out = run(&dir, &["--protocol", "MYSECRET/1"]);
    assert_eq!(out.status.code().unwrap_or(-1), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn bidirectional_pty_roundtrip() {
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("bidi", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    // Deterministic handshake so the pty is in raw mode before any payload
    // arrives (a bare `cat`/`head` would race with `stty` and the cooked
    // line discipline could echo or translate bytes):
    //   1. remote switches to raw, prints READY\n (raw: no translation)
    //   2. test sends a 2-byte trigger that `dd` consumes exactly
    //   3. `head -c N` then reads exactly the payload, echoes it, exits —
    //      terminating the session.
    let payload = b"the quick brown fox\njumps over the lazy dog\n".repeat(100);
    let n = payload.len();
    let mut child = client_cmd(port, &identity, &dir, "127.0.0.1");
    let mut child = child
        .arg("-t") // a command gets a terminal only on request
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("stty raw -echo; printf 'READY\\n'; dd bs=2 count=1 of=/dev/null 2>/dev/null; head -c {n}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // Wait for READY\n, then send trigger + payload.
    let mut ready_buf = Vec::new();
    let mut chunk = [0u8; 64];
    while !ready_buf.windows(6).any(|w| w == b"READY\n") {
        let r = stdout.read(&mut chunk).expect("read READY");
        assert!(r > 0, "remote did not signal readiness");
        ready_buf.extend_from_slice(&chunk[..r]);
    }
    let mut data = vec![b'x', b'\n'];
    data.extend_from_slice(&payload);
    stdin.write_all(&data).unwrap();
    drop(stdin);

    let mut out = ready_buf;
    stdout.read_to_end(&mut out).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
    assert_eq!(out.len() - 6, payload.len()); // minus the READY\n prefix
    assert_eq!(&out[6..], payload);
}

// Real ssh-keygen interop, when the tool is available.
#[test]
fn interop_with_ssh_keygen() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("ssh-keygen not available; skipping interop test");
        return;
    }
    let dir = TempDir::new("sshkeygen");
    let k = dir.0.join("k_ed25519");

    // 1. unencrypted key
    let st = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "saltsh-interop", "-f"])
        .arg(&k)
        .output()
        .unwrap();
    assert!(st.status.success(), "ssh-keygen failed: {:?}", st);
    let kp = sshkeys::load_private_key(&k, None).expect("parse unencrypted key");
    let pub_file = PathBuf::from(format!("{}.pub", k.display()));
    let pub_text = std::fs::read_to_string(&pub_file).unwrap();
    let parsed = sshkeys::parse_authorized_keys_line(&pub_text).expect("parse .pub");
    assert_eq!(parsed.public, kp.public);

    // 2. encrypted key (default ssh-keygen output: bcrypt + aes256-ctr)
    let k2 = dir.0.join("k2_ed25519");
    let st = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "hunter22", "-C", "saltsh-interop", "-f"])
        .arg(&k2)
        .output()
        .unwrap();
    assert!(st.status.success());
    assert!(sshkeys::load_private_key(&k2, Some("wrong")).is_err());
    let kp2 = sshkeys::load_private_key(&k2, Some("hunter22")).expect("parse encrypted key");
    assert_eq!(kp2.public, kp2.public);

    // 3. our written keys are readable by ssh-keygen -y
    let ours = sshkeys::generate_keypair();
    let k3 = dir.0.join("k3_ours");
    sshkeys::write_private_key_file(&k3, &ours, "saltsh-written").unwrap();
    let st = Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(&k3)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "ssh-keygen -y rejected our key: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let y_out = String::from_utf8_lossy(&st.stdout);
    let parsed = sshkeys::parse_authorized_keys_line(&y_out).unwrap();
    assert_eq!(parsed.public, ours.public);
}

// ---------------------------------------------------------------------------
// Regression tests for the 2026-11-28 audit findings

/// The descriptor targets a session process holds: `ls` lists its own
/// fds (everything it inherited, plus its handle on the directory, which
/// is filtered out). Reading /proc/self avoids needing ptrace access to
/// another process's fd table, which some sandboxes deny.
fn session_fd_targets(port: u16, identity: &Path, dir: &TempDir) -> Vec<String> {
    let out = client_cmd(port, identity, dir, "127.0.0.1")
        .args(["-t", "--", "/bin/ls", "-l", "--color=never", "/proc/self/fd/"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "listing failed");
    let out = out.stdout;
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.split_once(" -> ").map(|(_, t)| t.trim().to_string()))
        .map(|t| strip_ansi(&t))
        .filter(|t| !t.starts_with("/proc/"))
        .collect()
}

/// Strip ANSI SGR/CSI escape sequences (ls may still colorize on some
/// toolchains even with --color=never).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break; // 'm' terminates an SGR sequence
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn sessions_do_not_inherit_descriptors() {
    // Finding 1: PTY masters were opened without close-on-exec, so every
    // session inherited the terminals of all other live sessions (and could
    // read and type into them). A session may hold nothing but its own pty.
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("nofdleak", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);

    // session A stays alive while session B looks at its descriptors
    let mut a = client_cmd(port, &identity, &dir, "127.0.0.1");
    let mut a = a
        .args(["-t", "--", "/bin/sleep", "3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let targets = session_fd_targets(port, &identity, &dir);
    let _ = a.wait();
    assert!(!targets.is_empty());
    for t in &targets {
        assert!(
            t.starts_with("/dev/pts/"),
            "session inherited a foreign descriptor: {t} (all: {targets:?})"
        );
    }
}

#[test]
fn server_closes_pty_masters_after_sessions() {
    // Finding 6: the master was never closed when a session ended
    // normally, leaking one descriptor per session. Uses a separate server
    // process so its fd table can be inspected in isolation.
    let client_kp = sshkeys::generate_keypair();
    let dir = TempDir::new("masterleak");
    let host_key = dir.0.join("host_key");
    let authorized = dir.0.join("authorized_keys");
    sshkeys::write_private_key_file(&host_key, &sshkeys::generate_keypair(), "t").unwrap();
    std::fs::write(&authorized, sshkeys::authorized_keys_entry(&client_kp.public, "c")).unwrap();
    let (listener, port) = free_listener();
    drop(listener);
    let child = Command::new(bin())
        .args(["serve", "--listen", "127.0.0.1", "--port", &port.to_string(), "--host-key"])
        .arg(&host_key)
        .arg("--authorized-keys")
        .arg(&authorized)
        // never share the harness's stdio: a server outliving the test
        // (kill(2) is denied in some sandboxes) would hold it open
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let server_pid = child.id();
    let _guard = ServerProc(Some(child));
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(10)));
    let identity = write_client_key(&dir, &client_kp);
    for _ in 0..3 {
        let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
        assert_eq!(code, 0);
    }
    let ptys_open = || {
        std::fs::read_dir(format!("/proc/{server_pid}/fd"))
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|t| t.to_string_lossy().contains("ptmx"))
            .count()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while ptys_open() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(ptys_open(), 0, "server still holds pty masters of finished sessions");
}

/// Start a session whose main process prints its pid and sleeps, vanish
/// without any shutdown message, and require the process to be gone (hung
/// up AND reaped, not a zombie) shortly after.
fn assert_hangup_reaps(
    tag: &str,
    authorized_line: &str,
    argv: Vec<String>,
    pty: bool,
    client_kp: &KeyPair,
) {
    let (port, _dir) = start_server_with(tag, authorized_line, true);
    let mut c = RawClient::connect(port);
    assert_eq!(c.login("anyone", client_kp), Some(Msg::AuthOk));
    c.send(&Msg::Exec { argv, term: "dumb".into(), rows: 24, cols: 80, pty, env: vec![] });
    assert_eq!(c.recv(), Some(Msg::ExecOk { pty }));
    let mut seen = Vec::new();
    let pid = loop {
        match c.recv() {
            Some(Msg::PtyData(d)) => seen.extend_from_slice(&d),
            other => panic!("session ended early: {other:?}"),
        }
        let text = String::from_utf8_lossy(&seen);
        if let Some(rest) = text.split("PID=").nth(1) {
            if let Some(n) = rest.split(|ch: char| !ch.is_ascii_digit()).next().filter(|n| rest.len() > n.len()) {
                break n.parse::<u32>().unwrap();
            }
        }
    };
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    assert!(proc_path.exists());
    drop(c); // vanish without any shutdown message
    let deadline = Instant::now() + Duration::from_secs(5);
    while proc_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let state = std::fs::read_to_string(proc_path.join("stat")).unwrap_or_default();
    assert!(!proc_path.exists(), "session pid {pid} still present (stat: {state})");
}

#[test]
fn hangup_kills_and_reaps_the_session() {
    // Finding 6: a client that vanished left its session process unreaped
    // (a zombie per connection). The session must get SIGHUP and be reaped.
    let client_kp = sshkeys::generate_keypair();
    let line = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let argv = vec!["/bin/sh".into(), "-c".into(), "echo PID=$$; exec /bin/sleep 30".into()];
    assert_hangup_reaps("hangup", &line, argv.clone(), true, &client_kp);
    // the same without a terminal: closing the pipes plus SIGHUP
    if can_signal_children() {
        assert_hangup_reaps("hangup-pipes", &line, argv, false, &client_kp);
    }
}

/// Whether this process may deliver real signals to other processes.
/// Some sandboxes allow `kill(pid, 0)` but refuse every actual signal, so
/// probe with one.
fn can_signal_children() -> bool {
    let Ok(mut child) = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let ok = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) } == 0;
    drop(child.stdin.take()); // lets cat exit if the signal was refused
    let _ = child.wait();
    ok
}

#[test]
fn hangup_closes_a_forced_commands_pipes_and_reaps_it() {
    // A forced command runs on pipes. When its client vanishes, its stdin
    // is closed (EOF) — so a command waiting for input ends — and it is
    // reaped. (Independent of signal delivery.)
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/sh -c\" {}", entry.trim_end());
    let argv = vec!["echo PID=$$; exec /bin/cat >/dev/null".into()];
    assert_hangup_reaps("hangup-forced-eof", &line, argv, false, &client_kp);
}

#[test]
fn hangup_signals_a_forced_command() {
    // ...and a forced command that ignores its stdin still gets SIGHUP:
    // it is its own process group, like a PTY session. (Pipe sessions have
    // no terminal for the kernel to hang up, so this relies on kill(2).)
    if !can_signal_children() {
        eprintln!("signals to other processes are denied here; skipping");
        return;
    }
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/sh -c\" {}", entry.trim_end());
    let argv = vec!["echo PID=$$; exec /bin/sleep 30".into()];
    assert_hangup_reaps("hangup-forced-sig", &line, argv, false, &client_kp);
}

#[test]
fn login_grace_time_is_a_total_deadline() {
    // Finding 7: the handshake timeout restarted on every read, so a peer
    // trickling bytes could hold a server thread indefinitely.
    let (port, _dir) = start_server_tweaked("grace", "", true, |o, _| {
        o.login_grace_time = Duration::from_secs(2);
    });
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    let start = Instant::now();
    let mut closed_after = None;
    let mut buf = [0u8; 16];
    // one byte per ~400 ms: always "active", never finished
    for &b in b"SALTSH/1SALTSH/1" {
        if s.write_all(&[b]).is_err() {
            closed_after = Some(start.elapsed());
            break;
        }
        match s.read(&mut buf) {
            Ok(0) => {
                closed_after = Some(start.elapsed());
                break;
            }
            Ok(_) => panic!("unexpected data before the version line was complete"),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => {
                closed_after = Some(start.elapsed());
                break;
            }
        }
    }
    let t = closed_after.expect("server kept a trickling connection open past the grace time");
    assert!(t >= Duration::from_millis(1500) && t < Duration::from_secs(4), "closed after {t:?}");
}

#[test]
fn per_source_startup_limit_drops_excess_connections() {
    // Finding 7: no cap on unauthenticated connections (thread/fd
    // exhaustion). Excess connections from one source are closed at once.
    let (port, _dir) = start_server_tweaked("startups", "", true, |o, _| {
        o.per_source_max_startups = 2;
    });
    // let wait_ready()'s probe connection release its slot first
    std::thread::sleep(Duration::from_millis(300));
    let idle1 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _idle2 = TcpStream::connect(("127.0.0.1", port)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let is_closed = |s: &mut TcpStream| {
        s.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let mut b = [0u8; 1];
        match s.read(&mut b) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
        }
    };
    let mut third = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(is_closed(&mut third), "third concurrent unauthenticated connection must be dropped");
    drop(idle1);
    std::thread::sleep(Duration::from_millis(300));
    let mut fourth = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(!is_closed(&mut fourth), "a freed slot must admit the next connection");
}

#[test]
fn auth_replies_do_not_reveal_users_or_keys() {
    // Finding 9: unknown users got the connection closed, known users an
    // AUTH_FAIL, and authorized public keys an AUTH_CHALLENGE — an oracle
    // for both. Now every request is challenged and fails the same way.
    let authorized_kp = sshkeys::generate_keypair();
    let other_kp = sshkeys::generate_keypair();
    let (port, _dir) = start_server("oracle", &authorized_kp, false);
    for (user, kp) in [
        ("saltsh-no-such-user-98765", &other_kp),   // unknown user
        ("saltsh-no-such-user-98765", &authorized_kp),
    ] {
        let mut c = RawClient::connect(port);
        assert_eq!(c.login(user, kp), Some(Msg::AuthFail), "user {user}");
    }
    let (port, _dir) = start_server("oracle2", &authorized_kp, true);
    let mut c = RawClient::connect(port);
    // unauthorized key: challenged too, then refused
    assert_eq!(c.login("anyone", &other_kp), Some(Msg::AuthFail));
}

#[test]
fn uppercase_option_names_are_enforced() {
    // Finding 4: option names were matched case-sensitively, so an
    // OpenSSH-valid `COMMAND="..."` was ignored and the key unrestricted.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("COMMAND=\"/bin/echo restricted\" {}", entry.trim_end());
    let (port, dir) = start_server_with("upper", &line, true);
    let identity = write_client_key(&dir, &client_kp);
    let (code, stdout) = run_client(port, &identity, &dir, &["/bin/echo", "free"]);
    assert_eq!(code, 0);
    let out = String::from_utf8_lossy(&stdout);
    assert!(out.trim().starts_with("restricted"), "forced command not applied: {out:?}");
}

#[test]
fn unknown_option_refuses_the_key() {
    // Finding 4: unknown (e.g. misspelled) options were skipped, keeping
    // the key but dropping the restriction. Now the whole line is refused.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("frm=\"10.9.9.9\" {}", entry.trim_end());
    let (port, dir) = start_server_with("unknownopt", &line, true);
    let identity = write_client_key(&dir, &client_kp);
    let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
    assert_ne!(code, 0);
}

#[test]
fn hostile_authorized_keys_paths_are_refused_quickly() {
    // Finding 8: the file was read with no size limit, following symlinks
    // to devices: `-> /dev/zero` made the server allocate until it died.
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server_tweaked("devzero", "", true, |o, d| {
        let link = d.join("ak-zero");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        o.authorized_keys_path = Some(link);
    });
    let identity = write_client_key(&dir, &client_kp);
    let start = Instant::now();
    let (code, _) = run_client(port, &identity, &dir, &["/bin/true"]);
    assert_ne!(code, 0);
    assert!(start.elapsed() < Duration::from_secs(10));
    // ...and the server is still alive
    assert!(wait_ready(port, Instant::now() + Duration::from_secs(2)));
}

#[test]
fn tofu_pins_only_after_a_valid_signature() {
    // Finding 9: on first contact the key was written to known_hosts
    // before the server proved possession of it, so a garbage signature
    // still left a permanent (and wrong) pin behind.
    use x25519_dalek::{EphemeralSecret, PublicKey};
    let (listener, port) = free_listener();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"SALTSH/1\n");
            let mut ver = [0u8; 9];
            let _ = s.read_exact(&mut ver);
            let mut eph = [0u8; 32];
            let _ = s.read_exact(&mut eph);
            let mine = EphemeralSecret::random_from_rng(&mut saltsh::rng::os_rng());
            let mut reply = PublicKey::from(&mine).as_bytes().to_vec();
            reply.extend_from_slice(&sshkeys::generate_keypair().public); // valid point
            reply.extend_from_slice(&[0x11; 64]); // but no valid signature
            let _ = s.write_all(&reply);
            std::thread::sleep(Duration::from_millis(300));
        }
    });
    let dir = TempDir::new("tofu-sig");
    let identity = write_client_key(&dir, &sshkeys::generate_keypair());
    let out = client_cmd(port, &identity, &dir, "127.0.0.1")
        .arg("--")
        .arg("/bin/true")
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("signature verification failed"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pins = std::fs::read_to_string(dir.0.join(".saltsh/known_hosts")).unwrap_or_default();
    assert!(!pins.contains(&format!("127.0.0.1:{port}")), "bad key was pinned: {pins}");
}

#[test]
fn per_user_commands_run_through_login_shell_with_exact_argv() {
    // Finding 2: per-user sessions now go through the account's login
    // shell (so nologin/restricted shells are enforced); for a POSIX shell
    // the argv must still arrive exactly as sent.
    let _guard = PER_USER_LOCK.lock().unwrap();
    if !util::is_root() {
        eprintln!("per-user mode requires root; skipping");
        return;
    }
    let client_kp = sshkeys::generate_keypair();
    let home = util::home_dir().expect("HOME");
    let saltsh_dir = home.join(".saltsh");
    let ak = saltsh_dir.join("authorized_keys");
    let original = std::fs::read(&ak).ok();
    std::fs::create_dir_all(&saltsh_dir).unwrap();
    std::fs::write(&ak, sshkeys::authorized_keys_entry(&client_kp.public, "saltsh-test")).unwrap();

    let (port, dir) = start_server("loginshell", &client_kp, false);
    let identity = write_client_key(&dir, &client_kp);
    let (code, stdout) = run_client(
        port,
        &identity,
        &dir,
        &["/bin/sh", "-c", "printf '%s|' \"$@\"", "x", "a b", "", "c'd", "$HOME"],
    );
    match original {
        Some(data) => std::fs::write(&ak, data).unwrap(),
        None => {
            let _ = std::fs::remove_file(&ak);
        }
    }
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout), "a b||c'd|$HOME|");
}

#[test]
fn forced_command_runs_without_a_pty_and_is_binary_clean() {
    // Forced commands run on plain pipes: no terminal (so no TERM), and the
    // output arrives byte for byte — no \n -> \r\n rewriting, NUL and
    // control bytes intact. Ordinary commands keep their PTY.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/sh -c\" {}", entry.trim_end());
    let (port, dir) = start_server_with("nopty", &line, true);
    let identity = write_client_key(&dir, &client_kp);
    let (code, stdout) = run_client(
        port,
        &identity,
        &dir,
        &["if [ -t 0 ] || [ -t 1 ] || [ -t 2 ]; then echo TTY; fi; \
           printf 'a\\nb\\000\\r\\003'; printf '%s' \"${TERM-unset}\""],
    );
    assert_eq!(code, 0);
    assert_eq!(stdout, b"a\nb\0\r\x03unset", "got {:?}", String::from_utf8_lossy(&stdout));
}

#[test]
fn forced_command_stdin_is_passed_through_unmodified() {
    // Input bytes that a terminal would interpret (^C = SIGINT, ^D = EOF,
    // \r -> \n, ^Z, ^\\) must reach a forced command unchanged.
    let client_kp = sshkeys::generate_keypair();
    let data: Vec<u8> = (0u8..=255).chain(b"\x03\x04\x1a\x1c\r\n".iter().copied()).collect();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/usr/bin/head -c {}\" {}", data.len(), entry.trim_end());
    let (port, dir) = start_server_with("nopty-stdin", &line, true);
    let identity = write_client_key(&dir, &client_kp);
    let mut child = client_cmd(port, &identity, &dir, "127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&data).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, data);
}

#[test]
fn forced_command_holds_only_its_own_pipes() {
    // Descriptor isolation for pipe sessions: 0, 1 and 2 are the session's
    // pipes (1 and 2 the same one) and nothing else is inherited.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/bin/ls -l /proc/self/fd/\" {}", entry.trim_end());
    let (port, dir) = start_server_with("nopty-fds", &line, true);
    let identity = write_client_key(&dir, &client_kp);
    let (code, out) = run_client(port, &identity, &dir, &[]);
    assert_eq!(code, 0);
    let targets: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.split_once(" -> ").map(|(_, t)| t.trim().to_string()))
        .filter(|t| !t.starts_with("/proc/"))
        .collect();
    assert_eq!(targets.len(), 3, "{targets:?}");
    assert!(targets.iter().all(|t| t.starts_with("pipe:")), "{targets:?}");
    assert_eq!(targets[1], targets[2], "stdout and stderr share one pipe");
}

/// Run `/bin/sh -c script` with extra client flags; (exit code, stdout,
/// stderr).
fn run_flags(port: u16, identity: &Path, dir: &TempDir, flags: &[&str], script: &str) -> (i32, String, String) {
    let out = client_cmd(port, identity, dir, "127.0.0.1")
        .args(flags)
        .args(["--", "/bin/sh", "-c", script])
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const TTY_PROBE: &str = "if [ -t 0 ] && [ -t 1 ]; then printf 'TTY %s' \"$TERM\"; else printf 'NOTTY %s' \"${TERM-unset}\"; fi";

#[test]
fn pty_only_when_requested() {
    // Like ssh: a command runs without a terminal unless -t asks for one.
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("pty", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);
    let (code, out, _) = run_flags(port, &identity, &dir, &[], TTY_PROBE);
    assert_eq!((code, out.as_str()), (0, "NOTTY unset"));
    let (code, out, _) = run_flags(port, &identity, &dir, &["-t"], TTY_PROBE);
    assert_eq!(code, 0);
    assert!(out.starts_with("TTY ") && out.len() > 4, "{out:?}");
    let (_, out, _) = run_flags(port, &identity, &dir, &["-T"], TTY_PROBE);
    assert_eq!(out, "NOTTY unset");
}

#[test]
fn key_options_decide_terminal_permission() {
    // Forced commands get a terminal only with an explicit `pty` option;
    // `no-pty` (or `restrict`) denies it for any key. A refused request is
    // reported on the client's stderr.
    let client_kp = sshkeys::generate_keypair();
    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let entry = entry.trim_end();
    for (opts, want_tty) in [
        ("command=\"/bin/sh -c\"", false),
        ("pty,command=\"/bin/sh -c\"", true),
        ("restrict,pty,command=\"/bin/sh -c\"", true),
        ("no-pty", false),
        ("restrict", false),
    ] {
        let (port, dir) = start_server_with("ptyopt", &format!("{opts} {entry}"), true);
        let identity = write_client_key(&dir, &client_kp);
        // forced: the client argv is the script; otherwise run sh -c
        let out = if opts.contains("command=") {
            client_cmd(port, &identity, &dir, "127.0.0.1").args(["-t", "--", TTY_PROBE]).output().unwrap()
        } else {
            client_cmd(port, &identity, &dir, "127.0.0.1")
                .args(["-t", "--", "/bin/sh", "-c", TTY_PROBE])
                .output()
                .unwrap()
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{opts}: {stderr}");
        assert_eq!(stdout.starts_with("TTY "), want_tty, "{opts}: {stdout:?}");
        assert_eq!(stderr.contains("did not allocate a terminal"), !want_tty, "{opts}: {stderr}");
    }
}

#[test]
fn eof_reaches_commands_without_a_terminal() {
    // The client's end of input arrives as an (authenticated) EOF message,
    // so commands that read until EOF finish — also forced commands.
    let client_kp = sshkeys::generate_keypair();
    let data: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
    let (port, dir) = start_server("eof", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);
    let mut child = client_cmd(port, &identity, &dir, "127.0.0.1")
        .args(["--", "/bin/cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feed = data.clone();
    let writer = std::thread::spawn(move || stdin.write_all(&feed)); // then closes
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, data, "cat output differs ({} bytes)", out.stdout.len());

    let entry = sshkeys::authorized_keys_entry(&client_kp.public, "c");
    let line = format!("command=\"/usr/bin/wc -c\" {}", entry.trim_end());
    let (port, dir) = start_server_with("eof-forced", &line, true);
    let identity = write_client_key(&dir, &client_kp);
    let mut child = client_cmd(port, &identity, &dir, "127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&data[..12345]).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "12345");
}

#[test]
fn login_without_a_terminal_reads_commands_from_stdin() {
    // `saltsh host < script`: no command and stdin not a terminal -> the
    // login shell runs on pipes, reads the script, and ends at EOF.
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("script", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);
    let mut child = client_cmd(port, &identity, &dir, "127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"echo hi\nexit 3\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn command_options_need_no_double_dash() {
    // ssh-style parsing: the first word after the host starts the command,
    // so its options — and a literal `--` — reach it untouched.
    let client_kp = sshkeys::generate_keypair();
    let (port, dir) = start_server("nodd", &client_kp, true);
    let identity = write_client_key(&dir, &client_kp);
    let out = client_cmd(port, &identity, &dir, "127.0.0.1")
        .args(["/bin/sh", "-c", "printf '%s|' \"$@\"", "x", "-a", "--b", "--", "-p", "1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "-a|--b|--|-p|1|");
}
