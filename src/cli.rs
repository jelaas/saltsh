//! Hand-rolled command-line parsing (no extra dependencies).

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::util;

#[derive(Debug, Clone)]
pub struct ClientOpts {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub identity: Option<PathBuf>,
    pub passphrase: Option<String>,
    pub accept_new: bool,
    /// Protocol identifier sent in the version exchange (default
    /// "SALTSH/1", possibly overridden per host by ~/.saltsh/config);
    /// the wire line is `IDENT\n`. None = not given on the command line.
    pub protocol: Option<String>,
    /// Command argv (after `--` or any extra positionals).
    pub argv: Vec<String>,
    /// Terminal request: `Some(true)` with `-t`, `Some(false)` with `-T`,
    /// `None` = default (a PTY only for an interactive login on a terminal).
    pub pty: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ServerOpts {
    pub listen: String,
    pub port: u16,
    pub host_key_path: Option<PathBuf>,
    pub authorized_keys_path: Option<PathBuf>,
    /// Detach from the terminal and run in the background.
    pub daemonize: bool,
    /// Pidfile path; defaults to /var/run/saltsh.pid when daemonizing.
    pub pidfile: Option<PathBuf>,
    /// Protocol identifier expected in the version exchange (default
    /// "SALTSH/1"); the wire line is `IDENT\n`.
    pub protocol: String,
    /// Append all server logging to this file instead of stderr.
    pub log_file: Option<PathBuf>,
    /// Prefix every log line with a local timestamp.
    pub log_timestamps: bool,
    /// Total time an unauthenticated connection may take from accept to a
    /// complete EXEC request (OpenSSH `LoginGraceTime`).
    pub login_grace_time: std::time::Duration,
    /// Maximum concurrent unauthenticated connections (OpenSSH
    /// `MaxStartups`); further connections are closed immediately.
    pub max_startups: usize,
    /// Maximum concurrent unauthenticated connections from one source
    /// address (OpenSSH `PerSourceMaxStartups`).
    pub per_source_max_startups: usize,
}

/// Default `--login-grace-time` (OpenSSH's LoginGraceTime default).
pub const DEFAULT_LOGIN_GRACE_SECS: u64 = 120;
/// Default `--max-startups`.
pub const DEFAULT_MAX_STARTUPS: usize = 64;
/// Default `--per-source-max-startups`.
pub const DEFAULT_PER_SOURCE_MAX_STARTUPS: usize = 8;

impl Default for ServerOpts {
    fn default() -> Self {
        ServerOpts {
            listen: "0.0.0.0".to_string(),
            port: 23,
            host_key_path: None,
            authorized_keys_path: None,
            daemonize: false,
            pidfile: None,
            protocol: crate::crypto::DEFAULT_VERSION.to_string(),
            log_file: None,
            log_timestamps: false,
            login_grace_time: std::time::Duration::from_secs(DEFAULT_LOGIN_GRACE_SECS),
            max_startups: DEFAULT_MAX_STARTUPS,
            per_source_max_startups: DEFAULT_PER_SOURCE_MAX_STARTUPS,
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Client(ClientOpts),
    Serve(ServerOpts),
    Keygen(KeygenOpts),
    Hostkey(HostkeyOpts),
    Help,
    Version,
}

#[derive(Debug, Clone)]
pub struct HostkeyOpts {
    /// Hostnames/IPs to emit known_hosts lines for.
    pub hosts: Vec<String>,
    /// Port pinned in the emitted lines (must match what clients use).
    pub port: u16,
    /// Host key file (absolute); default follows the server's rules.
    pub host_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct KeygenOpts {
    /// Output path (default `~/.saltsh/id_ed25519`).
    pub path: Option<PathBuf>,
    pub passphrase: Option<String>,
    pub comment: String,
}

pub fn parse(args: &[String]) -> Result<Command> {
    match args.first().map(|s| s.as_str()) {
        None | Some("-h") | Some("--help") => Ok(Command::Help),
        Some("-V") | Some("--version") => Ok(Command::Version),
        Some("serve") | Some("server") => parse_serve(&args[1..]),
        Some("keygen") => parse_keygen(&args[1..]),
        Some("hostkey") => parse_hostkey(&args[1..]),
        _ => parse_client(args),
    }
}

/// Parse `saltsh hostkey [--port P] [--host-key PATH] host [host ...]`:
/// print known_hosts lines for the local host key, pre-seeding client TOFU.
fn parse_hostkey(args: &[String]) -> Result<Command> {
    let mut opts = HostkeyOpts {
        hosts: Vec::new(),
        port: 23,
        host_key_path: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "-p" | "--port" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| Error::usage("--port requires a value"))?;
                opts.port = parse_port(v)?;
            }
            "--host-key" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--host-key requires a path"))?;
                opts.host_key_path = Some(require_abs(v, "--host-key")?);
            }
            s if s.starts_with('-') && s.len() > 1 => {
                return Err(Error::usage(format!("unknown option '{s}' (see --help)")));
            }
            s => {
                // The host goes verbatim into a known_hosts line, so it must
                // be a single token of visible ASCII (no whitespace/control).
                if s.is_empty() || !s.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
                    return Err(Error::usage(format!("invalid host '{s}'")));
                }
                opts.hosts.push(s.to_string());
            }
        }
        i += 1;
    }
    if opts.hosts.is_empty() {
        return Err(Error::usage("hostkey requires at least one host"));
    }
    Ok(Command::Hostkey(opts))
}

fn parse_keygen(args: &[String]) -> Result<Command> {
    let mut opts = KeygenOpts {
        path: None,
        passphrase: None,
        comment: String::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-f" => {
                i += 1;
                // The one deliberate exception to the absolute-path rule:
                // `keygen -f relkey` writes into the current directory,
                // matching ssh-keygen's behavior.
                opts.path = Some(PathBuf::from(
                    args.get(i).ok_or_else(|| Error::usage("-f requires a path"))?,
                ));
            }
            "-N" | "--passphrase" => {
                i += 1;
                opts.passphrase = Some(
                    args.get(i)
                        .ok_or_else(|| Error::usage("-N requires a passphrase"))?
                        .clone(),
                );
            }
            "-C" | "--comment" => {
                i += 1;
                opts.comment = args
                    .get(i)
                    .ok_or_else(|| Error::usage("-C requires a comment"))?
                    .clone();
            }
            s if s.starts_with('-') && s.len() > 1 => {
                return Err(Error::usage(format!("unknown option '{s}' (see --help)")));
            }
            s => return Err(Error::usage(format!("unexpected argument '{s}'"))),
        }
        i += 1;
    }
    if opts.comment.is_empty() {
        opts.comment = format!(
            "{}@{}",
            util::default_username(),
            crate::sshkeys::hostname()
        );
    }
    Ok(Command::Keygen(opts))
}

fn parse_client(args: &[String]) -> Result<Command> {
    let mut opts = ClientOpts {
        host: String::new(),
        port: 23,
        username: String::new(),
        identity: None,
        passphrase: None,
        accept_new: false,
        protocol: None,
        argv: Vec::new(),
        pty: None,
    };
    // ssh-style: options may come before the host and directly after it,
    // but the first non-option word after the host starts the command, and
    // everything from there on is argv — `saltsh host ls -la` runs
    // `ls -la`, `saltsh host git log -- f` passes the `--` on to git. A
    // `--` before the command ends option parsing explicitly.
    let mut host: Option<String> = None;
    let mut argv: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                let mut rest = args[i + 1..].iter();
                if host.is_none() {
                    // `saltsh -- host cmd...`: the host may follow `--`
                    if let Some(h) = rest.next() {
                        host = Some(set_host(&mut opts, h)?);
                    }
                }
                argv.extend(rest.cloned());
                break;
            }
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--accept-new" => opts.accept_new = true,
            // -tt is accepted for ssh muscle memory; -t already forces
            "-t" | "-tt" => opts.pty = Some(true),
            "-T" => opts.pty = Some(false),
            "--protocol" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--protocol requires a value"))?;
                opts.protocol = Some(parse_protocol(v)?);
            }
            "-p" | "--port" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| Error::usage("--port requires a value"))?;
                opts.port = parse_port(v)?;
            }
            "-l" | "--user" => {
                i += 1;
                opts.username = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--user requires a value"))?
                    .clone();
            }
            "-i" | "--identity" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--identity requires a value"))?;
                opts.identity = Some(require_abs(v, "--identity")?);
            }
            "-P" | "--passphrase" => {
                i += 1;
                opts.passphrase = Some(
                    args.get(i)
                        .ok_or_else(|| Error::usage("--passphrase requires a value"))?
                        .clone(),
                );
            }
            s if s.starts_with('-') && s.len() > 1 => {
                return Err(Error::usage(format!("unknown option '{s}' (see --help)")));
            }
            s if host.is_none() => host = Some(set_host(&mut opts, s)?),
            _ => {
                // The command starts here: the exact elements, as split by
                // the invoking shell, are preserved (spec §2.6).
                argv.extend(args[i..].iter().cloned());
                break;
            }
        }
        i += 1;
    }
    let host = host.ok_or_else(|| Error::usage("missing host (see --help)"))?;
    opts.host = host;
    opts.argv = argv;
    if opts.username.is_empty() {
        opts.username = util::default_username();
    }
    Ok(Command::Client(opts))
}

/// Take the `[user@]host` positional: split on the LAST '@' (OpenSSH
/// convention), but only when -l/--user wasn't given before it — an
/// explicit -l takes precedence. Returns the host.
fn set_host(opts: &mut ClientOpts, s: &str) -> Result<String> {
    if opts.username.is_empty() {
        if let Some(idx) = s.rfind('@') {
            let (user, h) = (&s[..idx], &s[idx + 1..]);
            if user.is_empty() || h.is_empty() {
                return Err(Error::usage(format!("invalid host '{s}'")));
            }
            opts.username = user.to_string();
            return Ok(h.to_string());
        }
    }
    Ok(s.to_string())
}

fn parse_serve(args: &[String]) -> Result<Command> {
    let mut opts = ServerOpts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "-p" | "--port" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| Error::usage("--port requires a value"))?;
                opts.port = parse_port(v)?;
            }
            "--listen" => {
                i += 1;
                opts.listen = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--listen requires an address"))?
                    .clone();
            }
            "--host-key" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--host-key requires a path"))?;
                opts.host_key_path = Some(require_abs(v, "--host-key")?);
            }
            "--authorized-keys" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--authorized-keys requires a path"))?;
                opts.authorized_keys_path = Some(require_abs(v, "--authorized-keys")?);
            }
            "--daemonize" => opts.daemonize = true,
            "--pidfile" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--pidfile requires a path"))?;
                opts.pidfile = Some(require_abs(v, "--pidfile")?);
            }
            "--protocol" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--protocol requires a value"))?;
                opts.protocol = parse_protocol(v)?;
            }
            "--log-file" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--log-file requires a path"))?;
                opts.log_file = Some(require_abs(v, "--log-file")?);
            }
            "--log-timestamps" => opts.log_timestamps = true,
            "--login-grace-time" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--login-grace-time requires seconds"))?;
                let secs = parse_count(v, "--login-grace-time", 1, 3600)?;
                opts.login_grace_time = std::time::Duration::from_secs(secs as u64);
            }
            "--max-startups" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| Error::usage("--max-startups requires a number"))?;
                opts.max_startups = parse_count(v, "--max-startups", 1, 100_000)?;
            }
            "--per-source-max-startups" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| Error::usage("--per-source-max-startups requires a number"))?;
                opts.per_source_max_startups = parse_count(v, "--per-source-max-startups", 1, 100_000)?;
            }
            s if s.starts_with('-') => {
                return Err(Error::usage(format!("unknown option '{s}' (see --help)")));
            }
            s => return Err(Error::usage(format!("unexpected argument '{s}'"))),
        }
        i += 1;
    }
    Ok(Command::Serve(opts))
}

/// A bounded positive integer option value.
fn parse_count(v: &str, flag: &str, min: usize, max: usize) -> Result<usize> {
    match v.parse::<usize>() {
        Ok(n) if (min..=max).contains(&n) => Ok(n),
        _ => Err(Error::usage(format!("{flag} must be a number in {min}..={max}, got '{v}'"))),
    }
}

fn parse_port(v: &str) -> Result<u16> {
    v.parse::<u16>()
        .map_err(|_| Error::usage(format!("invalid port '{v}'")))
}

/// Validate a protocol identifier: 1..255 bytes of visible ASCII, no
/// spaces or control characters (the wire line is `IDENT\n`, and the
/// identifier is logged, so it must be safe and bounded).
pub(crate) fn parse_protocol(v: &str) -> Result<String> {
    if v.is_empty() || v.len() > 255 {
        return Err(Error::usage("--protocol must be 1..255 bytes"));
    }
    if !v.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(Error::usage(
            "--protocol may contain only visible ASCII (no spaces or control characters)",
        ));
    }
    Ok(v.to_string())
}

/// Path options must be absolute: saltsh never interprets a path relative
/// to the current working directory (the daemon chdirs to "/", and
/// relative paths there have caused real bugs). `~` is not expanded —
/// use `$HOME/...`.
fn require_abs(v: &str, flag: &str) -> Result<PathBuf> {
    let path = PathBuf::from(v);
    if !path.is_absolute() {
        return Err(Error::usage(format!(
            "{flag} requires an absolute path, got '{v}'"
        )));
    }
    Ok(path)
}

pub const USAGE: &str = "\
saltsh — a minimal SSH-like remote shell built on NaCl primitives

Usage:
  saltsh [options] [user@]host [--] [argv...]  connect and run a command
  saltsh serve [options]                   run the server (sshd role)
  saltsh keygen [options]                  generate an Ed25519 keypair
  saltsh hostkey [options] host [host...]  print known_hosts lines

Client options:
  -p, --port PORT          server port (default: 23, the abandoned telnet port)
  -l, --user USER          login name (default: $USER; overrides user@host)
  -i, --identity PATH      private key, absolute path (default:
                           ~/.saltsh/id_ed25519)
  -P, --passphrase PASS    private key passphrase (prompts if omitted)
  -t                       request a terminal (PTY) even when running a
                           command (e.g. for top, vim)
  -T                       never request a terminal
      --accept-new         automatically accept a new host key (TOFU)
      --protocol IDENT     protocol identifier sent in the version exchange
                           (default: SALTSH/1; both ends must match).
                           Unless given here, an ssh_config-style
                           ~/.saltsh/config Host section may set it per
                           host.
  -h, --help               show this help
  -V, --version            show version

  Like ssh, options may also follow the host; the first word after the
  host that is not an option starts the command, so no `--` is needed:
    saltsh alice@example.com ls -la /tmp
  The command argv is passed exactly as given — no shell re-splitting:
    saltsh alice@example.com echo a \"b c\" d      # 3 argv elements
  Like ssh, a terminal is requested only for an interactive login (no
  command) on a terminal; commands run on plain pipes (binary-clean, end
  of input is passed on) unless -t is given.

Server options:
  -p, --port PORT          listen port (default: 23; binding it requires root)
      --listen ADDR        bind address (default: 0.0.0.0)
      --host-key PATH      Ed25519 host key, OpenSSH format (absolute path;
                           generated if missing; default:
                           /etc/saltsh/host_key as root, else
                           ~/.saltsh/host_key)
      --authorized-keys PATH
                           single authorized_keys file (absolute path), run
                           commands as the server's own user. Without this
                           option the server looks up
                           ~<user>/.saltsh/authorized_keys and drops
                           privileges to <user> (requires root).
      --daemonize          detach from the terminal and run in the
                           background (double-fork; for init scripts and
                           systems without a service manager). Startup
                           errors are still reported on the terminal.
      --pidfile PATH       write the server pid here, absolute path
                           (default when daemonizing: /var/run/saltsh.pid)
      --protocol IDENT     protocol identifier expected in the version
                           exchange (default: SALTSH/1; both ends must
                           match). The server stays silent until a peer
                           sends the correct identifier — this only cuts
                           down on scanner noise, it is not real security.
      --log-file PATH      append all server logging to this file instead
                           of stderr (absolute path)
      --log-timestamps     prefix every log line with a local timestamp
                           ([YYYY-MM-DD HH:MM:SS])
      --login-grace-time SECS
                           total time a connection may take to authenticate
                           and send its command (default: 120)
      --max-startups N     max concurrent unauthenticated connections;
                           more are closed immediately (default: 64)
      --per-source-max-startups N
                           the same limit per client address (default: 8)

  Per-user mode runs every command through the account's login shell, so
  nologin / restricted shells are enforced (argv stays exact for POSIX
  shells). A command=\"...\" forced command gets the client's argv APPENDED
  as extra arguments - see README \"authorized_keys options\" before
  using one - and runs without a PTY (unless the key line says pty).

Keygen options:
  -f PATH                  output private key; may be relative to the
                           current directory (default: ~/.saltsh/id_ed25519,
                           the client's default identity)
  -N, --passphrase PASS    encrypt the key with PASS; '-N \"\"' means no
                           passphrase. Omit -N to be prompted (empty
                           answer = no passphrase).
  -C, --comment COMMENT    key comment (default: user@host)

  All path options except keygen -f must be absolute; `~` is not expanded
  (use $HOME/...).

Hostkey options:
  -p, --port PORT          port to pin (default: 23; must match the port
                           clients actually use)
      --host-key PATH      host key file, absolute path (default:
                           /etc/saltsh/host_key as root, else
                           ~/.saltsh/host_key)
  host [host ...]          hostname/IP to emit a line for

  Prints the exact lines to append to a client's ~/.saltsh/known_hosts,
  pre-seeding TOFU so first connect needs no prompt:
    saltsh hostkey example.com >> ~/.saltsh/known_hosts
";

pub fn version_string() -> String {
    format!("saltsh {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn client_argv_after_ddash() {
        let Command::Client(o) = parse(&s(&["host", "--", "a", "b c", "d"])).unwrap() else {
            panic!("not client")
        };
        assert_eq!(o.host, "host");
        assert_eq!(o.argv, vec!["a", "b c", "d"]);
        assert_eq!(o.port, 23);
    }

    #[test]
    fn client_argv_without_ddash() {
        let Command::Client(o) = parse(&s(&["host", "a", "b c"])).unwrap() else {
            panic!("not client")
        };
        assert_eq!(o.argv, vec!["a", "b c"]);
    }

    #[test]
    fn client_options() {
        let Command::Client(o) = parse(&s(&[
            "-p", "2223", "-l", "bob", "-i", "/tmp/k", "--accept-new",
            "host.example", "--", "ls",
        ]))
        .unwrap() else {
            panic!("not client")
        };
        assert_eq!(o.port, 2223);
        assert_eq!(o.username, "bob");
        assert_eq!(o.identity, Some(PathBuf::from("/tmp/k")));
        assert!(o.accept_new);
        assert_eq!(o.argv, vec!["ls"]);
        assert_eq!(o.pty, None);
        for (flag, want) in [("-t", Some(true)), ("-tt", Some(true)), ("-T", Some(false))] {
            let Command::Client(o) = parse(&s(&[flag, "host", "--", "top"])).unwrap() else {
                panic!("not client")
            };
            assert_eq!(o.pty, want, "{flag}");
        }
    }

    #[test]
    fn options_stop_at_the_command_like_ssh() {
        let client = |a: &[&str]| match parse(&s(a)).unwrap() {
            Command::Client(o) => o,
            _ => panic!("not client"),
        };
        // the command's own options need no `--`
        let o = client(&["host", "ls", "-la", "/tmp"]);
        assert_eq!(o.argv, vec!["ls", "-la", "/tmp"]);
        // options right after the host are still saltsh's
        let o = client(&["host", "-t", "-p", "2222", "top", "-d", "1"]);
        assert_eq!((o.pty, o.port), (Some(true), 2222));
        assert_eq!(o.argv, vec!["top", "-d", "1"]);
        // once the command started, saltsh options and `--` belong to it
        let o = client(&["host", "git", "log", "-p", "5", "--", "f"]);
        assert_eq!(o.port, 23);
        assert_eq!(o.argv, vec!["git", "log", "-p", "5", "--", "f"]);
        // `--` before the command ends option parsing; it may precede the host
        let o = client(&["host", "--", "-weird", "x"]);
        assert_eq!(o.argv, vec!["-weird", "x"]);
        let o = client(&["-l", "bob", "--", "-host", "cmd"]);
        assert_eq!((o.host.as_str(), o.username.as_str()), ("-host", "bob"));
        assert_eq!(o.argv, vec!["cmd"]);
        // unknown options before the command are still errors
        assert!(parse(&s(&["host", "-z", "ls"])).is_err());
    }

    #[test]
    fn serve_options() {
        let Command::Serve(o) = parse(&s(&[
            "serve", "--listen", "127.0.0.1", "-p", "2222", "--host-key", "/hk",
            "--daemonize", "--pidfile", "/run/s.pid",
        ]))
        .unwrap()
        else {
            panic!("not serve")
        };
        assert_eq!(o.listen, "127.0.0.1");
        assert_eq!(o.port, 2222);
        assert_eq!(o.host_key_path, Some(PathBuf::from("/hk")));
        assert!(o.daemonize);
        assert_eq!(o.pidfile, Some(PathBuf::from("/run/s.pid")));
    }

    #[test]
    fn user_at_host_parsing() {
        let Command::Client(o) = parse(&s(&["alice@example.com", "--", "ls"])).unwrap() else {
            panic!("not client")
        };
        assert_eq!(o.username, "alice");
        assert_eq!(o.host, "example.com");
        assert_eq!(o.argv, vec!["ls"]);

        // last '@' splits (username may itself contain '@')
        let Command::Client(o) = parse(&s(&["a@b@host"])).unwrap() else {
            panic!("not client")
        };
        assert_eq!(o.username, "a@b");
        assert_eq!(o.host, "host");

        // -l takes precedence: the positional is then just a host
        let Command::Client(o) = parse(&s(&["-l", "bob", "alice@host"])).unwrap() else {
            panic!("not client")
        };
        assert_eq!(o.username, "bob");
        assert_eq!(o.host, "alice@host");

        // malformed forms are rejected
        assert!(parse(&s(&["@host"])).is_err());
        assert!(parse(&s(&["user@"])).is_err());
    }

    #[test]
    fn hostkey_parsing() {
        let Command::Hostkey(o) =
            parse(&s(&["hostkey", "--host-key", "/etc/hk", "-p", "2323", "a.example", "10.0.0.1"]))
                .unwrap()
        else {
            panic!("not hostkey")
        };
        assert_eq!(o.hosts, vec!["a.example", "10.0.0.1"]);
        assert_eq!(o.port, 2323);
        assert_eq!(o.host_key_path, Some(PathBuf::from("/etc/hk")));
        // defaults
        let Command::Hostkey(o) = parse(&s(&["hostkey", "h"])).unwrap() else {
            panic!("not hostkey")
        };
        assert_eq!(o.port, 23);
        assert_eq!(o.host_key_path, None);
        // no hosts -> error
        assert!(parse(&s(&["hostkey"])).is_err());
        // hosts must be single safe tokens
        assert!(parse(&s(&["hostkey", "bad host"])).is_err());
        assert!(parse(&s(&["hostkey", "bad\nhost"])).is_err());
        assert!(parse(&s(&["hostkey", ""])).is_err());
        // host key path must be absolute
        assert!(parse(&s(&["hostkey", "--host-key", "rel", "h"])).is_err());
    }

    #[test]
    fn errors() {
        assert!(parse(&s(&[])).is_ok()); // help
        assert!(parse(&s(&["--nope", "host"])).is_err());
        assert!(parse(&s(&["host", "-p", "notaport"])).is_err());
    }

    #[test]
    fn protocol_option_validation() {
        // default is SALTSH/1 on both ends (None = not given on the CLI)
        let Command::Client(o) = parse(&s(&["host"])).unwrap() else { panic!() };
        assert_eq!(o.protocol, None);
        let Command::Serve(o) = parse(&s(&["serve"])).unwrap() else { panic!() };
        assert_eq!(o.protocol, "SALTSH/1");
        assert_eq!(o.log_file, None);
        // custom identifiers are accepted on both ends
        let Command::Client(o) = parse(&s(&["--protocol", "MYSECRET/2", "host"])).unwrap() else { panic!() };
        assert_eq!(o.protocol.as_deref(), Some("MYSECRET/2"));
        let Command::Serve(o) =
            parse(&s(&["serve", "--protocol", "X/1", "--log-file", "/var/log/saltsh.log"]))
                .unwrap()
        else {
            panic!()
        };
        assert_eq!(o.protocol, "X/1");
        assert_eq!(o.log_file, Some(PathBuf::from("/var/log/saltsh.log")));
        assert!(!o.log_timestamps);
        let Command::Serve(o) = parse(&s(&["serve", "--log-timestamps"])).unwrap() else {
            panic!()
        };
        assert!(o.log_timestamps);
        assert_eq!(o.login_grace_time, std::time::Duration::from_secs(120));
        assert_eq!((o.max_startups, o.per_source_max_startups), (64, 8));
        let Command::Serve(o) = parse(&s(&[
            "serve", "--login-grace-time", "5", "--max-startups", "3", "--per-source-max-startups", "1",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.login_grace_time, std::time::Duration::from_secs(5));
        assert_eq!((o.max_startups, o.per_source_max_startups), (3, 1));
        assert!(parse(&s(&["serve", "--login-grace-time", "0"])).is_err());
        assert!(parse(&s(&["serve", "--max-startups", "x"])).is_err());
        // invalid identifiers are rejected
        assert!(parse(&s(&["--protocol", "", "host"])).is_err());
        assert!(parse(&s(&["--protocol", "has space", "host"])).is_err());
        assert!(parse(&s(&["--protocol", "ctrl\nchar", "host"])).is_err());
        assert!(parse(&s(&["--protocol", &"x".repeat(256), "host"])).is_err());
        // log-file must be absolute
        assert!(parse(&s(&["serve", "--log-file", "rel.log"])).is_err());
    }

    #[test]
    fn path_options_must_be_absolute() {
        // client identity
        assert!(parse(&s(&["-i", "rel", "host"])).is_err());
        assert!(parse(&s(&["host", "-i", "./key"])).is_err());
        assert!(parse(&s(&["host", "-i", "/abs/key"])).is_ok());
        // server options
        assert!(parse(&s(&["serve", "--host-key", "rel"])).is_err());
        assert!(parse(&s(&["serve", "--authorized-keys", "rel"])).is_err());
        assert!(parse(&s(&["serve", "--pidfile", "rel"])).is_err());
        assert!(parse(&s(&["serve", "--host-key", "/abs"])).is_ok());
        // keygen -f is the one exception: relative paths are allowed
        assert!(parse(&s(&["keygen", "-f", "rel"])).is_ok());
        assert!(parse(&s(&["keygen", "-f", "/abs/key"])).is_ok());
        // the message tells the user what happened
        match parse(&s(&["serve", "--host-key", "rel"])) {
            Err(Error::Usage(m)) => assert!(m.contains("absolute path"), "{m}"),
            other => panic!("expected usage error, got {other:?}"),
        }
    }
}
