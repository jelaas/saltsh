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
    /// Command argv (after `--` or any extra positionals).
    pub argv: Vec<String>,
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
}

#[derive(Debug)]
pub enum Command {
    Client(ClientOpts),
    Serve(ServerOpts),
    Keygen(KeygenOpts),
    Help,
    Version,
}

#[derive(Debug, Clone)]
pub struct KeygenOpts {
    /// Output path (default `~/.ssh/saltsh_ed25519`).
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
        _ => parse_client(args),
    }
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
            std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into())
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
        argv: Vec::new(),
    };
    let mut host: Option<String> = None;
    let mut argv: Vec<String> = Vec::new();
    let mut after_ddash = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        if after_ddash {
            argv.push(a);
            i += 1;
            continue;
        }
        match a.as_str() {
            "--" => after_ddash = true,
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--accept-new" => opts.accept_new = true,
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
            s => {
                if host.is_none() {
                    // `[user@]host` form: split on the LAST '@' (OpenSSH
                    // convention), but only when -l/--user wasn't given —
                    // an explicit -l takes precedence.
                    if opts.username.is_empty() {
                        if let Some(idx) = s.rfind('@') {
                            let (user, h) = (&s[..idx], &s[idx + 1..]);
                            if user.is_empty() || h.is_empty() {
                                return Err(Error::usage(format!("invalid host '{s}'")));
                            }
                            opts.username = user.to_string();
                            host = Some(h.to_string());
                            i += 1;
                            continue;
                        }
                    }
                    host = Some(s.to_string());
                } else {
                    // extra positionals are argv, split by the invoking
                    // shell — the exact elements are preserved (spec §2.6)
                    argv.push(s.to_string());
                }
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

fn parse_serve(args: &[String]) -> Result<Command> {
    let mut opts = ServerOpts {
        listen: "0.0.0.0".to_string(),
        port: 23,
        host_key_path: None,
        authorized_keys_path: None,
        daemonize: false,
        pidfile: None,
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
            s if s.starts_with('-') => {
                return Err(Error::usage(format!("unknown option '{s}' (see --help)")));
            }
            s => return Err(Error::usage(format!("unexpected argument '{s}'"))),
        }
        i += 1;
    }
    Ok(Command::Serve(opts))
}

fn parse_port(v: &str) -> Result<u16> {
    v.parse::<u16>()
        .map_err(|_| Error::usage(format!("invalid port '{v}'")))
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

Client options:
  -p, --port PORT          server port (default: 23, the abandoned telnet port)
  -l, --user USER          login name (default: $USER; overrides user@host)
  -i, --identity PATH      private key, absolute path (default:
                           ~/.ssh/id_ed25519)
  -P, --passphrase PASS    private key passphrase (prompts if omitted)
      --accept-new         automatically accept a new host key (TOFU)
  -h, --help               show this help
  -V, --version            show version

  The command argv is passed exactly as given — no shell re-splitting:
    saltsh alice@example.com -- echo a \"b c\" d   # 3 argv elements

Server options:
  -p, --port PORT          listen port (default: 23; binding it requires root)
      --listen ADDR        bind address (default: 0.0.0.0)
      --host-key PATH      Ed25519 host key, OpenSSH format (absolute path;
                           generated if missing; default:
                           /etc/saltsh/host_key as root, else
                           ~/.config/saltsh/host_key)
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

Keygen options:
  -f PATH                  output private key; may be relative to the
                           current directory (default: ~/.ssh/saltsh_ed25519)
  -N, --passphrase PASS    encrypt the key with PASS (prompt-free)
  -C, --comment COMMENT    key comment (default: user@host)

  All path options except keygen -f must be absolute; `~` is not expanded
  (use $HOME/...).
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
    fn errors() {
        assert!(parse(&s(&[])).is_ok()); // help
        assert!(parse(&s(&["--nope", "host"])).is_err());
        assert!(parse(&s(&["host", "-p", "notaport"])).is_err());
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
