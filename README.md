# saltsh

A minimal SSH-like remote shell built on NaCl primitives, written in Rust.
Design document: [`SALTSH_SPEC.md`](SALTSH_SPEC.md).
Security audit: [`SECURITY.md`](SECURITY.md).

One binary, two roles:

```
saltsh [options] [user@]host [options] [argv...]  # client (ssh role)
saltsh serve [options]                   # server (sshd role)
saltsh keygen [options]                  # generate an Ed25519 keypair
```

## What it is

A single encrypted PTY connection:

* **Transport** — X25519 key exchange (forward secrecy), XSalsa20-Poly1305
  secretbox framing with per-direction sequence numbers, Ed25519 host-key
  signatures bound to a BLAKE2b-256 transcript hash, HKDF session keys.
* **Authentication** — key-only: one Ed25519 challenge/response over the
  encrypted channel, verified against `authorized_keys` (OpenSSH format).
  Per-entry `from="..."` source-address restrictions, `expiry-time="..."`
  and `command="..."` forced commands are honored; option parsing is
  fail-closed (see [authorized_keys options](#authorized_keys-options)).
  No passwords, no keyboard-interactive.
* **Session** — exactly one session per connection. Like ssh, an
  interactive login gets a PTY; commands (`saltsh host cmd args`) and
  forced commands run on plain pipes — binary-clean, with end of input
  passed on — unless `-t` asks for a terminal (see
  [How commands run](#how-commands-run)). The command argv is
  transmitted as a structured array and `execvp`'d verbatim:
  `saltsh host -- echo a "b c" d` passes **3** elements, not 4 (the OpenSSH
  argv bug). Resize (SIGWINCH) and signal forwarding (SIGINT/SIGTSTP) are
  supported; the remote exit status is returned to the client.
* **Host keys** — TOFU pinning in `~/.saltsh/known_hosts`
  (`host:port base64(pubkey)` lines). First connect prints the SHA-256
  fingerprint (OpenSSH-style, `ssh-keygen -lf`-compatible) and asks for
  confirmation (`--accept-new` skips the prompt). A key change is a hard
  fail (MITM protection).
* **Keys** — OpenSSH formats throughout: client identity defaults to
  `~/.saltsh/id_ed25519` (including passphrase-protected `bcrypt` +
  `aes256-ctr` keys, which are unwrapped with pure-Rust `bcrypt-pbkdf` +
  AES-256-CTR), server host keys are OpenSSH-format Ed25519 private keys,
  generated on first start.

Deliberately **not** implemented (see the spec's non-goals): SSH wire
compatibility, algorithm negotiation, multiplexed channels, SFTP/SCP, port
forwarding, agent forwarding, password auth, Windows PTYs.

## Usage

### Server

```console
# per-user mode (default; requires root): the requested user is resolved via
# /etc/passwd, keys are read from ~<user>/.saltsh/authorized_keys, and the
# session switches to <user> (all of the user's groups via setgroups, then
# setgid + setuid + chdir home) and runs the command through the user's
# login shell
$ sudo saltsh serve --listen 0.0.0.0 --port 23

# shared-file mode: run everything as the server's own user
$ saltsh serve --host-key /etc/saltsh/host_key --authorized-keys /etc/saltsh/authorized_keys

# daemon mode — for init scripts and systems without systemd:
$ sudo saltsh serve --daemonize --pidfile /run/saltsh.pid
$ kill "$(cat /run/saltsh.pid)"      # stop it

# file logging + a custom protocol identifier (scanner-noise reduction):
$ sudo saltsh serve --log-file /var/log/saltsh.log --protocol "SALTSH/1"
```

`--daemonize` performs a classic double-fork (fork → setsid → fork),
changes to `/`, and redirects stdio to `/dev/null`. The command exits 0
only once the daemon is actually up: the host key and the listen socket
are set up *before* detaching, so startup errors (bad key, port already in
use) still print on your terminal with a non-zero exit. Without
`--pidfile`, the pid is written to `/var/run/saltsh.pid`. All path options
(`--host-key`, `--authorized-keys`, `--pidfile`, `--log-file`) must be
absolute paths.

**Connection limits.** The whole login (version exchange, key exchange,
authentication and the command request) must finish within
`--login-grace-time` seconds (default 120, like OpenSSH's
`LoginGraceTime`) — a single deadline, not a per-read timeout. At most
`--max-startups` (default 64) unauthenticated connections are handled at
once, and at most `--per-source-max-startups` (default 8) from one client
address; further connections are closed immediately. Authenticated
sessions do not count against these limits.

Logging goes to stderr by default; with `--log-file PATH` all server
logging (host-key generation, startup, connections, auth, errors) is
appended to that file instead — including when daemonized, so a log file
is the recommended companion to `--daemonize`. With `--log-timestamps`,
every line is prefixed with a local-time `[YYYY-MM-DD HH:MM:SS]` stamp
(syslog style).

### Client configuration (`~/.saltsh/config`)

Optional, ssh_config-style. Currently one option is honored:

```
# per-host protocol identifier
Host *.example.com
    Protocol MYSECRET/1

Host 10.0.0.*
    Protocol SALTSH/2
```

* `Host` starts a section; its patterns (`*`, `?`, `!` negation, comma
  separated) are matched against the host given on the command line.
* The **first** matching section wins; within a section the first
  occurrence of an option wins.
* Command-line flags always override the file (`--protocol`).
* Unknown options and malformed lines are ignored.

### Pre-seeding host keys (skip the TOFU prompt)

The TOFU prompt on first connect can be avoided entirely by pinning the
host key in advance. On the **server**, query the exact line to add:

```console
$ saltsh hostkey example.com            # default port 23
example.com:23 AAAA...base64...
$ saltsh hostkey --port 2323 10.0.0.7   # non-default port
```

Then append the line to the client's `~/.saltsh/known_hosts`:

```console
$ echo 'example.com:23 AAAA...base64...' >> ~/.saltsh/known_hosts
```

The `host:port` part must match exactly what the client is given on its
command line (hostname as typed, port as connected). `saltsh hostkey`
reads the local host key file (`--host-key`, or `/etc/saltsh/host_key` as
root / `~/.saltsh/host_key` otherwise) — no network scan, so there is no
first-contact MITM ambiguity. A mismatch later still hard-fails, exactly
like a fresh TOFU pin.

### How commands run

* **Per-user mode**: every command runs through the account's **login
  shell**, like sshd. An account whose shell is `nologin`, `/bin/false`,
  `git-shell`, `rbash` or any other restricted shell therefore cannot run
  arbitrary programs by naming them. For POSIX shells (`sh`, `bash`,
  `dash`, `ash`, `ksh`, `mksh`, `zsh`, ...) the argv is still passed
  exactly — as positional parameters to `shell -c 'exec "$0" "$@"'`, never
  re-split. Any other login shell receives the argv as one OpenSSH-style
  string (`shell -c "'arg1' 'arg2' ..."`, each element single-quoted) and
  decides itself what to run.
* **Shared-file mode** (`--authorized-keys`): the argv is `execvp`'d
  directly as the server's own user.
* No command: the login shell starts as an interactive session.

**PTY or pipes.** A session gets a terminal only when the client asks for
one *and* the key allows it — the same model as ssh:

| client invocation | requests a PTY? |
|---|---|
| `saltsh host` (interactive login), stdin is a terminal | yes |
| `saltsh host < script.sh` (stdin not a terminal) | no — the shell reads the script, ends at EOF |
| `saltsh host cmd args...` | no |
| `saltsh -t host cmd args...` (e.g. `top`, `vim`) | yes |
| `saltsh -T host` | no |

| key (`authorized_keys`) | terminal allowed? |
|---|---|
| no options | yes |
| `command="..."` (forced command) | **no** — unless the line also says `pty` |
| `no-pty`, or `restrict` | no (`restrict,pty` re-allows it) |

`pty` / `no-pty` / `restrict` are applied in order, last one wins. If a
requested terminal is refused, the client says so on stderr and the
session runs on pipes.

Without a terminal:

* The byte streams pass through unmodified in both directions: no
  `\n` → `\r\n` rewriting, no echo, and input bytes such as `^C`, `^D`,
  `^Z` or `\r` reach the command as data instead of being interpreted.
* **End of input is passed on**: when the client's stdin ends (EOF, or
  `^D` typed at a local terminal) it sends an authenticated `EOF`
  message and the server closes the command's stdin — so `cat > file`,
  `wc`, `sort` and scripts piped into a login shell finish normally.
* stdout and stderr are merged into one stream (the protocol has a
  single data stream).
* `TERM` is not set, there is no controlling terminal, and window-size
  changes are ignored. The local terminal stays in normal (cooked) mode:
  line editing and echo happen locally, and Ctrl-C / Ctrl-Z are forwarded
  to the command as SIGINT / SIGTSTP. A disconnect closes the command's
  pipes and sends SIGHUP to its process group.

With a terminal the local terminal is switched to raw mode and every key
goes to the remote side; end of input is typed there (`^D`), and the
client's EOF is ignored.

Each session holds no other descriptor from the server (no other
session's terminal or pipes, no sockets, no log file), has default signal
dispositions, and — in per-user mode — exactly the user's supplementary
groups.

### Session environment

The server sheds its own inherited environment at startup (only `PATH`
survives) and builds every session's environment explicitly, so nothing
the server process knew — tokens, agent sockets, secrets — can leak into
a client shell. A session sees exactly:

```
PATH=...      (inherited from the server's PATH)
HOME=...      (the logged-in user's home directory, from /etc/passwd)
USER=..., LOGNAME=..., SHELL=...
TERM=...      (the client's terminal type)
SSH_ORIGINAL_COMMAND=...   (only with a command= forced command)
```

### Host key

The host key authenticates the server to clients (clients pin it via TOFU,
§6 of the spec). It is an OpenSSH-format Ed25519 private key, unencrypted —
the server never prompts for a passphrase.

**Where the server reads it from**, in order:

1. `--host-key PATH`, if given;
2. otherwise `/etc/saltsh/host_key` when running as root;
3. otherwise `~/.saltsh/host_key`.

**Generating it** — three ways, all equivalent:

```console
# 1. Let the first server start generate one (only if the file is missing):
$ sudo saltsh serve --port 23
saltsh: generated new host key at /etc/saltsh/host_key
saltsh: host key fingerprint SHA256:... (/etc/saltsh/host_key): per-user authorized_keys

# 2. Generate it explicitly (also writes host_key.pub, which can be deleted):
$ sudo saltsh keygen -f /etc/saltsh/host_key

# 3. With OpenSSH tooling — the format is interoperable (create the dir first):
$ sudo mkdir -p /etc/saltsh
$ sudo ssh-keygen -t ed25519 -N '' -f /etc/saltsh/host_key
```

The file is written with mode 0600 and parent directories are created as
needed. On every start the server prints the key's SHA-256 fingerprint,
compatible with `ssh-keygen -lf` for out-of-band verification:

```console
$ ssh-keygen -lf /etc/saltsh/host_key
256 SHA256:... comment (ED25519)
```

**Rotating the host key**: clients pin the old key in
`~/.saltsh/known_hosts` and will hard-fail with
"REMOTE HOST IDENTIFICATION HAS CHANGED" after a rotation. Remove the stale
`host:port` line (or the whole file) from each client to re-pin.

### authorized_keys options

```
# only allow this key from specific addresses (wildcards, CIDR, !negation)
from="10.0.0.0/8,192.168.1.7,!10.0.0.66" ssh-ed25519 AAAA... alice@work

# key stops working after this date (local time; append Z for UTC)
expiry-time="20271231" ssh-ed25519 AAAA... contractor

# forced command — READ THE WARNING BELOW before using one
command="/usr/local/bin/backup-only" ssh-ed25519 AAAA... backup-bot
```

* `from="..."` — comma-separated pattern list matched against the peer's
  IPv4 address (OpenSSH `match_pattern_list` semantics: a matching
  `!`-negated pattern rejects; otherwise any positive match allows). IPv4
  CIDR blocks match numerically; `*`/`?` wildcards are supported. saltsh
  is **IPv4-only**: both the client and server resolve and bind IPv4
  addresses, and IPv6 patterns never match.
* `expiry-time="YYYYMMDD[HHMM[SS]][Z]"` — the key is refused after this
  time.
* `command="..."` — forced command, split on whitespace; the client's argv
  is **appended** (see below). The original request is also available as
  `SSH_ORIGINAL_COMMAND`.

> **⚠ Forced commands receive the client's arguments.**
>
> In OpenSSH, `command="..."` *replaces* whatever the client asked for;
> the forced command can only look at the request via
> `$SSH_ORIGINAL_COMMAND`. **saltsh is different by design: it appends
> the client's argv to the forced command as extra arguments**, each
> element kept intact. `command="/bin/echo forced"` plus a client running
> `saltsh host -- a "b c"` executes `echo forced a "b c"`.
>
> A forced command is therefore only a restriction if the program you
> name is safe to run with **arbitrary extra arguments chosen by the
> client**. Many common programs are not:
>
> | forced command | the client sends | effect |
> |---|---|---|
> | `command="/bin/sh -c"` | `-- 'any shell code'` | runs anything |
> | `command="/usr/bin/env"` | `-- /bin/sh` | runs anything |
> | `command="/usr/bin/find /backups"` | `-- -exec /bin/sh -c '...' ;` | runs anything |
> | `command="/usr/bin/tar -czf - /data"` | `-- --checkpoint=1 --checkpoint-action=exec=...` | runs anything |
> | `command="/bin/cat /var/log/app.log"` | `-- /home/backup/.saltsh/id_ed25519` | reads any file the account can |
>
> Safe patterns:
>
> * Point `command=` at a small wrapper that **rejects arguments it does
>   not expect**:
>
>   ```sh
>   #!/bin/sh
>   # /usr/local/bin/backup-only: takes no client arguments at all
>   [ "$#" -eq 0 ] || { echo "backup-only: no arguments allowed" >&2; exit 1; }
>   exec /opt/backup/run
>   ```
>
>   or that checks each argument against an allowlist
>   (`case "$1" in status|start) ;; *) exit 1 ;; esac`).
> * Never name a shell, `env`, `find`, `xargs`, `tar`, `awk`, `git`, an
>   interpreter (`python3`, `perl`, ...) or any other program with
>   "run this"/"read that" options directly as a forced command.
> * Use `"$@"` in the wrapper, not `$SSH_ORIGINAL_COMMAND`: the latter is
>   the argv joined with single spaces, so argument boundaries are lost —
>   and never `eval` it.
> * In per-user mode the forced command (with its appended arguments)
>   still runs through the account's login shell, so a `nologin` account
>   stays locked even with a forced-command key.

**Parsing is fail-closed** — a restriction is never dropped silently:

* Option names are case-insensitive (`COMMAND=` = `command=`), as in
  OpenSSH. Values must be double-quoted; `\"` is the only escape.
* A line with an **unknown or misspelled option**, a duplicate
  `command=`/`from=`, a malformed `from=` CIDR block, an unparsable
  `expiry-time`, or an option saltsh cannot honor (`cert-authority`,
  `principals=`, `verify-required`) is **refused as a whole**, and the
  server logs a warning naming the file and line.
* Accepted without effect (saltsh has no forwarding, agent, X11 or rc
  features): `restrict`, `[no-]port-forwarding`, `[no-]agent-forwarding`,
  `[no-]x11-forwarding`, `[no-]user-rc`, `no-touch-required`,
  `permitopen=`, `permitlisten=`, `tunnel=`, `environment=` (saltsh never
  sets per-key variables). `pty`, `no-pty` and `restrict` control the
  terminal (see [How commands run](#how-commands-run)).
* Lines for other key types (`ssh-rsa`, ...) and comments are skipped.

**File checks** (like OpenSSH's `StrictModes`): an `authorized_keys` file
must be a regular file of at most 1 MiB, owned by root or its user and not
group/world-writable. In per-user mode every directory from the file up
to the user's home directory must pass the same ownership/mode check —
so a group-writable home (or `~/.saltsh`) disables key login for that
account until fixed. Symlinks to devices or FIFOs are refused. A refused
file is logged.

### Client

```console
$ saltsh example.com                    # default: $SHELL login shell
$ saltsh alice@example.com              # log in as a specific user
$ saltsh example.com echo a "b c" d     # exact argv, no shell re-splitting
$ saltsh example.com ls -la /tmp        # the command's options need no --
$ saltsh example.com sort < in > out    # no terminal: binary-clean, EOF passed on
$ saltsh example.com -t top             # a command that needs a terminal
$ saltsh -p 2323 -l alice -i ~/.saltsh/id_ed25519 example.com uname -a
```

Option parsing works like ssh's: options may come before the host and
directly after it, and the first word after the host that is not an
option starts the command — everything from there on (including words
like `-p` or `--`) is passed to the command unchanged. A `--` before the
command ends option parsing explicitly (`saltsh host -- -weird-cmd`).

The login name comes from `user@host`, then `-l/--user`, then `$USER`.
Options: `-t` (request a terminal for a command), `-T` (never request
one), `-p/--port` (23 — the abandoned telnet port), `-i/--identity`
(`~/.saltsh/id_ed25519`), `-P/--passphrase` (prompts if omitted),
`--accept-new`, `--protocol IDENT` (default `SALTSH/1`; must match the
server's). The first-contact host-key question is asked on the terminal
(`/dev/tty`), never read from stdin; without a terminal the connection is
refused — non-interactive use needs `--accept-new` or a pre-seeded
`known_hosts`. A host key is only pinned after the server has proven it
holds the private key. All path options must be **absolute**, with one exception:
`keygen -f` may be relative to the current directory. `~` is never
expanded — use `$HOME/...`.

The client never sends environment variables and cannot set any in the
remote session: the EXEC message carries only the command argv, the
terminal type (TERM, a dedicated field required for interactive programs),
and the window size. A server runs the session with its own environment —
locale (`LANG`/`LC_*`/`TZ`), `PATH`, `LD_*`, etc. are whatever the server
already has, and a modified client cannot influence them.

### Key generation

```console
$ saltsh keygen                  # writes ~/.saltsh/id_ed25519, prompts for a passphrase
$ saltsh keygen -N ''            # no passphrase
$ saltsh keygen -N 'hunter22'    # non-interactive passphrase
```

The default output path is the client's default identity, so `saltsh
keygen` followed by `saltsh <host>` just works. Keys are OpenSSH-format
(compatible with `ssh-keygen -y`), and you can keep using
`ssh-keygen -t ed25519` instead — both work interchangeably.

## Wire protocol (summary)

See §5 of the spec. Fixed cipher suite — there is no negotiation and
therefore no downgrade surface. The version identifier defaults to
`SALTSH/1` and is configurable with `--protocol` on both ends; the server
stays **silent** until a peer sends the correct `IDENT\n` line, so port
scanners get no banner. A custom identifier only reduces scan noise — it
is obscurity, not security (anyone can capture it). Packet framing after
KEX: `secretbox(nonce, u32_be(len) || plaintext)` with
`nonce = u64_be(seq) || 0^16`, one counter per direction. Message tags:
`0x01..0x05` auth, `0x10` exec (with a PTY-request flag), `0x11` exec ok
(says whether a PTY was allocated), `0x20` session data, `0x21` resize,
`0x22` exit status, `0x23` end of input, `0x30` signal. All integers
big-endian.

## Build

```console
$ make                    # build the static musl release binary
$ sudo make install       # /usr/local/sbin/saltsh
$ make test               # run the test suite
$ make clean
```

`make` is the greybeard front-end to cargo: `TARGET` picks the Rust target
(default `x86_64-unknown-linux-musl`; `make TARGET=` builds natively),
`PREFIX`/`SBINDIR` pick the install location, and `DESTDIR` supports
packaging. Equivalent cargo invocations:

```console
$ cargo build --release            # statically linked musl binary (see below)
$ cargo test                       # 57 unit + 52 end-to-end tests
```

`.cargo/config.toml` sets `x86_64-unknown-linux-musl` as the default target
(spec §8), producing a fully static single binary:

```console
$ rustup target add x86_64-unknown-linux-musl
$ cargo build --release
$ file target/x86_64-unknown-linux-musl/release/saltsh
... static-pie linked, stripped
```

The end-to-end tests can run against any artifact, e.g. the musl one:

```console
$ SALTSH_TEST_BIN=target/x86_64-unknown-linux-musl/release/saltsh cargo test --test integration
```

If `ssh-keygen` is installed, the interop test additionally proves that
real `ssh-keygen` output parses (plain and passphrase-protected keys) and
that keys written by saltsh are accepted by `ssh-keygen -y`.

## Dependency policy (spec §9)

Eleven direct crates, all pure Rust (RustCrypto / dalek families); the only
FFI surface is `libc` for PTY/process syscalls. No OpenSSL, no libsodium,
no tokio (thread-per-connection over `std::net`). `cargo tree` confirms no
C/C++ crates.

## Deviations from the draft spec

The spec is a design artifact; implementing it required four small,
deliberate adjustments, all documented in the code:

1. **Host public key in KEX.** The spec's §5.2 listing shows the server
   sending only `host_sig`, but TOFU (§6) requires the host's public key on
   first contact. The server sends `server_eph_pk || host_pk || host_sig`,
   exactly as SSH transmits the host key during key exchange.
2. **Manifest fixups.** `aes` 0.9 dropped its `ctr` feature, so AES-CTR
   comes from the `ctr` crate (0.10 pairs with `cipher` 0.5);
   `getrandom` needs its `sys_rng` feature for the `SysRng` OsRng shim;
   `ed25519-dalek` needs `rand_core` for `generate()`; `sha2` was added for
   the spec's SHA-256 fingerprints.
3. **Secretbox tag layout.** The `xsalsa20poly1305` crate emits
   `tag || ciphertext` (prefix tag), so the packet reader consumes a
   20-byte header (tag + encrypted length prefix) before the body. The
   plaintext framing is unchanged from §5.6.
4. **Rekey = disconnect.** Exceeding 2^32 packets or 2^40 bytes closes the
   connection rather than rekeying; v1 sessions cannot realistically reach
   either bound. A full rekey exchange is future work.
5. **PTY on request.** The spec's "interactive PTY only" became ssh's
   model: the client requests a PTY (EXEC carries a flag; by default only
   for interactive logins on a terminal, `-t`/`-T` override), the key may
   refuse it (`no-pty`, `restrict`, forced commands without `pty`), and
   the server answers with `EXEC_OK {pty}` (tag `0x11`). Sessions without
   a PTY run on pipes; the client signals end of input with `EOF` (tag
   `0x23`), an authenticated message rather than a TCP half-close (which
   an on-path attacker could forge to truncate a command's input).
   `PTY_DATA` (`0x20`) carries the session bytes either way. This changed
   the wire format: client and server must be the same version.

## Known limitations (v1)

* No algorithm negotiation by design — a primitive break means a protocol
  version bump.
* On a PTY the client's end of input is ignored (type `^D` in the remote
  terminal instead); sessions end when the remote process exits.
* A remote command that never reads its input eventually stalls the
  input direction (there is no flow-control window); signals sent from
  the client queue behind that input.
* Accounts that are locked or expired in `/etc/shadow` are not detected
  (no PAM); remove the account's `authorized_keys` or give it a `nologin`
  shell to lock it out of saltsh.
* For login shells that are not POSIX-compatible (fish, tcsh, ...) the
  per-user argv is passed as one quoted string, so exact-argv semantics
  are up to that shell.
* The client and server are Linux/Unix-only (PTY, termios) and IPv4-only.
