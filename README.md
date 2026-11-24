# saltsh

A minimal SSH-like remote shell built on NaCl primitives, written in Rust.
Design document: [`SALTSH_SPEC.md`](SALTSH_SPEC.md).
Security audit: [`SECURITY.md`](SECURITY.md).

One binary, two roles:

```
saltsh [options] [user@]host [--] [argv...]  # client (ssh role)
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
  Per-entry `from="..."` source-address restrictions and `command="..."`
  forced commands are honored. No passwords, no keyboard-interactive.
* **Session** — exactly one PTY per connection. The command argv is
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
# session drops privileges to <user> (setgid + initgroups + setuid + chdir
# home) before exec
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

Logging goes to stderr by default; with `--log-file PATH` all server
logging (host-key generation, startup, connections, auth, errors) is
appended to that file instead — including when daemonized, so a log file
is the recommended companion to `--daemonize`. With `--log-timestamps`,
every line is prefixed with a local-time `[YYYY-MM-DD HH:MM:SS]` stamp
(syslog style).

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

Two OpenSSH options are honored per entry:

```
# only allow this key from specific addresses (wildcards, CIDR, !negation)
from="10.0.0.0/8,192.168.1.7,!10.0.0.66" ssh-ed25519 AAAA... alice@work

# forced command: overrides whatever the client asks for
command="/opt/backup/run" ssh-ed25519 AAAA... backup-bot
```

* `from="..."` — comma-separated pattern list matched against the peer's
  IPv4 address (OpenSSH `match_pattern_list` semantics: a matching
  `!`-negated pattern rejects; otherwise any positive match allows). IPv4
  CIDR blocks match numerically; `*`/`?` wildcards are supported. Multiple
  `from=` options are concatenated. saltsh is **IPv4-only**: both the
  client and server resolve and bind IPv4 addresses, and IPv6 patterns
  never match (fail-closed).
* `command="..."` — forced command. The command string is split on
  whitespace and the client's requested argv is appended **as-is**, each
  element preserved as a single argument (no shell joining or
  re-splitting):
  `command="/bin/echo forced"` + client `-- a "b c"` executes
  `["echo", "forced", "a", "b c"]`. The original request is available to
  the forced command via `SSH_ORIGINAL_COMMAND`. Note this differs from
  OpenSSH, which runs the forced command through the user's shell; saltsh
  passes arguments directly to `execvp`.

### Client

```console
$ saltsh example.com                    # default: $SHELL login shell
$ saltsh alice@example.com              # log in as a specific user
$ saltsh example.com -- echo a "b c" d  # exact argv, no shell re-splitting
$ saltsh -p 2323 -l alice -i ~/.saltsh/id_ed25519 example.com -- uname -a
```

The login name comes from `user@host`, then `-l/--user`, then `$USER`.
Options: `-p/--port` (23 — the abandoned telnet port), `-i/--identity`
(`~/.saltsh/id_ed25519`), `-P/--passphrase` (prompts if omitted),
`--accept-new`, `--protocol IDENT` (default `SALTSH/1`; must match the
server's). All path options must be **absolute**, with one exception:
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
`0x01..0x05` auth, `0x10` exec, `0x20` pty data, `0x21` resize,
`0x22` exit status, `0x30` signal. All integers big-endian.

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
$ cargo test                       # 39 unit + 28 end-to-end tests
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

## Known limitations (v1)

* No algorithm negotiation by design — a primitive break means a protocol
  version bump.
* No EOF message in the session layer (like SSH): closing local stdin does
  not terminate the remote program; sessions end when the remote process
  exits.
* Per-user `authorized_keys` files are not ownership-checked (`StrictModes`
  equivalent is future hardening).
* The client and server are Linux/Unix-only (PTY, termios) and IPv4-only.
