# saltsh — Security Audit

Scope: the complete saltsh codebase (`src/`). Two audit rounds:

* **Round 1** — cryptography and untrusted input handling (findings
  F-1 … F-7, table in §4.1).
* **Round 2 (2026-11-28)** — full review of the whole codebase, with focus
  on the OS integration of the root daemon (PTY/fd handling, privilege
  drop, process lifecycle, resource limits) and on re-verifying every
  claim of round 1. Findings A-1 … A-12 (§4.2). Several round-1 claims
  turned out to be inaccurate; they are corrected in place below and
  listed in §4.3.

Every finding that required a code change was fixed and covered by a
regression test (§6). The fixes were verified on both the glibc build and
the statically linked musl release artifact.

Audited against the threat model of SALTSH_SPEC.md §11.

---

## 1. Threat model

* **Remote attacker, unauthenticated**: can open TCP connections to the
  server, send arbitrary bytes, and attempt resource exhaustion
  (slowloris, connection floods). Cannot break the crypto.
* **Remote attacker, authenticated as user U**: has a session as U (or a
  `command=`-restricted key, or an account with a restricted login shell)
  and may try to escape the restriction, reach other users' sessions,
  keep privileges they should not have, confuse logging, or abuse the
  protocol parser.
* **Local user on the server**: controls their own home directory
  (including `~/.saltsh/authorized_keys`, which the root daemon reads).
* **Active network attacker**: can intercept/modify/drop traffic but
  cannot forge Ed25519 signatures; may attempt downgrade, replay, or
  key-reuse attacks.
* **Local attacker on the client machine**: can read/write files the
  client user owns, including the TOFU store and private keys.

Out of scope: kernel/PTY driver vulnerabilities, side-channel extraction
of keys already in memory, supply-chain compromise of the dependency tree.

---

## 2. Cryptography

### 2.1 Key exchange (X25519)

| Check | Result |
|---|---|
| Ephemeral keys from OS CSPRNG (`getrandom` → `SysRng`, `UnwrapErr`) | ✅ |
| Forward secrecy (fresh ephemeral pair per connection) | ✅ |
| Low-order peer point rejected (`was_contributory`) on both sides | ✅ (F-1) |
| Shared secret used only via HKDF; its byte copy is zeroized after key derivation | ✅ (A-12) |

### 2.2 Session ID and transcript

* `session_id = BLAKE2b-256(version || version || client_eph || server_eph || K)`
  — exactly per spec §5.2.
* **Known deviation (accepted):** the host public key is not hashed into
  the transcript (SSH includes `K_S`). Not exploitable here because the
  host signature is verified against the *pinned* key and covers the
  session ID. Recommended for a future protocol revision.

### 2.3 Signatures (Ed25519)

| Check | Result |
|---|---|
| Both host and user signatures are checked with `ed25519-dalek`'s `verify_strict`: canonical `S`, **and** small-order `R` and weak (small-order) public keys rejected | ✅ (A-12 — round 1 used `Verifier::verify`, which does *not* reject small-order `R`/weak keys, contrary to what this document claimed) |
| Host signature covers `"saltsh-host-key-v1" ‖ session_id` | ✅ |
| User signature covers `"saltsh-user-auth-v1" ‖ session_id ‖ username ‖ pubkey_blob ‖ nonce` (fresh 32-byte server nonce → replay-proof) | ✅ |
| Implicit key confirmation: a MITM splitting the key exchange gets different session IDs, so the user signature fails | ✅ |
| Signature blob must be exactly 64 bytes | ✅ |

### 2.4 Key derivation (HKDF)

* `PRK = HKDF-Extract(salt = session_id, ikm = K)`; directional keys
  `c2s`/`s2c` via HKDF-Expand (HMAC-BLAKE2b-256) with distinct labels.

### 2.5 Packet framing (XSalsa20-Poly1305 secretbox)

| Check | Result |
|---|---|
| Nonce = `u64_be(seq) ‖ 0^16`, one counter per direction and key, never reused | ✅ |
| MAC verified before any plaintext is used; mismatch drops the connection | ✅ |
| Length prefix recovered via keystream probe, capped at 1 MiB before allocation (an on-path attacker can only cause a ≤1 MiB read followed by a MAC failure) | ✅ |
| Rekey thresholds (2^32 packets / 2^40 bytes) enforced by disconnecting | ✅ (F-2) |

### 2.6 Keys and key material in memory

* OpenSSH key parsing is bounds-checked and length-capped at every read.
* Encrypted keys: `bcrypt-pbkdf` (16 rounds on write; 1..2^20 accepted on
  read) + AES-256-CTR; checkint and seed/public consistency verified.
* Private key files are written mode 0600; `keygen` refuses to overwrite;
  the client warns about group/other-readable identity files.
* **Zeroization (A-12, corrected):** `KeyPair` zeroizes its seed on drop;
  every heap buffer that holds private key material while loading or
  writing a key (file contents, PEM/base64 text, decoded blob, decrypted
  blob, the AES key/IV) is a `Zeroizing` buffer, pre-sized so growth does
  not leave stale copies; session keys and the X25519 shared-secret copy
  are scrubbed after use; `SigningKey`, `EphemeralSecret` and the
  secretbox ciphers zeroize themselves on drop. This is best effort: the
  compiler may still leave transient stack copies, and the `ctr` cipher
  state is not zeroized. (Round 1 claimed full zeroization of
  intermediate key/IV buffers; the decrypted private blob and the key/IV
  copies were in fact not scrubbed.)

### 2.7 Protocol state machine

* The server speaks second and stays silent until the correct `IDENT\n`;
  anything else is closed without a reply (obscurity only, documented).
* After KEX only AUTH messages are accepted, after AUTH_OK only EXEC
  (answered by EXEC_OK), during the session only PTY_DATA/RESIZE/SIGNAL/EOF
  from the client; anything else drops the connection.
* End of input is an authenticated `EOF` message, never inferred from a
  TCP half-close: a FIN is not authenticated, so an on-path attacker could
  otherwise truncate a command's input (e.g. a backup stream) undetected.
* **Uniform authentication replies (A-9):** every well-formed AUTH_REQ is
  answered with a challenge, and every failure (unknown user, key not
  authorized, restriction not met, bad signature) with the same AUTH_FAIL
  after the signature. Previously an unknown user got the connection
  closed, a known user AUTH_FAIL, and an authorized *public* key a
  challenge — an oracle for valid usernames and for which public keys are
  authorized.

### 2.8 TOFU host keys

* Store `host:port base64(pubkey)`; key change is a hard fail.
* **Pin only after proof (A-10):** the host signature is verified (against
  the presented key, which must equal any existing pin) *before* anything
  is written to `known_hosts`. Previously the key was pinned first, so a
  server with a garbage signature left a permanent pin behind.
* **Confirmation on the terminal (A-10):** the first-contact question is
  asked on `/dev/tty`, never read from stdin (stdin carries session input,
  e.g. `cat file | saltsh host -- cmd`, whose first line could have
  answered "yes"). Without a terminal the connection is refused;
  non-interactive use needs `--accept-new` or pre-seeding.
* Appends are serialized with `flock`.
* **Inherent limitation:** first-contact TOFU cannot defend against an
  active MITM on that very first connection.

---

## 3. Untrusted input and OS integration

### 3.1 Network: message decoding (`msg.rs`)

* Every field is read through a bounds-checked cursor; u32 lengths capped
  (`MAX_STR` 64 KiB), `argc ≤ 256`, `env count ≤ 64`, username ≤ 255.
* Strings must be valid UTF-8 and NUL-free.
* Unknown tags and trailing bytes are rejected — **including AUTH_REQ**,
  which round 1 claimed but did not check (A-12).

### 3.2 Network: packet layer and version line (`wire.rs`)

* Packet length capped at 1 MiB before allocation; EINTR-safe; EOF vs.
  truncation distinguished.
* The version line is read one byte at a time, capped at 256 bytes;
  logged bytes are sanitized and truncated.

### 3.3 Session isolation: PTY and file descriptors (A-1, critical)

**Finding:** sessions were started with `forkpty(3)`. Both musl and glibc
open the PTY master **without close-on-exec**, and the server is a single
multi-threaded process. Every session child therefore inherited the PTY
masters of all other sessions alive at that moment (and of finished
sessions, see A-6) across `exec`. Any authenticated user could read
another user's terminal output and inject keystrokes into another user's
shell — including root's. Confirmed on the shipped musl binary: a second
session held `/dev/pts/ptmx` belonging to the first.

**Fix:**

* The PTY is opened by saltsh itself: `/dev/ptmx` and the slave with
  `O_CLOEXEC` atomically (no window in which a concurrently forking
  thread could inherit them). Forced commands run on pipes instead of a
  PTY (§3.6.1); those are created `O_CLOEXEC` as well.
* The child performs `login_tty` itself (setsid, `TIOCSCTTY`, dup2 onto
  0/1/2 — for pipe sessions setsid and dup2 only) and then closes
  **every** descriptor ≥ 3 (`close_range`, with a loop fallback) before
  `exec` — so nothing from the server process (other PTYs or pipes,
  client sockets, the log file) can reach a session even if a future
  change forgets `O_CLOEXEC`.
* Regression tests: `sessions_do_not_inherit_descriptors`,
  `forced_command_holds_only_its_own_pipes`, `open_pty_is_close_on_exec`.

### 3.4 Session command and login shell (A-2, high)

**Finding:** in per-user mode the account's login shell was only used for
interactive sessions; a requested argv was `execvp`'d directly. Accounts
relying on their shell as the access boundary — `nologin`, `/bin/false`,
`git-shell`, `rbash`, `scponly`, ... — could run any program by naming it
(`saltsh svc@host -- /bin/sh`). OpenSSH always runs commands through the
login shell. Confirmed: a `/usr/sbin/nologin` account ran `/usr/bin/id`.

**Fix:** per-user sessions always run through the account's login shell
(empty passwd shell = `/bin/sh`):

* POSIX shells: `shell -c 'exec "$0" "$@"' argv...` — the shell is the
  gatekeeper, and the argv still arrives exactly as sent (no
  re-splitting; spec §2.6 preserved).
* Any other shell: `shell -c "<argv, each element single-quoted>"`
  (OpenSSH semantics), so restricted shells apply their own policy and
  `nologin`/`false` refuse.
* Applies to forced commands as well. Shared-file mode (server's own
  identity) is unchanged.
* Regression tests: `command_argv_*`, `real_posix_shell_execs_argv_unchanged`,
  `per_user_commands_run_through_login_shell_with_exact_argv`.

### 3.5 Privilege drop (A-5, medium)

**Finding:** the child called `initgroups()` without checking its
result. musl's `initgroups` uses a fixed 32-entry buffer and returns -1
*without calling `setgroups`* for users in more than 32 groups — the
session then kept the server's supplementary groups. Confirmed on the
shipped musl binary: a user in 41 groups got the server's `adm` and
`disk` groups (raw block-device access, i.e. root) instead of their own.

**Fix:**

* The full group list is computed in the parent with `getgrouplist`
  (dynamically sized); the child installs it with `setgroups` and exits on
  failure, then `setgid`, `setuid` (checked), and finally verifies that
  `setuid(0)`/`seteuid(0)` fail (sshd-style paranoia).
* `chdir(home)` failure falls back to `/`.
* The child now really makes only async-signal-safe calls between `fork`
  and `exec` (setsid, ioctl, dup2, close_range/close, signal,
  sigprocmask, setgroups, setgid, setuid, chdir) plus `execvpe` (stack-only
  PATH search in musl and glibc). The environment is passed as a
  pre-built `envp` — round 1 claimed async-signal safety while calling
  `setenv` and `initgroups` (both allocate) in the child (A-12).
* SIGPIPE is reset to its default and the signal mask cleared, so
  sessions do not inherit the daemon's `SIG_IGN` (A-12).

### 3.6 Session process lifecycle (A-6, medium)

**Findings:**

* The PTY master was never closed when a session ended normally — one
  leaked descriptor per session (and, together with A-1, inherited by
  every later session).
* On client hang-up the master was closed while the pump thread could
  still be reading it; the fd number could be reused by another
  connection's socket or PTY and then read by the stale pump — a
  cross-session confusion bug.
* On hang-up the child was never reaped (one zombie per connection), and
  a race between "child exited" and "PTY EOF" could report exit code 255
  and also skip reaping.
* After reaping, `kill(-pid, SIGHUP)` was sent to a pid that could
  already have been recycled (round-1 residual risk 5).

**Fix:**

* The pump thread is a scoped thread woken through a close-on-exec pipe;
  the master is an `OwnedFd` closed only after the pump was joined —
  use-after-close is impossible by construction.
* Child exit is detected with `waitid(..., WNOWAIT)`: the zombie keeps the
  pid and process group reserved while stragglers get their SIGHUP; only
  then is it reaped. The session ends when the child has exited **and**
  output is drained (or a 2 s straggler grace period expired).
* On hang-up or any connection error the session's process group gets
  SIGHUP and the child is handed to a single reaper thread (so a
  `nohup`ed session holds no connection thread).
* Regression tests: `server_closes_pty_masters_after_sessions`,
  `hangup_kills_and_reaps_the_session`.

### 3.6.1 PTY only on request (change after round 2)

Like ssh, a session gets a PTY only when the client requests one (by
default only for an interactive login on a terminal; `-t`/`-T` override)
**and** the key permits it: `no-pty`/`restrict` deny it, and forced
commands get one only with an explicit `pty` option. All other sessions
run on plain pipes: stdin from one pipe, stdout and stderr merged on
another, no controlling terminal, no `TERM`; the client's end of input
arrives as an authenticated `EOF` message and closes the command's
stdin. Rationale: commands and forced commands are mostly automation; a
terminal's line discipline corrupted their byte streams (`\n` → `\r\n`,
`^C`/`^D`/`^Z` interpreted, input echoed into the output), there was no
way to end their input, and restricted keys got a terminal they do not
need. Security-relevant properties are the same for both kinds:
the child is still its own session/process group (`setsid`), gets SIGHUP
on disconnect, has its pipes closed and is reaped; descriptor isolation
and privilege drop are identical. Without a terminal the kernel cannot
hang the session up on its own, so delivery of that SIGHUP relies on
`kill(2)`; even if it is ignored, the closed pipes give the command EOF
on input and EPIPE on output. Regression tests:
`forced_command_runs_without_a_pty_and_is_binary_clean`,
`forced_command_stdin_is_passed_through_unmodified`,
`forced_command_holds_only_its_own_pipes`,
`hangup_closes_a_forced_commands_pipes_and_reaps_it`,
`hangup_signals_a_forced_command`, `pty_only_when_requested`,
`key_options_decide_terminal_permission`,
`eof_reaches_commands_without_a_terminal`,
`login_without_a_terminal_reads_commands_from_stdin`,
`pty_permission_is_ordered`.

### 3.7 `authorized_keys` handling (A-4, A-8)

**A-4 (medium) — fail-open option parsing.** Option names were matched
case-sensitively and unknown options were skipped. OpenSSH matches
option names case-insensitively and refuses a line it cannot parse, so
an OpenSSH-valid `COMMAND="..."` or `From="..."` — or a misspelled
`frm=` — silently became an *unrestricted* key. Duplicates were merged
(widening `from=`), malformed CIDR blocks silently never matched (so a
broken `!negation` admitted the excluded host), and `expiry-time`,
`cert-authority` etc. were ignored.

**Fix:** a parser following OpenSSH's syntax that fails closed:
case-insensitive names; values must be double-quoted (`\"` the only
escape); a line with an unknown option, a duplicate `command`/`from`, a
malformed CIDR (or one with host bits set), an invalid `expiry-time`, or
an option saltsh cannot honor (`cert-authority`, `principals`,
`verify-required`) is refused as a whole and logged. `expiry-time` is
enforced. Options with nothing to enforce in saltsh (forwarding, agent,
X11, user-rc, `environment=`) are accepted explicitly; `pty`, `no-pty`
and `restrict` decide terminal permission (§3.6.1).

**A-8 (medium) — hostile key file paths.** The root daemon read the
per-user file with `read_to_string`: unbounded, following symlinks, and
blocking. A local user pointing `~/.saltsh/authorized_keys` at
`/dev/zero` made the daemon allocate until it was killed (every session
with it); a FIFO stalled the thread; there were no ownership checks
(round-1 residual risk 4).

**Fix:** the file is opened `O_NONBLOCK`, must be a regular file (checked
on the opened descriptor), ≤ 1 MiB, owned by root or the account and not
group/world-writable; in per-user mode every directory up to and
including the home directory must pass the same check (OpenSSH
`StrictModes`). The shared `--authorized-keys` file must be owned by root
or the server's user and not group/world-writable.

Regression tests: `option_names_are_case_insensitive`,
`unknown_or_unsupported_options_refuse_the_line`, `quoting_follows_openssh`,
`expiry_time_is_parsed`, `load_authorized_keys_policy`,
`uppercase_option_names_are_enforced`, `unknown_option_refuses_the_key`,
`hostile_authorized_keys_paths_are_refused_quickly`.

**By design, documented (finding A-3):** a forced command gets the
client's argv **appended** as extra arguments (OpenSSH replaces the
request instead). A forced command is only a restriction if the named
program is safe with arbitrary extra arguments; the README carries a
prominent warning with unsafe examples (`sh -c`, `env`, `find`, `tar`,
`cat`) and a safe wrapper pattern.

### 3.8 Session environment

* The client cannot set environment variables (the EXEC `env[]` field is
  ignored) — F-4.
* The session environment is built explicitly and passed as `envp`:
  `PATH` (the server's), `HOME`/`USER`/`LOGNAME`/`SHELL` from passwd,
  `TERM` (protocol field), `SSH_ORIGINAL_COMMAND` for forced commands.
  Nothing else — also not in `run_on` (tests), where the process
  environment is not cleared.
* The server sheds its own environment at startup (now via `vars_os`, so a
  non-UTF-8 variable can no longer abort startup).

### 3.9 Resource exhaustion / DoS (A-7, medium)

**Findings:** the "handshake timeout" was a per-read socket timeout that
restarted on every byte (a peer trickling one byte per 59 s held a thread
for hours, contrary to the round-1 claim of "at most ~60 s"); there was no
cap on concurrent connections; accept errors such as `EMFILE` were
retried in a tight loop that flooded the log; and a failed thread spawn
panicked — with `panic = "abort"`, killing the whole server.

**Fix:**

* One absolute deadline for the whole pre-session phase (version, KEX,
  auth, EXEC): `--login-grace-time`, default 120 s.
* `--max-startups` (default 64) concurrent unauthenticated connections and
  `--per-source-max-startups` (default 8) per client address; excess
  connections are closed immediately. Slots are released after
  authentication.
* Accept errors back off (100 ms) and are logged at most every 10 s with a
  count of suppressed messages; thread-spawn failures drop the connection
  and are logged the same way.
* Packet and field size caps bound per-connection memory; the per-user
  key file read is capped at 1 MiB.
* Regression tests: `login_grace_time_is_a_total_deadline`,
  `per_source_startup_limit_drops_excess_connections`,
  `startup_limiter_counts_and_releases`.

### 3.10 Logging

* Wire-controlled strings are sanitized before logging (F-5); key-file
  warnings contain line numbers and sanitized option names only, never
  file content.
* `--log-file` is created with mode 0640 (it names users, peers and full
  command lines).

---

## 4. Findings

### 4.1 Round 1

| # | Finding | Severity | Fix |
|---|---|---|---|
| F-1 | Non-contributory X25519 peer key accepted | High | `was_contributory()` on both sides |
| F-4 | Client-forwarded environment bypassed `command=` | Medium | `env[]` ignored entirely |
| F-7 | No handshake timeouts | Medium | Per-read timeout — **insufficient, see A-7** |
| F-2 | Rekey thresholds never enforced | Low | Disconnect at threshold |
| F-5 | Control characters in usernames forged log lines | Low | `log_safe()` |
| F-3 | Derived session keys lingered on the stack | Low | `zeroize()` |
| F-6 | IPv4-mapped IPv6 peers vs. `from=` | Low | IPv4-only |

### 4.2 Round 2 (2026-11-28)

| # | Finding | Severity | Fix | Section |
|---|---|---|---|---|
| A-1 | PTY masters inherited by every other session (read/inject into other users' terminals, incl. root's) | **Critical** | Own PTY open with `O_CLOEXEC`; child closes all fds ≥ 3 | §3.3 |
| A-2 | Login shell not enforced: `nologin`/restricted-shell accounts could run any program | High | Commands run through the login shell (argv-exact for POSIX shells) | §3.4 |
| A-3 | Forced command gets client argv appended | (by design) | Prominent documentation | §3.7, README |
| A-4 | Fail-open `authorized_keys` options (case, unknown, duplicates, bad CIDR, `expiry-time`) | Medium | Fail-closed OpenSSH-style parser | §3.7 |
| A-5 | Unchecked `initgroups`; musl keeps root's groups for users in > 32 groups | Medium (High on systems where root has e.g. `disk`) | `getgrouplist` + checked `setgroups` | §3.5 |
| A-6 | PTY master leak, use-after-close, unreaped children, pid-reuse on SIGHUP | Medium | Scoped pump, `WNOWAIT`, reaper | §3.6 |
| A-7 | Per-read "timeout", no connection cap, accept-error spin, spawn panic aborts server | Medium | Total deadline, MaxStartups, backoff | §3.9 |
| A-8 | Key file read unbounded/following devices/FIFOs as root; no StrictModes | Medium | Regular file, 1 MiB, owner/mode checks | §3.7 |
| A-9 | Auth replies revealed valid users and authorized public keys | Low | Uniform challenge + AUTH_FAIL | §2.7 |
| A-10 | TOFU pinned before signature check; prompt answered from stdin | Low | Verify first; ask on `/dev/tty` | §2.8 |
| A-11 | Pre-existing test assumed musl's `strerror` text | — (test) | libc-neutral assertion | — |
| A-12 | Inaccurate round-1 claims (strict verify, zeroization, AUTH_REQ trailing bytes, async-signal safety) and related hygiene (SIGPIPE inherited, shared-secret copy) | Low | Made the claims true where feasible, corrected the rest | §2.3, §2.6, §3.1, §3.5 |

### 4.3 Corrected round-1 statements

* "`Verifier::verify` performs strict verification (rejects small-order
  `R`)" — false; it only checks canonical `S`. Now `verify_strict`.
* "Intermediate key/IV buffers are zeroized on drop" — only partly true.
* "Unknown tags and trailing bytes are rejected" — not for AUTH_REQ.
* "The child only makes async-signal-safe calls between fork and exec" —
  it called `setenv` and `initgroups`.
* "Each attacker connection costs at most ~60 s of a thread" — the timeout
  was per read, not per connection.

## 5. Residual risks (accepted, documented)

1. **First-contact MITM** — inherent to TOFU; fingerprint shown for
   out-of-band verification; `--accept-new` opts out; `saltsh hostkey`
   pre-seeding avoids it.
2. **Host key not in the exchange transcript** — the pinned-key signature
   still authenticates the exchange; recommended for a protocol revision.
3. **Forced commands receive the client's argv** (A-3, by design) — only
   safe with wrappers that validate their arguments (README).
4. **Locked/expired accounts** (`/etc/shadow`) are not detected — no PAM;
   use `nologin` or remove the key file.
5. **No flow-control window** — a command that never reads its input
   eventually blocks the input direction (and signals queued behind it).
6. **Non-POSIX login shells** receive the argv as one quoted string
   (OpenSSH semantics), so exact-argv behavior depends on that shell.
7. **Timing** — the key-file lookup happens before the challenge is sent,
   so response latency may still differ slightly between existing and
   unknown users (the message flow no longer does).
8. **`flock` on the TOFU store** can be held by a local process to stall
   pinning (local-only DoS).
9. **Passphrase via `-P`** is visible in process listings.
10. **Terminal escape sequences** from a hostile server reach the client
    terminal (same as ssh).
11. **Lingering sessions** — a session that ignores SIGHUP (`nohup`) keeps
    running after its client disconnects, as with sshd; it is reaped when
    it exits.

## 6. Testing

* 57 unit tests + 52 integration tests (109 total), all passing on the
  glibc build and on the static musl build (`cargo test` with the default
  musl target). Round 2 added: descriptor isolation across sessions, PTY
  close-on-exec, PTY master release, hang-up reaping, login-shell argv
  exactness, total login deadline, per-source startup limit, uniform auth
  replies, case-insensitive and fail-closed option parsing, key-file
  policy (regular file, size, StrictModes, `/dev/zero`, FIFO), expiry
  times, TOFU pin-after-verify, AUTH_REQ trailing bytes.
* Fixes for A-1, A-2, A-4 and A-5 were additionally checked against the
  previously shipped musl binary (before) and the new one (after), with
  real unprivileged accounts in per-user mode.
* `cargo clippy` clean.
