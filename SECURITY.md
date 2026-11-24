# saltsh — Security Audit

Scope: the complete saltsh codebase (`src/`), commit state after the audit
fixes described below. Two areas were audited, as requested:

1. **Cryptography** — primitive selection and use, protocol construction,
   key management, and the handshake state machine.
2. **Untrusted input handling** — every byte path that an attacker can
   influence (network peer, remote user, local key files).

Audited against the threat model of SALTSH_SPEC.md §11. Where a finding
required a code change, the change was made, tested, and is listed in
[Fixed during audit](#fixed-during-audit).

---

## 1. Threat model

* **Remote attacker, unauthenticated**: can open TCP connections to the
  server, send arbitrary bytes, and attempt slowloris-style resource
  exhaustion. Cannot break the crypto.
* **Remote attacker, authenticated as user U**: has a shell as U (or a
  `command=`-restricted key) and may try to escape the restriction,
  confuse logging, or abuse the protocol parser.
* **Active network attacker**: can intercept/modify/drop traffic but
  cannot forge Ed25519 signatures; may attempt downgrade, replay, or
  key-reuse attacks.
* **Local attacker on the client machine**: can read/write files the
  client user owns, including the TOFU store and private keys.

Out of scope: kernel/PTY driver vulnerabilities, side-channel extraction
of keys already in memory, supply-chain compromise of the dependency tree.

---

## 2. Cryptography audit

### 2.1 Key exchange (X25519)

| Check | Result |
|---|---|
| Ephemeral keys from OS CSPRNG (`getrandom` → `SysRng`, `UnwrapErr`) | ✅ |
| Forward secrecy (fresh ephemeral pair per connection) | ✅ |
| Low-order peer point rejected (`was_contributory`) | ✅ **fixed** — was missing (F-1) |
| Shared secret used only via HKDF, never directly | ✅ |

**F-1 (fixed):** Neither side checked for a non-contributory peer public
key. An all-zero X25519 output (RFC 7748 §7) makes every derived session
key a known constant. Both client and server now abort the handshake on a
low-order peer point (covered by an integration test that sends the
low-order point over a raw socket).

### 2.2 Session ID and transcript

* `session_id = BLAKE2b-256(version || version || client_eph || server_eph || K)`
  — exactly per spec §5.2. The ephemeral public keys bind the exchange to
  the session ID; the shared secret enters through `K`.
* **Known deviation (accepted, documented in README):** the host public key
  is not hashed into the transcript (SSH includes `K_S`). This is not
  exploitable here because the host signature is verified against the
  *pinned* key and covers the session ID: a substitute key would fail
  signature verification, and a first-contact MITM is the inherent TOFU
  limitation (§2.9). Recommended for a future protocol revision.

### 2.3 Signatures (Ed25519)

| Check | Result |
|---|---|
| `ed25519-dalek` 3.0 `Verifier::verify` performs **strict** verification (canonical `S`, rejects small-order `R`) — verified against the crate source (`raw_verify` → `InternalSignature::try_from`) | ✅ |
| Host signature covers `"saltsh-host-key-v1" ‖ session_id` (domain-separated, binds the whole exchange) | ✅ |
| User signature covers `"saltsh-user-auth-v1" ‖ session_id ‖ username ‖ pubkey_blob ‖ nonce` — binds the session, the claimed identity, the offered key, and a fresh 32-byte server nonce (replay-proof) | ✅ |
| The user signature provides **implicit key confirmation**: a MITM that split the key exchange would derive a different `session_id` per direction, so the client's signature would not verify on the server — the attack is detected at auth time | ✅ |
| Signature blob length must be exactly 64 bytes | ✅ |

### 2.4 Key derivation (HKDF)

* `PRK = HKDF-Extract(salt = session_id, ikm = K)`; directional keys
  `c2s`/`s2c` via HKDF-Expand with distinct info labels — correct HKDF
  usage (RFC 5869) with HMAC-BLAKE2b-256. Separate keys and separate
  sequence counters per direction.

### 2.5 Packet framing (XSalsa20-Poly1305 secretbox)

| Check | Result |
|---|---|
| Nonce = `u64_be(seq) ‖ 0^16`, one counter per direction, starts at 0, never reused under one key | ✅ |
| Sequence overflow (`u64::MAX`) rejected before encryption | ✅ |
| MAC verified before any plaintext is released; any mismatch drops the connection | ✅ |
| Plaintext length is inside the secretbox; recovered via the keystream-probe trick (`peek_len`), bounded by `MAX_PACKET` (1 MiB) before allocation | ✅ |
| The `peek_len` probe runs the cipher under the same nonce as the incoming packet. It only generates keystream locally (no output crosses the wire) and never seals a second plaintext under that nonce — safe | ✅ |
| Rekey thresholds (2^32 packets / 2^40 bytes, spec §5.6) enforced by dropping the connection | ✅ **fixed** — the counters existed but were never consulted (F-2) |
| AEAD AAD unused; context binding lives in the transcript/signatures instead | ✅ |

### 2.6 Keys

* OpenSSH key parsing is bounds-checked and length-capped at every cursor
  read; oversized fields (> 1 MiB), wrong key types, and checkint
  mismatches are rejected (wrong passphrase vs. corrupt file are
  distinguished).
* Encrypted keys: `bcrypt-pbkdf` with the OpenSSH default 16 rounds for
  writes; reads accept rounds 1..2^20 and reject 0. AES-256-CTR unwrap
  uses the standard OpenSSH key‖IV layout with a full 128-bit counter.
* Seed consistency is verified after decryption (public half of the 64-byte
  private blob must match the declared public key, and the derived
  verifying key must match).
* Private key files are written mode 0600; `keygen` refuses to overwrite.
* The client warns when its identity file is group/other-readable
  (ssh-style) — **added** during the audit.
* `SigningKey`, session keys, and intermediate key/IV buffers are zeroized
  on drop (dalek/zeroize); stack copies of the derived session keys are now
  explicitly scrubbed — **fixed** (F-3).

### 2.7 Entropy

* All randomness (X25519 ephemerals, auth challenge nonces, bcrypt salts)
  comes from `getrandom` via `SysRng`. No `rand` crate, no userspace PRNG.

### 2.8 Protocol state machine

* Version exchange: the **server speaks second** and stays silent until the
  peer sends the correct `IDENT\n` line; anything else is closed without a
  reply. The identifier is configurable (`--protocol`, default `SALTSH/1`)
  on both ends and is byte-compared; it feeds the transcript/session ID.
  The custom identifier only reduces scanner noise — obscurity, not
  security (explicitly documented as such).
* After KEX, only AUTH messages are accepted; after AUTH_OK, only EXEC;
  during the session, only PTY_DATA/RESIZE/SIGNAL. Anything else is a
  protocol error and the connection is dropped (fail-closed at every stage).
* Single-shot auth (AUTH_FAIL closes), per spec §5.4.

### 2.9 TOFU host keys

* Store `host:port base64(pubkey)`; key change is a **hard fail**;
  first contact requires explicit user confirmation (`yes`) unless
  `--accept-new`.
* Fingerprints are OpenSSH-compatible `SHA256:` hashes (`ssh-keygen -lf`
  format).
* Append operations are serialized with `flock` (parallel clients cannot
  interleave lines).
* **Inherent limitation (documented):** first-contact TOFU cannot defend
  against an active MITM on that very first connection — the user is shown
  the fingerprint to compare out-of-band. `--accept-new` skips this check
  by design.
* A malicious *local* process could hold the `flock` to stall pinning
  (local-only DoS; noted as a hardening TODO).

---

## 3. Untrusted input handling audit

### 3.1 Network: message decoding (`msg.rs`)

Every field is read through a bounds-checked cursor; all of the following
are enforced and unit-tested:

* u32 length prefixes bounded (`MAX_STR` 64 KiB for strings);
* `argc ≤ 256`, `env count ≤ 64`, username ≤ 255;
* strings must be valid UTF-8 and NUL-free (so `CString` construction
  cannot fail);
* unknown tags and trailing bytes are rejected;
* no `panic!`/`unwrap`/`expect` reachable from malformed input (all
  `expect`s are on length-verified slices).

### 3.2 Network: packet layer (`wire.rs`)

* Length prefix decrypted via the keystream probe, capped at 1 MiB before
  the body buffer is allocated; truncated headers and bodies are handled;
  EINTR-safe reads; EOF distinguished from truncation.
* The pre-encryption version line is read one byte at a time, capped at
  256 bytes — a peer cannot make the server buffer arbitrary data.
* Anything logged from that untrusted line is sanitized
  (`wire::display_safe`: non-printables become `?`) and truncated to the
  configured identifier's length, so a hostile banner can neither forge
  log lines nor flood them. The client applies the same sanitization to
  its mismatch error message.

### 3.3 Server: EXEC handling

* argv is passed verbatim to `execvp` (the §2.6 argv guarantee) — the
  server never invokes a shell on the client's string.
* `TERM` is NUL-checked, capped, and applied via the dedicated protocol
  field; the client cannot override it with any other mechanism.
* `rows`/`cols` are clamped to 1..4096 / 1..16384 before the ioctl.
* `SIGNAL` is range-checked (1..64) and only delivered to the session's own
  child pid, and only before it has been reaped.
* **No client-controlled environment variables — hard guarantee:** the
  server ignores the EXEC `env[]` field entirely (`..` destructuring) and
  the saltsh client always sends it empty. This supersedes the earlier
  blocklist fix (F-4) with a structural guarantee: even a modified client
  cannot inject `PATH`, `LD_PRELOAD`, or anything else.
* **The server's own environment cannot leak either:** `run()` replaces the
  inherited environment with PATH-only at startup (covered end-to-end by
  `server_clears_env_and_sets_home`, which poisons the server env with
  tokens and verifies none reach the session). Each session environment is
  then built explicitly in the fork child: `HOME`/`USER`/`LOGNAME`/`SHELL`
  from the passwd entry of the logged-in user, plus `TERM` (terminal-type
  protocol field) and, for `command=` forced commands only,
  `SSH_ORIGINAL_COMMAND` (the requested argv).
* Username: length-capped, NUL-free, used only in `getpwnam` (no shell);
  log output is now sanitized of control characters — **fixed (F-5)** —
  preventing log-line forgery via embedded newlines/escapes.

### 3.4 Server: privilege drop (per-user mode)

* `setgid → initgroups → setuid → chdir(home)` in the forked child, in the
  correct order; any failure exits before exec (shared-file mode runs as
  the server's own identity and chdirs to its passwd home). All argv and
  environment CStrings and pointer arrays are pre-built before `forkpty`,
  and the child only makes async-signal-safe calls between fork and exec.
* `getpwnam` static storage is protected by a mutex; fields are copied out
  immediately (thread-per-connection server).
* The requested username is only ever matched against that user's own
  `~<user>/.saltsh/authorized_keys`; per-entry `from=` restrictions are
  checked against the peer's IPv4 address.

### 3.5 Server: `authorized_keys` parsing

* Local file, but still treated as hostile: bounds-checked, base64 errors
  handled, unknown options ignored, unparsable lines skipped.
* `from=` pattern lists: iterative glob (`*`/`?`), numeric IPv4 CIDR
  matching, OpenSSH `!`-negation semantics; an empty list denies
  (fail-closed); no recursion, no allocation driven by list length beyond
  the file size.
* Peer addresses are plain IPv4: both sides resolve and bind IPv4
  addresses only, and `from=` matching is IPv4-only with IPv6 patterns
  failing closed — making the earlier canonicalization fix (F-6)
  unnecessary.

### 3.6 Client

* All server-supplied bytes flow through the same bounded decoder; session
  output goes only to stdout (a hostile server can emit terminal escape
  sequences — inherent to remote shells, same as ssh).
* Exit codes are masked to a byte.
* Signal handlers only set atomics (async-signal-safe).
* Private key: permission warning (see §2.6); passphrase prompting uses
  /dev/tty with echo disabled and zeroizes the buffer; `-P` on the command
  line is visible in `ps` — documented trade-off.

### 3.7 Resource exhaustion / DoS

* **Handshake timeout — fixed (F-7):** the pre-session phase (version, KEX,
  auth, EXEC) now runs under a 60 s socket timeout on both sides, so an
  unauthenticated peer can no longer hold a server thread indefinitely
  (slowloris). Timeouts are removed before the session pump — an idle
  interactive shell is never killed.
* Packet and field size caps bound per-connection memory.
* **Residual:** the accept loop still spawns a thread per connection with
  no concurrency cap (ssh's `MaxStartups` equivalent). With the handshake
  timeout, each attacker connection costs at most ~60 s of a thread;
  recommend a connection-count limiter or prefork for exposed deployments.
* A client that floods PTY input faster than the remote program consumes
  it causes backpressure (blocked pump) rather than memory growth; no
  flow-control windowing exists (explicit spec non-goal).

---

## 4. Fixed during audit

| # | Finding | Severity | Fix |
|---|---|---|---|
| F-1 | Non-contributory X25519 peer key accepted → all-zero shared secret | High | `was_contributory()` check on both sides + integration test |
| F-4 | Client-forwarded `PATH`/`LD_PRELOAD`/etc. bypasses `command=` restrictions | Medium | Superseded: the server now ignores the `env[]` field entirely (structural guarantee, verified by `client_cannot_set_server_env`) |
| F-7 | No handshake timeouts → slowloris thread exhaustion | Medium | 60 s socket timeout during pre-session phase, cleared for the session |
| F-2 | Rekey thresholds computed but never enforced | Low | Connection dropped at 2^32 packets / 2^40 bytes |
| F-5 | Control characters in usernames forge log lines | Low | `log_safe()` on all logged wire strings |
| F-3 | Derived session keys linger on the stack | Low | Explicit `zeroize()` after box construction |
| F-6 | IPv4-mapped IPv6 peers could evade `from=` patterns | Low | Made moot: the whole tool is IPv4-only (v4-only bind/resolve; IPv6 patterns fail closed) |
| — | No warning for loose private-key permissions | Low | ssh-style mode warning |

## 5. Residual risks (accepted, documented)

1. **First-contact MITM** — inherent to TOFU; mitigated by fingerprint
   display for out-of-band verification; `--accept-new` opts out.
2. **Host key not in the exchange transcript** — deviation from SSH's
   construction; the pinned-key signature still authenticates the exchange.
   Recommended for a protocol revision.
3. **No connection-count cap** (MaxStartups equivalent) — see §3.7.
4. **No StrictModes-style ownership checks** on per-user
   `~user/.saltsh/authorized_keys` — in per-user mode the file authorizes
   exactly its owner; in shared mode the file is the administrator's.
5. **`kill(-pid, SIGHUP)`** after reaping has a tiny PID-reuse window;
   bounded blast radius (SIGHUP to an unrelated process group), standard
   daemon practice.
6. **No AES-GCM-style key confirmation packet** — implicit confirmation via
   the transcript-bound signatures is considered sufficient (see §2.3).
7. **`flock` on the TOFU store can be held by a local process** to stall
   pinning (local-only DoS).
8. **Passphrase via `-P`** is visible in process listings; the interactive
   prompt is the private path.
9. **Terminal escape sequences** from a hostile server reach the client
   terminal (same as ssh).

## 6. Testing

* 39 unit tests + 29 integration tests (68 total), including: tamper
  detection, framing round-trips, malformed-message rejection,
  client-cannot-set-env, log sanitization, low-order-point rejection (both
  directions), silent-until-valid handshake, custom protocol identifiers,
  file logging, TOFU pinning, forced commands, `from=` restrictions,
  privilege drop, daemonization, and full client↔server sessions.
* `cargo clippy --all-targets` clean; `SALTSH_TEST_BIN` runs the suite
  against the statically linked musl release artifact.
