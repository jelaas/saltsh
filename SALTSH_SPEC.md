# saltsh — Feasibility Analysis & Specification

Status: draft design artifact (for later reference)
Date: 2026-11
Tool: a minimal SSH-like remote shell built on NaCl primitives, written in Rust.

---

## 1. Executive summary / verdict

**Feasible, low risk.** The project reduces to a *single encrypted PTY connection*
with Ed25519 key auth and correct argv passing. The cryptographic primitives map
1:1 onto mature pure-Rust crates, and the scope decisions below remove the hardest
parts of SSH (negotiation, multiplexing, file transfer, password auth).

Estimated effort: **~2–4 weeks** to a working tool for an experienced systems
programmer, plus ongoing fuzzing/hardening.

---

## 2. Requirements (final, as decided)

1. Transport over NaCl primitives: X25519 key exchange, XSalsa20-Poly1305 AEAD,
   Ed25519 signatures.
2. **Key auth only** — no password, no keyboard-interactive.
3. **No SSH wire compatibility** — clean-room, versioned, purpose-built protocol.
4. **Interactive PTY only** — no SFTP, no SCP, no port forwarding.
5. **Static link against musl** — single portable Linux binary.
6. **Correct argv passing** — arguments are transmitted as a structured array and
   `execvp`'d exactly; `saltsh <host> -- a "b c" d` yields 3 argv elements, not 4.
7. Host-key trust via **TOFU pinning**.
8. Keys reuse **OpenSSH format** (interop with `ssh-keygen`). password protection of client keys supported.
9. **As few dependencies as possible**, and only ones written in Rust.

### Explicit non-goals
- No algorithm negotiation / crypto agility (fixed primitives only).
- No multiplexed channels or flow control (one connection = one PTY).
- No user/password database, PAM, or rate limiting (key auth only).
- No Windows PTY support (Unix first; `conpty` is a separate effort).
- No agent forwarding, no known-hosts hashing of hostnames.

---

## 3. Architecture

Three phases, all over a single TCP connection (default port 2222,
thread-per-connection via `std::net`):

```
1. HANDSHAKE + KEX      X25519 eph keys, Ed25519 host-key signature
2. AUTH                 Ed25519 challenge/response over the encrypted channel
3. SESSION              exec argv -> PTY byte pump, bidirectional
```

Layers (from the SSH mental model, minus everything we dropped):

| Layer | Status |
|---|---|
| Transport (KEX + AEAD framing) | kept, simplified |
| User authentication | key-only, single challenge/response |
| Connection / channels | **removed** (single channel) |
| Session (PTY + exec) | kept |
| SFTP / port-forward / subsystem | **removed** |

---

## 4. Cryptographic design

NaCl primitives and their Rust crates:

| Purpose | NaCl primitive | Crate |
|---|---|---|
| Key exchange | X25519 (eph) | `x25519-dalek` |
| Signatures | Ed25519 (`crypto_sign`) | `ed25519-dalek` |
| Bulk AEAD | XSalsa20-Poly1305 (`crypto_secretbox`) | `xsalsa20poly1305` |
| KDF | HKDF | `hkdf` |
| Transcript/session-id hash | BLAKE2b-256 | `blake2` |
| Entropy | OS CSPRNG | `getrandom` + `rand_core` shim |

The "no negotiation" property is a security win: a single fixed algorithm set
removes the entire downgrade-attack surface that plagues SSH.

---

## 5. Wire protocol specification

### 5.1 Version exchange
Both sides send `SALTSH/1\n`; mismatch aborts.

### 5.2 Key exchange
```
client -> server:  client_eph_pk   (32 bytes X25519)
server -> client:  server_eph_pk   (32 bytes X25519)
server -> client:  host_sig        (Ed25519 signature)
```
- `K = X25519(eph)`.
- `transcript = client_version || server_version || client_eph_pk || server_eph_pk`.
- `session_id = BLAKE2b-256(transcript || K)`.
- Host signature covers `"saltsh-host-key-v1" || session_id`; client verifies
  against the pinned host key (TOFU, see §6).

### 5.3 Session-key derivation (HKDF)
```
PRK  = HKDF-Extract(salt = session_id, ikm = K)
c2s  = HKDF-Expand(PRK, "c2s", 32)     # client->server key
s2c  = HKDF-Expand(PRK, "s2c", 32)     # server->client key
```
Separate keys and separate nonce counters per direction.

### 5.4 Authentication (key-only)
```
client -> server:  username || pubkey_blob
server -> client:  32-byte nonce
client -> server:  Ed25519 signature over
                   "saltsh-user-auth-v1" || session_id || username || pubkey_blob || nonce
server -> client:  AUTH_OK  |  AUTH_FAIL
```
Server verifies against `authorized_keys` (OpenSSH format).

### 5.5 Exec (argv correctness)
```
client -> server:  [ u32 argc || (u32 len || bytes) * argc ] || TERM || rows || cols || env[]
```
The server reconstructs the exact `char **` and calls `execvp` directly — **no
shell re-splitting**. This is the fix for the OpenSSH argv bug.

### 5.6 Stream framing (everything after KEX)
```
packet = secretbox(nonce, u32_be(plaintext_len) || plaintext)
nonce  = u64_be(sequence_number) || 16 zero bytes    # 24-byte nonce
```
- One sequence counter per direction, starts at 0, never reused with a key.
- `secretbox` is AEAD (XSalsa20-Poly1305) -> tampering is detected; drop connection.
- **Rekey** after 2^32 packets or 2^40 bytes, whichever first.

### 5.7 Message types (1-byte tag + payload)

| Tag | Name | Dir | Payload |
|---|---|---|---|
| 0x01 | AUTH_REQ | c->s | username, pubkey |
| 0x02 | AUTH_CHALLENGE | s->c | 32-byte nonce |
| 0x03 | AUTH_SIG | c->s | Ed25519 signature |
| 0x04 / 0x05 | AUTH_OK / AUTH_FAIL | s->c | — |
| 0x10 | EXEC | c->s | argv[], TERM, rows, cols, env[] |
| 0x20 | PTY_DATA | both | raw bytes |
| 0x21 | RESIZE | c->s | rows, cols |
| 0x22 | EXIT_STATUS | s->c | u32 exit code |
| 0x30 | SIGNAL | c->s | signal number (Ctrl-C / Ctrl-Z) |

All integers big-endian; all strings `u32` length-prefixed.

---

## 6. Host-key trust (TOFU pinning)

- Store: `~/.config/saltsh/known_hosts`, lines `host:port base64(Ed25519 pubkey)`.
- First connect: print SHA-256 fingerprint, prompt accept (skip via `--accept-new`).
- Mismatch: **hard fail** (MITM protection), matching OpenSSH semantics.

---

## 7. Key format (OpenSSH)

- **Public key** — `ssh-ed25519 AAAA... comment` = base64 of
  `(string "ssh-ed25519" || string 32-byte pubkey)`.
- **Private key** — `-----BEGIN OPENSSH PRIVATE KEY-----`:
  - `cipher=none, kdf=none` -> extract 64-byte Ed25519 seed (needs `base64` only).
  - `kdf=bcrypt, cipher=aes256-ctr` (default `ssh-keygen` output) -> `bcrypt-pbkdf`
    + `aes`(ctr) + `cipher` to unwrap.

Both are pure-Rust crates; the latter adds ~3 deps (already in the manifest).

---

## 8. Static musl build

- Target: `x86_64-unknown-linux-musl` -> fully static single binary.
- Add target: `rustup target add x86_64-unknown-linux-musl`.
- Build: `cargo build --release --target x86_64-unknown-linux-musl`.
- Optionally set default via `.cargo/config.toml`:
  ```toml
  [build]
  target = "x86_64-unknown-linux-musl"
  ```
- Crypto stack is pure Rust / `no_std`-friendly -> no musl issues.
- `getrandom` on musl uses the raw `getrandom` syscall (no glibc dependency).
- Caveat: musl *is* a C library (the OS libc), so "only Rust-written dependencies"
  means *no third-party C libraries* (no OpenSSL/libsodium). `libc` is the sole
  FFI surface for PTY/process syscalls, which is unavoidable on Unix.

---

## 9. Dependency manifest

11 direct crates, all pure Rust (see `Cargo.toml` for pinned versions):

| Crate | Role |
|---|---|
| `x25519-dalek` | key exchange |
| `ed25519-dalek` | signatures |
| `xsalsa20poly1305` | AEAD (secretbox) |
| `hkdf` | key derivation |
| `blake2` | transcript / session id |
| `bcrypt-pbkdf` | OpenSSH key KDF |
| `aes` + `cipher` | OpenSSH key unwrap (aes256-ctr) |
| `getrandom` + `rand_core` | entropy + traits |
| `zeroize` | key hygiene |
| `base64` | key encoding |
| `libc` | PTY/process (only FFI) |

Transitive deps are all RustCrypto/dalek family. No C, no OpenSSL, no libsodium.
Networking uses `std::net` (thread-per-connection); no tokio/async.

---

## 10. Effort estimate

| Component | Effort |
|---|---|
| Transport + X25519 KEX + secretbox framing | 1–1.5 wks |
| Ed25519 auth + host-key store (TOFU) | 0.5–1 wk |
| PTY server (openpty, raw mode, resize, exit status) | 1 wk |
| argv serialization + execvp | days |
| Client (raw-mode TTY, signal forwarding) | 1 wk |
| OpenSSH key parsing (pub + encrypted priv) | 0.5 wk |
| musl static build + CI | days |
| Fuzzing + hardening | ongoing |

---

## 11. Risks & mitigations

1. **Protocol design is the real risk, not crypto.** NaCl primitives are safe;
   the danger is in combination (nonce reuse, sequence-number overflow, missing
   transcript hashing). Mitigation: fixed primitives, monotonic per-direction
   counters, rekey, transcript-bound signatures.
2. **No crypto agility.** A future primitive break requires a protocol version
   bump. Mitigation: versioned wire protocol.
3. **Key parsing correctness** (OpenSSH binary format). Mitigation: unit tests
   against real `ssh-keygen` output; fuzz the parser.
4. **PTY/platform specifics** (`/dev/ptmx`, ioctls, SIGWINCH). Mitigation:
   Linux-first, isolate in a small module behind `libc`.
5. **Side channels / constant-time.** dalek crates are constant-time; review
   our own key comparisons and length handling.

---

## 12. Open questions / next steps

1. Exact dependency version resolution — run `cargo build` + `cargo tree`;
   confirm `rand_core`/`getrandom` majors match the dalek crates' expectations.
2. Whether to ship passphrase-protected key support in v1 (deps already included)
   or defer for a smaller first cut.
3. Default port and config-file layout (`~/.config/saltsh/`).
4. Signal-forwarding semantics (which signals to map, e.g. SIGINT/SIGTSTP/SIGWINCH).

Next artifacts (on request): Rust type/signature definitions for the KEX/AUTH
state machine, or the `OsRng` shim + module skeleton.
