//! saltsh — a minimal SSH-like remote shell built on NaCl primitives.
//!
//! See `SALTSH_SPEC.md` for the design. This crate implements:
//!
//! * transport: X25519 key exchange + XSalsa20-Poly1305 secretbox framing,
//!   with transcript-bound Ed25519 host signatures and per-direction
//!   sequence numbers (§5),
//! * authentication: single Ed25519 challenge/response, key-only (§5.4),
//! * session: a single PTY carrying an `execvp`'d argv, with resize and
//!   signal forwarding (§5.5, §5.7),
//! * host-key trust: TOFU pinning in `~/.config/saltsh/known_hosts` (§6),
//! * OpenSSH key interop: public keys, `authorized_keys`, and private keys
//!   with `cipher=none` or `bcrypt`+`aes256-ctr` (§7).

pub mod cli;
pub mod client;
pub mod crypto;
pub mod error;
pub mod msg;
pub mod pty;
pub mod rng;
pub mod server;
pub mod sshkeys;
pub mod tofu;
pub mod util;
pub mod wire;

pub use error::{Error, Result};
