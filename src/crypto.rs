//! NaCl cryptographic core (spec §4, §5.2, §5.3, §5.6).
//!
//! * session id / transcript hash: BLAKE2b-256
//! * key derivation: HKDF (HMAC-BLAKE2b-256)
//! * packet framing: XSalsa20-Poly1305 secretbox over
//!   `u32_be(plaintext_len) || plaintext`, nonce = `u64_be(seq) || 0^16`.
//!
//! One sequence counter per direction, starting at 0, never reused with a
//! key. AEAD guarantees tamper detection; any MAC failure drops the
//! connection.

use blake2::digest::Digest;
use blake2::Blake2b256;
use hkdf::SimpleHkdf;
use xsalsa20poly1305::aead::{Aead, KeyInit, Payload};
use xsalsa20poly1305::{Nonce, XSalsa20Poly1305};

use crate::error::{Error, Result};

/// Wire protocol version line (spec §5.1).
pub const VERSION_LINE: &[u8] = b"SALTSH/1\n";

/// Domain separator for host-key signatures (spec §5.2).
pub const HOST_SIG_CONTEXT: &[u8] = b"saltsh-host-key-v1";
/// Domain separator for user-auth signatures (spec §5.4).
pub const USER_SIG_CONTEXT: &[u8] = b"saltsh-user-auth-v1";

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16; // Poly1305
/// Maximum plaintext size of a single packet.
pub const MAX_PACKET: usize = 1 << 20; // 1 MiB
/// Rekey thresholds (spec §5.6); exceeding one closes the connection
/// (rekeying is not implemented in v1 — see README).
pub const REKEY_PACKETS: u64 = 1 << 32;
pub const REKEY_BYTES: u64 = 1 << 40;

/// BLAKE2b-256 over the concatenation of `parts`.
pub fn blake2b256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    Digest::finalize(h).into()
}

/// session_id = BLAKE2b-256(client_version || server_version ||
///                         client_eph_pk || server_eph_pk || K)   (spec §5.2)
pub fn session_id(
    client_version: &[u8],
    server_version: &[u8],
    client_eph_pk: &[u8; 32],
    server_eph_pk: &[u8; 32],
    shared_secret: &[u8; 32],
) -> [u8; 32] {
    blake2b256(&[
        client_version,
        server_version,
        client_eph_pk,
        server_eph_pk,
        shared_secret,
    ])
}

/// HKDF-Extract(salt = session_id, ikm = K), then HKDF-Expand for the two
/// directional keys (spec §5.3).
pub fn derive_keys(session_id: &[u8; 32], shared_secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = SimpleHkdf::<Blake2b256>::new(Some(session_id), shared_secret);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"c2s", &mut c2s)
        .map_err(|e| Error::Crypto(format!("hkdf expand (c2s) failed: {e}")))?;
    hk.expand(b"s2c", &mut s2c)
        .map_err(|e| Error::Crypto(format!("hkdf expand (s2c) failed: {e}")))?;
    Ok((c2s, s2c))
}

fn make_nonce(seq: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&n)
}

/// Encrypting side of a directional packet stream.
pub struct SealBox {
    cipher: XSalsa20Poly1305,
    seq: u64,
    bytes: u64,
}

impl SealBox {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        SealBox {
            cipher: XSalsa20Poly1305::new_from_slice(key).expect("32-byte key"),
            seq: 0,
            bytes: 0,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// True once either rekey threshold is exceeded.
    pub fn needs_rekey(&self) -> bool {
        self.seq >= REKEY_PACKETS || self.bytes >= REKEY_BYTES
    }

    /// Encrypt one packet: secretbox(nonce, u32_be(len) || plaintext).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.seq == u64::MAX {
            return Err(Error::Crypto("sequence number exhausted".into()));
        }
        if plaintext.len() > MAX_PACKET {
            return Err(Error::Crypto("packet exceeds maximum size".into()));
        }
        let mut pkt = Vec::with_capacity(4 + plaintext.len() + TAG_LEN);
        pkt.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        pkt.extend_from_slice(plaintext);
        let nonce = make_nonce(self.seq);
        let ct = self
            .cipher
            .encrypt(&nonce, Payload { msg: &pkt, aad: b"" })
            .map_err(|_| Error::Crypto("secretbox seal failed".into()))?;
        self.seq += 1;
        self.bytes = self.bytes.saturating_add(plaintext.len() as u64);
        Ok(ct)
    }
}

/// Decrypting side of a directional packet stream.
pub struct OpenBox {
    cipher: XSalsa20Poly1305,
    seq: u64,
    bytes: u64,
}

impl OpenBox {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        OpenBox {
            cipher: XSalsa20Poly1305::new_from_slice(key).expect("32-byte key"),
            seq: 0,
            bytes: 0,
        }
    }

    pub fn needs_rekey(&self) -> bool {
        self.seq >= REKEY_PACKETS || self.bytes >= REKEY_BYTES
    }

    /// Recover the plaintext length from the 4 encrypted length-prefix bytes
    /// (`ct_len` = the ciphertext of the u32 length, i.e. wire bytes 16..20
    /// of the packet), without consuming the sequence number. The length
    /// prefix sits inside the secretbox, so we exploit that the keystream
    /// for the prefix equals the ciphertext of four zero bytes. Note the
    /// crate's output layout is `tag(16) || ciphertext`, hence the `TAG_LEN`
    /// offset.
    pub fn peek_len(&self, ct_len: &[u8; 4]) -> Result<u32> {
        let nonce = make_nonce(self.seq);
        let probe = self
            .cipher
            .encrypt(&nonce, Payload { msg: &[0u8; 4], aad: b"" })
            .map_err(|_| Error::Crypto("secretbox keystream failed".into()))?;
        let mut b = [0u8; 4];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = ct_len[i] ^ probe[TAG_LEN + i];
        }
        let len = u32::from_be_bytes(b) as usize;
        if len > MAX_PACKET {
            return Err(Error::proto("packet exceeds maximum size"));
        }
        Ok(len as u32)
    }

    /// Verify and decrypt a full packet (ciphertext including 16-byte tag).
    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        if ct.len() < 4 + TAG_LEN {
            return Err(Error::proto("packet too short"));
        }
        if self.seq == u64::MAX {
            return Err(Error::Crypto("sequence number exhausted".into()));
        }
        let nonce = make_nonce(self.seq);
        let pt = self
            .cipher
            .decrypt(&nonce, Payload { msg: ct, aad: b"" })
            .map_err(|_| Error::proto("secretbox authentication failed (possible tampering)"))?;
        if pt.len() < 4 {
            return Err(Error::proto("packet too short after decryption"));
        }
        let len = u32::from_be_bytes(pt[0..4].try_into().expect("4 bytes")) as usize;
        if len > MAX_PACKET {
            return Err(Error::proto("packet exceeds maximum size"));
        }
        if len != pt.len() - 4 {
            return Err(Error::proto("framing length mismatch"));
        }
        self.seq += 1;
        self.bytes = self.bytes.saturating_add(len as u64);
        Ok(pt[4..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng;

    #[test]
    fn seal_open_roundtrip() {
        let key = rng::random_bytes::<32>();
        let mut sb = SealBox::new(&key);
        let mut ob = OpenBox::new(&key);
        for (i, msg) in [&b""[..], b"hello", b"x".repeat(70000).as_slice()].iter().enumerate() {
            let ct = sb.seal(msg).unwrap();
            assert_eq!(ct.len(), msg.len() + 4 + TAG_LEN);
            let pt = ob.open(&ct).unwrap();
            assert_eq!(pt, *msg);
            assert_eq!(sb.seq(), (i + 1) as u64);
        }
    }

    #[test]
    fn tampering_is_detected() {
        let key = rng::random_bytes::<32>();
        let mut sb = SealBox::new(&key);
        let mut ob = OpenBox::new(&key);
        let mut ct = sb.seal(b"attack at dawn").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(ob.open(&ct).is_err());
    }

    #[test]
    fn peek_len_matches_sealed_len() {
        let key = rng::random_bytes::<32>();
        let mut sb = SealBox::new(&key);
        let ob = OpenBox::new(&key);
        let msg = [0xABu8; 12345];
        let ct = sb.seal(&msg).unwrap();
        let head: [u8; 4] = ct[TAG_LEN..TAG_LEN + 4].try_into().unwrap();
        assert_eq!(ob.peek_len(&head).unwrap(), 12345);
    }

    #[test]
    fn rekey_thresholds() {
        let key = [0u8; 32];
        let sb = SealBox::new(&key);
        assert!(!sb.needs_rekey());
    }

    #[test]
    fn derive_keys_deterministic_and_directional() {
        let sid = [1u8; 32];
        let k = [2u8; 32];
        let (a1, b1) = derive_keys(&sid, &k).unwrap();
        let (a2, b2) = derive_keys(&sid, &k).unwrap();
        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
        assert_ne!(a1, b1);
    }

    #[test]
    fn session_id_changes_with_inputs() {
        let v = VERSION_LINE;
        let z = [0u8; 32];
        let s1 = session_id(v, v, &z, &z, &z);
        let s2 = session_id(v, v, &z, &z, &[1u8; 32]);
        assert_ne!(s1, s2);
    }
}
