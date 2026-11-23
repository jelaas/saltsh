//! CSPRNG shim over `getrandom` (spec §4).
//!
//! `getrandom::SysRng` implements rand_core 0.10's `TryRng` over the OS
//! entropy source; wrapping it in `rand_core::UnwrapErr` upgrades it to the
//! infallible `Rng + CryptoRng` that the dalek crates expect — without
//! pulling in the full `rand` crate. On musl, `getrandom` issues the raw
//! `getrandom(2)` syscall, so no glibc dependency is introduced.

use getrandom::SysRng;
use rand_core::UnwrapErr;

/// Infallible CSPRNG backed by the OS entropy source.
pub type OsRng = UnwrapErr<SysRng>;

pub fn os_rng() -> OsRng {
    UnwrapErr(SysRng)
}

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub fn fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS entropy source failed");
}

/// Return `N` cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::Rng;

    #[test]
    fn os_rng_produces_bytes() {
        let a = random_bytes::<32>();
        let b = random_bytes::<32>();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn os_rng_implements_rng_traits() {
        let mut rng = os_rng();
        let _x: u32 = Rng::next_u32(&mut rng);
        let _y: u64 = Rng::next_u64(&mut rng);
        let mut buf = [0u8; 17];
        Rng::fill_bytes(&mut rng, &mut buf);
    }
}
