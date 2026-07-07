//! The single source of randomness for this crate. Every nonce, salt, DEK, and identity
//! seed is filled from the operating system CSPRNG via `OsRng`. Routing all
//! randomness through one helper makes it auditable that nothing here ever uses a
//! predictable or caller-supplied source.

use rand_core::{OsRng, RngCore};

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
///
/// `OsRng` reads directly from the operating system entropy source and is infallible in
/// practice on supported platforms (it panics only if the OS RNG itself is unavailable,
/// which is an unrecoverable environment failure, not a condition callers can handle).
pub(crate) fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// Convenience for the common fixed-size case.
pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill_random(&mut out);
    out
}
