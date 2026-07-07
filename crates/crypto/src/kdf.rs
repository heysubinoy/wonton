//! Argon2id passphrase key derivation: turn a human passphrase into a
//! 32-byte symmetric "unlock key" that encrypts the user's private-key seed. The KDF
//! parameters (salt, memory, iterations, parallelism) are returned/stored alongside the
//! ciphertext so any machine can re-derive the same key from the same passphrase.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::KEY_LEN;
use crate::rng::random_array;
use crate::CryptoError;

/// Argon2id salt length in bytes (128 bits — the size Argon2 recommends and the minimum the
/// RFC allows for general use).
pub const SALT_LEN: usize = 16;

/// Default memory cost in KiB. **19456 KiB = 19 MiB.**
///
/// This is OWASP's current (2024) recommended Argon2id configuration
/// (m = 19 MiB, t = 2, p = 1), chosen as our documented minimum. It
/// resists GPU/ASIC attacks far better than PBKDF2 while remaining fast enough (<1s) to
/// derive interactively on commodity hardware. Because the parameters are stored per wrapped
/// key, they can be raised later without breaking old keys — each key re-derives with the
/// parameters it was created under.
pub const DEFAULT_M_COST_KIB: u32 = 19_456;
/// Default number of iterations (time cost). OWASP recommendation for the 19 MiB profile.
pub const DEFAULT_T_COST: u32 = 2;
/// Default degree of parallelism (lanes). OWASP recommendation for the 19 MiB profile.
pub const DEFAULT_P_COST: u32 = 1;

/// Argon2id parameters needed to reproduce an unlock key from a passphrase. Contains no
/// secret material (the salt is public), so it is safe to serialize and store next to the
/// wrapped private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub salt: [u8; SALT_LEN],
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Argon2Params {
    /// Fresh parameters using the documented defaults and a new random 128-bit salt. Use
    /// this when creating a new identity; the returned params must be stored so the same key
    /// can be re-derived later.
    pub fn recommended() -> Self {
        Argon2Params {
            salt: random_array::<SALT_LEN>(),
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

/// A 32-byte key derived from a passphrase via Argon2id. Used to encrypt/decrypt the private
/// key seed. Wiped on drop and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnlockKey([u8; KEY_LEN]);

impl UnlockKey {
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for UnlockKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnlockKey(<redacted>)")
    }
}

/// Derive a 32-byte unlock key from `passphrase` under the given Argon2id `params`.
///
/// Deterministic: the same passphrase + salt + params always yield the same key (this is
/// what lets any machine re-derive access). The caller owns `passphrase` and is responsible
/// for zeroizing its own buffer after the call; this function does not retain it.
///
/// Note: Argon2id cannot tell a "wrong" passphrase from a right one — it will happily derive
/// *a* key from any input. Detecting a wrong passphrase happens one layer up, when the
/// derived key fails to open the AEAD-wrapped private key (see [`crate::unlock`]).
pub fn derive_unlock_key(
    passphrase: &[u8],
    params: &Argon2Params,
) -> Result<UnlockKey, CryptoError> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, &params.salt, &mut out)
        .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;

    let key = UnlockKey(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_for_same_inputs() {
        let params = Argon2Params::recommended();
        let a = derive_unlock_key(b"correct horse battery staple", &params).unwrap();
        let b = derive_unlock_key(b"correct horse battery staple", &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_passphrase_gives_different_key() {
        let params = Argon2Params::recommended();
        let a = derive_unlock_key(b"passphrase one", &params).unwrap();
        let b = derive_unlock_key(b"passphrase two", &params).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let p1 = Argon2Params::recommended();
        let mut p2 = p1.clone();
        p2.salt[0] ^= 0xFF;
        let a = derive_unlock_key(b"same passphrase", &p1).unwrap();
        let b = derive_unlock_key(b"same passphrase", &p2).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn defaults_match_owasp_profile() {
        let p = Argon2Params::recommended();
        assert_eq!(p.m_cost_kib, 19_456);
        assert_eq!(p.t_cost, 2);
        assert_eq!(p.p_cost, 1);
    }

    #[test]
    fn invalid_params_fail_closed() {
        // m_cost below the Argon2 minimum (8 * p_cost) must error, not panic.
        let params = Argon2Params {
            salt: [0u8; SALT_LEN],
            m_cost_kib: 1,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(matches!(
            derive_unlock_key(b"x", &params).unwrap_err(),
            CryptoError::InvalidKdfParams(_)
        ));
    }
}
