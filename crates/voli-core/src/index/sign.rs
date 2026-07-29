//! Ed25519 signing and verification for the index (spec §5, §10).
//!
//! The client verifies the downloaded snapshot against an embedded public key
//! and refuses an unsigned or invalid index. Signing lives here too as a
//! test/CI helper — the real registry key is offline and never in this binary.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::IndexError;

/// Public half of the production index-signing key (rotated 2026-07-24 per
/// Voli.md §10.1; the retired dev key remains only as a test fixture value).
pub const DEV_PUBKEY: &str = "9fa724f7004638687ef8332d1bff3d15fd7792745b051f91cce0adefd303a2fa";

/// Env override for the verification pubkey (hex). **Debug builds only** — see
/// [`active_pubkey_hex`].
pub const PUBKEY_ENV: &str = "VOLI_INDEX_PUBKEY";

/// Sign `bytes` with a 32-byte Ed25519 secret key, returning the 64-byte
/// signature. Test/CI helper — the registry signs the *decompressed* snapshot.
pub fn sign(bytes: &[u8], secret_key: &[u8; 32]) -> [u8; 64] {
    let key = SigningKey::from_bytes(secret_key);
    key.sign(bytes).to_bytes()
}

/// Verify a detached Ed25519 signature over `bytes` against a hex-encoded
/// public key. Returns `Ok(())` only on a valid signature.
pub fn verify(bytes: &[u8], sig: &[u8], pubkey_hex: &str) -> Result<(), IndexError> {
    let vk = verifying_key(pubkey_hex)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| IndexError::BadSignature)?;
    let signature = Signature::from_bytes(&sig);
    vk.verify_strict(bytes, &signature)
        .map_err(|_| IndexError::BadSignature)
}

/// The verification key to use.
///
/// A **release** build always uses the embedded [`DEV_PUBKEY`]. The
/// `$VOLI_INDEX_PUBKEY` override is honoured in debug builds only: voli writes
/// persistent user environment variables on a package's behalf, so in a shipped
/// binary an installed package could otherwise repoint the trust root for every
/// future `voli update`. Release-mode staging must use
/// [`super::net::update_with_pubkey`] instead of an env var.
pub fn active_pubkey_hex() -> String {
    if cfg!(debug_assertions) {
        resolve_pubkey_hex(std::env::var(PUBKEY_ENV).ok())
    } else {
        DEV_PUBKEY.to_string()
    }
}

fn resolve_pubkey_hex(env_val: Option<String>) -> String {
    match env_val {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEV_PUBKEY.to_string(),
    }
}

fn verifying_key(pubkey_hex: &str) -> Result<VerifyingKey, IndexError> {
    let bytes = hex::decode(pubkey_hex.trim())
        .map_err(|e| IndexError::BadKey(format!("pubkey not hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| IndexError::BadKey("pubkey must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| IndexError::BadKey(e.to_string()))
}

/// Derive the hex public key from a 32-byte secret key. Test/CI helper.
pub fn public_key_hex(secret_key: &[u8; 32]) -> String {
    hex::encode(
        SigningKey::from_bytes(secret_key)
            .verifying_key()
            .to_bytes(),
    )
}

/// Decode a 32-byte secret key from hex. Test/CI helper.
pub fn secret_key_from_hex(hex_str: &str) -> Result<[u8; 32], IndexError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| IndexError::BadKey(format!("secret not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| IndexError::BadKey("secret key must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dev secret in `registry-dev/dev-signing-key.hex` must derive exactly
    /// the embedded [`DEV_PUBKEY`], guarding against drift. The key file is
    /// gitignored (never in CI clones), so read at runtime and skip if absent —
    /// this check only means something on a machine that holds the key anyway.
    #[test]
    fn dev_pubkey_matches_stored_secret() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../registry-dev/dev-signing-key.hex"
        );
        let Ok(hex_str) = std::fs::read_to_string(path) else {
            eprintln!("skipped: no local signing key at {path}");
            return;
        };
        let secret = secret_key_from_hex(&hex_str).expect("valid dev secret");
        assert_eq!(public_key_hex(&secret), DEV_PUBKEY);
    }

    #[test]
    fn sign_verify_round_trip() {
        let secret = [7u8; 32];
        let pk = public_key_hex(&secret);
        let msg = b"the quick brown fox";
        let sig = sign(msg, &secret);
        assert!(verify(msg, &sig, &pk).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let secret = [7u8; 32];
        let pk = public_key_hex(&secret);
        let sig = sign(b"original", &secret);
        assert!(matches!(
            verify(b"tampered", &sig, &pk),
            Err(IndexError::BadSignature)
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sig = sign(b"msg", &[1u8; 32]);
        let other = public_key_hex(&[2u8; 32]);
        assert!(verify(b"msg", &sig, &other).is_err());
    }

    #[test]
    fn env_override_wins_when_set() {
        assert_eq!(resolve_pubkey_hex(Some("abcd".into())), "abcd");
        assert_eq!(resolve_pubkey_hex(Some("  ".into())), DEV_PUBKEY);
        assert_eq!(resolve_pubkey_hex(None), DEV_PUBKEY);
    }

    /// A shipped (release) binary must never let an environment variable move
    /// the trust root: voli writes persistent user env vars for packages, so
    /// that would be a package-installable trust-root swap.
    #[test]
    fn env_override_is_debug_builds_only() {
        let planted = "ab".repeat(32);
        // SAFETY: no other test in this binary reads PUBKEY_ENV.
        unsafe { std::env::set_var(PUBKEY_ENV, &planted) };
        let active = active_pubkey_hex();
        unsafe { std::env::remove_var(PUBKEY_ENV) };

        if cfg!(debug_assertions) {
            assert_eq!(active, planted);
        } else {
            assert_eq!(
                active, DEV_PUBKEY,
                "release builds must ignore the override"
            );
        }
    }
}
