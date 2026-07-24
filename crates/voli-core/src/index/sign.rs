//! Ed25519 signing and verification for the index (spec §5, §10).
//!
//! The client verifies the downloaded snapshot against an embedded public key
//! and refuses an unsigned or invalid index. Signing lives here too as a
//! test/CI helper — the real registry key is offline and never in this binary.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::IndexError;

/// Public half of the development signing key.
///
// DEV KEY — replace before public launch
pub const DEV_PUBKEY: &str = "8889001cad89219e037858025da3ecc081922248ae5f8b1bec443badf379a8ab";

/// Env override for the verification pubkey (hex), for tests and staging.
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

/// The verification key to use: `$VOLI_INDEX_PUBKEY` if set, else [`DEV_PUBKEY`].
pub fn active_pubkey_hex() -> String {
    resolve_pubkey_hex(std::env::var(PUBKEY_ENV).ok())
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
}
