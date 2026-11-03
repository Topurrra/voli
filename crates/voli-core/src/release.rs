//! Release-asset signing for `voli self-update` (supply-chain review item 1).
//!
//! `self-update` replaces the running binary, so a tampered release asset is
//! full code execution on every user machine. A same-origin `.sha256` asset
//! only proves the download was not corrupted — whoever can publish the
//! release can publish the hash too. Each release therefore also carries a
//! detached Ed25519 signature (`<asset>.sig`, produced by `voli-index-tool
//! sign-assets` in release.yml), and `self-update` verifies it against the
//! public key embedded here before extracting anything. A missing hash or a
//! missing/invalid signature aborts the update — fail closed, no exceptions.
//!
//! The signing secret lives in the release workflow as the Actions secret
//! `VOLI_RELEASE_SIGNING_KEY`. That key is *online* (CI holds it) — stated
//! plainly, unlike the old "offline key" wording for the index key. Its blast
//! radius is bounded: it only signs voli release assets, it is independent of
//! the index-signing key, and rotating it only requires shipping the new
//! public key in the next release.
//!
//! `$VOLI_RELEASE_PUBKEY` overrides the key in debug builds only, mirroring
//! [`crate::index::sign::PUBKEY_ENV`] — a release binary must never let an
//! installed package move its own trust roots.

use sha2::{Digest, Sha256};

/// Public half of the release-asset signing key. The matching secret is
/// `registry-dev/release-signing-key.hex` on the signing machine (gitignored)
/// and the `VOLI_RELEASE_SIGNING_KEY` Actions secret in CI. Rotate by running
/// `voli-index-tool keygen`, updating this constant, and shipping both in the
/// same release.
pub const RELEASE_PUBKEY: &str = "7bf2593015e5eaead6cc1678f915ed3a136aaa057587cb81bac55f6ceedee053";

/// Env override for the verification pubkey (hex). Debug builds only.
pub const RELEASE_PUBKEY_ENV: &str = "VOLI_RELEASE_PUBKEY";

/// Why a downloaded release asset was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseVerifyError {
    /// The `.sha256` asset content did not hash-match the archive.
    HashMismatch { expected: String, actual: String },
    /// The signature is not valid for this asset under the given key.
    BadSignature,
}

impl std::fmt::Display for ReleaseVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReleaseVerifyError::HashMismatch { expected, actual } => {
                write!(f, "sha256 mismatch: expected {expected}, got {actual}")
            }
            ReleaseVerifyError::BadSignature => {
                write!(f, "release signature invalid under the pinned key")
            }
        }
    }
}

impl std::error::Error for ReleaseVerifyError {}

/// The verification key to use: [`RELEASE_PUBKEY`], or `$VOLI_RELEASE_PUBKEY`
/// in debug builds (test/staging hook only — a shipped binary must not be
/// repointable by anything an installed package can write).
pub fn active_release_pubkey_hex() -> String {
    if cfg!(debug_assertions) {
        match std::env::var(RELEASE_PUBKEY_ENV) {
            Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => RELEASE_PUBKEY.to_string(),
        }
    } else {
        RELEASE_PUBKEY.to_string()
    }
}

/// Full fail-closed gate for a downloaded release asset, against an explicit
/// pubkey (hex). Both checks must pass; any failure (including malformed
/// input) refuses the asset.
///
/// * `asset` — the downloaded archive bytes.
/// * `sha256_text` — the content of the `.sha256` asset (first whitespace-
///   delimited token is the hex digest, tolerating `sha256sum` layout).
/// * `sig_hex` — the content of the `.sig` asset (hex-encoded 64-byte
///   Ed25519 signature over the raw asset bytes).
pub fn verify_release_asset_with_key(
    asset: &[u8],
    sha256_text: &str,
    sig_hex: &str,
    pubkey_hex: &str,
) -> Result<(), ReleaseVerifyError> {
    // 1. Hash: corruption check.
    let expected = sha256_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if expected.is_empty() {
        return Err(ReleaseVerifyError::HashMismatch {
            expected: "<empty>".into(),
            actual: hex::encode(Sha256::digest(asset)),
        });
    }
    let actual = hex::encode(Sha256::digest(asset));
    if actual != expected {
        return Err(ReleaseVerifyError::HashMismatch { expected, actual });
    }

    // 2. Signature: authenticity check against the pinned key.
    let sig = hex::decode(sig_hex.trim())
        .map_err(|_| ReleaseVerifyError::BadSignature)?
        .to_vec();
    crate::index::sign::verify(asset, &sig, pubkey_hex)
        .map_err(|_| ReleaseVerifyError::BadSignature)
}

/// [`verify_release_asset_with_key`] against [`active_release_pubkey_hex`].
pub fn verify_release_asset(
    asset: &[u8],
    sha256_text: &str,
    sig_hex: &str,
) -> Result<(), ReleaseVerifyError> {
    verify_release_asset_with_key(asset, sha256_text, sig_hex, &active_release_pubkey_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [9u8; 32];

    fn sign_with_test_key(asset: &[u8]) -> (String, String) {
        let pk = crate::index::sign::public_key_hex(&SECRET);
        let sig = crate::index::sign::sign(asset, &SECRET);
        (pk, hex::encode(sig))
    }

    fn sha_text(asset: &[u8]) -> String {
        hex::encode(Sha256::digest(asset))
    }

    #[test]
    fn valid_asset_passes_both_checks() {
        let asset = b"voli release archive bytes";
        let (pk, sig) = sign_with_test_key(asset);
        assert!(verify_release_asset_with_key(asset, &sha_text(asset), &sig, &pk).is_ok());
    }

    #[test]
    fn tampered_asset_fails_hash() {
        let asset = b"original bytes";
        let (pk, sig) = sign_with_test_key(asset);
        assert_eq!(
            verify_release_asset_with_key(b"tampered bytes", &sha_text(asset), &sig, &pk),
            Err(ReleaseVerifyError::HashMismatch {
                expected: sha_text(asset),
                actual: sha_text(b"tampered bytes"),
            })
        );
    }

    #[test]
    fn tampered_signature_fails() {
        let asset = b"voli release archive bytes";
        let (pk, sig) = sign_with_test_key(asset);
        let mut bad = hex::decode(&sig).unwrap();
        bad[0] ^= 0xff;
        assert_eq!(
            verify_release_asset_with_key(asset, &sha_text(asset), &hex::encode(&bad), &pk),
            Err(ReleaseVerifyError::BadSignature)
        );
    }

    #[test]
    fn signature_from_wrong_key_fails() {
        let asset = b"voli release archive bytes";
        let pk = crate::index::sign::public_key_hex(&SECRET);
        let sig = crate::index::sign::sign(asset, &[3u8; 32]);
        assert_eq!(
            verify_release_asset_with_key(asset, &sha_text(asset), &hex::encode(sig), &pk),
            Err(ReleaseVerifyError::BadSignature)
        );
    }

    #[test]
    fn empty_hash_text_fails() {
        let asset = b"bytes";
        let (pk, sig) = sign_with_test_key(asset);
        assert!(matches!(
            verify_release_asset_with_key(asset, "", &sig, &pk),
            Err(ReleaseVerifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn non_hex_signature_fails() {
        let asset = b"bytes";
        let (pk, _) = sign_with_test_key(asset);
        assert_eq!(
            verify_release_asset_with_key(asset, &sha_text(asset), "not-hex", &pk),
            Err(ReleaseVerifyError::BadSignature)
        );
    }

    #[test]
    fn embedded_pubkey_is_well_formed() {
        let bytes = hex::decode(RELEASE_PUBKEY).expect("release pubkey is hex");
        assert_eq!(bytes.len(), 32, "release pubkey must be 32 bytes");
    }
}
