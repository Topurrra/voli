//! Per-record authenticated encryption at rest.
//!
//! Every on-disk record is `E = NONCE(24) || AEAD_ciphertext(P) || TAG(16)`,
//! where the ciphertext+tag is `P + 16` bytes. XChaCha20-Poly1305 is
//! length-preserving, so `E = 24 + P + 16` is **constant** for a fixed plaintext
//! width `P` — the record stays fixed-width, `seek(seq * E)` still lands exactly,
//! and a truncated tail fails the AEAD tag (treated as a torn tail, not read).
//!
//! `AAD = seq` (the record's slot index, little-endian) binds a ciphertext to its
//! position: copying record 5's bytes into slot 3 makes the tag verification fail,
//! so splicing and reordering are caught for free.
//!
//! [`seal_with`] / [`open_with`] take that AAD explicitly, so a caller can bind a
//! record to more than its slot. The summary tree uses this to bind a summary to
//! the exact memories it describes: if those memories change, the summary no
//! longer authenticates and is rebuilt rather than believed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::{Error, Result, os_random};

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;

/// On-disk sealed length for a `plain`-byte plaintext record.
pub const fn sealed_len(plain: usize) -> usize {
    NONCE_LEN + plain + TAG_LEN
}

/// Seal one fixed-width plaintext record under an explicit `aad`.
/// Returns `NONCE(24) || ciphertext(plain + 16)`.
pub fn seal_with(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    os_random(&mut nonce)?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a record sealed under `aad`. A wrong key, a tampered byte, a torn
/// (truncated) tail, or a mismatched AAD all fail the AEAD tag and return `Err` —
/// never a partial or wrong plaintext.
pub fn open_with(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("record too short to be sealed".into()));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| {
            Error::Crypto("record failed authentication (tampered, torn, or wrong key)".into())
        })
}

/// Seal one fixed-width plaintext record for slot `seq`.
pub fn seal(key: &[u8; 32], seq: u64, plain: &[u8]) -> Result<Vec<u8>> {
    seal_with(key, &seq.to_le_bytes(), plain)
}

/// Open a sealed record for slot `seq`. A record spliced from another slot fails
/// the tag, so splicing and reordering are caught for free.
pub fn open(key: &[u8; 32], seq: u64, sealed: &[u8]) -> Result<Vec<u8>> {
    open_with(key, &seq.to_le_bytes(), sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [7u8; 32];
        let plain = b"a fixed width record padded out";
        let sealed = seal(&key, 3, plain).unwrap();
        assert_eq!(sealed.len(), sealed_len(plain.len()));
        assert_eq!(open(&key, 3, &sealed).unwrap(), plain);
    }

    #[test]
    fn wrong_slot_fails() {
        let key = [7u8; 32];
        let sealed = seal(&key, 5, b"record five").unwrap();
        // AAD = seq: opening as a different slot fails (anti-splice).
        assert!(open(&key, 3, &sealed).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [7u8; 32];
        // The summary tree binds a record to the memories it describes: change
        // the description and the same bytes must stop opening.
        let sealed = seal_with(&key, b"leaves:a,b,c", b"summary of a,b,c").unwrap();
        assert_eq!(
            open_with(&key, b"leaves:a,b,c", &sealed).unwrap(),
            b"summary of a,b,c"
        );
        assert!(open_with(&key, b"leaves:a,c", &sealed).is_err());
    }

    #[test]
    fn wrong_key_and_flip_fail() {
        let key = [7u8; 32];
        let mut sealed = seal(&key, 0, b"secret").unwrap();
        assert!(open(&[8u8; 32], 0, &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip a tag byte
        assert!(open(&key, 0, &sealed).is_err());
    }
}
