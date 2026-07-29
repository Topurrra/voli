//! Key custody — where the 32-byte master key comes from.
//!
//! Ported almost verbatim from the KeepItLocal memory engine (`key.rs`). Two
//! custody modes:
//!
//! * **Passphrase** (portable default): the master key is `Argon2id(passphrase,
//!   salt)`. The salt, the Argon2 params, and a small **verifier** live in a
//!   cleartext `custody.json` sidecar. The verifier is a fixed known constant
//!   sealed under the derived key, so a wrong passphrase is rejected *before any
//!   record is read* — even on a brand-new empty store. Cleartext is required and
//!   safe: the salt is not secret and the key itself is never written.
//! * **Keyring** (Windows only): a random master key stored in the OS Credential
//!   Manager as a **64-char hex string** (Windows corrupts raw-binary secrets —
//!   a documented real bug), used when no `custody.json` is present.
//!
//! A passphrase-wrapped **recovery blob** ([`wrap_master_key`]) can be stored
//! beside the vault so a wiped keychain is survivable.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{NONCE_LEN, TAG_LEN};
use crate::{Error, Result, os_random};

const CUSTODY_FILE: &str = "custody.json";
const RECOVERY_SALT_LEN: usize = 16;

/// Fixed known plaintext sealed under the derived key as the wrong-passphrase
/// verifier. Decrypting it back to this exact constant proves the key is correct
/// without touching real vault data (works even for an empty store). The AAD
/// domain-separates it from any other ciphertext under the same key.
const VERIFIER_PLAINTEXT: &[u8] = b"stela passphrase custody ok";
const VERIFIER_AAD: &[u8] = b"stela/custody-verifier/v1";

/// SHIPPING Argon2id cost: 19 MiB, 2 passes, 1 lane (a strong per-vault unlock).
const SHIP_M_COST_KIB: u32 = 19 * 1024;
const SHIP_T_COST: u32 = 2;
const SHIP_P_COST: u32 = 1;

/// FAST test profile — the Argon2 minimum (m ≥ 8·p). Used only when
/// `STELA_ARGON2_TEST_FAST` is set, so CI never runs a full-cost KDF. Params are
/// stored per-vault, so this can never weaken an already-created strong vault.
const FAST_M_COST_KIB: u32 = 16;
const FAST_T_COST: u32 = 1;
const FAST_P_COST: u32 = 1;

/// Default memory directory: `%LOCALAPPDATA%\voli\memory`, else `~/.stela/memory`.
/// Overridable by `$STELA_DIR` or `$VOLI_MEMORY_DIR` (checked by the CLI).
pub fn default_memory_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(p).join("voli").join("memory");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".stela").join("memory")
}

/// The directory a project-local store lives in, relative to the project root.
pub const PROJECT_MEMORY_REL: &str = ".voli/memory";

/// The project-local memory store governing `start`, if one exists.
///
/// Walks `start` and its ancestors looking for an initialized `.voli/memory`.
/// Existence is the opt-in: a project has a store only once someone ran
/// `voli memory init --project` there, so this can never silently redirect
/// writes away from the global store in a directory that never asked for it.
/// The nearest one wins, which is what you want for a repo inside a repo.
pub fn project_memory_dir(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        let candidate = current.join(".voli").join("memory");
        if candidate.is_dir() {
            return Some(candidate);
        }
        dir = current.parent();
    }
    None
}

/// Lowercase hex of a raw key (64 chars).
pub fn to_hex_key(key: &[u8; 32]) -> String {
    hex::encode(key)
}

/// Derive a 32-byte master key from a passphrase with explicit Argon2id params.
/// The result is `Zeroizing`, wiped on drop.
pub fn derive_key_with(
    passphrase: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut_slice())
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    Ok(out)
}

/// The Argon2id params a NEW passphrase vault is created with.
pub fn default_argon2_params() -> (u32, u32, u32) {
    if std::env::var_os("STELA_ARGON2_TEST_FAST").is_some() {
        (FAST_M_COST_KIB, FAST_T_COST, FAST_P_COST)
    } else {
        (SHIP_M_COST_KIB, SHIP_T_COST, SHIP_P_COST)
    }
}

/// How a vault's master key is custodied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMode {
    /// OS keychain (Windows Credential Manager).
    Keyring,
    /// Argon2id passphrase, `custody.json` sidecar present.
    Passphrase,
}

#[derive(Serialize, Deserialize)]
struct CustodyFile {
    mode: String,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    /// Per-vault random Argon2 salt (hex). Not secret.
    salt_hex: String,
    /// `nonce(24) || AEAD(VERIFIER_PLAINTEXT)` (hex): the wrong-passphrase verifier.
    verifier_hex: String,
}

fn custody_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(CUSTODY_FILE)
}

/// Whether the vault at `vault_dir` is passphrase-custodied (has a `custody.json`)
/// or keyring-custodied. Cheap, no crypto.
pub fn custody_mode(vault_dir: &Path) -> CustodyMode {
    if custody_path(vault_dir).exists() {
        CustodyMode::Passphrase
    } else {
        CustodyMode::Keyring
    }
}

fn seal_verifier(master: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(master));
    let mut nonce = [0u8; NONCE_LEN];
    os_random(&mut nonce)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: VERIFIER_PLAINTEXT,
                aad: VERIFIER_AAD,
            },
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Verify a candidate `master` against the stored verifier. A wrong key fails the
/// AEAD tag ⇒ [`Error::BadPassphrase`] — never a panic, never a partial open.
fn check_verifier(master: &[u8; 32], blob: &[u8]) -> Result<()> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("custody verifier too short".into()));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(master));
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: VERIFIER_AAD,
            },
        )
        .map_err(|_| Error::BadPassphrase)?;
    if pt.as_slice() != VERIFIER_PLAINTEXT {
        return Err(Error::BadPassphrase);
    }
    Ok(())
}

/// Create passphrase custody for a NEW vault: random salt + default Argon2 params,
/// derive the key, and write the cleartext `custody.json` atomically. Returns the
/// derived master key. Does not create the vault itself.
pub fn create_passphrase_custody(
    vault_dir: &Path,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let (m, t, p) = default_argon2_params();
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    os_random(&mut salt)?;
    let master = derive_key_with(passphrase, &salt, m, t, p)?;
    let verifier = seal_verifier(&master)?;
    let file = CustodyFile {
        mode: "passphrase".into(),
        m_cost_kib: m,
        t_cost: t,
        p_cost: p,
        salt_hex: hex::encode(salt),
        verifier_hex: hex::encode(verifier),
    };
    write_custody_atomically(vault_dir, &file)?;
    Ok(master)
}

/// Re-derive the master key to OPEN a passphrase vault: read `custody.json`,
/// derive with the STORED salt+params, and verify. Wrong passphrase ⇒
/// [`Error::BadPassphrase`]; no sidecar ⇒ [`Error::Msg`].
pub fn derive_master_for_open(vault_dir: &Path, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let file = read_custody(vault_dir)?;
    let salt =
        hex::decode(&file.salt_hex).map_err(|_| Error::Crypto("custody salt malformed".into()))?;
    let verifier = hex::decode(&file.verifier_hex)
        .map_err(|_| Error::Crypto("custody verifier malformed".into()))?;
    let master = derive_key_with(passphrase, &salt, file.m_cost_kib, file.t_cost, file.p_cost)?;
    check_verifier(&master, &verifier)?;
    Ok(master)
}

fn read_custody(vault_dir: &Path) -> Result<CustodyFile> {
    let bytes = std::fs::read(custody_path(vault_dir)).map_err(|_| {
        Error::Msg("this vault has no passphrase custody (open it with the keyring instead)".into())
    })?;
    let file: CustodyFile = serde_json::from_slice(&bytes)?;
    if file.mode != "passphrase" {
        return Err(Error::Crypto("unrecognized custody mode".into()));
    }
    Ok(file)
}

fn write_custody_atomically(vault_dir: &Path, file: &CustodyFile) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(vault_dir)?;
    let path = custody_path(vault_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(file)?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

// ── recovery blob ───────────────────────────────────────────────────────────

/// Wrap the master key under a recovery PASSPHRASE:
/// `salt(16) || nonce(24) || AEAD(master, argon2id(passphrase, salt))`. Store it
/// beside the vault so a lost keychain is survivable.
pub fn wrap_master_key(master: &[u8; 32], passphrase: &str) -> Result<Vec<u8>> {
    let (m, t, p) = default_argon2_params();
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    os_random(&mut salt)?;
    let wrap = derive_key_with(passphrase, &salt, m, t, p)?;
    let mut nonce = [0u8; NONCE_LEN];
    os_random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(wrap.as_slice()));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), master.as_slice())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let mut out = Vec::with_capacity(RECOVERY_SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Recover the master key from a recovery blob + passphrase. A wrong passphrase or
/// tampered blob fails closed.
pub fn unwrap_master_key(blob: &[u8], passphrase: &str) -> Result<[u8; 32]> {
    if blob.len() < RECOVERY_SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("recovery blob too short".into()));
    }
    let (salt, rest) = blob.split_at(RECOVERY_SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let (m, t, p) = default_argon2_params();
    let wrap = derive_key_with(passphrase, salt, m, t, p)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(wrap.as_slice()));
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| Error::Crypto("wrong recovery passphrase or corrupt recovery file".into()))?;
    pt.try_into()
        .map_err(|_| Error::Crypto("recovery payload wrong length".into()))
}

const RECOVERY_FILE: &str = "recovery.blob";

/// Where the passphrase-wrapped recovery blob lives, beside the vault.
pub fn recovery_blob_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(RECOVERY_FILE)
}

/// Wrap `master` under a recovery `passphrase` and write it beside the vault
/// atomically (sibling temp + fsync + rename). Run this while access still works,
/// so a later keychain wipe is survivable. Overwrites any existing blob.
pub fn write_recovery_blob(vault_dir: &Path, master: &[u8; 32], passphrase: &str) -> Result<()> {
    use std::io::Write;
    let blob = wrap_master_key(master, passphrase)?;
    std::fs::create_dir_all(vault_dir)?;
    let path = recovery_blob_path(vault_dir);
    let tmp = path.with_extension("blob.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&blob)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Read the recovery blob beside the vault and unwrap the master key with
/// `passphrase`. No blob ⇒ an actionable message; wrong passphrase ⇒ fails closed.
/// Cross-platform: this recovers the KEY; re-seeding the OS keychain from it is the
/// caller's platform-specific step (see [`store_master_key`] on Windows).
pub fn recover_master(vault_dir: &Path, passphrase: &str) -> Result<[u8; 32]> {
    let path = recovery_blob_path(vault_dir);
    let blob = std::fs::read(&path).map_err(|_| {
        Error::Msg(format!(
            "no recovery blob at {}. Run `voli memory recover --save` before you lose access.",
            path.display()
        ))
    })?;
    unwrap_master_key(&blob, passphrase)
}

// ── OS keychain custody (Windows only) ──────────────────────────────────────
//
// Gated to Windows: the crate stays green on non-Windows CI, where passphrase
// custody is the portable default. macOS/Linux keychain support is a later pass.

#[cfg(windows)]
const KEYCHAIN_SERVICE: &str = "com.voli.memory";
#[cfg(windows)]
const KEYCHAIN_USER: &str = "master-key";

/// Load the master key from the OS keychain, generating + storing one on first
/// run. Stored as a **hex string** (Windows Credential Manager corrupts raw
/// binary — a documented real bug).
#[cfg(windows)]
pub fn load_or_create_master_key() -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    if let Ok(stored) = entry.get_password()
        && let Ok(bytes) = hex::decode(stored.trim())
        && let Ok(k) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(k);
    }
    let mut k = [0u8; 32];
    os_random(&mut k)?;
    entry
        .set_password(&to_hex_key(&k))
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    Ok(k)
}

/// Read the master key from the keychain WITHOUT creating one. `Ok(None)` =
/// keychain reachable but no entry; `Err` = keychain unavailable or malformed.
#[cfg(windows)]
pub fn load_master_key() -> Result<Option<[u8; 32]>> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    match entry.get_password() {
        Ok(stored) => {
            let bytes = hex::decode(stored.trim())
                .map_err(|_| Error::KeyDerivation("stored master key is malformed".into()))?;
            let k: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::KeyDerivation("stored master key is malformed".into()))?;
            Ok(Some(k))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::KeyDerivation(e.to_string())),
    }
}

/// Store (overwrite) the master key in the keychain — re-establishes custody
/// after a recovery or rotation.
#[cfg(windows)]
pub fn store_master_key(key: &[u8; 32]) -> Result<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER)
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    entry
        .set_password(&to_hex_key(key))
        .map_err(|e| Error::KeyDerivation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() {
        // SAFETY: single-threaded test setup; never full-cost KDF in tests.
        unsafe { std::env::set_var("STELA_ARGON2_TEST_FAST", "1") };
    }

    #[test]
    fn derive_is_deterministic_and_32_bytes() {
        fast();
        let salt = [7u8; 16];
        let a = derive_key_with(
            "correct horse",
            &salt,
            FAST_M_COST_KIB,
            FAST_T_COST,
            FAST_P_COST,
        )
        .unwrap();
        let b = derive_key_with(
            "correct horse",
            &salt,
            FAST_M_COST_KIB,
            FAST_T_COST,
            FAST_P_COST,
        )
        .unwrap();
        assert_eq!(*a, *b);
        assert_eq!(to_hex_key(&a).len(), 64);
        let c = derive_key_with(
            "wrong horse",
            &salt,
            FAST_M_COST_KIB,
            FAST_T_COST,
            FAST_P_COST,
        )
        .unwrap();
        assert_ne!(*a, *c);
    }

    #[test]
    fn verifier_accepts_right_key_and_rejects_wrong() {
        let right = [11u8; 32];
        let blob = seal_verifier(&right).unwrap();
        assert!(check_verifier(&right, &blob).is_ok());
        assert!(matches!(
            check_verifier(&[12u8; 32], &blob),
            Err(Error::BadPassphrase)
        ));
        assert!(check_verifier(&right, &blob[..NONCE_LEN]).is_err());
    }

    #[test]
    fn passphrase_custody_roundtrip_and_wrong_pass() {
        fast();
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(custody_mode(dir.path()), CustodyMode::Keyring);
        let created = create_passphrase_custody(dir.path(), "correct horse").unwrap();
        assert_eq!(custody_mode(dir.path()), CustodyMode::Passphrase);
        let opened = derive_master_for_open(dir.path(), "correct horse").unwrap();
        assert_eq!(*created, *opened);
        assert!(matches!(
            derive_master_for_open(dir.path(), "wrong horse"),
            Err(Error::BadPassphrase)
        ));
    }

    #[test]
    fn recovery_blob_roundtrip() {
        fast();
        let master = [42u8; 32];
        let blob = wrap_master_key(&master, "rescue phrase").unwrap();
        assert_eq!(unwrap_master_key(&blob, "rescue phrase").unwrap(), master);
        assert!(unwrap_master_key(&blob, "nope").is_err());
    }
}
