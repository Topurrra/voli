//! `voli update`: fetch, verify, and atomically swap the index (spec §5, §10).
//!
//! Flow: GET `index.json` (tiny: epoch/sha256/size) → if it *hints* at something
//! newer, GET `index.sqlite.zst` → decompress bounded by the declared size →
//! sha256- and size-check → verify the Ed25519 signature over the *decompressed*
//! bytes → read the epoch stamped **inside** the signed snapshot → install only
//! if that signed epoch beats the local one → atomic temp+rename into
//! `db\index.sqlite` → save meta. Any verification failure leaves the existing
//! index untouched (we only rename after all checks pass). Offline is soft: we
//! report the local copy's date rather than erroring.
//!
//! `index.json` is unauthenticated, so nothing it says is ever trusted: it is a
//! fetch hint and nothing more. The epoch we persist and compare comes from the
//! signed snapshot ([`super::stamp_epoch`]), which is what stops a replayed but
//! genuinely-signed older snapshot from downgrading — and permanently freezing —
//! the client.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{IndexError, index_db_path, sign};
use crate::paths::Paths;

/// `index.json` — the tiny freshness pointer published beside the snapshot.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteIndex {
    pub epoch: u64,
    pub sha256: String,
    pub size: u64,
}

/// Local `db\index.meta.json` — what we last successfully installed.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IndexMeta {
    pub epoch: u64,
    pub sha256: String,
    pub size: u64,
    /// Unix ms when we fetched it (for the offline "using local copy from …").
    pub fetched_at: i64,
}

/// Result of an update attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Local index already matched the remote epoch; nothing downloaded.
    UpToDate { epoch: u64 },
    /// A newer snapshot was verified and installed.
    Updated { epoch: u64, size: u64 },
    /// The index host was unreachable; the local copy (if any) still stands.
    Offline {
        local_epoch: Option<u64>,
        /// `YYYY-MM-DD` of the local copy, if we have one.
        local_date: Option<String>,
    },
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on any epoch we will accept: unix seconds at 2100-01-01. Epochs
/// are build timestamps, so anything beyond this is forged. Enforcing it on the
/// *local* meta too is what un-freezes a client whose meta was already poisoned
/// with a huge epoch by a pre-fix build.
pub const MAX_EPOCH: u64 = 4_102_444_800;

/// Hard caps on bytes we read before we have verified anything. All three of
/// these fetches happen pre-trust, so an attacker controls the response.
const MAX_JSON_BYTES: u64 = 64 * 1024;
/// An Ed25519 signature is exactly 64 bytes; there is nothing else to read.
const MAX_SIG_BYTES: u64 = 64;
/// Ceiling for both the compressed download and the inflated snapshot.
const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;

fn meta_path(root: &Path) -> std::path::PathBuf {
    Paths::at(root).db().join("index.meta.json")
}

fn read_local_meta(root: &Path) -> Option<IndexMeta> {
    let text = std::fs::read_to_string(meta_path(root)).ok()?;
    let meta: IndexMeta = serde_json::from_str(&text).ok()?;
    // A meta claiming an impossible epoch can only have come from a forged
    // index.json accepted by an older client. Ignoring it re-enables updates
    // instead of leaving the client wedged at u64::MAX forever.
    (meta.epoch <= MAX_EPOCH).then_some(meta)
}

/// Refresh the local index from `index_url` (the base URL that hosts
/// `index.json`, `index.sqlite.zst`, and `index.sig`), verifying against the
/// embedded production key.
pub fn update(root: &Path, index_url: &str) -> Result<UpdateOutcome, IndexError> {
    update_with_pubkey(root, index_url, &sign::active_pubkey_hex())
}

/// [`update`] against an explicit hex public key. Lets tests exercise the real
/// flow with a throwaway key instead of the process-wide `VOLI_INDEX_PUBKEY`
/// override, which release builds ignore (see [`sign::active_pubkey_hex`]).
pub fn update_with_pubkey(
    root: &Path,
    index_url: &str,
    pubkey_hex: &str,
) -> Result<UpdateOutcome, IndexError> {
    Paths::at(root).ensure()?;
    let base = index_url.trim_end_matches('/');
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(CALL_TIMEOUT)
        .build();

    let local = read_local_meta(root);

    // 1. Freshness *hint*. Unreachable here = offline; fall back to local copy.
    //    Nothing in this file is authenticated — it only decides whether we
    //    bother downloading the snapshot.
    let json = match get_bytes(&agent, &format!("{base}/index.json"), MAX_JSON_BYTES) {
        Ok(body) => body,
        Err(IndexError::Http { .. }) => {
            return Ok(UpdateOutcome::Offline {
                local_epoch: local.as_ref().map(|m| m.epoch),
                local_date: local.as_ref().map(|m| fmt_date_utc(m.fetched_at)),
            });
        }
        Err(e) => return Err(e),
    };
    let remote: RemoteIndex = serde_json::from_slice(&json)?;
    if remote.epoch > MAX_EPOCH {
        return Err(IndexError::BadEpoch(remote.epoch));
    }
    if remote.size > MAX_SNAPSHOT_BYTES {
        return Err(IndexError::TooLarge {
            url: format!("{base}/index.sqlite.zst"),
            limit: MAX_SNAPSHOT_BYTES,
        });
    }

    // 2. Cheap no-op when the hint says we already have it.
    if let Some(m) = &local
        && m.epoch >= remote.epoch
    {
        return Ok(UpdateOutcome::UpToDate { epoch: m.epoch });
    }

    // 3. Snapshot: download compressed, then inflate under a hard cap. The cap
    //    is enforced *during* inflation, so a zstd bomb can never allocate more
    //    than the declared size before we notice.
    let compressed = get_bytes(
        &agent,
        &format!("{base}/index.sqlite.zst"),
        MAX_SNAPSHOT_BYTES,
    )?;
    let mut db_bytes = Vec::new();
    zstd::Decoder::new(&compressed[..])
        .map_err(|e| IndexError::Decompress(e.to_string()))?
        .take(remote.size.saturating_add(1))
        .read_to_end(&mut db_bytes)
        .map_err(|e| IndexError::Decompress(e.to_string()))?;

    // 4. Size + hash against index.json. Still unauthenticated, but it means a
    //    truncated or over-long inflation stops here.
    if db_bytes.len() as u64 != remote.size {
        return Err(IndexError::SizeMismatch {
            expected: remote.size,
            actual: db_bytes.len() as u64,
        });
    }
    let actual_sha = hex::encode(Sha256::digest(&db_bytes));
    if !actual_sha.eq_ignore_ascii_case(&remote.sha256) {
        return Err(IndexError::Sha256Mismatch {
            expected: remote.sha256.clone(),
            actual: actual_sha,
        });
    }

    // 5. Signature over the decompressed bytes. Everything past this point is
    //    authentic — but authentic does not mean *current*.
    let sig = get_bytes(&agent, &format!("{base}/index.sig"), MAX_SIG_BYTES)?;
    sign::verify(&db_bytes, &sig, pubkey_hex)?;

    // 6. Stage the verified snapshot, then read the epoch the registry signed
    //    into it. Only now do we know how old this snapshot really is.
    let dst = index_db_path(root);
    let tmp = dst.with_extension("sqlite.tmp");
    std::fs::write(&tmp, &db_bytes)?;
    let signed_epoch = match staged_epoch(&tmp, local.as_ref().map(|m| m.epoch)) {
        Ok(epoch) => epoch,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    let Some(signed_epoch) = signed_epoch else {
        // Authentic, but not newer than what we already have: a replay. Keep
        // the local index and report the truth.
        let _ = std::fs::remove_file(&tmp);
        return Ok(UpdateOutcome::UpToDate {
            epoch: local.map(|m| m.epoch).unwrap_or(0),
        });
    };

    // 7. Atomic swap.
    std::fs::rename(&tmp, &dst)?;

    // 8. Persist meta — with the *signed* epoch, never the one from index.json.
    let meta = IndexMeta {
        epoch: signed_epoch,
        sha256: remote.sha256,
        size: remote.size,
        fetched_at: now_unix_ms(),
    };
    std::fs::write(meta_path(root), serde_json::to_string_pretty(&meta)?)?;

    Ok(UpdateOutcome::Updated {
        epoch: meta.epoch,
        size: meta.size,
    })
}

/// Validate the epoch signed into the staged snapshot. `Ok(None)` means it is
/// authentic but not newer than `local_epoch` — a downgrade attempt or a
/// harmless race, either way we keep what we have.
fn staged_epoch(tmp: &Path, local_epoch: Option<u64>) -> Result<Option<u64>, IndexError> {
    let epoch = super::read_epoch(tmp)?.ok_or(IndexError::UnsignedEpoch)?;
    if epoch > MAX_EPOCH {
        return Err(IndexError::BadEpoch(epoch));
    }
    Ok((local_epoch.is_none_or(|local| epoch > local)).then_some(epoch))
}

fn get_bytes(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>, IndexError> {
    let resp = agent.get(url).call().map_err(|e| IndexError::Http {
        url: url.to_string(),
        source: Box::new(e),
    })?;
    let mut buf = Vec::new();
    // Read one byte past the cap so an over-long body is detected, not silently
    // truncated into something that might still hash correctly.
    resp.into_reader()
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(IndexError::TooLarge {
            url: url.to_string(),
            limit,
        });
    }
    Ok(buf)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Format a unix-ms instant as `YYYY-MM-DD` (UTC).
///
/// ponytail: hand-rolled civil-date conversion (Howard Hinnant's algorithm) to
/// avoid pulling in `chrono`/`time` for one date string. UTC only.
fn fmt_date_utc(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_conversion_matches_known_epochs() {
        assert_eq!(fmt_date_utc(0), "1970-01-01");
        // 2021-01-01T00:00:00Z = 1609459200 s
        assert_eq!(fmt_date_utc(1_609_459_200_000), "2021-01-01");
        // 2025-07-24
        assert_eq!(fmt_date_utc(1_753_315_200_000), "2025-07-24");
    }
}
