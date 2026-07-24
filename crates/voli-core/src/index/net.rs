//! `voli update`: fetch, verify, and atomically swap the index (spec §5, §10).
//!
//! Flow: GET `index.json` (tiny: epoch/sha256/size) → if newer than local meta,
//! GET `index.sqlite.zst` → decompress → sha256- and size-check against
//! `index.json` → verify the Ed25519 signature over the *decompressed* bytes →
//! atomic temp+rename into `db\index.sqlite` → save meta. Any verification
//! failure leaves the existing index untouched (we only rename after all checks
//! pass). Offline is soft: we report the local copy's date rather than erroring.

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

fn meta_path(root: &Path) -> std::path::PathBuf {
    Paths::at(root).db().join("index.meta.json")
}

fn read_local_meta(root: &Path) -> Option<IndexMeta> {
    let text = std::fs::read_to_string(meta_path(root)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Refresh the local index from `index_url` (the base URL that hosts
/// `index.json`, `index.sqlite.zst`, and `index.sig`).
pub fn update(root: &Path, index_url: &str) -> Result<UpdateOutcome, IndexError> {
    Paths::at(root).ensure()?;
    let base = index_url.trim_end_matches('/');
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(CALL_TIMEOUT)
        .build();

    let local = read_local_meta(root);

    // 1. Freshness pointer. Unreachable here = offline; fall back to local copy.
    let remote: RemoteIndex = match get_string(&agent, &format!("{base}/index.json")) {
        Ok(body) => serde_json::from_str(&body)?,
        Err(IndexError::Http { .. }) => {
            return Ok(UpdateOutcome::Offline {
                local_epoch: local.as_ref().map(|m| m.epoch),
                local_date: local.as_ref().map(|m| fmt_date_utc(m.fetched_at)),
            });
        }
        Err(e) => return Err(e),
    };

    // 2. Epoch check — cheap no-op when unchanged.
    if let Some(m) = &local
        && m.epoch >= remote.epoch
    {
        return Ok(UpdateOutcome::UpToDate { epoch: m.epoch });
    }

    // 3. Snapshot: download compressed, decompress.
    let compressed = get_bytes(&agent, &format!("{base}/index.sqlite.zst"))?;
    let db_bytes = zstd::stream::decode_all(&compressed[..])
        .map_err(|e| IndexError::Decompress(e.to_string()))?;

    // 4. Size + hash against index.json.
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

    // 5. Signature over the decompressed bytes.
    let sig = get_bytes(&agent, &format!("{base}/index.sig"))?;
    sign::verify(&db_bytes, &sig, &sign::active_pubkey_hex())?;

    // 6. Atomic swap: write temp beside the target, then rename over it.
    let dst = index_db_path(root);
    let tmp = dst.with_extension("sqlite.tmp");
    std::fs::write(&tmp, &db_bytes)?;
    std::fs::rename(&tmp, &dst)?;

    // 7. Persist meta.
    let meta = IndexMeta {
        epoch: remote.epoch,
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

fn get_string(agent: &ureq::Agent, url: &str) -> Result<String, IndexError> {
    agent
        .get(url)
        .call()
        .map_err(|e| IndexError::Http {
            url: url.to_string(),
            source: Box::new(e),
        })?
        .into_string()
        .map_err(IndexError::Io)
}

fn get_bytes(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, IndexError> {
    let resp = agent.get(url).call().map_err(|e| IndexError::Http {
        url: url.to_string(),
        source: Box::new(e),
    })?;
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf)?;
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
