//! The package-index client (spec §5, §10, §11 step 6).
//!
//! The index is a signed sqlite snapshot the client downloads and queries
//! offline. This module owns four concerns, one submodule each:
//!
//! - [`build`] — compile parsed [`Manifest`]s into an `index.sqlite` (used by
//!   tests and, later, the registry CI compiler).
//! - [`sign`] — Ed25519 sign/verify plus the embedded `DEV_PUBKEY`.
//! - [`net`] — the `voli update` download/verify/atomic-swap flow.
//! - [`query`] — `search`, `info`, and the install-miss `did_you_mean`.
//!
//! Search/info/did-you-mean run against the local sqlite — instant, offline.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

pub mod build;
pub mod net;
pub mod query;
pub mod sign;

pub use build::build;
pub use net::{UpdateOutcome, update};
pub use query::{
    SearchHit, Suggestion, did_you_mean, did_you_mean_ref, info, info_ref, manifest_at,
    manifest_at_ref, search,
};
pub use sign::{DEV_PUBKEY, sign, verify};

/// Errors from the index client.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("index db error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manifest serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("manifest error: {0}")]
    Manifest(#[from] crate::manifest::ManifestError),

    #[error("no package index yet — run `voli update` first")]
    NoIndex,

    #[error("couldn't reach index at {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("index snapshot decompression failed: {0}")]
    Decompress(String),
    #[error("index hash mismatch: index.json says {expected}, snapshot is {actual}")]
    Sha256Mismatch { expected: String, actual: String },
    #[error("index size mismatch: index.json says {expected} bytes, snapshot is {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("index signature is invalid — refusing to install an untrusted index")]
    BadSignature,
    #[error("bad Ed25519 key: {0}")]
    BadKey(String),
}

/// Path to the local index sqlite: `<root>\db\index.sqlite`.
pub fn index_db_path(root: &Path) -> PathBuf {
    crate::paths::Paths::at(root).db().join("index.sqlite")
}

/// Open the local index read-only, or [`IndexError::NoIndex`] if not fetched yet.
fn open_index(root: &Path) -> Result<Connection, IndexError> {
    let path = index_db_path(root);
    if !path.exists() {
        return Err(IndexError::NoIndex);
    }
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?)
}

/// The newest version string among the rows for `(kind, name)`, if any.
fn latest_version(
    conn: &Connection,
    kind: crate::manifest::Kind,
    name: &str,
) -> Result<Option<String>, IndexError> {
    let table = if kind == crate::manifest::Kind::App {
        "packages"
    } else if conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'agent_packages')",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        "agent_packages"
    } else {
        return Ok(None);
    };
    let versions: Vec<String> = if kind == crate::manifest::Kind::App {
        let mut stmt = conn.prepare("SELECT DISTINCT version FROM packages WHERE name = ?1")?;
        stmt.query_map([name], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    } else {
        let mut stmt = conn.prepare(&format!(
            "SELECT DISTINCT version FROM {table} WHERE kind = ?1 AND name = ?2"
        ))?;
        stmt.query_map(rusqlite::params![kind.as_str(), name], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    Ok(versions.into_iter().max_by(|a, b| cmp_version(a, b)))
}

/// Compare two version strings, numeric-aware (`1.10.0 > 1.9.0`).
///
/// ponytail: naive dotted/dashed tokenization, not full semver — pre-release
/// precedence (`1.0.0-rc1 < 1.0.0`) is *not* modeled. Swap in the `semver` crate
/// if the catalog ever needs real pre-release ordering.
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let ta = tokenize_version(a);
    let tb = tokenize_version(b);
    for (x, y) in ta.iter().zip(tb.iter()) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(nx), Ok(ny)) => nx.cmp(&ny),
            _ => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    ta.len().cmp(&tb.len())
}

fn tokenize_version(v: &str) -> Vec<&str> {
    v.split(['.', '-', '+', '_'])
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_is_numeric_aware() {
        assert_eq!(cmp_version("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(cmp_version("2.0.0", "1.99.99"), Ordering::Greater);
        assert_eq!(cmp_version("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp_version("1.0", "1.0.1"), Ordering::Less);
    }
}
