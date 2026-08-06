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

pub use build::{build, read_epoch, stamp_epoch};
pub use net::{MAX_EPOCH, UpdateOutcome, update, update_with_pubkey};
pub use query::{
    SearchHit, Suggestion, did_you_mean, did_you_mean_ref, info, info_ref, manifest_at,
    manifest_at_ref, newest_satisfying, resolved_alias, search,
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

    #[error("alias '{alias}' on '{package}' is already a real package name")]
    AliasShadowsPackage { alias: String, package: String },
    #[error("alias '{alias}' is claimed by both '{first}' and '{second}'")]
    AliasClaimedTwice {
        alias: String,
        first: String,
        second: String,
    },

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
    #[error("{url} is larger than the {limit}-byte cap for this index file")]
    TooLarge { url: String, limit: u64 },
    #[error(
        "index snapshot carries no signed epoch — it was built by a registry older than this \
         client; refusing it because an unsigned epoch can be replayed to force a downgrade"
    )]
    UnsignedEpoch,
    #[error("index epoch {0} is out of range — refusing it")]
    BadEpoch(u64),
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
    Ok(versions_of(conn, kind, name)?
        .into_iter()
        .max_by(|a, b| cmp_version(a, b)))
}

/// Every distinct version string for `(kind, name)`, unordered. Empty when the
/// package (or the agent-packages table) is absent.
fn versions_of(
    conn: &Connection,
    kind: crate::manifest::Kind,
    name: &str,
) -> Result<Vec<String>, IndexError> {
    if kind == crate::manifest::Kind::App {
        let mut stmt = conn.prepare("SELECT DISTINCT version FROM packages WHERE name = ?1")?;
        return Ok(stmt
            .query_map([name], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?);
    }
    if !conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'agent_packages')",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(Vec::new());
    }
    let mut stmt =
        conn.prepare("SELECT DISTINCT version FROM agent_packages WHERE kind = ?1 AND name = ?2")?;
    Ok(stmt
        .query_map(rusqlite::params![kind.as_str(), name], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?)
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

/// True if version `v` satisfies a `[depends]` `constraint`.
///
/// Grammar (the operators the catalog actually uses): `*` or empty (any); a bare
/// version for an exact match (`1.2.3`, optionally written `=1.2.3`); the
/// comparisons `>=`, `>`, `<=`, `<`; and the range shorthands `^` (caret) and
/// `~` (tilde). Ordering and equality reuse [`cmp_version`], so this inherits its
/// numeric-aware, dotted/dashed tokenization (and its lack of pre-release
/// precedence).
///
/// ponytail: hand-rolled over single constraints - no unions (`>=1,<2`). Swap in
/// the `semver` crate if the catalog ever needs unions or real pre-release order.
fn satisfies(v: &str, constraint: &str) -> bool {
    let c = constraint.trim();
    if c.is_empty() || c == "*" {
        return true;
    }
    if let Some(base) = c.strip_prefix(">=") {
        return cmp_version(v, base.trim()) != Ordering::Less;
    }
    if let Some(base) = c.strip_prefix("<=") {
        return cmp_version(v, base.trim()) != Ordering::Greater;
    }
    if let Some(base) = c.strip_prefix('>') {
        return cmp_version(v, base.trim()) == Ordering::Greater;
    }
    if let Some(base) = c.strip_prefix('<') {
        return cmp_version(v, base.trim()) == Ordering::Less;
    }
    if let Some(base) = c.strip_prefix('^') {
        let base = base.trim();
        return cmp_version(v, base) != Ordering::Less && below(v, &caret_upper(base));
    }
    if let Some(base) = c.strip_prefix('~') {
        let base = base.trim();
        return cmp_version(v, base) != Ordering::Less && below(v, &tilde_upper(base));
    }
    let base = c.strip_prefix('=').map(str::trim).unwrap_or(c);
    cmp_version(v, base) == Ordering::Equal
}

/// Numeric components of a version, stopping at the first non-numeric token
/// (`1.2.3-rc1` -> `[1, 2, 3]`). Used to build caret/tilde upper bounds.
fn numeric_parts(v: &str) -> Vec<u64> {
    let mut parts = Vec::new();
    for tok in v.split(['.', '-', '+', '_']) {
        match tok.parse::<u64>() {
            Ok(n) => parts.push(n),
            Err(_) => break,
        }
    }
    parts
}

/// Exclusive upper bound for a caret constraint, as numeric parts. `^1.2.3` ->
/// `[2]` (<2.0.0); `^0.2.3` -> `[0, 3]` (<0.3.0); `^0.0.3` -> `[0, 0, 4]`. An
/// all-zero base bumps its last component (`^0.0.0` -> `[0, 0, 1]`).
fn caret_upper(base: &str) -> Vec<u64> {
    let mut parts = numeric_parts(base);
    if parts.is_empty() {
        return parts;
    }
    let idx = parts
        .iter()
        .position(|&n| n != 0)
        .unwrap_or(parts.len() - 1);
    parts[idx] += 1;
    parts.truncate(idx + 1);
    parts
}

/// Exclusive upper bound for a tilde constraint, as numeric parts. `~1.2.3` and
/// `~1.2` -> `[1, 3]` (<1.3.0); `~1` -> `[2]` (<2.0.0).
fn tilde_upper(base: &str) -> Vec<u64> {
    let mut parts = numeric_parts(base);
    if parts.is_empty() {
        return parts;
    }
    let idx = if parts.len() >= 2 { 1 } else { 0 };
    parts[idx] += 1;
    parts.truncate(idx + 1);
    parts
}

/// True if `v`'s numeric parts fall below an exclusive `upper` bound. An empty
/// bound (unparseable base) imposes no ceiling.
fn below(v: &str, upper: &[u64]) -> bool {
    upper.is_empty() || numeric_parts(v).as_slice() < upper
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

    #[test]
    fn satisfies_matches_operators() {
        // star / empty: anything.
        assert!(satisfies("1.0.0", "*"));
        assert!(satisfies("9.9.9", ""));
        // exact (bare and =).
        assert!(satisfies("1.2.3", "1.2.3"));
        assert!(satisfies("1.2.3", "=1.2.3"));
        assert!(!satisfies("1.2.4", "1.2.3"));
        // Comparisons (>= before >, <= before < in the parser). Same component
        // count on both sides so the naive comparator's length tie-break
        // (`1.2.0` > `1.2`) does not muddy equality.
        assert!(satisfies("1.2.0", ">=1.2.0"));
        assert!(satisfies("2.0.0", ">=1.2.0"));
        assert!(!satisfies("1.1.9", ">=1.2.0"));
        assert!(satisfies("1.1.0", "<1.2.0"));
        assert!(!satisfies("1.2.0", "<1.2.0"));
        assert!(satisfies("1.2.0", "<=1.2.0"));
        assert!(!satisfies("1.2.1", "<=1.2.0"));
        assert!(satisfies("1.3.0", ">1.2.0"));
        assert!(!satisfies("1.2.0", ">1.2.0"));
        // caret: ^1.2.3 -> >=1.2.3, <2.0.0.
        assert!(satisfies("1.9.9", "^1.2.3"));
        assert!(!satisfies("2.0.0", "^1.2.3"));
        assert!(!satisfies("1.2.2", "^1.2.3"));
        // caret with a leading zero: ^0.2.3 -> >=0.2.3, <0.3.0.
        assert!(satisfies("0.2.9", "^0.2.3"));
        assert!(!satisfies("0.3.0", "^0.2.3"));
        // tilde: ~1.2 -> >=1.2.0, <1.3.0.
        assert!(satisfies("1.2.9", "~1.2"));
        assert!(!satisfies("1.3.0", "~1.2"));
    }
}
