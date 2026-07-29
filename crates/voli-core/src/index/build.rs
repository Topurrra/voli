//! Index builder (spec §5): parsed manifests → `index.sqlite`.
//!
//! App rows retain the v0.5 `packages` and `packages_fts` schema so released
//! clients never see agent packages. Skills and MCPs use parallel typed tables.
//!
//! This is a library function so the registry CI compiler reuses it verbatim.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::{IndexError, cmp_version};
use crate::manifest::Manifest;

const SCHEMA: &str = "\
CREATE TABLE packages (
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    arch          TEXT NOT NULL,
    description   TEXT,
    homepage      TEXT,
    license       TEXT,
    kind          TEXT NOT NULL,
    manifest_toml TEXT NOT NULL,
    PRIMARY KEY (name, version, arch)
);
CREATE VIRTUAL TABLE packages_fts USING fts5(name, description, bin_names);
CREATE TABLE agent_packages (
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    arch          TEXT NOT NULL,
    description   TEXT,
    homepage      TEXT,
    license       TEXT,
    kind          TEXT NOT NULL,
    manifest_toml TEXT NOT NULL,
    PRIMARY KEY (kind, name, version, arch)
);
CREATE VIRTUAL TABLE agent_packages_fts
    USING fts5(kind UNINDEXED, name, description, bin_names);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);";

/// Build an `index.sqlite` at `out` from the given manifests (overwrites `out`).
///
/// Errors out if FTS5 is unavailable in the linked sqlite, or on any duplicate
/// (name, version, arch).
pub fn build(manifests: &[Manifest], out: &Path) -> Result<(), IndexError> {
    if out.exists() {
        std::fs::remove_file(out)?;
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut conn = Connection::open(out)?;
    conn.execute_batch(SCHEMA)?;

    let tx = conn.transaction()?;
    for m in manifests {
        let manifest_toml = toml::to_string(m)?;
        let table = if m.kind == crate::manifest::Kind::App {
            "packages"
        } else {
            "agent_packages"
        };
        for (arch, present) in [
            ("any", m.source.any.is_some()),
            ("x64", m.source.x64.is_some()),
            ("arm64", m.source.arm64.is_some()),
        ] {
            if !present {
                continue;
            }
            tx.execute(
                &format!(
                    "INSERT INTO {table}
                   (name, version, arch, description, homepage, license, kind, manifest_toml)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
                ),
                rusqlite::params![
                    m.name,
                    m.version,
                    arch,
                    m.description,
                    m.homepage,
                    m.license,
                    m.kind.as_str(),
                    manifest_toml,
                ],
            )?;
        }
    }

    // FTS: one row per package identity, using the newest version's manifest.
    for m in latest_per_identity(manifests) {
        let bin_names = bin_search_terms(m);
        if m.kind == crate::manifest::Kind::App {
            tx.execute(
                "INSERT INTO packages_fts (name, description, bin_names)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![m.name, m.description, bin_names],
            )?;
        } else {
            tx.execute(
                "INSERT INTO agent_packages_fts (kind, name, description, bin_names)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![m.kind.as_str(), m.name, m.description, bin_names],
            )?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Stamp the snapshot's epoch into its `meta` table — i.e. *inside* the bytes
/// the registry signs.
///
/// `index.json` is fetched over plain HTTP with no signature, so the epoch it
/// advertises is attacker-controlled: replaying a genuine older snapshot under
/// a forged huge epoch would otherwise downgrade the client *and* freeze it at
/// that epoch forever. The client compares this signed value, never the JSON.
pub fn stamp_epoch(db: &Path, epoch: u64) -> Result<(), IndexError> {
    Connection::open(db)?.execute(
        "INSERT INTO meta (key, value) VALUES ('epoch', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [epoch.to_string()],
    )?;
    Ok(())
}

/// Read the signed epoch stamped by [`stamp_epoch`]. `None` means the snapshot
/// predates the `meta` table — the client treats that as untrusted.
pub fn read_epoch(db: &Path) -> Result<Option<u64>, IndexError> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        return Ok(None);
    }
    let raw: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key = 'epoch'", [], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(raw.and_then(|v| v.trim().parse().ok()))
}

/// One manifest per distinct package identity, the one with the newest version.
fn latest_per_identity(manifests: &[Manifest]) -> Vec<&Manifest> {
    let mut best: std::collections::BTreeMap<(&str, &str), &Manifest> =
        std::collections::BTreeMap::new();
    for m in manifests {
        best.entry((m.kind.as_str(), &m.name))
            .and_modify(|cur| {
                if cmp_version(&m.version, &cur.version).is_gt() {
                    *cur = m;
                }
            })
            .or_insert(m);
    }
    best.into_values().collect()
}

/// Space-joined searchable bin terms: each bin's shim name and its path stem,
/// so `search rg` finds ripgrep whose only bin is `rg.exe`.
fn bin_search_terms(m: &Manifest) -> String {
    let mut terms = Vec::new();
    for b in &m.bin {
        terms.push(b.shim_name());
        if let Some(stem) = Path::new(b.path()).file_stem().and_then(|s| s.to_str())
            && !terms.iter().any(|t| t == stem)
        {
            terms.push(stem.to_string());
        }
    }
    terms.join(" ")
}
