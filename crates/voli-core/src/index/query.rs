//! Local index queries: `search`, `info`, `did_you_mean` (spec §5).
//!
//! All read the downloaded `index.sqlite` — instant and offline. A missing
//! index surfaces as [`IndexError::NoIndex`] ("run `voli update` first").

use rusqlite::{Connection, OptionalExtension};

use super::{IndexError, latest_version, open_index};
use crate::manifest::{Kind, Manifest, PackageRef};

/// Minimum Jaro-Winkler similarity for a did-you-mean suggestion (spec §5).
const DYM_THRESHOLD: f64 = 0.75;
const DYM_LIMIT: usize = 5;

/// A search result row: package name, latest version, short description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub kind: Kind,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
}

/// A did-you-mean suggestion for an install miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub kind: Kind,
    pub name: String,
    /// A representative bin name (e.g. `rg` for ripgrep), if any.
    pub bin: Option<String>,
    pub description: Option<String>,
}

/// Search the index: FTS5 match first, substring fallback if it finds nothing.
/// Results are ranked (best first for FTS; name-ordered for the fallback).
pub fn search(root: &std::path::Path, query: &str) -> Result<Vec<SearchHit>, IndexError> {
    let conn = open_index(root)?;
    let mut names = fts_names(&conn, query)?;
    if names.is_empty() {
        names = substring_names(&conn, query)?;
    }
    let mut hits = Vec::with_capacity(names.len());
    for package in names {
        if let Some(version) = latest_version(&conn, package.kind, &package.name)? {
            let description = description_of(&conn, package.kind, &package.name, &version)?;
            hits.push(SearchHit {
                kind: package.kind,
                name: package.name,
                version,
                description,
            });
        }
    }
    Ok(hits)
}

/// Full manifest of the latest version of `name`, or `None` if not in the index.
pub fn info(root: &std::path::Path, name: &str) -> Result<Option<Manifest>, IndexError> {
    info_ref(
        root,
        &PackageRef {
            kind: Kind::App,
            name: name.to_string(),
        },
    )
}

/// Full manifest of the latest version of a kind-qualified package identity.
pub fn info_ref(
    root: &std::path::Path,
    package: &PackageRef,
) -> Result<Option<Manifest>, IndexError> {
    let conn = open_index(root)?;
    let name = resolve(&conn, package)?;
    let Some(version) = latest_version(&conn, package.kind, &name)? else {
        return Ok(None);
    };
    let toml_text: String = if package.kind == Kind::App {
        conn.query_row(
            "SELECT manifest_toml FROM packages
             WHERE name = ?1 AND version = ?2 LIMIT 1",
            rusqlite::params![name, version],
            |r| r.get(0),
        )?
    } else {
        conn.query_row(
            "SELECT manifest_toml FROM agent_packages
             WHERE kind = ?1 AND name = ?2 AND version = ?3 LIMIT 1",
            rusqlite::params![package.kind.as_str(), name, version],
            |r| r.get(0),
        )?
    };
    Ok(Some(Manifest::from_toml_str(&toml_text)?))
}

/// The real package name for `package`, following an alias if the name is one.
///
/// A real package always wins over an alias, so a catalog that later reuses a
/// retired name resolves to the live package rather than the redirect. Exactly
/// one hop: the build rejects an alias pointing at another alias, so there is
/// no chain to walk and no cycle to guard against.
fn resolve(conn: &Connection, package: &PackageRef) -> Result<String, IndexError> {
    if latest_version(conn, package.kind, &package.name)?.is_some() {
        return Ok(package.name.clone());
    }
    if !table_exists(conn, "aliases")? {
        return Ok(package.name.clone()); // index predates aliases
    }
    let aliased: Option<String> = conn
        .query_row(
            "SELECT name FROM aliases WHERE alias = ?1 AND kind = ?2",
            rusqlite::params![package.name, package.kind.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(aliased.unwrap_or_else(|| package.name.clone()))
}

/// The real name `name` resolves to, or `None` when it is already real or
/// unknown. Callers use this to *report* a rename; resolution itself is
/// automatic in [`info_ref`] and [`manifest_at_ref`].
pub fn resolved_alias(
    root: &std::path::Path,
    package: &PackageRef,
) -> Result<Option<String>, IndexError> {
    let conn = open_index(root)?;
    let real = resolve(&conn, package)?;
    Ok((real != package.name).then_some(real))
}

/// Manifest of a specific `name`@`version`, or `None` if that exact (name,
/// version) pair is not in the index. Used by the remote installer to pin `@version`.
pub fn manifest_at(
    root: &std::path::Path,
    name: &str,
    version: &str,
) -> Result<Option<Manifest>, IndexError> {
    manifest_at_ref(
        root,
        &PackageRef {
            kind: Kind::App,
            name: name.to_string(),
        },
        version,
    )
}

/// Manifest of a specific kind-qualified package identity at `version`.
pub fn manifest_at_ref(
    root: &std::path::Path,
    package: &PackageRef,
    version: &str,
) -> Result<Option<Manifest>, IndexError> {
    let conn = open_index(root)?;
    let name = resolve(&conn, package)?;
    let toml_text: Option<String> = if package.kind == Kind::App {
        conn.query_row(
            "SELECT manifest_toml FROM packages
             WHERE name = ?1 AND version = ?2 LIMIT 1",
            rusqlite::params![name, version],
            |r| r.get(0),
        )
        .ok()
    } else if table_exists(&conn, "agent_packages")? {
        conn.query_row(
            "SELECT manifest_toml FROM agent_packages
             WHERE kind = ?1 AND name = ?2 AND version = ?3 LIMIT 1",
            rusqlite::params![package.kind.as_str(), name, version],
            |r| r.get(0),
        )
        .ok()
    } else {
        None
    };
    match toml_text {
        Some(t) => Ok(Some(Manifest::from_toml_str(&t)?)),
        None => Ok(None),
    }
}

/// All indexed versions of an app `name` (following an alias), newest first.
fn versions(root: &std::path::Path, name: &str) -> Result<Vec<String>, IndexError> {
    let conn = open_index(root)?;
    let name = resolve(
        &conn,
        &PackageRef {
            kind: Kind::App,
            name: name.to_string(),
        },
    )?;
    let mut vs = super::versions_of(&conn, Kind::App, &name)?;
    vs.sort_by(|a, b| super::cmp_version(b, a));
    Ok(vs)
}

/// The newest indexed app version of `name` that satisfies `constraint`, or
/// `None` when none do. Ordering and matching reuse `cmp_version`/`satisfies`,
/// keeping constraint resolution consistent with the rest of version handling.
pub fn newest_satisfying(
    root: &std::path::Path,
    name: &str,
    constraint: &str,
) -> Result<Option<String>, IndexError> {
    Ok(versions(root, name)?
        .into_iter()
        .find(|v| super::satisfies(v, constraint)))
}

/// Suggestions for a name that missed: Jaro-Winkler ≥ 0.75 over package names
/// AND bin names, best 5 first (spec §5 install-miss path).
pub fn did_you_mean(root: &std::path::Path, wrong: &str) -> Result<Vec<Suggestion>, IndexError> {
    did_you_mean_ref(
        root,
        &PackageRef {
            kind: Kind::App,
            name: wrong.to_string(),
        },
    )
}

/// Suggestions within the same package kind as `wrong`.
pub fn did_you_mean_ref(
    root: &std::path::Path,
    wrong: &PackageRef,
) -> Result<Vec<Suggestion>, IndexError> {
    let conn = open_index(root)?;
    let name_to_match = wrong.name.to_ascii_lowercase();

    // (name, bin_names) for this package kind, cheap and no manifest parsing.
    let rows: Vec<(String, String)> = if wrong.kind == Kind::App {
        let mut stmt = conn.prepare("SELECT name, bin_names FROM packages_fts")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    } else if table_exists(&conn, "agent_packages_fts")? {
        let mut stmt =
            conn.prepare("SELECT name, bin_names FROM agent_packages_fts WHERE kind = ?1")?;
        stmt.query_map([wrong.kind.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    } else {
        Vec::new()
    };

    let mut scored: Vec<(f64, String)> = Vec::new();
    for (name, bin_names) in rows {
        let mut best = strsim::jaro_winkler(&name_to_match, &name.to_ascii_lowercase());
        for bin in bin_names.split_whitespace() {
            best = best.max(strsim::jaro_winkler(
                &name_to_match,
                &bin.to_ascii_lowercase(),
            ));
        }
        if best >= DYM_THRESHOLD {
            scored.push((best, name));
        }
    }
    // Best score first; ties broken by name for stable output.
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.cmp(&b.1))
    });
    scored.truncate(DYM_LIMIT);

    let mut out = Vec::with_capacity(scored.len());
    for (_, name) in scored {
        let bin = first_bin(&conn, wrong.kind, &name)?;
        let description = latest_version(&conn, wrong.kind, &name)?
            .map(|v| description_of(&conn, wrong.kind, &name, &v))
            .transpose()?
            .flatten();
        out.push(Suggestion {
            kind: wrong.kind,
            name,
            bin,
            description,
        });
    }
    Ok(out)
}

/// FTS5 names, best-match first. Empty query or no tokens → no FTS results.
fn fts_names(conn: &Connection, query: &str) -> Result<Vec<PackageRef>, IndexError> {
    // Pure-alphanumeric prefix tokens, AND-joined; punctuation stripped so a
    // user query can never inject FTS5 match syntax.
    let match_expr = query
        .split_whitespace()
        .map(|t| {
            t.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
        })
        .filter(|t| !t.is_empty())
        .map(|t| format!("{t}*"))
        .collect::<Vec<_>>()
        .join(" ");
    if match_expr.is_empty() {
        return Ok(Vec::new());
    }
    let mut names: Vec<PackageRef> = {
        let mut stmt = conn
            .prepare("SELECT name FROM packages_fts WHERE packages_fts MATCH ?1 ORDER BY rank")?;
        stmt.query_map([&match_expr], |row| {
            Ok(PackageRef {
                kind: Kind::App,
                name: row.get(0)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    if table_exists(conn, "agent_packages_fts")? {
        let mut stmt = conn.prepare(
            "SELECT kind, name FROM agent_packages_fts
             WHERE agent_packages_fts MATCH ?1 ORDER BY rank",
        )?;
        names.extend(
            stmt.query_map([&match_expr], package_ref_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    Ok(names)
}

/// Substring fallback over name and description, name-ordered.
fn substring_names(conn: &Connection, query: &str) -> Result<Vec<PackageRef>, IndexError> {
    let like = format!("%{}%", query.trim());
    let mut stmt = conn.prepare(
        "SELECT DISTINCT name FROM packages
         WHERE name LIKE ?1 OR IFNULL(description, '') LIKE ?1
         ORDER BY name ASC",
    )?;
    let mut names = stmt
        .query_map([&like], |row| {
            Ok(PackageRef {
                kind: Kind::App,
                name: row.get(0)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if table_exists(conn, "agent_packages")? {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT kind, name FROM agent_packages
             WHERE name LIKE ?1 OR IFNULL(description, '') LIKE ?1
             ORDER BY name ASC, kind ASC",
        )?;
        names.extend(
            stmt.query_map([&like], package_ref_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        );
    }
    Ok(names)
}

fn description_of(
    conn: &Connection,
    kind: Kind,
    name: &str,
    version: &str,
) -> Result<Option<String>, IndexError> {
    if kind == Kind::App {
        Ok(conn.query_row(
            "SELECT description FROM packages
             WHERE name = ?1 AND version = ?2 LIMIT 1",
            rusqlite::params![name, version],
            |r| r.get::<_, Option<String>>(0),
        )?)
    } else {
        Ok(conn.query_row(
            "SELECT description FROM agent_packages
             WHERE kind = ?1 AND name = ?2 AND version = ?3 LIMIT 1",
            rusqlite::params![kind.as_str(), name, version],
            |r| r.get::<_, Option<String>>(0),
        )?)
    }
}

/// First searchable bin term for a package (the `rg` in ripgrep), from FTS.
fn first_bin(conn: &Connection, kind: Kind, name: &str) -> Result<Option<String>, IndexError> {
    let bin_names: Option<String> = if kind == Kind::App {
        conn.query_row(
            "SELECT bin_names FROM packages_fts WHERE name = ?1 LIMIT 1",
            [name],
            |r| r.get(0),
        )
        .ok()
    } else if table_exists(conn, "agent_packages_fts")? {
        conn.query_row(
            "SELECT bin_names FROM agent_packages_fts
             WHERE kind = ?1 AND name = ?2 LIMIT 1",
            rusqlite::params![kind.as_str(), name],
            |r| r.get(0),
        )
        .ok()
    } else {
        None
    };
    Ok(bin_names
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .filter(|s| !s.is_empty()))
}

fn package_ref_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PackageRef> {
    let kind: String = row.get(0)?;
    let name = row.get(1)?;
    let kind = match kind.as_str() {
        "app" => Kind::App,
        "mcp" => Kind::Mcp,
        "skill" => Kind::Skill,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(PackageRef { kind, name })
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, IndexError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
        [table],
        |row| row.get(0),
    )?)
}
