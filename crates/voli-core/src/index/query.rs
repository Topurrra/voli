//! Local index queries: `search`, `info`, `did_you_mean` (spec §5).
//!
//! All read the downloaded `index.sqlite` — instant and offline. A missing
//! index surfaces as [`IndexError::NoIndex`] ("run `voli update` first").

use rusqlite::Connection;

use super::{IndexError, latest_version, open_index};
use crate::manifest::Manifest;

/// Minimum Jaro-Winkler similarity for a did-you-mean suggestion (spec §5).
const DYM_THRESHOLD: f64 = 0.75;
const DYM_LIMIT: usize = 5;

/// A search result row: package name, latest version, short description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
}

/// A did-you-mean suggestion for an install miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
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
    for name in names {
        if let Some(version) = latest_version(&conn, &name)? {
            let description = description_of(&conn, &name, &version)?;
            hits.push(SearchHit {
                name,
                version,
                description,
            });
        }
    }
    Ok(hits)
}

/// Full manifest of the latest version of `name`, or `None` if not in the index.
pub fn info(root: &std::path::Path, name: &str) -> Result<Option<Manifest>, IndexError> {
    let conn = open_index(root)?;
    let Some(version) = latest_version(&conn, name)? else {
        return Ok(None);
    };
    let toml_text: String = conn.query_row(
        "SELECT manifest_toml FROM packages WHERE name = ?1 AND version = ?2 LIMIT 1",
        rusqlite::params![name, version],
        |r| r.get(0),
    )?;
    Ok(Some(Manifest::from_toml_str(&toml_text)?))
}

/// Suggestions for a name that missed: Jaro-Winkler ≥ 0.75 over package names
/// AND bin names, best 5 first (spec §5 install-miss path).
pub fn did_you_mean(root: &std::path::Path, wrong: &str) -> Result<Vec<Suggestion>, IndexError> {
    let conn = open_index(root)?;
    let wrong = wrong.to_ascii_lowercase();

    // (name, bin_names) for every package — cheap, no manifest parsing.
    let mut stmt = conn.prepare("SELECT name, bin_names FROM packages_fts")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut scored: Vec<(f64, String)> = Vec::new();
    for (name, bin_names) in rows {
        let mut best = strsim::jaro_winkler(&wrong, &name.to_ascii_lowercase());
        for bin in bin_names.split_whitespace() {
            best = best.max(strsim::jaro_winkler(&wrong, &bin.to_ascii_lowercase()));
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
        let bin = first_bin(&conn, &name)?;
        let description = latest_version(&conn, &name)?
            .map(|v| description_of(&conn, &name, &v))
            .transpose()?
            .flatten();
        out.push(Suggestion {
            name,
            bin,
            description,
        });
    }
    Ok(out)
}

/// FTS5 names, best-match first. Empty query or no tokens → no FTS results.
fn fts_names(conn: &Connection, query: &str) -> Result<Vec<String>, IndexError> {
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
    let mut stmt =
        conn.prepare("SELECT name FROM packages_fts WHERE packages_fts MATCH ?1 ORDER BY rank")?;
    let names = stmt
        .query_map([&match_expr], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(names)
}

/// Substring fallback over name and description, name-ordered.
fn substring_names(conn: &Connection, query: &str) -> Result<Vec<String>, IndexError> {
    let like = format!("%{}%", query.trim());
    let mut stmt = conn.prepare(
        "SELECT DISTINCT name FROM packages
         WHERE name LIKE ?1 OR IFNULL(description, '') LIKE ?1
         ORDER BY name ASC",
    )?;
    let names = stmt
        .query_map([&like], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(names)
}

fn description_of(
    conn: &Connection,
    name: &str,
    version: &str,
) -> Result<Option<String>, IndexError> {
    Ok(conn.query_row(
        "SELECT description FROM packages WHERE name = ?1 AND version = ?2 LIMIT 1",
        rusqlite::params![name, version],
        |r| r.get::<_, Option<String>>(0),
    )?)
}

/// First searchable bin term for a package (the `rg` in ripgrep), from FTS.
fn first_bin(conn: &Connection, name: &str) -> Result<Option<String>, IndexError> {
    let bin_names: Option<String> = conn
        .query_row(
            "SELECT bin_names FROM packages_fts WHERE name = ?1 LIMIT 1",
            [name],
            |r| r.get(0),
        )
        .ok();
    Ok(bin_names
        .and_then(|s| s.split_whitespace().next().map(str::to_string))
        .filter(|s| !s.is_empty()))
}
