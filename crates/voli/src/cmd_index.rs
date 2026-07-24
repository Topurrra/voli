//! `voli update` / `search` / `info` — the index client CLI (spec §5, §9, §11
//! step 6). The heavy lifting lives in `voli_core::index`; this file is just
//! argument plumbing, human/`--json` formatting, and exit codes.
//!
//! Signatures match how `main.rs` routes (`root` resolved by the caller, plain
//! `i32` exit code returned).

use std::path::Path;

use voli_core::config::Config;
use voli_core::index::{self, IndexError, UpdateOutcome};

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;

/// Index base URL: `VOLI_INDEX_URL` env override → `config.toml` `index_url`.
fn index_url(root: &Path) -> String {
    if let Some(u) = std::env::var_os("VOLI_INDEX_URL") {
        return u.to_string_lossy().into_owned();
    }
    Config::load(&root.join("config.toml")).index_url
}

/// Map an index error to a clean one-line message + error exit code.
fn fail(context: &str, e: IndexError) -> i32 {
    eprintln!("error: {context}: {e}");
    EXIT_ERROR
}

// ---- voli update ----------------------------------------------------------

pub fn run_update(root: &Path, json: bool) -> i32 {
    match index::update(root, &index_url(root)) {
        Ok(outcome) => {
            print_update(&outcome, json);
            match outcome {
                // Offline with no local copy is the only "nothing usable" case.
                UpdateOutcome::Offline {
                    local_epoch: None, ..
                } => EXIT_ERROR,
                _ => EXIT_OK,
            }
        }
        Err(e) => fail("update failed", e),
    }
}

fn print_update(outcome: &UpdateOutcome, json: bool) {
    if json {
        let v = match outcome {
            UpdateOutcome::UpToDate { epoch } => {
                serde_json::json!({ "status": "up_to_date", "epoch": epoch })
            }
            UpdateOutcome::Updated { epoch, size } => {
                serde_json::json!({ "status": "updated", "epoch": epoch, "size": size })
            }
            UpdateOutcome::Offline {
                local_epoch,
                local_date,
            } => serde_json::json!({
                "status": "offline",
                "local_epoch": local_epoch,
                "local_date": local_date,
            }),
        };
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return;
    }
    match outcome {
        UpdateOutcome::UpToDate { epoch } => {
            println!("index is already up to date (epoch {epoch})");
        }
        UpdateOutcome::Updated { epoch, size } => {
            println!("updated index to epoch {epoch} ({size} bytes)");
        }
        UpdateOutcome::Offline {
            local_epoch: Some(_),
            local_date,
        } => {
            let when = local_date.as_deref().unwrap_or("an earlier date");
            eprintln!("couldn't reach index, using local copy from {when}");
        }
        UpdateOutcome::Offline {
            local_epoch: None, ..
        } => {
            eprintln!("couldn't reach index and no local copy is present");
            eprintln!("       check your connection, then run `voli update` again");
        }
    }
}

// ---- voli search ----------------------------------------------------------

pub fn run_search(root: &Path, query: &str, json: bool) -> i32 {
    let hits = match index::search(root, query) {
        Ok(h) => h,
        Err(e) => return fail("search failed", e),
    };

    if json {
        let arr: Vec<_> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.name,
                    "version": h.version,
                    "description": h.description,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        return EXIT_OK;
    }

    if hits.is_empty() {
        println!("no packages match '{query}'");
        return EXIT_OK;
    }
    let namew = hits.iter().map(|h| h.name.len()).max().unwrap_or(0);
    let verw = hits.iter().map(|h| h.version.len()).max().unwrap_or(0);
    for h in &hits {
        let desc = h.description.as_deref().unwrap_or("");
        println!("{:<namew$}  {:<verw$}  {}", h.name, h.version, desc);
    }
    EXIT_OK
}

// ---- voli info ------------------------------------------------------------

pub fn run_info(root: &Path, package: &str, json: bool) -> i32 {
    let found = match index::info(root, package) {
        Ok(m) => m,
        Err(e) => return fail("info failed", e),
    };

    let Some(m) = found else {
        return info_not_found(root, package, json);
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&m).unwrap());
        return EXIT_OK;
    }
    println!("{} {}", m.name, m.version);
    if let Some(d) = &m.description {
        println!("  {d}");
    }
    if let Some(h) = &m.homepage {
        println!("  homepage: {h}");
    }
    if let Some(l) = &m.license {
        println!("  license:  {l}");
    }
    let arches: Vec<&str> = [
        m.source.x64.as_ref().map(|_| "x64"),
        m.source.arm64.as_ref().map(|_| "arm64"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !arches.is_empty() {
        println!("  arch:     {}", arches.join(", "));
    }
    if !m.bin.is_empty() {
        let bins: Vec<String> = m.bin.iter().map(|b| b.shim_name()).collect();
        println!("  bin:      {}", bins.join(", "));
    }
    EXIT_OK
}

/// Not-found path: emit did-you-mean suggestions (spec §5) and exit non-zero.
fn info_not_found(root: &Path, package: &str, json: bool) -> i32 {
    if json {
        println!("null");
        return EXIT_ERROR;
    }
    eprintln!("error: package '{package}' not found");
    if let Ok(suggestions) = index::did_you_mean(root, package) {
        print_suggestions(&suggestions);
    }
    EXIT_ERROR
}

/// Shared "Did you mean:" block, also used later by the install-miss path.
pub fn print_suggestions(suggestions: &[index::Suggestion]) {
    if suggestions.is_empty() {
        return;
    }
    eprintln!("Did you mean:");
    let namew = suggestions.iter().map(|s| s.name.len()).max().unwrap_or(0);
    for s in suggestions {
        let bin = s
            .bin
            .as_ref()
            .map(|b| format!(" ({b})"))
            .unwrap_or_default();
        let desc = s.description.as_deref().unwrap_or("");
        eprintln!("  {:<namew$}{bin}  {desc}", s.name);
    }
}
