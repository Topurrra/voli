//! `voli update` / `search` / `info` — the index client CLI (spec §5, §9, §11
//! step 6). The heavy lifting lives in `voli_core::index`; this file is just
//! argument plumbing, human/`--json` formatting, and exit codes.
//!
//! Signatures match how `main.rs` routes (`root` resolved by the caller, plain
//! `i32` exit code returned).

use std::path::Path;

use voli_core::config::Config;
use voli_core::index::{self, IndexError, UpdateOutcome};
use voli_core::{Kind, PackageRef};

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
    crate::print_index_error(context, &e);
    EXIT_ERROR
}

// ---- voli update ----------------------------------------------------------

pub fn run_update(root: &Path, json: bool) -> i32 {
    let spinner = (!json).then(|| crate::stage_spinner("refreshing package index".to_string()));
    let result = index::update(root, &index_url(root));
    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }
    match result {
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
        Err(e) => fail("update the package index", e),
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
            println!(
                "{} index is already up to date (epoch {epoch})",
                crate::success_mark()
            );
        }
        UpdateOutcome::Updated { epoch, size } => {
            println!(
                "{} updated index to epoch {epoch} ({size} bytes)",
                crate::success_mark()
            );
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
    let spinner = (!json).then(|| crate::stage_spinner(format!("searching for {query}")));
    let hits = match index::search(root, query) {
        Ok(h) => h,
        Err(e) => {
            if let Some(spinner) = spinner {
                spinner.finish_and_clear();
            }
            return fail("search packages", e);
        }
    };
    if let Some(spinner) = spinner {
        spinner.finish_and_clear();
    }

    if json {
        let arr: Vec<_> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "kind": h.kind.as_str(),
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
    let display_names: Vec<String> = hits
        .iter()
        .map(|hit| qualified_name(hit.kind, &hit.name))
        .collect();
    let namew = display_names.iter().map(String::len).max().unwrap_or(0);
    let verw = hits.iter().map(|h| h.version.len()).max().unwrap_or(0);
    for (h, name) in hits.iter().zip(display_names) {
        let desc = h.description.as_deref().unwrap_or("");
        println!("{name:<namew$}  {:<verw$}  {}", h.version, desc);
    }
    EXIT_OK
}

// ---- voli info ------------------------------------------------------------

pub fn run_info(root: &Path, package: &str, json: bool) -> i32 {
    let package_ref = match PackageRef::parse(package) {
        Ok(package) => package,
        Err(error) => {
            eprintln!("error: invalid package '{package}': {error}");
            return EXIT_ERROR;
        }
    };
    let found = match index::info_ref(root, &package_ref) {
        Ok(m) => m,
        Err(e) => return fail("read package information", e),
    };

    let Some(m) = found else {
        return info_not_found(root, &package_ref, package, json);
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&m).unwrap());
        return EXIT_OK;
    }
    // Showing a package under a name the user did not type, without saying so,
    // is how someone ends up believing `python` is still in the catalog.
    if m.name != package_ref.name {
        println!("note: {} is now {}", package_ref.name, m.name);
    }
    println!("{} {}", qualified_name(m.kind, &m.name), m.version);
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
        m.source.any.as_ref().map(|_| "any"),
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
fn info_not_found(root: &Path, package_ref: &PackageRef, package: &str, json: bool) -> i32 {
    if json {
        println!("null");
        return EXIT_ERROR;
    }
    eprintln!("error: package '{package}' not found");
    if let Ok(suggestions) = index::did_you_mean_ref(root, package_ref) {
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
    let namew = suggestions
        .iter()
        .map(|suggestion| qualified_name(suggestion.kind, &suggestion.name).len())
        .max()
        .unwrap_or(0);
    for s in suggestions {
        let name = qualified_name(s.kind, &s.name);
        let bin = s
            .bin
            .as_ref()
            .map(|b| format!(" ({b})"))
            .unwrap_or_default();
        let desc = s.description.as_deref().unwrap_or("");
        eprintln!("  {name:<namew$}{bin}  {desc}");
    }
}

fn qualified_name(kind: Kind, name: &str) -> String {
    match kind {
        Kind::App => name.to_string(),
        Kind::Mcp | Kind::Skill => format!("{}/{name}", kind.as_str()),
    }
}
