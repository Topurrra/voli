//! `voli install <pkg>[@version] …` (spec §9, §11 step 9).
//!
//! Two paths, auto-detected:
//! - **local**: a single `<name>.toml` file argument plus `--archive <path>` runs
//!   the local engine directly (the step-3 path, kept verbatim).
//! - **network**: everything else resolves names against the downloaded index,
//!   downloads (with a progress bar), and installs deps-first.
//!
//! `--json` swaps the human output (progress bars + confirmations) for a single
//! machine report.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use voli_core::{
    Manifest, RemoteError, RemoteReport, Step, env, install_manifest, install_remote_env,
};

use crate::cmd_index;

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;

/// Entry point for the `install` subcommand.
pub fn run(
    packages: &[String],
    archive: Option<&Path>,
    root: &Path,
    json: bool,
    yes: bool,
    no_env: bool,
) -> i32 {
    // `--yes`, `--json`, or a non-TTY stdin all mean "don't wait for input":
    // apply env without prompting (spec §8, §9).
    let auto = yes || json || !std::io::stdin().is_terminal();
    if let Some((manifest, name)) = local_manifest(packages) {
        return install_local_path(manifest, name, archive, root, auto, no_env);
    }
    install_network(packages, root, json, auto, no_env)
}

/// Build the per-package env consent closure (spec §8). Prints the requested
/// vars, then applies without prompting when `auto`, skips entirely when
/// `no_env`, and otherwise asks `Apply? [Y/n]` (default yes).
fn env_consent(auto: bool, no_env: bool) -> impl FnMut(&str, &[(String, String)]) -> bool {
    move |name: &str, resolved: &[(String, String)]| {
        if no_env {
            println!("{name} requested environment variables — skipped (--no-env)");
            return false;
        }
        println!("{name} wants to set environment variables:");
        for (k, v) in resolved {
            println!("  {k} = {v}");
        }
        if auto {
            return true;
        }
        print!("Apply? [Y/n] ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        let a = line.trim().to_ascii_lowercase();
        a.is_empty() || a == "y" || a == "yes"
    }
}

/// If this is the local-manifest form (exactly one `<name>.toml` file arg),
/// return (manifest path, arg). Otherwise `None` → treat as network install.
fn local_manifest(packages: &[String]) -> Option<(&Path, &str)> {
    if packages.len() != 1 {
        return None;
    }
    let arg = &packages[0];
    let p = Path::new(arg);
    (arg.ends_with(".toml") && p.is_file()).then_some((p, arg.as_str()))
}

fn install_local_path(
    manifest: &Path,
    _arg: &str,
    archive: Option<&Path>,
    root: &Path,
    auto: bool,
    no_env: bool,
) -> i32 {
    let Some(archive) = archive else {
        eprintln!("error: --archive <path> is required to install from a local manifest");
        return EXIT_ERROR;
    };
    let text = match std::fs::read_to_string(manifest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", manifest.display());
            return EXIT_ERROR;
        }
    };
    let parsed = match Manifest::from_toml_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: invalid manifest: {e}");
            return EXIT_ERROR;
        }
    };
    let mut consent = env_consent(auto, no_env);
    match install_manifest(
        &parsed,
        archive,
        &[],
        root,
        &env::env_subkey(),
        &mut consent,
    ) {
        Ok(r) => {
            println!("installed {} {}", r.name, r.version);
            println!("  files: {}", r.version_dir.display());
            for shim in &r.shims {
                println!("  shim:  {}", shim.display());
            }
            print_env_note(&r.env_applied);
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: install failed: {e}");
            EXIT_ERROR
        }
    }
}

/// Split `name[@version]`; an empty version (`"foo@"`) is treated as unpinned.
fn parse_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once('@') {
        Some((name, ver)) if !ver.is_empty() => (name, Some(ver)),
        Some((name, _)) => (name, None),
        None => (spec, None),
    }
}

fn install_network(packages: &[String], root: &Path, json: bool, auto: bool, no_env: bool) -> i32 {
    let mut agg = RemoteReport::default();
    let mut failure: Option<(String, RemoteError)> = None;
    let subkey = env::env_subkey();
    let mut consent = env_consent(auto, no_env);

    for spec in packages {
        let (name, version) = parse_spec(spec);
        let mut reporter = Reporter::new(json);
        match install_remote_env(name, version, root, &subkey, &mut consent, &mut |s| {
            reporter.step(s)
        }) {
            Ok(mut report) => {
                agg.installed.append(&mut report.installed);
                agg.skipped.append(&mut report.skipped);
            }
            Err(e) => {
                failure = Some((name.to_string(), e));
                break; // a failure stops the chain (spec §9)
            }
        }
    }

    if json {
        print_json(&agg, failure.as_ref());
    } else if let Some((name, e)) = &failure {
        print_error(name, e);
    }
    if failure.is_some() {
        EXIT_ERROR
    } else {
        EXIT_OK
    }
}

/// Drives the live per-package progress bar from [`Step`] events (human mode).
/// In `--json` mode it does nothing — the report is printed once at the end.
struct Reporter {
    json: bool,
    bar: Option<ProgressBar>,
}

impl Reporter {
    fn new(json: bool) -> Reporter {
        Reporter { json, bar: None }
    }

    fn step(&mut self, step: Step) {
        if self.json {
            return;
        }
        match step {
            Step::Downloading { name, version } => {
                let pb = ProgressBar::new_spinner();
                pb.enable_steady_tick(Duration::from_millis(100));
                pb.set_style(
                    ProgressStyle::with_template("{spinner} {msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_spinner()),
                );
                pb.set_message(format!("downloading {name} {version}"));
                self.bar = Some(pb);
            }
            Step::Progress { done, total } => {
                if let Some(pb) = &self.bar {
                    match total {
                        Some(total) => {
                            if pb.length() != Some(total) {
                                pb.set_length(total);
                                pb.set_style(
                                    ProgressStyle::with_template(
                                        "{msg} [{bar:30}] {bytes}/{total_bytes}",
                                    )
                                    .unwrap_or_else(|_| ProgressStyle::default_bar())
                                    .progress_chars("=> "),
                                );
                            }
                            pb.set_position(done);
                        }
                        None => pb.set_position(done),
                    }
                }
            }
            Step::Installed(r) => {
                if let Some(pb) = self.bar.take() {
                    pb.finish_and_clear();
                }
                println!("installed {} {}", r.name, r.version);
                for shim in &r.shims {
                    println!("  shim: {}", shim.display());
                }
                print_env_note(&r.env_applied);
            }
            Step::Skipped { name, version } => {
                if let Some(pb) = self.bar.take() {
                    pb.finish_and_clear();
                }
                println!("{name} {version} already installed — skipped");
            }
        }
    }
}

/// Confirm the env vars that were actually applied (spec §8). Empty when the
/// package set none or the user declined.
fn print_env_note(env_applied: &[(String, String)]) {
    for (k, v) in env_applied {
        println!("  env:  {k} = {v}");
    }
}

fn print_error(name: &str, e: &RemoteError) {
    match e {
        RemoteError::NotFound { suggestions, .. } => {
            eprintln!("error: package '{name}' not found");
            cmd_index::print_suggestions(suggestions);
        }
        other => eprintln!("error: install failed: {other}"),
    }
}

fn print_json(agg: &RemoteReport, failure: Option<&(String, RemoteError)>) {
    let installed: Vec<_> = agg
        .installed
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "version": r.version,
                "version_dir": r.version_dir.display().to_string(),
                "shims": r.shims.iter().map(|s| s.display().to_string()).collect::<Vec<_>>(),
                "env_requested": r.env_requested.iter()
                    .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let skipped: Vec<_> = agg
        .skipped
        .iter()
        .map(|(n, v)| serde_json::json!({ "name": n, "version": v }))
        .collect();

    let mut obj = serde_json::json!({
        "ok": failure.is_none(),
        "installed": installed,
        "skipped": skipped,
    });
    if let Some((name, e)) = failure {
        let suggestions = match e {
            RemoteError::NotFound { suggestions, .. } => suggestions
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "bin": s.bin,
                        "description": s.description,
                    })
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        obj["error"] = serde_json::json!({
            "package": name,
            "message": e.to_string(),
            "suggestions": suggestions,
        });
    }
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
