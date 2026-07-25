//! voli command-line application.

mod cmd_index;
mod cmd_install;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use voli_core::{
    Action, Paths, State, Step, UpgradeOutcome, config, env, self_install, uninstall, upgrade,
};

/// Exit code for a runtime error (bad args, install failure, …).
const EXIT_ERROR: i32 = 1;

#[derive(Parser)]
#[command(
    name = "voli",
    bin_name = "voli",
    version,
    about = "A fast, no-admin package manager for Windows",
    arg_required_else_help = true
)]
struct Cli {
    /// Assume "yes" to prompts; never wait for interactive input.
    #[arg(long, global = true)]
    yes: bool,

    /// Emit machine-readable JSON where supported.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install one or more packages (pkg[@version] …).
    ///
    /// Installs from the signed index by default. To use a local manifest, pass
    /// `<name>.toml` together with `--archive <path>`.
    Install {
        #[arg(required = true)]
        packages: Vec<String>,
        /// Local archive to install from (required for a local `.toml` manifest).
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Do not apply any `[env]` environment variables (spec §8).
        #[arg(long)]
        no_env: bool,
    },
    /// Delete one or more packages.
    #[command(alias = "uninstall")]
    Delete {
        #[arg(required = true)]
        packages: Vec<String>,
        /// Also remove persist dirs (user data). Off by default.
        #[arg(long)]
        purge: bool,
    },
    /// Refresh the local package index.
    Update,
    /// Upgrade installed packages.
    Upgrade {
        packages: Vec<String>,
        /// Upgrade everything (except pinned packages).
        #[arg(long)]
        all: bool,
    },
    /// List installed packages with versions.
    List,
    /// Search the local index.
    Search {
        #[arg(required = true)]
        query: String,
    },
    /// Show details for a package.
    Info {
        #[arg(required = true)]
        package: String,
    },
    /// Pin a package (exclude from `upgrade --all`).
    Pin {
        #[arg(required = true)]
        package: String,
    },
    /// Unpin a package.
    Unpin {
        #[arg(required = true)]
        package: String,
    },
    /// Show the environment variables a package set (from the ledger).
    Env {
        #[arg(required = true)]
        package: String,
    },
    /// Remove non-current version dirs and stale cache.
    Cleanup {
        /// Delete cache entries older than N days (0 = all). Default 30.
        #[arg(long, default_value_t = 30)]
        cache_days: u64,
        /// Print what would be removed without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Install voli itself: copy binaries to bin\ and add shims\ to PATH.
    Setup,
    /// Get or set configuration values.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Diagnose PATH, env drift, broken shims, and root-folder warnings.
    Doctor,
    /// Resolve a shim to its real target.
    Which {
        #[arg(required = true)]
        bin: String,
    },
    /// Update voli itself.
    SelfUpdate,
    /// Delete voli and all installed packages completely (zero trace).
    #[command(alias = "self-uninstall")]
    SelfDelete,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print a config value.
    Get {
        #[arg(required = true)]
        key: String,
    },
    /// Set a config value.
    Set {
        #[arg(required = true)]
        key: String,
        #[arg(required = true)]
        value: String,
    },
}

fn main() {
    let cli = Cli::parse();

    // Nudge (message only, no action) when running from outside <root>\bin.
    if !matches!(cli.command, Command::Setup) {
        maybe_offer_setup();
    }

    let code = match &cli.command {
        Command::Install {
            packages,
            archive,
            no_env,
        } => cmd_install::run(
            packages,
            archive.as_deref(),
            &root(),
            cli.json,
            cli.yes,
            *no_env,
        ),
        Command::Delete { packages, purge } => cmd_delete(packages, *purge),
        Command::List => cmd_list(cli.json),
        Command::Upgrade { packages, all } => cmd_upgrade(packages, *all, cli.json),
        Command::Pin { package } => cmd_pin(package, true),
        Command::Unpin { package } => cmd_pin(package, false),
        Command::Env { package } => cmd_env(package, cli.json),
        Command::Cleanup {
            cache_days,
            dry_run,
        } => cmd_cleanup(*cache_days, *dry_run, cli.json),
        Command::Setup => cmd_setup(),
        Command::Config { action } => cmd_config(action, cli.json),
        Command::Doctor => cmd_doctor(cli.json),
        Command::Which { bin } => cmd_which(bin),
        Command::Update => cmd_index::run_update(&root(), cli.json),
        Command::Search { query } => cmd_index::run_search(&root(), query, cli.json),
        Command::Info { package } => cmd_index::run_info(&root(), package, cli.json),
        Command::SelfUpdate => cmd_self_update(),
        Command::SelfDelete => cmd_self_delete(cli.yes),
    };
    std::process::exit(code);
}

/// If voli is not running from `<root>\bin`, print a one-line hint to run
/// `voli setup`. Message only — never takes action (spec §11 step 5).
fn maybe_offer_setup() {
    let Ok(root) = config::resolve_root() else {
        return;
    };
    let bin = root.join("bin");
    let running_in_bin = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
        .zip(std::fs::canonicalize(&bin).ok())
        .map(|(dir, canon_bin)| std::fs::canonicalize(&dir).ok() == Some(canon_bin))
        .unwrap_or(false);
    if !running_in_bin {
        eprintln!("note: voli is not installed under {}", bin.display());
        eprintln!("      run `voli setup` to install it and add shims to your PATH.");
    }
}

fn root() -> PathBuf {
    match config::resolve_root() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot resolve voli root: {e}");
            std::process::exit(EXIT_ERROR);
        }
    }
}

fn cmd_delete(packages: &[String], purge: bool) -> i32 {
    let root = root();
    let mut code = 0;
    for name in packages {
        match uninstall(name, &root, purge) {
            Ok(r) => {
                println!("deleted {} {}", r.name, r.version);
                if r.kept_persist {
                    println!("  kept persist data (use --purge to remove it)");
                }
            }
            Err(e) => {
                eprintln!("error: delete '{name}' failed: {e}");
                code = EXIT_ERROR;
            }
        }
    }
    code
}

fn cmd_list(json: bool) -> i32 {
    let state = match State::open(&Paths::at(root()).state_db()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open state db: {e}");
            return EXIT_ERROR;
        }
    };
    let pkgs = match state.list() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot read state db: {e}");
            return EXIT_ERROR;
        }
    };

    if json {
        let arr: Vec<_> = pkgs
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "installed_at": p.installed_at,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else if pkgs.is_empty() {
        println!("no packages installed");
    } else {
        for p in &pkgs {
            println!("{}  {}", p.name, p.version);
        }
    }
    0
}

fn cmd_upgrade(packages: &[String], all: bool, json: bool) -> i32 {
    let root = root();

    // Determine the target set: explicit names, or every non-pinned package.
    let targets: Vec<(String, bool)> = if all {
        let state = match State::open(&Paths::at(&root).state_db()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: cannot open state db: {e}");
                return EXIT_ERROR;
            }
        };
        match state.list() {
            Ok(pkgs) => pkgs
                .into_iter()
                .filter(|p| p.name != "@voli")
                .map(|p| (p.name, p.pinned))
                .collect(),
            Err(e) => {
                eprintln!("error: cannot list installed packages: {e}");
                return EXIT_ERROR;
            }
        }
    } else if packages.is_empty() {
        eprintln!("error: specify a package to upgrade, or use --all");
        return EXIT_ERROR;
    } else {
        // Explicit upgrade proceeds even if pinned (spec §9), with a note.
        packages.iter().map(|n| (n.clone(), false)).collect()
    };

    let mut code = 0;
    let mut results = Vec::new();
    for (name, pinned_under_all) in &targets {
        if all && *pinned_under_all {
            if !json {
                println!("{name}: pinned — skipped");
            }
            results.push(serde_json::json!({ "name": name, "status": "pinned" }));
            continue;
        }
        // Explicit upgrade of a pinned package proceeds, with a note.
        if !all {
            let pinned = State::open(&Paths::at(&root).state_db())
                .ok()
                .and_then(|s| s.is_pinned(name).ok())
                .unwrap_or(false);
            if pinned && !json {
                println!("note: {name} is pinned; upgrading anyway (explicit request)");
            }
        }

        match upgrade(name, &root, &mut |s| upgrade_step(json, s)) {
            Ok(UpgradeOutcome::UpToDate { version }) => {
                if !json {
                    println!("{name} is up to date ({version})");
                }
                results.push(
                    serde_json::json!({ "name": name, "status": "up_to_date", "version": version }),
                );
            }
            Ok(UpgradeOutcome::Upgraded(r)) => {
                if !json {
                    println!(
                        "✓ upgraded {} {} -> {}",
                        r.name, r.from_version, r.to_version
                    );
                }
                results.push(serde_json::json!({
                    "name": r.name,
                    "status": "upgraded",
                    "from": r.from_version,
                    "to": r.to_version,
                }));
            }
            Err(e) => {
                if !json {
                    eprintln!("error: upgrade '{name}' failed: {e}");
                }
                results.push(serde_json::json!({ "name": name, "status": "error", "message": e.to_string() }));
                code = EXIT_ERROR;
            }
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": code == 0,
                "results": results,
            }))
            .unwrap()
        );
    }
    code
}

/// One-line download note for an upgrade (human mode only). ponytail: upgrade
/// prints a note rather than a live bar — the rich progress bar already exists
/// for install and download is cache-aware/fast.
fn upgrade_step(json: bool, step: Step) {
    if json {
        return;
    }
    if let Step::Downloading { name, version } = step {
        println!("downloading {name} {version}...");
    }
}

fn cmd_pin(package: &str, pin: bool) -> i32 {
    let mut state = match State::open(&Paths::at(root()).state_db()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open state db: {e}");
            return EXIT_ERROR;
        }
    };
    match state.set_pinned(package, pin) {
        Ok(true) => {
            println!("{} {package}", if pin { "pinned" } else { "unpinned" });
            0
        }
        Ok(false) => {
            eprintln!("error: '{package}' is not installed");
            EXIT_ERROR
        }
        Err(e) => {
            eprintln!("error: cannot update pin: {e}");
            EXIT_ERROR
        }
    }
}

/// `voli env <pkg>`: show the env vars a package set, from its ledger (spec §8).
fn cmd_env(package: &str, json: bool) -> i32 {
    let root = root();
    let state = match State::open(&Paths::at(&root).state_db()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open state db: {e}");
            return EXIT_ERROR;
        }
    };
    if !state.is_installed(package).unwrap_or(false) {
        eprintln!("error: '{package}' is not installed");
        return EXIT_ERROR;
    }
    let actions = match state.actions_for(package) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: cannot read ledger: {e}");
            return EXIT_ERROR;
        }
    };
    let subkey = env_subkey();

    let mut entries = Vec::new();
    for a in &actions {
        match a {
            Action::EnvSet { key, value, .. } => {
                let current = env::get(&subkey, key).ok().flatten();
                entries.push((key.clone(), value.clone(), current));
            }
            Action::PathAdded { segment } => {
                let present = env::get(&subkey, "Path")
                    .ok()
                    .flatten()
                    .map(|p| env::path_has_segment(&p, segment))
                    .unwrap_or(false);
                entries.push((
                    "PATH".to_string(),
                    segment.clone(),
                    present.then(|| segment.clone()),
                ));
            }
            _ => {}
        }
    }

    if json {
        let arr: Vec<_> = entries
            .iter()
            .map(|(k, v, cur)| serde_json::json!({ "key": k, "value": v, "current": cur }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        return 0;
    }
    if entries.is_empty() {
        println!("{package} set no environment variables");
        return 0;
    }
    println!("{package} set:");
    for (k, v, _cur) in &entries {
        println!("  {k} = {v}");
    }
    0
}

/// `voli cleanup`: remove non-current version dirs, `bin\*.old` self-update
/// leftovers, and cache entries older than `cache_days` (0 = all). Reports bytes
/// freed. `--dry-run` prints without deleting. Never touches persist (spec §11).
fn cmd_cleanup(cache_days: u64, dry_run: bool, json: bool) -> i32 {
    use voli_core::cleanup_versions;

    let root = root();
    let paths = Paths::at(&root);
    let state = match State::open(&paths.state_db()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open state db: {e}");
            return EXIT_ERROR;
        }
    };
    let pkgs = match state.list() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot list installed packages: {e}");
            return EXIT_ERROR;
        }
    };

    let mut removed_dirs: Vec<String> = Vec::new();
    let mut freed: u64 = 0;

    // 1. Non-current version dirs, per package.
    for p in &pkgs {
        if p.name == "@voli" {
            continue;
        }
        match cleanup_versions(&root, &p.name, &p.version, dry_run) {
            Ok((dirs, bytes)) => {
                freed += bytes;
                removed_dirs.extend(dirs.iter().map(|d| d.display().to_string()));
            }
            Err(e) => eprintln!("warning: cleanup of {} failed: {e}", p.name),
        }
    }

    // 2. bin\*.old self-update leftovers.
    let bin = root.join("bin");
    if let Ok(entries) = std::fs::read_dir(&bin) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("old") {
                freed += entry.metadata().map(|m| m.len()).unwrap_or(0);
                removed_dirs.push(path.display().to_string());
                if !dry_run {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    // 3. Stale cache entries (mtime older than cache_days; 0 = all).
    let cache = paths.cache();
    let now = std::time::SystemTime::now();
    let max_age = std::time::Duration::from_secs(cache_days * 24 * 60 * 60);
    if let Ok(entries) = std::fs::read_dir(&cache) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let stale = cache_days == 0
                || entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|mt| now.duration_since(mt).ok())
                    .map(|age| age >= max_age)
                    .unwrap_or(false);
            if stale {
                freed += entry.metadata().map(|m| m.len()).unwrap_or(0);
                removed_dirs.push(path.display().to_string());
                if !dry_run {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dry_run": dry_run,
                "freed_bytes": freed,
                "removed": removed_dirs,
            }))
            .unwrap()
        );
    } else {
        let verb = if dry_run { "would remove" } else { "removed" };
        if removed_dirs.is_empty() {
            println!("cleanup: nothing to remove");
        } else {
            for d in &removed_dirs {
                println!("  {verb}: {d}");
            }
            println!(
                "cleanup: {verb} {} item(s), {} freed",
                removed_dirs.len(),
                human_bytes(freed)
            );
        }
    }
    0
}

/// Render a byte count as a short human string (KiB/MiB/GiB).
fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

// Test hook shared by setup, doctor, and the env flows: point env mutations /
// checks at a scratch subkey so tests and smoke runs never touch the real user
// Environment. The real logic lives in `voli_core::env` so core flows resolve
// the same subkey (spec §8).
fn env_subkey() -> String {
    env::env_subkey()
}

fn cmd_setup() -> i32 {
    let root = root();
    match self_install(&root, None, &env_subkey()) {
        Ok(r) => {
            println!("✓ voli installed to {}", r.bin_dir.display());
            for f in &r.copied {
                println!("  bin: {f}");
            }
            if r.path_added {
                println!("  added {} to your PATH", r.shims_dir.display());
                println!("  open a new shell for the PATH change to take effect.");
            } else {
                println!("  {} already on PATH", r.shims_dir.display());
            }
            if cmd_index::run_update(&root, false) != 0 {
                eprintln!("voli is installed; run `voli update` once the index is reachable.");
            }
            0
        }
        Err(e) => {
            eprintln!("error: setup failed: {e}");
            EXIT_ERROR
        }
    }
}

const GITHUB_RELEASE_API: &str = "https://api.github.com/repos/Topurrra/voli/releases/latest";

fn stage_spinner(message: String) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.set_message(message);
    pb
}

fn cmd_self_update() -> i32 {
    use std::cmp::Ordering;

    use sha2::{Digest, Sha256};

    let current = env!("CARGO_PKG_VERSION");
    println!("voli {current}: checking for updates...");

    // 1. Query GitHub API for the latest release.
    let resp = match ureq::get(GITHUB_RELEASE_API)
        .set("User-Agent", concat!("voli/", env!("CARGO_PKG_VERSION")))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot reach GitHub API: {e}");
            return EXIT_ERROR;
        }
    };
    let body_str = match resp.into_string() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading API response: {e}");
            return EXIT_ERROR;
        }
    };
    let body: serde_json::Value = match serde_json::from_str(&body_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: bad API JSON: {e}");
            return EXIT_ERROR;
        }
    };

    let tag = body["tag_name"].as_str().unwrap_or("unknown");
    let latest = tag.trim_start_matches('v');
    match voli_core::index::cmp_version(latest, current) {
        Ordering::Less => {
            println!("✓ local version {current} is newer than latest release {latest}");
            return 0;
        }
        Ordering::Equal => {
            println!("✓ already up to date ({current})");
            return 0;
        }
        Ordering::Greater => {}
    }
    println!("updating {current} -> {latest}");

    // 2. Find the zip asset (stable name uploaded by release.yml).
    let asset_name = "voli-x64.zip";
    let sha_name = format!("{asset_name}.sha256");
    let mut zip_url = None;
    let mut sha_url = None;
    if let Some(assets) = body["assets"].as_array() {
        for a in assets {
            let name = a["name"].as_str().unwrap_or("");
            let url = a["browser_download_url"].as_str().unwrap_or("");
            if name == asset_name {
                zip_url = Some(url.to_string());
            } else if name == sha_name {
                sha_url = Some(url.to_string());
            }
        }
    }
    let Some(zip_url) = zip_url else {
        eprintln!("error: release {tag} has no {asset_name} asset");
        return EXIT_ERROR;
    };

    // 3. Download the zip.
    let zip_resp = match ureq::get(&zip_url)
        .set("User-Agent", concat!("voli/", env!("CARGO_PKG_VERSION")))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: download failed: {e}");
            return EXIT_ERROR;
        }
    };
    let total = zip_resp
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let download = total.map_or_else(ProgressBar::new_spinner, ProgressBar::new);
    if total.is_some() {
        download.set_style(
            ProgressStyle::with_template(
                "{msg} [{bar:30}] {bytes}/{total_bytes} {percent}% ({bytes_per_sec}, {eta})",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
        );
    } else {
        download.enable_steady_tick(Duration::from_millis(100));
        download.set_style(
            ProgressStyle::with_template("{spinner} {msg} {bytes} ({bytes_per_sec})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
    }
    download.set_message(format!("downloading voli {latest}"));
    let mut zip_bytes = Vec::new();
    let read = {
        let mut reader = download.wrap_read(zip_resp.into_reader());
        reader.read_to_end(&mut zip_bytes)
    };
    download.finish_and_clear();
    if let Err(e) = read {
        eprintln!("error: reading download: {e}");
        return EXIT_ERROR;
    }
    println!("✓ downloaded voli {latest}");

    // 4. Verify sha256 if a checksums asset exists.
    if let Some(sha_url) = sha_url {
        let verifying = stage_spinner("verifying sha256".to_string());
        let sha_resp = match ureq::get(&sha_url)
            .set("User-Agent", concat!("voli/", env!("CARGO_PKG_VERSION")))
            .call()
        {
            Ok(response) => response,
            Err(e) => {
                verifying.finish_and_clear();
                eprintln!("error: checksum download failed: {e}");
                return EXIT_ERROR;
            }
        };
        let expected = match sha_resp.into_string() {
            Ok(value) => value,
            Err(e) => {
                verifying.finish_and_clear();
                eprintln!("error: reading checksum: {e}");
                return EXIT_ERROR;
            }
        };
        let expected = expected
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let actual = hex::encode(Sha256::digest(&zip_bytes));
        verifying.finish_and_clear();
        if actual != expected {
            eprintln!("error: sha256 mismatch: expected {expected}, got {actual}");
            return EXIT_ERROR;
        }
        println!("✓ sha256 verified");
    } else {
        eprintln!("warning: no .sha256 asset found; skipping hash verification");
    }

    // 5. Extract to temp and swap binaries.
    let td = match tempfile::tempdir() {
        Ok(td) => td,
        Err(e) => {
            eprintln!("error: cannot create temp dir: {e}");
            return EXIT_ERROR;
        }
    };
    let zip_path = td.path().join("release.zip");
    if let Err(e) = std::fs::write(&zip_path, &zip_bytes) {
        eprintln!("error: writing temp zip: {e}");
        return EXIT_ERROR;
    }
    let extract_dir = td.path().join("extracted");
    std::fs::create_dir_all(&extract_dir).ok();
    let extracting = stage_spinner(format!("extracting voli {latest}"));
    {
        let file = match std::fs::File::open(&zip_path) {
            Ok(f) => f,
            Err(e) => {
                extracting.finish_and_clear();
                eprintln!("error: opening zip: {e}");
                return EXIT_ERROR;
            }
        };
        let mut archive = match zip::ZipArchive::new(file) {
            Ok(a) => a,
            Err(e) => {
                extracting.finish_and_clear();
                eprintln!("error: reading zip: {e}");
                return EXIT_ERROR;
            }
        };
        if let Err(e) = archive.extract(&extract_dir) {
            extracting.finish_and_clear();
            eprintln!("error: extracting zip: {e}");
            return EXIT_ERROR;
        }
    }
    extracting.finish_and_clear();
    println!("✓ extracted voli {latest}");

    // 6. Replace binaries in bin\ using the .new/.old rename dance.
    let root = root();
    let bin_dir = root.join("bin");
    let mut updated = Vec::new();
    let installing = stage_spinner(format!("installing voli {latest}"));
    for name in ["voli.exe", "voli-shim.exe", "voli-shim-gui.exe"] {
        let src = extract_dir.join(name);
        if src.is_file() {
            let dst = bin_dir.join(name);
            if let Err(e) = replace_binary(&src, &dst) {
                installing.finish_and_clear();
                eprintln!("error: replacing {name}: {e}");
                return EXIT_ERROR;
            }
            updated.push(name.to_string());
        }
    }

    if updated.is_empty() {
        installing.finish_and_clear();
        eprintln!("error: no binaries found in the release archive");
        return EXIT_ERROR;
    }
    installing.finish_and_clear();
    println!("✓ updated to {latest}: {}", updated.join(", "));
    0
}

/// Copy `src` over `dst`, coping with a locked running exe (.new/.old dance).
fn replace_binary(src: &Path, dst: &Path) -> std::io::Result<()> {
    let staged = {
        let mut s = dst.as_os_str().to_os_string();
        s.push(".new");
        PathBuf::from(s)
    };
    std::fs::copy(src, &staged)?;
    if dst.exists() {
        if std::fs::rename(&staged, dst).is_ok() {
            return Ok(());
        }
        let old = {
            let mut s = dst.as_os_str().to_os_string();
            s.push(".old");
            PathBuf::from(s)
        };
        let _ = std::fs::remove_file(&old);
        std::fs::rename(dst, &old)?;
        std::fs::rename(&staged, dst)?;
    } else {
        std::fs::rename(&staged, dst)?;
    }
    Ok(())
}

fn cmd_self_delete(auto_yes: bool) -> i32 {
    let root = root();
    let paths = Paths::at(&root);

    // Safety rail: refuse if root doesn't look like a voli installation.
    if !root.join("bin").join("voli.exe").exists() || !root.join("db").join("state.sqlite").exists()
    {
        eprintln!(
            "error: {} does not look like a voli root (missing bin\\voli.exe or db\\state.sqlite)",
            root.display()
        );
        eprintln!("refusing to delete a directory that is not a voli installation.");
        return EXIT_ERROR;
    }

    // Gather what will be removed.
    let state = match State::open(&paths.state_db()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open state db: {e}");
            return EXIT_ERROR;
        }
    };
    let pkgs: Vec<String> = match state.list() {
        Ok(list) => list
            .iter()
            .filter(|p| p.name != "@voli")
            .map(|p| p.name.clone())
            .collect(),
        Err(e) => {
            eprintln!("error: cannot list packages: {e}");
            return EXIT_ERROR;
        }
    };
    drop(state);

    // Prompt (default NO — the only voli prompt that defaults to no).
    if !auto_yes {
        println!("This will PERMANENTLY remove:");
        println!("  - voli itself (bin, shims, db, cache)");
        if pkgs.is_empty() {
            println!("  - no installed packages");
        } else {
            println!(
                "  - {} installed package(s): {}",
                pkgs.len(),
                pkgs.join(", ")
            );
        }
        println!(
            "  - all persist data, env vars, PATH entries, shortcuts, and Apps & Features keys"
        );
        println!("  - the voli root: {}", root.display());
        println!();
        print!("This cannot be undone. Proceed? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).ok();
        if !answer.trim().eq_ignore_ascii_case("y") && !answer.trim().eq_ignore_ascii_case("yes") {
            println!("aborted.");
            return 0;
        }
    }

    // 1. Uninstall every package (purge — persist goes too).
    let env_subkey = env_subkey();
    for name in &pkgs {
        match uninstall(name, &root, true) {
            Ok(_) => println!("  deleted {name}"),
            Err(e) => eprintln!("  warning: delete {name} failed: {e}"),
        }
    }

    // 2. Remove @voli ledger items (PATH entry, self-shim).
    {
        let mut state = match State::open(&paths.state_db()) {
            Ok(s) => s,
            Err(_) => {
                // State db may already be gone; proceed.
                eprintln!("  warning: cannot open state db for @voli cleanup");
                return cleanup_root(&root);
            }
        };
        if let Ok(actions) = state.actions_for("@voli") {
            for a in actions.iter().rev() {
                match a {
                    Action::PathAdded { segment } => {
                        let _ = env::remove_from_path(&env_subkey, segment);
                    }
                    Action::ShimWritten { shim, exe } => {
                        let _ = std::fs::remove_file(shim);
                        let _ = std::fs::remove_file(exe);
                    }
                    _ => {}
                }
            }
        }
        let _ = state.remove_package("@voli");
        env::broadcast_change();
    }

    // 3. Delete everything under root except bin\voli.exe (which is running).
    cleanup_root(&root)
}

/// Remove the entire voli root, deterministically, while we are still running.
///
/// Windows will not DELETE a running exe, but it will happily MOVE one — so we
/// move our own binary out to %TEMP% first, at which point nothing in the root
/// is locked and a plain remove_dir_all wipes it synchronously (no detached
/// helper races, works even under process-tree-killing Job Objects). The moved
/// exe in %TEMP% gets a best-effort background delete; if that dies, a single
/// orphan file in the temp dir is the worst case and the OS cleans temp anyway.
fn cleanup_root(root: &Path) -> i32 {
    // 3a. Move the running exe out of the tree.
    let parked = std::env::temp_dir().join(format!("voli-selfdelete-{}.exe", std::process::id()));
    if let Ok(me) = std::env::current_exe() {
        let _ = std::fs::remove_file(&parked);
        if std::fs::rename(&me, &parked).is_err() {
            // Cross-volume temp (rename can't move a running exe between
            // volumes) — park it inside root's parent instead.
            let fallback = root.with_extension("voli-selfdelete.exe");
            if std::fs::rename(&me, &fallback).is_ok() {
                let _ = std::fs::remove_dir_all(root);
                schedule_temp_delete(root, &fallback);
                println!();
                println!("voli removed itself. The bear waves goodbye. \u{1F43B}");
                return 0;
            }
            // Can't move at all — extremely unusual; leave bin\voli.exe and
            // tell the user rather than pretending.
            let _ = std::fs::remove_dir_all(root.join("apps"));
            let _ = std::fs::remove_dir_all(root.join("shims"));
            let _ = std::fs::remove_dir_all(root.join("db"));
            let _ = std::fs::remove_dir_all(root.join("cache"));
            let _ = std::fs::remove_file(root.join("config.toml"));
            eprintln!(
                "warning: could not relocate the running voli.exe; delete {} manually.",
                root.display()
            );
            return 0;
        }
    }

    // 3b. Nothing in root is locked now — synchronous, verifiable removal.
    let root_removed = std::fs::remove_dir_all(root).is_ok() || !root.exists();

    // 3c. The invoking shim may still lock the root until this process exits.
    schedule_temp_delete(root, &parked);

    println!();
    if !root_removed {
        println!("finishing locked-file cleanup in the background...");
    }
    println!("voli removed itself. The bear waves goodbye. \u{1F43B}");
    0
}

/// Best-effort detached delete of the root and parked executable.
/// Breakaway first so tree-killing Job Objects don't reap the helper; if even
/// that dies, one orphan file in %TEMP% is the accepted worst case.
fn schedule_temp_delete(root: &Path, parked: &Path) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Stdio;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        let cmd = "for /l %n in (1,1,15) do (\
            rmdir /s /q \"%VOLI_DELETE_ROOT%\" 2>nul & \
            del /f /q \"%VOLI_DELETE_EXE%\" 2>nul & \
            if not exist \"%VOLI_DELETE_ROOT%\" if not exist \"%VOLI_DELETE_EXE%\" exit 0 & \
            ping -n 2 127.0.0.1 >nul)";
        let spawn = |flags: u32| {
            let mut command = std::process::Command::new("cmd");
            command
                .args(["/d", "/q", "/c"])
                .raw_arg(cmd)
                .env("VOLI_DELETE_ROOT", root)
                .env("VOLI_DELETE_EXE", parked)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(flags);
            command.spawn()
        };
        if spawn(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB).is_err() {
            let _ = spawn(CREATE_NO_WINDOW | DETACHED_PROCESS);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(parked);
    }
}

fn cmd_config(action: &ConfigAction, json: bool) -> i32 {
    match action {
        ConfigAction::Get { key } => cmd_config_get(key, json),
        ConfigAction::Set { key, value } => cmd_config_set(key, value),
    }
}

/// Path of the config file that owns `key`: `root` lives in the bootstrap
/// config, everything else in `<root>\config.toml`.
fn config_file_for(key: &str) -> Option<PathBuf> {
    if key == "root" {
        config::bootstrap_config_path()
    } else {
        Some(root().join("config.toml"))
    }
}

fn cmd_config_get(key: &str, json: bool) -> i32 {
    if key != "root" && key != "index_url" {
        eprintln!("error: unknown config key '{key}' (known: root, index_url)");
        return EXIT_ERROR;
    }
    let Some(path) = config_file_for(key) else {
        eprintln!("error: cannot locate config file for '{key}'");
        return EXIT_ERROR;
    };
    let value = config::Config::load(&path).get(key);
    if json {
        println!("{}", serde_json::json!({ "key": key, "value": value }));
    } else {
        match value {
            Some(v) => println!("{v}"),
            None => println!("(unset)"),
        }
    }
    0
}

fn cmd_config_set(key: &str, value: &str) -> i32 {
    if key != "root" && key != "index_url" {
        eprintln!("error: unknown config key '{key}' (known: root, index_url)");
        return EXIT_ERROR;
    }
    if key == "root"
        && let Some(provider) = config::synced_provider(Path::new(value))
    {
        eprintln!(
            "warning: '{value}' looks like a {provider} sync folder; running exes from \
             synced folders is unreliable (spec §3). Prefer a local disk path."
        );
    }
    let Some(path) = config_file_for(key) else {
        eprintln!("error: cannot locate config file for '{key}'");
        return EXIT_ERROR;
    };
    match config::set_raw(&path, key, value) {
        Ok(()) => {
            println!("set {key} = {value}");
            if key == "root" {
                println!(
                    "  (takes effect on next run; bootstrap: {})",
                    path.display()
                );
            }
            0
        }
        Err(e) => {
            eprintln!("error: could not write {}: {e}", path.display());
            EXIT_ERROR
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

struct Check {
    status: Status,
    name: String,
    detail: String,
}

fn cmd_doctor(json: bool) -> i32 {
    let root = root();
    let paths = Paths::at(&root);
    let env_subkey = env_subkey();

    let mut checks: Vec<Check> = Vec::new();
    let mut add = |status, name: &str, detail: String| {
        checks.push(Check {
            status,
            name: name.to_string(),
            detail,
        })
    };

    // 1. shims dir on user PATH?
    let shims = paths.shims();
    let shims_str = shims.to_string_lossy().into_owned();
    match env::get(&env_subkey, "Path") {
        Ok(path) => {
            let present = path
                .as_deref()
                .map(|p| env::path_has_segment(p, &shims_str))
                .unwrap_or(false);
            if present {
                add(Status::Pass, "shims on PATH", shims_str.clone());
            } else {
                add(
                    Status::Fail,
                    "shims on PATH",
                    format!("{shims_str} is not on your user PATH (run `voli setup`)"),
                );
            }
        }
        Err(e) => add(
            Status::Fail,
            "shims on PATH",
            format!("cannot read PATH: {e}"),
        ),
    }

    // 2. bin dir + binaries present?
    let bin = root.join("bin");
    let missing: Vec<&str> = ["voli.exe", "voli-shim.exe", "voli-shim-gui.exe"]
        .into_iter()
        .filter(|b| !bin.join(b).is_file())
        .collect();
    if !bin.is_dir() {
        add(
            Status::Fail,
            "bin dir",
            format!("{} does not exist (run `voli setup`)", bin.display()),
        );
    } else if missing.is_empty() {
        add(Status::Pass, "bin binaries", bin.display().to_string());
    } else {
        add(
            Status::Fail,
            "bin binaries",
            format!("missing in {}: {}", bin.display(), missing.join(", ")),
        );
    }

    // 3. root on a synced folder?
    match config::synced_provider(&root) {
        Some(provider) => add(
            Status::Warn,
            "root location",
            format!("{} looks like a {provider} sync folder", root.display()),
        ),
        None => add(Status::Pass, "root location", root.display().to_string()),
    }

    // 4. state db openable?
    let state = match State::open(&paths.state_db()) {
        Ok(s) => {
            add(
                Status::Pass,
                "state db",
                paths.state_db().display().to_string(),
            );
            Some(s)
        }
        Err(e) => {
            add(Status::Fail, "state db", format!("cannot open: {e}"));
            None
        }
    };

    // 5 + 6. per-package shims, shim targets, and current junctions.
    if let Some(state) = &state {
        match state.list() {
            Ok(pkgs) => {
                for p in &pkgs {
                    if p.name == "@voli" {
                        continue; // synthetic self entry has no shims/junction
                    }
                    check_package(&paths, state, p, &env_subkey, &mut add);
                }
            }
            Err(e) => add(
                Status::Fail,
                "installed packages",
                format!("cannot list: {e}"),
            ),
        }
    }

    // 7. Orphaned Apps & Features keys (key exists but package not in state db).
    {
        let base = voli_core::uninstall_reg::uninstall_base();
        match voli_core::uninstall_reg::list_voli_keys(&base) {
            Ok(keys) => {
                let installed: std::collections::HashSet<String> = state
                    .as_ref()
                    .and_then(|s| s.list().ok())
                    .map(|pkgs| pkgs.into_iter().map(|p| p.name).collect())
                    .unwrap_or_default();
                let orphans: Vec<&String> =
                    keys.iter().filter(|k| !installed.contains(*k)).collect();
                if orphans.is_empty() {
                    add(Status::Pass, "uninstall keys", "no orphans".to_string());
                } else {
                    let names: Vec<&str> = orphans.iter().map(|s| s.as_str()).collect();
                    add(
                        Status::Warn,
                        "uninstall keys",
                        format!("orphaned: {}", names.join(", ")),
                    );
                }
            }
            Err(_) => {
                // Cannot read the key — not fatal.
            }
        }
    }

    let failed = checks.iter().any(|c| c.status == Status::Fail);

    if json {
        let arr: Vec<_> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "status": c.status.label(),
                    "check": c.name,
                    "detail": c.detail,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": !failed,
                "checks": arr,
            }))
            .unwrap()
        );
    } else {
        for c in &checks {
            println!("[{}] {} — {}", c.status.label(), c.name, c.detail);
        }
        println!();
        println!("{}", if failed { "doctor: FAIL" } else { "doctor: OK" });
    }

    if failed { EXIT_ERROR } else { 0 }
}

/// Check one installed package's shims (present + target exists) and its
/// `current` junction (resolves).
fn check_package(
    paths: &Paths,
    state: &State,
    pkg: &voli_core::InstalledPkg,
    env_subkey: &str,
    add: &mut impl FnMut(Status, &str, String),
) {
    use voli_core::Action;

    // current junction must resolve to a real directory.
    let current = paths.current(&pkg.name);
    if current.exists() {
        add(
            Status::Pass,
            "junction",
            format!("{} -> ok", current.display()),
        );
    } else {
        add(
            Status::Fail,
            "junction",
            format!("{} is broken or missing", current.display()),
        );
    }

    let actions = match state.actions_for(&pkg.name) {
        Ok(a) => a,
        Err(e) => {
            add(
                Status::Fail,
                "shims",
                format!("{}: cannot read ledger: {e}", pkg.name),
            );
            return;
        }
    };
    for a in &actions {
        if let Action::ShimWritten { shim, exe } = a {
            if !exe.is_file() {
                add(
                    Status::Fail,
                    "shim",
                    format!("{} missing shim exe {}", pkg.name, exe.display()),
                );
                continue;
            }
            // The .shim file's first line is the real target path.
            let target_ok = std::fs::read_to_string(shim)
                .ok()
                .and_then(|b| b.lines().next().map(|l| l.trim().to_string()))
                .map(|t| Path::new(&t).exists())
                .unwrap_or(false);
            if target_ok {
                add(
                    Status::Pass,
                    "shim",
                    format!("{}: {}", pkg.name, shim.display()),
                );
            } else {
                add(
                    Status::Fail,
                    "shim",
                    format!("{}: target of {} does not exist", pkg.name, shim.display()),
                );
            }
        }
    }

    // Env drift (spec §8): if the live registry value differs from what we set,
    // WARN — never auto-fix (the user may have edited it deliberately).
    for a in &actions {
        if let Action::EnvSet { key, value, .. } = a {
            let current = env::get(env_subkey, key).ok().flatten();
            match current.as_deref() {
                Some(cur) if cur == value => add(
                    Status::Pass,
                    "env",
                    format!("{}: {key} = {value}", pkg.name),
                ),
                Some(cur) => add(
                    Status::Warn,
                    "env drift",
                    format!("{}: {key} is now '{cur}' (voli set '{value}')", pkg.name),
                ),
                None => add(
                    Status::Warn,
                    "env drift",
                    format!("{}: {key} was removed (voli set '{value}')", pkg.name),
                ),
            }
        }
    }
}

fn cmd_which(bin: &str) -> i32 {
    let base = bin.strip_suffix(".exe").unwrap_or(bin);
    let shim = Paths::at(root()).shims().join(format!("{base}.shim"));
    match std::fs::read_to_string(&shim) {
        Ok(body) => {
            // Line 1 of a .shim is the target path (spec §6).
            match body.lines().next() {
                Some(target) if !target.trim().is_empty() => {
                    println!("{}", target.trim());
                    0
                }
                _ => {
                    eprintln!("error: shim {} is empty or malformed", shim.display());
                    EXIT_ERROR
                }
            }
        }
        Err(_) => {
            eprintln!("error: no shim for '{bin}' (looked for {})", shim.display());
            EXIT_ERROR
        }
    }
}
