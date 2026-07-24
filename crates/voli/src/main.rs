//! voli CLI (spec §9). Phase 1 step 1: every v1 subcommand exists as a stub that
//! prints "not implemented yet" and exits with code 2.

mod cmd_index;
mod cmd_install;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use voli_core::{Paths, State, config, env, self_install, uninstall};

/// Exit code for a command that is not yet implemented.
const EXIT_UNIMPLEMENTED: i32 = 2;
/// Exit code for a runtime error (bad args, install failure, …).
const EXIT_ERROR: i32 = 1;

#[derive(Parser)]
#[command(
    name = "voli",
    version,
    about = "A fast, no-admin package manager for Windows"
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
    /// In this build only local installs are wired: pass a path to a
    /// `<name>.toml` manifest together with `--archive <path>`.
    Install {
        #[arg(required = true)]
        packages: Vec<String>,
        /// Local archive to install from (required for a local `.toml` manifest).
        #[arg(long)]
        archive: Option<PathBuf>,
    },
    /// Uninstall one or more packages.
    Uninstall {
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
    /// Remove non-current version dirs and stale cache.
    Cleanup,
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
        Command::Install { packages, archive } => {
            cmd_install::run(packages, archive.as_deref(), &root(), cli.json)
        }
        Command::Uninstall { packages, purge } => cmd_uninstall(packages, *purge),
        Command::List => cmd_list(cli.json),
        Command::Setup => cmd_setup(),
        Command::Config { action } => cmd_config(action, cli.json),
        Command::Doctor => cmd_doctor(cli.json),
        Command::Which { bin } => cmd_which(bin),
        Command::Update => cmd_index::run_update(&root(), cli.json),
        Command::Search { query } => cmd_index::run_search(&root(), query, cli.json),
        Command::Info { package } => cmd_index::run_info(&root(), package, cli.json),
        other => {
            eprintln!("voli {}: not implemented yet", name_of(other));
            EXIT_UNIMPLEMENTED
        }
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

fn name_of(cmd: &Command) -> &'static str {
    match cmd {
        Command::Install { .. } => "install",
        Command::Uninstall { .. } => "uninstall",
        Command::Update => "update",
        Command::Upgrade { .. } => "upgrade",
        Command::List => "list",
        Command::Search { .. } => "search",
        Command::Info { .. } => "info",
        Command::Pin { .. } => "pin",
        Command::Unpin { .. } => "unpin",
        Command::Cleanup => "cleanup",
        Command::Setup => "setup",
        Command::Config { .. } => "config",
        Command::Doctor => "doctor",
        Command::Which { .. } => "which",
        Command::SelfUpdate => "self-update",
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

fn cmd_uninstall(packages: &[String], purge: bool) -> i32 {
    let root = root();
    let mut code = 0;
    for name in packages {
        match uninstall(name, &root, purge) {
            Ok(r) => {
                println!("uninstalled {} {}", r.name, r.version);
                if r.kept_persist {
                    println!("  kept persist data (use --purge to remove it)");
                }
            }
            Err(e) => {
                eprintln!("error: uninstall '{name}' failed: {e}");
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

// Test hook shared by setup and doctor: point env mutations/checks at a scratch
// subkey so tests and smoke runs never touch the real user Environment.
fn env_subkey() -> String {
    std::env::var("VOLI_ENV_SUBKEY").unwrap_or_else(|_| env::ENVIRONMENT.to_string())
}

fn cmd_setup() -> i32 {
    let root = root();
    match self_install(&root, None, &env_subkey()) {
        Ok(r) => {
            println!("voli installed to {}", r.bin_dir.display());
            for f in &r.copied {
                println!("  bin: {f}");
            }
            if r.path_added {
                println!("  added {} to your PATH", r.shims_dir.display());
                println!("  open a new shell for the PATH change to take effect.");
            } else {
                println!("  {} already on PATH", r.shims_dir.display());
            }
            0
        }
        Err(e) => {
            eprintln!("error: setup failed: {e}");
            EXIT_ERROR
        }
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
    if let Some(state) = state {
        match state.list() {
            Ok(pkgs) => {
                for p in &pkgs {
                    if p.name == "@voli" {
                        continue; // synthetic self entry has no shims/junction
                    }
                    check_package(&paths, &state, p, &mut add);
                }
            }
            Err(e) => add(
                Status::Fail,
                "installed packages",
                format!("cannot list: {e}"),
            ),
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
