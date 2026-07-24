//! voli CLI (spec §9). Phase 1 step 1: every v1 subcommand exists as a stub that
//! prints "not implemented yet" and exits with code 2.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use voli_core::{Paths, State, install_local, uninstall};

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

    let code = match &cli.command {
        Command::Install { packages, archive } => cmd_install(packages, archive.as_deref()),
        Command::Uninstall { packages, purge } => cmd_uninstall(packages, *purge),
        Command::List => cmd_list(cli.json),
        other => {
            eprintln!("voli {}: not implemented yet", name_of(other));
            EXIT_UNIMPLEMENTED
        }
    };
    std::process::exit(code);
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
        Command::Config { .. } => "config",
        Command::Doctor => "doctor",
        Command::Which { .. } => "which",
        Command::SelfUpdate => "self-update",
    }
}

fn root() -> PathBuf {
    match Paths::resolve() {
        Ok(p) => p.root,
        Err(e) => {
            eprintln!("error: cannot resolve voli root: {e}");
            std::process::exit(EXIT_ERROR);
        }
    }
}

fn cmd_install(packages: &[String], archive: Option<&Path>) -> i32 {
    // Only local `.toml` installs are wired in this build (network is step 9).
    if packages.len() != 1 {
        eprintln!("error: this build installs one local manifest at a time");
        return EXIT_ERROR;
    }
    let pkg = &packages[0];
    let manifest_path = Path::new(pkg);
    let is_local = pkg.ends_with(".toml") && manifest_path.is_file();
    if !is_local {
        eprintln!("error: network install is not implemented yet (spec §11 step 9)");
        eprintln!("       for now, pass a local '<name>.toml' manifest plus --archive <path>");
        return EXIT_ERROR;
    }
    let Some(archive) = archive else {
        eprintln!("error: --archive <path> is required to install from a local manifest");
        return EXIT_ERROR;
    };

    match install_local(manifest_path, archive, &root()) {
        Ok(r) => {
            println!("installed {} {}", r.name, r.version);
            println!("  files: {}", r.version_dir.display());
            for shim in &r.shims {
                println!("  shim:  {}", shim.display());
            }
            for (k, v) in &r.env_requested {
                println!("  note: manifest requests env {k}={v} (env feature not applied yet)");
            }
            0
        }
        Err(e) => {
            eprintln!("error: install failed: {e}");
            EXIT_ERROR
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
