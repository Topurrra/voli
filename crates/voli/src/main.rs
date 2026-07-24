//! voli CLI (spec §9). Phase 1 step 1: every v1 subcommand exists as a stub that
//! prints "not implemented yet" and exits with code 2.

use clap::{Parser, Subcommand};

/// Exit code for a command that is not yet implemented.
const EXIT_UNIMPLEMENTED: i32 = 2;

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
    Install {
        #[arg(required = true)]
        packages: Vec<String>,
    },
    /// Uninstall one or more packages.
    Uninstall {
        #[arg(required = true)]
        packages: Vec<String>,
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

    let what = match &cli.command {
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
    };

    eprintln!("voli {what}: not implemented yet");
    std::process::exit(EXIT_UNIMPLEMENTED);
}
