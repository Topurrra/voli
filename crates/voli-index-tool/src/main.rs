//! `voli-index-tool` — validate and compile the Voli package registry (§11 step 7).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "voli-index-tool",
    about = "Validate and build the Voli package index"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse, layout-check, and de-duplicate every manifest under <dir>.
    Validate {
        /// The `manifests/` directory (`<letter>/<name>/<version>.toml`).
        dir: PathBuf,
    },
    /// Validate, then compile → compress → sign → write index.json into --out.
    Build {
        /// The `manifests/` directory.
        dir: PathBuf,
        /// Output directory for index.sqlite(.zst), index.sig, index.json.
        #[arg(long)]
        out: PathBuf,
        /// Hex-encoded 32-byte Ed25519 secret key file.
        #[arg(long)]
        key: PathBuf,
        /// Unix seconds for index.json (else $SOURCE_DATE_EPOCH, else now).
        #[arg(long)]
        epoch: Option<u64>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate { dir } => {
            let errors = voli_index_tool::validate(&dir)?;
            if errors.is_empty() {
                println!("ok: all manifests under {} are valid", dir.display());
                Ok(ExitCode::SUCCESS)
            } else {
                for e in &errors {
                    eprintln!("error: {e}");
                }
                eprintln!("\n{} manifest error(s) found", errors.len());
                Ok(ExitCode::FAILURE)
            }
        }
        Command::Build {
            dir,
            out,
            key,
            epoch,
        } => {
            let meta = voli_index_tool::build(&dir, &out, &key, epoch)?;
            println!(
                "built index: {} manifests, {} bytes, sha256 {}, epoch {}",
                meta.manifests, meta.size, meta.sha256, meta.epoch
            );
            println!(
                "wrote index.sqlite, index.sqlite.zst, index.sig, index.json to {}",
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
