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
    /// Generate a fresh Ed25519 signing keypair (see docs/Voli.md §10 key management).
    Keygen {
        /// Where to write the hex secret key. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
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
        Command::Keygen { out } => {
            if out.exists() {
                anyhow::bail!(
                    "{} already exists — refusing to overwrite a key",
                    out.display()
                );
            }
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("os rng failed: {e}"))?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
            let pubkey = hex::encode(signing.verifying_key().to_bytes());
            std::fs::write(&out, hex::encode(secret))?;
            println!(
                "secret key written to {}   <- GitHub secret VOLI_INDEX_SIGNING_KEY; never commit",
                out.display()
            );
            println!("public key: {pubkey}");
            println!("  -> embed as DEV_PUBKEY replacement in crates/voli-core/src/index/sign.rs");
            Ok(ExitCode::SUCCESS)
        }
    }
}
