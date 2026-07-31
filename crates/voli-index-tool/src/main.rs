//! `voli-index-tool` — validate and compile the Voli package registry (§11 step 7).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use voli_core::manifest::Sources;
use voli_core::{Bin, Kind, Manifest, Source, SourceKind};

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
    /// Rewrite every manifest under <dir> into canonical form.
    ///
    /// Run this after any tool that generates manifests: the generator can emit
    /// whatever valid TOML is convenient and this makes it canonical, so no
    /// generator has to reimplement the canonical shape and drift from it.
    Fmt {
        /// The `manifests/` directory.
        dir: PathBuf,
        /// Rewrite the files. Without it, only list what would change (and exit
        /// non-zero if anything would), which is the shape a CI check wants.
        #[arg(long)]
        write: bool,
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
    /// Scaffold a manifest from a GitHub release asset URL.
    New {
        /// Direct download URL of the archive asset.
        url: String,
        /// Package name (lowercase, dashes).
        #[arg(long)]
        name: String,
        /// Output manifests directory (writes <letter>/<name>/<version>.toml).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check supported release endpoints and emit updated manifests.
    Bump {
        /// The `manifests/` directory.
        dir: PathBuf,
        /// Max packages to bump per run (downloads are the cost).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Generate Voli's checked-in global agent target table from agents.ts.
    SyncAgentTargets {
        /// Local copy of vercel-labs/skills/src/agents.ts.
        source: PathBuf,
        /// Generated Rust file consumed by voli-core.
        #[arg(long)]
        out: PathBuf,
        /// Exact upstream git revision recorded in the generated file.
        #[arg(long)]
        revision: String,
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
        Command::Fmt { dir, write } => {
            let changed = voli_index_tool::format_dir(&dir, write)?;
            if changed.is_empty() {
                println!("ok: every manifest under {} is canonical", dir.display());
                return Ok(ExitCode::SUCCESS);
            }
            for c in &changed {
                println!(
                    "{}: {}",
                    if write { "formatted" } else { "would format" },
                    c
                );
            }
            println!("\n{} manifest(s)", changed.len());
            // Without --write this is a check, and a check that found work to do
            // has failed. With --write the work is done, so it succeeded.
            Ok(if write {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
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
        Command::New { url, name, out } => {
            let m = wizard(&url, &name)?;
            let toml = m.to_canonical_toml();
            match out {
                Some(dir) => {
                    let letter = &m.name[..1];
                    let dest = dir.join(letter).join(&m.name);
                    std::fs::create_dir_all(&dest)?;
                    let file = dest.join(format!("{}.toml", m.version));
                    std::fs::write(&file, &toml)?;
                    println!("wrote {}", file.display());
                }
                None => print!("{toml}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Bump { dir, limit } => {
            let summary = voli_index_tool::bump(&dir, limit)?;
            println!("\n{}", summary);
            Ok(ExitCode::SUCCESS)
        }
        Command::SyncAgentTargets {
            source,
            out,
            revision,
        } => {
            let summary = voli_index_tool::sync_agent_targets(&source, &out, &revision)?;
            println!("imported {} stable global agent targets", summary.imported);
            for (id, reason) in summary.excluded {
                println!("excluded {id}: {reason}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Manifest wizard: download → sha256 → sniff → inspect → assemble.
///
/// Returns the parsed-and-validated `Manifest`; the caller writes
/// [`Manifest::to_canonical_toml`]. Emitting TOML by hand here is what made a
/// wizard-authored manifest land non-canonical, so that the first `bump` or
/// `scoop-sync` to touch it reformatted the whole file.
fn wizard(url: &str, name: &str) -> anyhow::Result<Manifest> {
    // 1. Download to temp.
    eprintln!("downloading {url} ...");
    let resp = ureq::get(url)
        .set(
            "User-Agent",
            concat!("voli-index-tool/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;
    let mut bytes = Vec::new();
    resp.into_reader().read_to_end(&mut bytes)?;
    eprintln!("downloaded {} bytes", bytes.len());

    // 2. sha256.
    let sha256 = hex::encode(Sha256::digest(&bytes));

    // 3. Sniff archive type from URL extension.
    let ext = archive_ext(url);

    // 4. Guess version from the URL (last path segment minus extension).
    let version = guess_version(url);

    // 5. Extract to temp dir and inspect.
    let td = tempfile::tempdir()?;
    let extract_root = td.path().join("x");
    std::fs::create_dir_all(&extract_root)?;
    let archive_path = td.path().join(format!("archive{ext}"));
    std::fs::write(&archive_path, &bytes)?;
    extract_for_wizard(&archive_path, &extract_root, ext)?;

    // 6. Detect single wrapper dir → extract_dir.
    let (extract_dir, search_root) = detect_wrapper(&extract_root);

    // 7. Find *.exe at root of search_root → bin candidates.
    let bins = find_bins(&search_root);

    // 8. Assemble the real struct — the shape the client actually parses.
    let m = wizard_manifest(name, &version, url, &sha256, extract_dir, bins);

    // 9. Validate the canonical text with the real parser: what ships is what
    //    gets checked, and re-parsing proves the serializer round-trips.
    Manifest::from_toml_str(&m.to_canonical_toml())
        .map_err(|e| anyhow::anyhow!("generated manifest failed validation: {e}"))
}

/// The manifest shape the wizard produces: one x64 archive source, plus the
/// wrapper dir and root `*.exe` list it detected. Split out from the download so
/// the generated shape is testable without a network.
fn wizard_manifest(
    name: &str,
    version: &str,
    url: &str,
    sha256: &str,
    extract_dir: Option<String>,
    bins: Vec<String>,
) -> Manifest {
    Manifest {
        name: name.to_string(),
        version: version.to_string(),
        // A brand-new package has no former name to answer to.
        aliases: Vec::new(),
        description: None,
        homepage: None,
        icon: None,
        license: None,
        kind: Kind::App,
        source: Sources {
            x64: Some(Source {
                url: url.to_string(),
                sha256: Some(sha256.to_string()),
                sha512: None,
                extra: Vec::new(),
                kind: SourceKind::Archive,
                extract_dir: None,
            }),
            ..Sources::default()
        },
        extract_dir,
        file_name: None,
        bin: bins.into_iter().map(Bin::Path).collect(),
        env: BTreeMap::new(),
        depends: BTreeMap::new(),
        autoupdate: None,
        persist: Vec::new(),
        gui: None,
        shortcuts: Vec::new(),
        write_file: Vec::new(),
    }
}

fn archive_ext(url: &str) -> &'static str {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    for ext in [".tar.gz", ".tgz", ".zip", ".7z"] {
        if path.ends_with(ext) {
            return ext;
        }
    }
    ".zip"
}

fn guess_version(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let last = path.rsplit('/').next().unwrap_or("1.0.0");
    // Strip archive extension.
    let stem = last
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tgz")
        .trim_end_matches(".zip")
        .trim_end_matches(".7z");
    // Version = a segment of digits and dots only, so arch tokens like
    // "x86_64"/"arm64" never leak in ("14.1.1-x86" bug: greedy match ate them).
    for seg in stem.split(['-', '_']) {
        let clean = seg.trim_start_matches('v');
        if !clean.is_empty()
            && clean.contains('.')
            && clean.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return clean.to_string();
        }
    }
    // Fallback: a bare number segment (e.g. "tool-7.zip").
    for seg in stem.split(['-', '_']) {
        if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) {
            return seg.to_string();
        }
    }
    "1.0.0".to_string()
}

fn extract_for_wizard(archive: &Path, dest: &Path, ext: &str) -> anyhow::Result<()> {
    match ext {
        ".zip" => {
            let file = std::fs::File::open(archive)?;
            let mut zip = zip::ZipArchive::new(file)?;
            zip.extract(dest)?;
        }
        ".7z" => {
            sevenz_rust2::decompress_file(archive, dest)?;
        }
        ".tar.gz" | ".tgz" => {
            let file = std::fs::File::open(archive)?;
            let gz = flate2::read::GzDecoder::new(file);
            let mut ar = tar::Archive::new(gz);
            ar.unpack(dest)?;
        }
        _ => anyhow::bail!("unsupported archive type: {ext}"),
    }
    Ok(())
}

/// If the extraction root contains exactly one directory (a wrapper), return
/// its name and the path inside it.
fn detect_wrapper(root: &Path) -> (Option<String>, PathBuf) {
    let entries: Vec<_> = std::fs::read_dir(root)
        .map(|rd| rd.flatten().collect())
        .unwrap_or_default();
    if entries.len() == 1
        && entries[0]
            .file_type()
            .map(|ft| ft.is_dir())
            .unwrap_or(false)
    {
        let name = entries[0].file_name().to_string_lossy().into_owned();
        return (Some(name), entries[0].path());
    }
    (None, root.to_path_buf())
}

/// Find *.exe files directly inside `dir` (non-recursive).
fn find_bins(dir: &Path) -> Vec<String> {
    let mut bins: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.path().extension().and_then(|x| x.to_str()) == Some("exe")
                        && e.file_type().map(|ft| ft.is_file()).unwrap_or(false)
                })
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    bins.sort();
    bins
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_version_dotted() {
        assert_eq!(
            guess_version(
                "https://github.com/o/r/releases/download/v14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"
            ),
            "14.1.1"
        );
    }

    #[test]
    fn guess_version_v_prefix_tag() {
        assert_eq!(
            guess_version("https://github.com/o/r/releases/download/v2.3.4/tool-2.3.4.zip"),
            "2.3.4"
        );
    }

    #[test]
    fn guess_version_bare_number() {
        assert_eq!(guess_version("https://example.com/tool-7.zip"), "7");
    }

    #[test]
    fn guess_version_fallback() {
        assert_eq!(guess_version("https://example.com/mytool.zip"), "1.0.0");
    }

    /// A wizard-authored manifest must already be canonical. If it is not, the
    /// first `bump` or `scoop-sync` to touch the file reformats every line of it
    /// — the exact churn the canonical form exists to prevent.
    #[test]
    fn wizard_output_is_canonical() {
        let url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip";
        let m = wizard_manifest(
            "ripgrep",
            &guess_version(url),
            url,
            &hex::encode(Sha256::digest(b"payload")),
            Some("ripgrep-14.1.1-x86_64-pc-windows-msvc".to_string()),
            vec!["rg.exe".to_string()],
        );
        let text = m.to_canonical_toml();
        let parsed = Manifest::from_toml_str(&text).expect("wizard output must validate");
        assert!(parsed.is_canonical_toml(&text), "not canonical:\n{text}");
        // The struct survives the round trip, so `new` writing the canonical text
        // and the client parsing it agree on every optional field.
        assert_eq!(parsed, m);
        assert_eq!(parsed.version, "14.1.1");
        assert_eq!(parsed.bin[0].path(), "rg.exe");
    }

    #[test]
    fn guess_version_no_arch_leak() {
        // The "14.1.1-x86 bug": arch tokens must not leak into the version.
        assert_eq!(
            guess_version("https://x/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"),
            "14.1.1"
        );
    }
}
