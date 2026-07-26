//! `voli-index-tool` — validate and compile the Voli package registry (§11 step 7).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

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
        Command::New { url, name, out } => {
            let toml = wizard(&url, &name)?;
            match out {
                Some(dir) => {
                    // Parse version from the generated TOML to build the path.
                    let m = voli_core::Manifest::from_toml_str(&toml)?;
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
    }
}

/// Manifest wizard: download → sha256 → sniff → inspect → emit TOML.
fn wizard(url: &str, name: &str) -> anyhow::Result<String> {
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

    // 8. Emit TOML.
    let mut toml = String::new();
    toml.push_str(&format!("name = \"{name}\"\n"));
    toml.push_str(&format!("version = \"{version}\"\n"));
    toml.push_str("kind = \"app\"\n");
    if let Some(d) = &extract_dir {
        toml.push_str(&format!("extract_dir = \"{d}\"\n"));
    }
    if !bins.is_empty() {
        let bin_list: Vec<String> = bins.iter().map(|b| format!("\"{b}\"")).collect();
        toml.push_str(&format!("bin = [{}]\n", bin_list.join(", ")));
    }
    toml.push('\n');
    toml.push_str("[source.x64]\n");
    toml.push_str(&format!("url = \"{url}\"\n"));
    toml.push_str(&format!("sha256 = \"{sha256}\"\n"));

    // 9. Validate with the real parser before returning.
    voli_core::Manifest::from_toml_str(&toml)
        .map_err(|e| anyhow::anyhow!("generated manifest failed validation: {e}"))?;

    Ok(toml)
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

    #[test]
    fn guess_version_no_arch_leak() {
        // The "14.1.1-x86 bug": arch tokens must not leak into the version.
        assert_eq!(
            guess_version("https://x/ripgrep-14.1.1-x86_64-pc-windows-msvc.zip"),
            "14.1.1"
        );
    }
}
