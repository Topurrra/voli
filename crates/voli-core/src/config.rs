//! Client configuration in `<root>\config.toml` (spec §3, §9).
//!
//! Two keys today:
//! - `index_url` — where `voli update` fetches the index snapshot from. Lives in
//!   `<root>\config.toml`.
//! - `root` — the voli root override. This is special: it can only take effect
//!   through the **bootstrap** config at `%LOCALAPPDATA%\voli\config.toml`,
//!   because we have to know the root before we can read a config that lives
//!   inside it. `root` written to a non-bootstrap config is inert (a warned
//!   unknown-ish key at read time only if read from the wrong file — we simply
//!   never look for it there).
//!
//! Missing file or missing keys fall back to defaults. Unknown keys warn (to
//! stderr) but never fail — forward compatibility with newer config files.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default index location: the pinned `index` release tag (spec §5),
/// overridable via `voli config set index_url`. Deliberately NOT
/// `/releases/latest/download` — "latest" resolves to whatever release was
/// published most recently, so creating any other release (e.g. `skills`)
/// would silently repoint every client's index fetch and 404 it.
pub const DEFAULT_INDEX_URL: &str =
    "https://github.com/Topurrra/voli-registry/releases/download/index";

/// The recognised config keys. Anything else warns on load.
const KNOWN_KEYS: &[&str] = &["root", "index_url"];

/// Typed view of a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Root override — only meaningful in the bootstrap file.
    pub root: Option<PathBuf>,
    /// Index snapshot base URL.
    pub index_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            root: None,
            index_url: DEFAULT_INDEX_URL.to_string(),
        }
    }
}

impl Config {
    /// Load and type-check a config file. Missing file → defaults. Unknown keys
    /// warn to stderr and are ignored (never fail).
    pub fn load(path: &Path) -> Config {
        let table = read_table(path);
        for k in table.keys() {
            if !KNOWN_KEYS.contains(&k.as_str()) {
                eprintln!(
                    "warning: unknown config key '{k}' in {} (ignored)",
                    path.display()
                );
            }
        }
        Config {
            root: table
                .get("root")
                .and_then(|v| v.as_str())
                .map(PathBuf::from),
            index_url: table
                .get("index_url")
                .and_then(|v| v.as_str())
                .map(|url| checked_index_url(url, path))
                .unwrap_or_else(|| DEFAULT_INDEX_URL.to_string()),
        }
    }

    /// Read a single key's current string value, or `None` if unset/unknown.
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "root" => self.root.as_ref().map(|p| p.display().to_string()),
            "index_url" => Some(self.index_url.clone()),
            _ => None,
        }
    }
}

/// Accept an `index_url` only if we would actually fetch it over http(s).
/// Anything else (`file:`, `ftp:`, a bare path, a UNC share) points the trust
/// chain somewhere it was never meant to go, so we warn and fall back to the
/// default rather than honour it. Plain `http` is allowed — the snapshot is
/// signed either way — but warned about, since the default is https.
fn checked_index_url(url: &str, path: &Path) -> String {
    let scheme = url.trim().to_ascii_lowercase();
    if scheme.starts_with("https://") {
        return url.to_string();
    }
    if scheme.starts_with("http://") {
        eprintln!(
            "warning: index_url in {} uses plain http; the index is signed, but the fetch \
             is not confidential",
            path.display()
        );
        return url.to_string();
    }
    eprintln!(
        "warning: ignoring index_url '{url}' in {} — only http(s) URLs are supported \
         (using the default)",
        path.display()
    );
    DEFAULT_INDEX_URL.to_string()
}

/// Parse `path` as a TOML table; empty on missing file or parse error.
fn read_table(path: &Path) -> toml::Table {
    match fs::read_to_string(path) {
        Ok(text) => match text.parse::<toml::Table>() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("warning: could not parse {}: {e}", path.display());
                toml::Table::new()
            }
        },
        Err(_) => toml::Table::new(),
    }
}

/// Set one key in the TOML file at `path`, creating the file/parent as needed.
/// A read-modify-write that preserves other keys already in the file.
pub fn set_raw(path: &Path, key: &str, value: &str) -> io::Result<()> {
    let mut table = read_table(path);
    table.insert(key.to_string(), toml::Value::String(value.to_string()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = toml::to_string(&table)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(path, text)
}

/// The fixed bootstrap config location: `%LOCALAPPDATA%\voli\config.toml`.
/// This is where the `root` override lives, independent of any overridden root.
pub fn bootstrap_config_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|l| PathBuf::from(l).join("voli").join("config.toml"))
}

/// Resolve the effective voli root:
/// `VOLI_ROOT` env (test/override) → bootstrap `root` key → `%LOCALAPPDATA%\voli`.
pub fn resolve_root() -> io::Result<PathBuf> {
    if let Some(r) = std::env::var_os("VOLI_ROOT") {
        return Ok(PathBuf::from(r));
    }
    if let Some(bp) = bootstrap_config_path()
        && let Some(r) = Config::load(&bp).root
    {
        return Ok(r);
    }
    let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "LOCALAPPDATA is not set and VOLI_ROOT was not provided",
        )
    })?;
    Ok(PathBuf::from(local).join("voli"))
}

/// If `path` looks like it lives under a known cloud-sync folder, return the
/// provider name so callers can warn (spec §3: running exes from synced folders
/// breaks). Substring heuristic — deliberately loose.
pub fn synced_provider(path: &Path) -> Option<&'static str> {
    let s = path.to_string_lossy().to_ascii_lowercase();
    const PROVIDERS: &[(&str, &str)] = &[
        ("onedrive", "OneDrive"),
        ("dropbox", "Dropbox"),
        ("google drive", "Google Drive"),
        ("googledrive", "Google Drive"),
    ];
    PROVIDERS
        .iter()
        .find(|(needle, _)| s.contains(needle))
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("nope.toml"));
        assert_eq!(cfg.index_url, DEFAULT_INDEX_URL);
        assert_eq!(cfg.root, None);
    }

    #[test]
    fn round_trip_index_url() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        set_raw(&p, "index_url", "https://example.com/idx").unwrap();
        let cfg = Config::load(&p);
        assert_eq!(cfg.index_url, "https://example.com/idx");
        assert_eq!(
            cfg.get("index_url").as_deref(),
            Some("https://example.com/idx")
        );
    }

    #[test]
    fn round_trip_root_and_preserves_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        set_raw(&p, "index_url", "https://example.com/idx").unwrap();
        set_raw(&p, "root", "D:\\voli").unwrap();
        let cfg = Config::load(&p);
        assert_eq!(cfg.root, Some(PathBuf::from("D:\\voli")));
        // second write must not clobber the first key
        assert_eq!(cfg.index_url, "https://example.com/idx");
    }

    #[test]
    fn unknown_key_ignored_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        set_raw(&p, "mystery", "42").unwrap();
        set_raw(&p, "index_url", "https://x").unwrap();
        let cfg = Config::load(&p); // warns to stderr, does not panic
        assert_eq!(cfg.index_url, "https://x");
    }

    #[test]
    fn non_http_index_url_falls_back_to_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        for bad in [
            "file:///C:/evil/index",
            r"\\attacker\share\index",
            "ftp://example.com/idx",
            "example.com/idx",
        ] {
            set_raw(&p, "index_url", bad).unwrap();
            assert_eq!(
                Config::load(&p).index_url,
                DEFAULT_INDEX_URL,
                "{bad} must not be used as an index URL"
            );
        }
        // Plain http warns but is still honoured (the snapshot is signed).
        set_raw(&p, "index_url", "http://127.0.0.1:8080/idx").unwrap();
        assert_eq!(Config::load(&p).index_url, "http://127.0.0.1:8080/idx");
    }

    #[test]
    fn synced_provider_detects() {
        assert_eq!(
            synced_provider(Path::new("C:\\Users\\n\\OneDrive\\voli")),
            Some("OneDrive")
        );
        assert_eq!(
            synced_provider(Path::new("C:\\Users\\n\\Dropbox\\voli")),
            Some("Dropbox")
        );
        assert_eq!(synced_provider(Path::new("D:\\voli")), None);
    }
}
