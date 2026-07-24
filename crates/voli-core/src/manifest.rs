//! Package manifest types and validation (spec §4).
//!
//! One TOML file per package version. Declarative only — there is deliberately
//! no script field, and the grammar cannot express one.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Package kind. Only `App` is wired in v1; `Mcp`/`Skill` are v2 (spec §11 phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    App,
    Mcp,
    Skill,
}

/// A per-architecture download source.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    pub sha256: String,
}

/// Sources keyed by architecture. At least one arch must be present.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub x64: Option<Source>,
    pub arm64: Option<Source>,
}

/// A shim to create. Either a bare relative path (`"rg.exe"`) or the table form
/// `{ name = "t2", path = "tool2.exe", args = "--flag" }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Bin {
    Path(String),
    Table {
        name: String,
        path: String,
        #[serde(default)]
        args: Option<String>,
    },
}

impl Bin {
    /// The archive-relative path this bin points at.
    pub fn path(&self) -> &str {
        match self {
            Bin::Path(p) => p,
            Bin::Table { path, .. } => path,
        }
    }
}

/// The full package manifest.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    pub kind: Kind,

    #[serde(default)]
    pub source: Sources,

    #[serde(default)]
    pub extract_dir: Option<String>,
    #[serde(default)]
    pub bin: Vec<Bin>,

    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub depends: BTreeMap<String, String>,

    /// CI-only metadata (checkver / url_template). Captured but not interpreted
    /// by the client.
    #[serde(default)]
    pub autoupdate: Option<toml::Value>,

    #[serde(default)]
    pub persist: Vec<String>,
    #[serde(default)]
    pub gui: Option<bool>,
}

/// Errors from parsing or validating a manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid package name '{0}': must be lowercase alphanumeric and dashes only")]
    Name(String),

    #[error("no source: at least one of [source.x64] or [source.arm64] is required")]
    NoSource,

    #[error("invalid sha256 for {arch}: must be 64 hex characters")]
    Sha256 { arch: &'static str },

    #[error("invalid bin path '{0}': must be relative (no absolute paths, no '..')")]
    BinPath(String),

    #[error("invalid env value for '{key}': only the {{dir}} template variable is allowed")]
    EnvTemplate { key: String },
}

impl Manifest {
    /// Parse and validate a manifest from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Manifest, ManifestError> {
        let m: Manifest = toml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        validate_name(&self.name)?;

        if self.source.x64.is_none() && self.source.arm64.is_none() {
            return Err(ManifestError::NoSource);
        }
        if let Some(s) = &self.source.x64 {
            check_sha256(&s.sha256, "x64")?;
        }
        if let Some(s) = &self.source.arm64 {
            check_sha256(&s.sha256, "arm64")?;
        }

        for b in &self.bin {
            check_bin_path(b.path())?;
        }

        for (key, val) in &self.env {
            check_env_template(key, val)?;
        }

        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), ManifestError> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(ManifestError::Name(name.to_string()))
    }
}

fn check_sha256(hash: &str, arch: &'static str) -> Result<(), ManifestError> {
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ManifestError::Sha256 { arch })
    }
}

fn check_bin_path(path: &str) -> Result<(), ManifestError> {
    let p = std::path::Path::new(path);
    let absolute = p.is_absolute()
        || path.starts_with('/')
        || path.starts_with('\\')
        // Windows drive-letter root, e.g. C:\...
        || path.chars().nth(1) == Some(':');
    let has_parent = p
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    if absolute || has_parent {
        Err(ManifestError::BinPath(path.to_string()))
    } else {
        Ok(())
    }
}

/// Env values may contain literal text and the single template var `{dir}`.
/// Any other `{...}` placeholder is rejected.
fn check_env_template(key: &str, val: &str) -> Result<(), ManifestError> {
    let mut rest = val;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or_else(|| ManifestError::EnvTemplate {
            key: key.to_string(),
        })?;
        let placeholder = &after[..close];
        if placeholder != "dir" {
            return Err(ManifestError::EnvTemplate {
                key: key.to_string(),
            });
        }
        rest = &after[close + 1..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
name = "ripgrep"
version = "14.1.1"
description = "Recursively search directories with a regex"
homepage = "https://github.com/BurntSushi/ripgrep"
license = "MIT OR Unlicense"
kind = "app"
extract_dir = "ripgrep-14.1.1-x86_64-pc-windows-msvc"
bin = ["rg.exe", { name = "t2", path = "sub/tool2.exe", args = "--flag" }]
persist = ["config", "data"]
gui = false

[source.x64]
url = "https://example.com/rg-x64.zip"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[source.arm64]
url = "https://example.com/rg-arm64.zip"
sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[env]
JAVA_HOME = "{dir}"
PATH = "{dir}\\bin"

[depends]
vcredist = "*"

[autoupdate]
checkver = { github = "BurntSushi/ripgrep" }
"#;

    #[test]
    fn full_manifest_parses() {
        let m = Manifest::from_toml_str(FULL).expect("should parse");
        assert_eq!(m.name, "ripgrep");
        assert_eq!(m.version, "14.1.1");
        assert_eq!(m.kind, Kind::App);
        assert!(m.source.x64.is_some());
        assert!(m.source.arm64.is_some());
        assert_eq!(m.bin.len(), 2);
        assert_eq!(m.bin[0], Bin::Path("rg.exe".to_string()));
        assert_eq!(m.bin[1].path(), "sub/tool2.exe");
        assert_eq!(m.env.get("JAVA_HOME").unwrap(), "{dir}");
        assert_eq!(m.persist, vec!["config", "data"]);
        assert_eq!(m.gui, Some(false));
    }

    #[test]
    fn testdata_ripgrep_parses() {
        let s = include_str!("../testdata/ripgrep.toml");
        Manifest::from_toml_str(s).expect("testdata manifest should parse");
    }

    fn minimal(extra: &str) -> String {
        format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
{extra}

[source.x64]
url = "https://example.com/a.zip"
sha256 = "{hash}"
"#,
            hash = "c".repeat(64),
            extra = extra,
        )
    }

    #[test]
    fn rejects_short_sha256() {
        let s = r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha256 = "abc123"
"#;
        assert!(matches!(
            Manifest::from_toml_str(s),
            Err(ManifestError::Sha256 { .. })
        ));
    }

    #[test]
    fn rejects_non_hex_sha256() {
        let s = format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha256 = "{}"
"#,
            "z".repeat(64)
        );
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::Sha256 { .. })
        ));
    }

    #[test]
    fn rejects_absolute_bin_path() {
        let s = minimal(r#"bin = ["C:\\windows\\rg.exe"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::BinPath(_))
        ));
    }

    #[test]
    fn rejects_unix_absolute_bin_path() {
        let s = minimal(r#"bin = ["/usr/bin/rg"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::BinPath(_))
        ));
    }

    #[test]
    fn rejects_parent_dir_bin_path() {
        let s = minimal(r#"bin = ["../escape.exe"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::BinPath(_))
        ));
    }

    #[test]
    fn rejects_bad_env_template() {
        let s = minimal("[env]\nFOO = \"{home}/x\"");
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::EnvTemplate { .. })
        ));
    }

    #[test]
    fn accepts_dir_env_template() {
        let s = minimal("[env]\nFOO = \"{dir}\\\\bin\"");
        Manifest::from_toml_str(&s).expect("{dir} template should be allowed");
    }

    #[test]
    fn rejects_bad_name() {
        let s = r#"
name = "Rip_Grep"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"#;
        assert!(matches!(
            Manifest::from_toml_str(s),
            Err(ManifestError::Name(_))
        ));
    }

    #[test]
    fn rejects_no_source() {
        let s = r#"
name = "app"
version = "1.0.0"
kind = "app"
"#;
        assert!(matches!(
            Manifest::from_toml_str(s),
            Err(ManifestError::NoSource)
        ));
    }
}
