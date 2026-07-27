//! Package manifest types and validation (spec §4).
//!
//! One TOML file per package version. Declarative only — there is deliberately
//! no script field, and the grammar cannot express one.

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Package kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    App,
    Mcp,
    Skill,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Mcp => "mcp",
            Self::Skill => "skill",
        }
    }
}

/// A package identity. Bare names remain app references for compatibility.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageRef {
    pub kind: Kind,
    pub name: String,
}

impl PackageRef {
    pub fn parse(value: &str) -> Result<Self, PackageRefError> {
        value.parse()
    }
}

impl FromStr for PackageRef {
    type Err = PackageRefError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, name) = match value.split_once('/') {
            Some(("app", name)) => (Kind::App, name),
            Some(("mcp", name)) => (Kind::Mcp, name),
            Some(("skill", name)) => (Kind::Skill, name),
            Some((kind, _)) => return Err(PackageRefError::Kind(kind.to_string())),
            None => (Kind::App, value),
        };
        validate_name(name).map_err(|_| PackageRefError::Name(name.to_string()))?;
        Ok(Self {
            kind,
            name: name.to_string(),
        })
    }
}

/// Errors from parsing a package reference.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackageRefError {
    #[error("unknown package kind '{0}': expected app, mcp, or skill")]
    Kind(String),
    #[error("invalid package name '{0}': must be lowercase alphanumeric and dashes only")]
    Name(String),
}

/// How a source payload is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    /// Regular archive (zip/7z/tar.gz) — extracted directly.
    #[default]
    Archive,
    /// Installer binary (.exe/.msi) — extracted with 7-Zip (no-execute),
    /// never run. Hash-verified before extraction.
    InstallerArchive,
}

impl SourceKind {
    fn is_archive(&self) -> bool {
        *self == Self::Archive
    }
}

/// A per-architecture download source.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub url: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub sha512: Option<String>,
    /// Additional archives extracted into subdirectories of the version dir.
    #[serde(default)]
    pub extra: Vec<ExtraSource>,
    /// How the payload is handled (default: archive).
    #[serde(default, skip_serializing_if = "SourceKind::is_archive")]
    pub kind: SourceKind,
}

impl Source {
    /// The primary hash value (sha256 or sha512, whichever is present).
    /// Panics if neither is set — unreachable after validation.
    pub fn hash(&self) -> &str {
        self.sha256
            .as_deref()
            .or(self.sha512.as_deref())
            .expect("validated: exactly one hash is present")
    }

    /// True when the primary hash is sha512 (false = sha256).
    pub fn is_sha512(&self) -> bool {
        self.sha512.is_some()
    }
}

/// An extra download extracted into a subdirectory of the version dir.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraSource {
    pub url: String,
    pub sha256: String,
    pub extract_to: String,
}

/// Sources keyed by architecture. At least one arch must be present.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub any: Option<Source>,
    pub x64: Option<Source>,
    pub arm64: Option<Source>,
}

/// A shim to create. Either a bare relative path (`"rg.exe"`) or the table form
/// `{ name = "t2", path = "tool2.exe", args = "--flag" }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

/// A Start Menu shortcut. Either a bare relative exe path (`"myapp.exe"`) or
/// the table form `{ target = "myapp.exe", name = "My App" }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Shortcut {
    Path(String),
    Table { target: String, name: String },
}

impl Shortcut {
    /// The archive-relative path this shortcut points at.
    pub fn target(&self) -> &str {
        match self {
            Shortcut::Path(p) => p,
            Shortcut::Table { target, .. } => target,
        }
    }

    /// The display name for the `.lnk` file (without extension).
    pub fn link_name(&self) -> String {
        match self {
            Shortcut::Table { name, .. } => name.clone(),
            Shortcut::Path(p) => std::path::Path::new(p)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.clone()),
        }
    }
}

/// A file to write into the version dir during install (declarative, no code).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteFile {
    pub path: String,
    pub content: String,
}

impl Bin {
    /// The archive-relative path this bin points at.
    pub fn path(&self) -> &str {
        match self {
            Bin::Path(p) => p,
            Bin::Table { path, .. } => path,
        }
    }

    /// The base name for the generated `<name>.shim` / `<name>.exe` pair.
    /// Table form uses its explicit `name`; bare paths use the file stem.
    pub fn shim_name(&self) -> String {
        match self {
            Bin::Table { name, .. } => name.clone(),
            Bin::Path(p) => std::path::Path::new(p)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.clone()),
        }
    }

    /// Optional args to prepend, written as line 2 of the `.shim` file.
    pub fn args(&self) -> Option<&str> {
        match self {
            Bin::Table { args, .. } => args.as_deref(),
            Bin::Path(_) => None,
        }
    }
}

/// The full package manifest.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
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

    /// Start Menu shortcuts to create (spec §4).
    #[serde(default)]
    pub shortcuts: Vec<Shortcut>,
    /// Files to write into the version dir after extraction.
    #[serde(default)]
    pub write_file: Vec<WriteFile>,
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

    #[error("invalid skill source: exactly one [source.any] archive is required")]
    SkillSource,

    #[error("invalid skill name '{0}': expected the Agent Skills name format")]
    SkillName(String),

    #[error("invalid skill archive URL '{0}': expected .zip, .tar.gz, or .tgz")]
    SkillArchiveUrl(String),

    #[error("[source.any] is only allowed for skill packages")]
    UniversalSource,

    #[error("source for {arch}: exactly one of sha256 or sha512 is required")]
    HashRequired { arch: &'static str },

    #[error("invalid {alg} for {arch}: must be {len} hex characters")]
    BadHash {
        alg: &'static str,
        arch: &'static str,
        len: usize,
    },

    #[error("invalid {field} path '{path}': must be relative (no absolute paths, no '..')")]
    RelativePath { field: &'static str, path: String },

    #[error("invalid env value for '{key}': only the {{dir}} template variable is allowed")]
    EnvTemplate { key: String },

    #[error("invalid icon URL '{0}': must be an HTTPS URL")]
    IconUrl(String),

    #[error("field '{0}' is not allowed for skill packages")]
    SkillField(&'static str),
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

        if let Some(icon) = &self.icon {
            check_icon_url(icon)?;
        }

        if self.kind == Kind::Skill {
            validate_skill_name(&self.name)?;
            let Some(source) = &self.source.any else {
                return Err(ManifestError::SkillSource);
            };
            if self.source.x64.is_some() || self.source.arm64.is_some() {
                return Err(ManifestError::SkillSource);
            }
            check_source_hash(source, "any")?;
            check_extra_sources(source, "any")?;
            self.validate_skill()?;
            if !is_skill_archive_url(&source.url) {
                return Err(ManifestError::SkillArchiveUrl(source.url.clone()));
            }
        } else {
            if self.source.any.is_some() {
                return Err(ManifestError::UniversalSource);
            }
            if self.source.x64.is_none() && self.source.arm64.is_none() {
                return Err(ManifestError::NoSource);
            }
            if let Some(s) = &self.source.x64 {
                check_source_hash(s, "x64")?;
                check_extra_sources(s, "x64")?;
            }
            if let Some(s) = &self.source.arm64 {
                check_source_hash(s, "arm64")?;
                check_extra_sources(s, "arm64")?;
            }
        }

        for b in &self.bin {
            check_relative(b.path(), "bin")?;
        }

        for (key, val) in &self.env {
            check_env_template(key, val)?;
        }

        for sc in &self.shortcuts {
            check_relative(sc.target(), "shortcut")?;
        }

        for wf in &self.write_file {
            check_relative(&wf.path, "write_file")?;
        }

        Ok(())
    }

    fn validate_skill(&self) -> Result<(), ManifestError> {
        let app_field = if self.extract_dir.is_some() {
            Some("extract_dir")
        } else if !self.bin.is_empty() {
            Some("bin")
        } else if !self.env.is_empty() {
            Some("env")
        } else if !self.depends.is_empty() {
            Some("depends")
        } else if !self.persist.is_empty() {
            Some("persist")
        } else if self.gui.is_some() {
            Some("gui")
        } else if !self.shortcuts.is_empty() {
            Some("shortcuts")
        } else if !self.write_file.is_empty() {
            Some("write_file")
        } else {
            None
        };
        if let Some(field) = app_field {
            return Err(ManifestError::SkillField(field));
        }
        let source = self
            .source
            .any
            .as_ref()
            .expect("validated: skill has a universal source");
        if source.kind != SourceKind::Archive {
            return Err(ManifestError::SkillField("source.kind"));
        }
        if !source.extra.is_empty() {
            return Err(ManifestError::SkillField("source.extra"));
        }
        Ok(())
    }
}

fn check_icon_url(url: &str) -> Result<(), ManifestError> {
    let valid = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|host| !host.is_empty() && !host.chars().any(char::is_whitespace));
    if valid {
        Ok(())
    } else {
        Err(ManifestError::IconUrl(url.to_string()))
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

fn validate_skill_name(name: &str) -> Result<(), ManifestError> {
    if name.len() <= 64 && !name.starts_with('-') && !name.ends_with('-') && !name.contains("--") {
        Ok(())
    } else {
        Err(ManifestError::SkillName(name.to_string()))
    }
}

fn is_skill_archive_url(url: &str) -> bool {
    let path = url
        .split_once("#/")
        .map(|(_, path)| path)
        .unwrap_or_else(|| url.split(['?', '#']).next().unwrap_or(url))
        .to_ascii_lowercase();
    path.ends_with(".zip") || path.ends_with(".tar.gz") || path.ends_with(".tgz")
}

fn check_source_hash(source: &Source, arch: &'static str) -> Result<(), ManifestError> {
    match (&source.sha256, &source.sha512) {
        (Some(h), None) => check_hex(h, 64, "sha256", arch),
        (None, Some(h)) => check_hex(h, 128, "sha512", arch),
        _ => Err(ManifestError::HashRequired { arch }),
    }
}

fn check_extra_sources(source: &Source, arch: &'static str) -> Result<(), ManifestError> {
    for ex in &source.extra {
        check_hex(&ex.sha256, 64, "sha256", arch)?;
        check_relative(&ex.extract_to, "extra extract_to")?;
    }
    Ok(())
}

fn check_hex(
    hash: &str,
    len: usize,
    alg: &'static str,
    arch: &'static str,
) -> Result<(), ManifestError> {
    if hash.len() == len && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ManifestError::BadHash { alg, arch, len })
    }
}

fn check_relative(path: &str, field: &'static str) -> Result<(), ManifestError> {
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
        Err(ManifestError::RelativePath {
            field,
            path: path.to_string(),
        })
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
icon = "https://example.com/ripgrep.svg"
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
        assert_eq!(m.icon.as_deref(), Some("https://example.com/ripgrep.svg"));
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
    fn source_kind_defaults_and_parses_installer_archive() {
        let regular = Manifest::from_toml_str(&minimal("")).unwrap();
        assert_eq!(
            regular.source.x64.as_ref().unwrap().kind,
            SourceKind::Archive
        );
        assert!(
            !toml::to_string(&regular)
                .unwrap()
                .contains("kind = \"archive\"")
        );

        let installer = Manifest::from_toml_str(&minimal(
            "[source.arm64]\nurl = \"https://example.com/setup.exe\"\nsha256 = \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"\nkind = \"installer-archive\"",
        ))
        .unwrap();
        assert_eq!(
            installer.source.arm64.as_ref().unwrap().kind,
            SourceKind::InstallerArchive
        );
        assert!(
            toml::to_string(&installer)
                .unwrap()
                .contains("kind = \"installer-archive\"")
        );
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
            Err(ManifestError::BadHash { .. })
        ));
    }

    #[test]
    fn rejects_non_https_icon() {
        let s = minimal(r#"icon = "http://example.com/app.png""#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::IconUrl(_))
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
            Err(ManifestError::BadHash { .. })
        ));
    }

    #[test]
    fn rejects_absolute_bin_path() {
        let s = minimal(r#"bin = ["C:\\windows\\rg.exe"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::RelativePath { .. })
        ));
    }

    #[test]
    fn rejects_unix_absolute_bin_path() {
        let s = minimal(r#"bin = ["/usr/bin/rg"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::RelativePath { .. })
        ));
    }

    #[test]
    fn rejects_parent_dir_bin_path() {
        let s = minimal(r#"bin = ["../escape.exe"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::RelativePath { .. })
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

    #[test]
    fn accepts_sha512_instead_of_sha256() {
        let s = format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha512 = "{}"
"#,
            "a".repeat(128)
        );
        let m = Manifest::from_toml_str(&s).expect("sha512 should be accepted");
        assert!(m.source.x64.as_ref().unwrap().is_sha512());
        assert_eq!(m.source.x64.as_ref().unwrap().hash(), "a".repeat(128));
    }

    #[test]
    fn rejects_both_sha256_and_sha512() {
        let s = format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha256 = "{}"
sha512 = "{}"
"#,
            "a".repeat(64),
            "b".repeat(128)
        );
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::HashRequired { .. })
        ));
    }

    #[test]
    fn rejects_neither_sha256_nor_sha512() {
        let s = r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
"#;
        assert!(matches!(
            Manifest::from_toml_str(s),
            Err(ManifestError::HashRequired { .. })
        ));
    }

    #[test]
    fn parses_shortcuts_both_forms() {
        let s =
            minimal(r#"shortcuts = ["myapp.exe", { target = "sub/tool.exe", name = "My Tool" }]"#);
        let m = Manifest::from_toml_str(&s).expect("shortcuts should parse");
        assert_eq!(m.shortcuts.len(), 2);
        assert_eq!(m.shortcuts[0].target(), "myapp.exe");
        assert_eq!(m.shortcuts[0].link_name(), "myapp");
        assert_eq!(m.shortcuts[1].target(), "sub/tool.exe");
        assert_eq!(m.shortcuts[1].link_name(), "My Tool");
    }

    #[test]
    fn rejects_shortcut_traversal() {
        let s = minimal(r#"shortcuts = ["../evil.exe"]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::RelativePath { .. })
        ));
    }

    #[test]
    fn parses_write_file() {
        let s = minimal(
            r#"write_file = [{ path = "portable.ini", content = "[settings]\nportable=true" }]"#,
        );
        let m = Manifest::from_toml_str(&s).expect("write_file should parse");
        assert_eq!(m.write_file.len(), 1);
        assert_eq!(m.write_file[0].path, "portable.ini");
    }

    #[test]
    fn rejects_write_file_traversal() {
        let s = minimal(r#"write_file = [{ path = "../evil.ini", content = "x" }]"#);
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::RelativePath { .. })
        ));
    }

    #[test]
    fn parses_extra_sources() {
        let s = format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha256 = "{}"
extra = [{{ url = "https://example.com/b.zip", sha256 = "{}", extract_to = "plugins" }}]
"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        let m = Manifest::from_toml_str(&s).expect("extra sources should parse");
        let src = m.source.x64.as_ref().unwrap();
        assert_eq!(src.extra.len(), 1);
        assert_eq!(src.extra[0].extract_to, "plugins");
    }

    #[test]
    fn rejects_extra_extract_to_traversal() {
        let s = format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://example.com/a.zip"
sha256 = "{}"
extra = [{{ url = "https://example.com/b.zip", sha256 = "{}", extract_to = "../escape" }}]
"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::RelativePath { .. })
        ));
    }

    #[test]
    fn standard_skill_archive_parses_without_extra_schema() {
        let s = format!(
            r#"
name = "tdd"
version = "1.0.0"
description = "Test-driven development workflow"
kind = "skill"

[source.any]
url = "https://example.com/tdd.zip"
sha256 = "{}"
"#,
            "a".repeat(64)
        );
        let skill = Manifest::from_toml_str(&s).expect("standard skill archive should parse");
        assert_eq!(skill.kind, Kind::Skill);
        assert!(skill.bin.is_empty());
        assert!(!toml::to_string(&skill).unwrap().contains("[skill]"));
    }

    #[test]
    fn skill_manifest_enforces_name_and_archive_shape_early() {
        let long_name = "a".repeat(65);
        for name in ["-tdd", "tdd-", "test--driven", long_name.as_str()] {
            let text = format!(
                r#"
name = "{name}"
version = "1.0.0"
kind = "skill"

[source.any]
url = "https://example.com/tdd.zip"
sha256 = "{}"
"#,
                "a".repeat(64)
            );
            assert!(matches!(
                Manifest::from_toml_str(&text),
                Err(ManifestError::SkillName(_))
            ));
        }

        let extensionless = format!(
            r#"
name = "tdd"
version = "1.0.0"
kind = "skill"

[source.any]
url = "https://example.com/download"
sha256 = "{}"
"#,
            "a".repeat(64)
        );
        assert!(matches!(
            Manifest::from_toml_str(&extensionless),
            Err(ManifestError::SkillArchiveUrl(_))
        ));
    }

    #[test]
    fn skill_rejects_app_only_fields() {
        for (field, extra) in [
            ("extract_dir", r#"extract_dir = "wrapped""#),
            ("bin", r#"bin = ["tool.exe"]"#),
            ("env", r#"env = { PATH = "{dir}" }"#),
            ("depends", r#"depends = { app = "*" }"#),
            ("persist", r#"persist = ["config"]"#),
            ("gui", "gui = false"),
            ("shortcuts", r#"shortcuts = ["tool.exe"]"#),
            (
                "write_file",
                r#"write_file = [{ path = "config", content = "x" }]"#,
            ),
        ] {
            let s = format!(
                r#"
name = "tdd"
version = "1.0.0"
kind = "skill"
{extra}

[source.any]
url = "https://example.com/tdd.zip"
sha256 = "{}"
"#,
                "a".repeat(64)
            );
            assert!(matches!(
                Manifest::from_toml_str(&s),
                Err(ManifestError::SkillField(actual)) if actual == field
            ));
        }
    }

    #[test]
    fn skill_rejects_nonstandard_source_features() {
        let s = format!(
            r#"
name = "tdd"
version = "1.0.0"
kind = "skill"

[source.any]
url = "https://example.com/tdd.exe"
sha256 = "{}"
kind = "installer-archive"
"#,
            "a".repeat(64)
        );
        assert!(matches!(
            Manifest::from_toml_str(&s),
            Err(ManifestError::SkillField("source.kind"))
        ));
    }

    #[test]
    fn universal_source_is_skill_only() {
        let app = minimal("").replace("[source.x64]", "[source.any]");
        assert!(matches!(
            Manifest::from_toml_str(&app),
            Err(ManifestError::UniversalSource)
        ));

        let skill = minimal("")
            .replace(r#"kind = "app""#, r#"kind = "skill""#)
            .replace("[source.x64]", "[source.any]");
        Manifest::from_toml_str(&skill).expect("skill accepts a universal source");

        let arch_skill = minimal("").replace(r#"kind = "app""#, r#"kind = "skill""#);
        assert!(matches!(
            Manifest::from_toml_str(&arch_skill),
            Err(ManifestError::SkillSource)
        ));
    }

    #[test]
    fn package_refs_are_qualified_without_weakening_manifest_names() {
        assert_eq!(
            PackageRef::parse("foo").unwrap(),
            PackageRef {
                kind: Kind::App,
                name: "foo".to_string(),
            }
        );
        assert_eq!(PackageRef::parse("app/foo").unwrap().kind, Kind::App);
        assert_eq!(PackageRef::parse("mcp/foo").unwrap().kind, Kind::Mcp);
        assert_eq!(PackageRef::parse("skill/foo").unwrap().kind, Kind::Skill);
        assert!(matches!(
            PackageRef::parse("skill/foo/bar"),
            Err(PackageRefError::Name(name)) if name == "foo/bar"
        ));
        assert!(matches!(
            PackageRef::parse("other/foo"),
            Err(PackageRefError::Kind(kind)) if kind == "other"
        ));
        assert!(matches!(
            Manifest::from_toml_str(&minimal("").replace("name = \"app\"", "name = \"app/foo\"")),
            Err(ManifestError::Name(name)) if name == "app/foo"
        ));
    }
}
