//! Filesystem layout resolution (spec §3).
//!
//! The voli root defaults to `%LOCALAPPDATA%\voli` on Windows,
//! `~/.local/share/voli` (or `$XDG_DATA_HOME/voli`) on Linux, and
//! `~/Library/Application Support/voli` on macOS. It is overridable via the
//! `VOLI_ROOT` environment variable (which is also how the test suite isolates
//! each run into a tempdir).

use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillScope {
    Global,
    Project,
}

impl SkillScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
        }
    }
}

/// Agent installations supported by the skill installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillTarget {
    id: &'static str,
    project_dir: &'static str,
    global_dir: &'static str,
    marker: &'static str,
    appdata_marker: Option<&'static str>,
}

impl SkillTarget {
    pub(crate) const fn new_full(
        id: &'static str,
        project_dir: &'static str,
        global_dir: &'static str,
        marker: &'static str,
    ) -> Self {
        Self {
            id,
            project_dir,
            global_dir,
            marker,
            appdata_marker: None,
        }
    }

    pub(crate) const fn new_full_with_appdata(
        id: &'static str,
        project_dir: &'static str,
        global_dir: &'static str,
        marker: &'static str,
        appdata_marker: &'static str,
    ) -> Self {
        Self {
            id,
            project_dir,
            global_dir,
            marker,
            appdata_marker: Some(appdata_marker),
        }
    }

    #[allow(non_upper_case_globals)]
    pub const ClaudeCode: Self =
        Self::new_full("claude-code", ".claude/skills", ".claude/skills", ".claude");
    #[allow(non_upper_case_globals)]
    pub const Codex: Self = Self::new_full("codex", ".agents/skills", ".agents/skills", ".codex");
    #[allow(non_upper_case_globals)]
    pub const Cursor: Self =
        Self::new_full("cursor", ".agents/skills", ".cursor/skills", ".cursor");
    #[allow(non_upper_case_globals)]
    pub const Windsurf: Self = Self::new_full(
        "windsurf",
        ".windsurf/skills",
        ".codeium/windsurf/skills",
        ".codeium/windsurf",
    );

    pub fn as_str(self) -> &'static str {
        self.id
    }

    /// Resolve an agent's global skills directory from an explicit home path.
    pub fn global_skills_dir(self, home: &Path) -> PathBuf {
        home.join(self.global_dir)
    }

    pub fn project_skills_dir(self, project: &Path) -> PathBuf {
        project.join(self.project_dir)
    }

    pub fn skills_dir(self, scope: SkillScope, home: &Path, project: &Path) -> PathBuf {
        match scope {
            SkillScope::Global => self.global_skills_dir(home),
            SkillScope::Project => self.project_skills_dir(project),
        }
    }

    pub fn marker_path(self, home: &Path) -> PathBuf {
        home.join(self.marker)
    }

    pub fn is_detected(self, home: &Path) -> bool {
        self.is_detected_in(home, appdata_dir().as_deref())
    }

    pub fn is_detected_in(self, home: &Path, appdata: Option<&Path>) -> bool {
        if self.marker_path(home).exists() {
            return true;
        }
        let Some(marker) = self.appdata_marker else {
            return false;
        };
        // Primary hint (APPDATA on Windows, first candidate on unix).
        if appdata.is_some_and(|base| base.join(marker).exists()) {
            return true;
        }
        // On unix also probe the other well-known config locations, so a
        // marker in any of them counts as detected.
        #[cfg(not(windows))]
        {
            for base in appdata_candidates(home) {
                if base.join(marker).exists() {
                    return true;
                }
            }
        }
        false
    }

    pub fn all() -> &'static [SkillTarget] {
        GENERATED_SKILL_TARGETS
    }
}

include!("agent_targets_generated.rs");

impl FromStr for SkillTarget {
    type Err = SkillTargetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        GENERATED_SKILL_TARGETS
            .iter()
            .copied()
            .find(|target| target.id == value)
            .ok_or_else(|| SkillTargetError(value.to_string()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SkillTargetError(String);

impl std::fmt::Display for SkillTargetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "unknown skill target '{}': supported targets are {}",
            self.0,
            SKILL_TARGET_IDS.join(", ")
        )
    }
}

impl std::error::Error for SkillTargetError {}

/// Resolved on-disk layout rooted at a single directory.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// Resolve the root: `VOLI_ROOT` if set, else the platform default
    /// ([`default_root`]).
    pub fn resolve() -> std::io::Result<Paths> {
        let root = if let Some(r) = std::env::var_os("VOLI_ROOT") {
            PathBuf::from(r)
        } else {
            default_root().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, default_root_error())
            })?
        };
        Ok(Paths::at(root))
    }

    /// Layout rooted at an explicit directory.
    pub fn at(root: impl Into<PathBuf>) -> Paths {
        Paths { root: root.into() }
    }

    pub fn apps(&self) -> PathBuf {
        self.root.join("apps")
    }
    pub fn shims(&self) -> PathBuf {
        self.root.join("shims")
    }
    pub fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }
    pub fn db(&self) -> PathBuf {
        self.root.join("db")
    }
    pub fn state_db(&self) -> PathBuf {
        self.db().join("state.sqlite")
    }

    pub fn app_dir(&self, name: &str) -> PathBuf {
        self.apps().join(name)
    }
    pub fn version_dir(&self, name: &str, version: &str) -> PathBuf {
        self.app_dir(name).join(version)
    }
    pub fn current(&self, name: &str) -> PathBuf {
        self.app_dir(name).join("current")
    }
    pub fn persist_root(&self, name: &str) -> PathBuf {
        self.app_dir(name).join("persist")
    }

    /// Create the four top-level subdirs (apps, shims, cache, db). Idempotent.
    /// These are shared infrastructure, not per-package state — never rolled back.
    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [self.apps(), self.shims(), self.cache(), self.db()] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}

/// The current user's home directory: `HOME` first on unix (where `USERPROFILE`
/// does not exist), `USERPROFILE` first on Windows. Returns `None` when neither
/// is set.
pub fn user_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    }
}

/// The platform-default voli root (before `VOLI_ROOT` is considered):
/// `%LOCALAPPDATA%\voli` on Windows, `$XDG_DATA_HOME/voli` (or
/// `~/.local/share/voli`) on Linux, `~/Library/Application Support/voli` on
/// macOS. Returns `None` when the home directory cannot be determined.
pub fn default_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(|l| PathBuf::from(l).join("voli"))
    }
    #[cfg(target_os = "macos")]
    {
        user_home().map(|h| h.join("Library").join("Application Support").join("voli"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from)
            && xdg.is_absolute()
        {
            return Some(xdg.join("voli"));
        }
        user_home().map(|h| h.join(".local").join("share").join("voli"))
    }
}

fn default_root_error() -> &'static str {
    #[cfg(windows)]
    {
        "LOCALAPPDATA is not set and VOLI_ROOT was not provided"
    }
    #[cfg(target_os = "macos")]
    {
        "HOME is not set and VOLI_ROOT was not provided"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "neither XDG_DATA_HOME nor HOME is set and VOLI_ROOT was not provided"
    }
}

/// The roaming-app-data directory used for agent-marker detection:
/// `%APPDATA%` on Windows; on unix the first of the well-known config roots.
/// See [`appdata_candidates`] for the full probe list.
fn appdata_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        appdata_candidates_opt().into_iter().next()
    }
}

#[cfg(not(windows))]
fn appdata_candidates_opt() -> Vec<PathBuf> {
    user_home()
        .map(|home| appdata_candidates(&home))
        .unwrap_or_default()
}

/// Every directory probed for an `appdata_marker` on unix, most specific first:
/// `$XDG_CONFIG_HOME`, `~/.config`, and (macOS only)
/// `~/Library/Application Support`.
#[cfg(not(windows))]
fn appdata_candidates(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from)
        && xdg.is_absolute()
    {
        out.push(xdg);
    }
    out.push(home.join(".config"));
    #[cfg(target_os = "macos")]
    {
        out.push(home.join("Library").join("Application Support"));
    }
    out
}

impl AsRef<Path> for Paths {
    fn as_ref(&self) -> &Path {
        &self.root
    }
}
