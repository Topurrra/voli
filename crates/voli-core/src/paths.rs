//! Filesystem layout resolution (spec §3).
//!
//! The voli root defaults to `%LOCALAPPDATA%\voli` and is overridable via the
//! `VOLI_ROOT` environment variable (which is also how the test suite isolates
//! each run into a tempdir).

use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Agent installations supported by the skill installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillTarget {
    id: &'static str,
    global_dir: &'static str,
}

impl SkillTarget {
    pub(crate) const fn new(id: &'static str, global_dir: &'static str) -> Self {
        Self { id, global_dir }
    }

    #[allow(non_upper_case_globals)]
    pub const ClaudeCode: Self = Self::new("claude-code", ".claude/skills");
    #[allow(non_upper_case_globals)]
    pub const Codex: Self = Self::new("codex", ".agents/skills");
    #[allow(non_upper_case_globals)]
    pub const Cursor: Self = Self::new("cursor", ".cursor/skills");
    #[allow(non_upper_case_globals)]
    pub const Windsurf: Self = Self::new("windsurf", ".codeium/windsurf/skills");

    pub fn as_str(self) -> &'static str {
        self.id
    }

    /// Resolve an agent's global skills directory from an explicit home path.
    pub fn global_skills_dir(self, home: &Path) -> PathBuf {
        home.join(self.global_dir)
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
    /// Resolve the root: `VOLI_ROOT` if set, else `%LOCALAPPDATA%\voli`.
    pub fn resolve() -> std::io::Result<Paths> {
        let root = if let Some(r) = std::env::var_os("VOLI_ROOT") {
            PathBuf::from(r)
        } else {
            let local = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "LOCALAPPDATA is not set and VOLI_ROOT was not provided",
                )
            })?;
            PathBuf::from(local).join("voli")
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

impl AsRef<Path> for Paths {
    fn as_ref(&self) -> &Path {
        &self.root
    }
}
