//! Filesystem layout resolution (spec §3).
//!
//! The voli root defaults to `%LOCALAPPDATA%\voli` and is overridable via the
//! `VOLI_ROOT` environment variable (which is also how the test suite isolates
//! each run into a tempdir).

use std::path::{Path, PathBuf};

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
