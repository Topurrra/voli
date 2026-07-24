//! Install from the index: resolve → download → local engine (spec §11 step 9).
//!
//! [`install_remote`] looks a package up in the already-downloaded index,
//! resolves its flat dependency set (deps-first, cycle-safe), downloads each
//! archive (hash-keyed cache), and hands each off to the local install engine
//! ([`crate::install::install_manifest`]). Packages already recorded in the
//! state ledger are skipped. A failure stops the chain; packages installed
//! before it stay installed (each is its own transactional local install), and
//! the caller learns what succeeded from the [`Step`] callbacks it already
//! received.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::path::Path;

use crate::fetch::{self, FetchError};
use crate::index::{self, IndexError, Suggestion};
use crate::install::{self, EnvConsent, InstallError, InstallReport, UpgradeReport};
use crate::manifest::Manifest;
use crate::paths::Paths;
use crate::state::State;

/// Progress events emitted as [`install_remote`] works through the chain.
#[derive(Debug)]
pub enum Step<'a> {
    /// Starting on a package: about to download (or hit cache) then install.
    Downloading { name: &'a str, version: &'a str },
    /// Download byte progress for the current package.
    Progress { done: u64, total: Option<u64> },
    /// A package was freshly installed.
    Installed(&'a InstallReport),
    /// A package was already installed and left untouched.
    Skipped { name: &'a str, version: &'a str },
}

/// What a full [`install_remote`] run produced.
#[derive(Debug, Default)]
pub struct RemoteReport {
    /// Freshly installed packages, in the order they were installed (deps first).
    pub installed: Vec<InstallReport>,
    /// Packages that were already installed and skipped (name, version).
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Install(#[from] InstallError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("no package index yet — run `voli update` first")]
    NoIndex,
    #[error("package '{name}' not found")]
    NotFound {
        name: String,
        suggestions: Vec<Suggestion>,
    },
    #[error("package '{package}' depends on '{dep}', which is not in the index")]
    UnknownDep { package: String, dep: String },
    #[error("package '{0}' has no x64 source in the index")]
    NoArch(String),
}

/// Install `name` (optionally pinned to `version`) and its dependencies.
///
/// `on_step` receives [`Step`] events; the CLI drives its progress bar from
/// them. Deps are installed before dependents. Already-installed packages are
/// skipped. Errors stop the chain — earlier installs remain.
pub fn install_remote(
    name: &str,
    version: Option<&str>,
    root: &Path,
    on_step: &mut dyn FnMut(Step),
) -> Result<RemoteReport, RemoteError> {
    // Bare form: no env consent context, so `[env]` blocks are skipped. The CLI
    // uses [`install_remote_env`] to drive the consent prompt (spec §8).
    install_remote_env(
        name,
        version,
        root,
        crate::env::ENVIRONMENT,
        &mut install::skip_env,
        on_step,
    )
}

/// Like [`install_remote`], but applies each package's `[env]` block subject to
/// `consent` (spec §8). `env_subkey` is the registry subkey to write to
/// ([`crate::env::env_subkey`] in production; a scratch subkey in tests).
pub fn install_remote_env(
    name: &str,
    version: Option<&str>,
    root: &Path,
    env_subkey: &str,
    consent: &mut EnvConsent,
    on_step: &mut dyn FnMut(Step),
) -> Result<RemoteReport, RemoteError> {
    // Resolve the whole chain up front (deps-first). This also surfaces a typo
    // (NotFound + suggestions) or an unknown dep before anything is downloaded.
    let plan = resolve_chain(root, name, version)?;

    let state = State::open(&Paths::at(root).state_db())
        .map_err(|e| RemoteError::Install(InstallError::Sqlite(e)))?;
    let cache = Paths::at(root).cache();

    let mut report = RemoteReport::default();
    for manifest in &plan {
        if state
            .is_installed(&manifest.name)
            .map_err(|e| RemoteError::Install(InstallError::Sqlite(e)))?
        {
            on_step(Step::Skipped {
                name: &manifest.name,
                version: &manifest.version,
            });
            report
                .skipped
                .push((manifest.name.clone(), manifest.version.clone()));
            continue;
        }

        let source = manifest
            .source
            .x64
            .as_ref()
            .ok_or_else(|| RemoteError::NoArch(manifest.name.clone()))?;

        on_step(Step::Downloading {
            name: &manifest.name,
            version: &manifest.version,
        });
        let archive = fetch::download(&source.url, &source.sha256, &cache, &mut |done, total| {
            on_step(Step::Progress { done, total })
        })?;

        let installed = install::install_manifest(manifest, &archive, root, env_subkey, consent)?;
        on_step(Step::Installed(&installed));
        report.installed.push(installed);
    }

    Ok(report)
}

/// Result of an [`upgrade`] attempt.
#[derive(Debug)]
pub enum UpgradeOutcome {
    /// The installed version is already the newest in the index.
    UpToDate { version: String },
    /// A newer version was installed (junction flipped; old dir kept for cleanup).
    Upgraded(UpgradeReport),
}

/// Upgrade one installed package to the newest version in the local index
/// (spec §3, §9, §11 step 10).
///
/// Compares the installed version against the index's latest; if newer, it
/// downloads (cache-aware, with progress via `on_step`) and performs the
/// junction-flip upgrade. Env values carry forward (see [`install::upgrade_install`]).
/// Pin policy is the caller's concern (the CLI skips pinned packages under
/// `--all`).
pub fn upgrade(
    name: &str,
    root: &Path,
    on_step: &mut dyn FnMut(Step),
) -> Result<UpgradeOutcome, RemoteError> {
    let state = State::open(&Paths::at(root).state_db())
        .map_err(|e| RemoteError::Install(InstallError::Sqlite(e)))?;
    let current = state
        .installed_version(name)
        .map_err(|e| RemoteError::Install(InstallError::Sqlite(e)))?
        .ok_or_else(|| RemoteError::Install(InstallError::NotInstalled(name.to_string())))?;
    drop(state);

    let latest = index::info(root, name)?.ok_or_else(|| RemoteError::NotFound {
        name: name.to_string(),
        suggestions: index::did_you_mean(root, name).unwrap_or_default(),
    })?;

    if index::cmp_version(&latest.version, &current) != Ordering::Greater {
        return Ok(UpgradeOutcome::UpToDate { version: current });
    }

    let source = latest
        .source
        .x64
        .as_ref()
        .ok_or_else(|| RemoteError::NoArch(name.to_string()))?;

    on_step(Step::Downloading {
        name: &latest.name,
        version: &latest.version,
    });
    let cache = Paths::at(root).cache();
    let archive = fetch::download(&source.url, &source.sha256, &cache, &mut |done, total| {
        on_step(Step::Progress { done, total })
    })?;

    let report = install::upgrade_install(&latest, &archive, root)?;
    Ok(UpgradeOutcome::Upgraded(report))
}

/// Resolve `name`(@`version`) plus all transitive `[depends]` into a deps-first,
/// duplicate-free install order. Cycle-safe: a node is marked visited on entry,
/// so a back-edge to an in-progress node is ignored rather than looping.
fn resolve_chain(
    root: &Path,
    name: &str,
    version: Option<&str>,
) -> Result<Vec<Manifest>, RemoteError> {
    let mut order: Vec<Manifest> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    visit(root, name, version, None, &mut visited, &mut order)?;
    Ok(order)
}

fn visit(
    root: &Path,
    name: &str,
    version: Option<&str>,
    parent: Option<&str>,
    visited: &mut HashSet<String>,
    order: &mut Vec<Manifest>,
) -> Result<(), RemoteError> {
    if !visited.insert(name.to_string()) {
        return Ok(());
    }

    let manifest = match lookup(root, name, version) {
        Ok(Some(m)) => m,
        Ok(None) => {
            // A missing top-level package (no parent) is a typo — offer
            // suggestions; a missing dependency is a broken index manifest.
            return Err(match parent {
                None => RemoteError::NotFound {
                    name: name.to_string(),
                    suggestions: index::did_you_mean(root, name).unwrap_or_default(),
                },
                Some(p) => RemoteError::UnknownDep {
                    package: p.to_string(),
                    dep: name.to_string(),
                },
            });
        }
        Err(IndexError::NoIndex) => return Err(RemoteError::NoIndex),
        Err(e) => return Err(RemoteError::Index(e)),
    };

    // Deps first (post-order). Version constraints are not yet honoured — deps
    // always resolve to the newest indexed version.
    // ponytail: constraint strings (`"*"`, `">=1.2"`) are ignored in v1; wire a
    // real resolver in only when the catalog carries non-`*` constraints.
    let deps: Vec<String> = manifest.depends.keys().cloned().collect();
    for dep in deps {
        visit(root, &dep, None, Some(name), visited, order)?;
    }

    order.push(manifest);
    Ok(())
}

/// The manifest for `name` at `version` (or the newest version if `None`).
fn lookup(root: &Path, name: &str, version: Option<&str>) -> Result<Option<Manifest>, IndexError> {
    match version {
        Some(v) => index::manifest_at(root, name, v),
        None => index::info(root, name),
    }
}
