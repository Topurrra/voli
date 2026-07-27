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
use std::sync::mpsc;
use std::thread;

use crate::fetch::{self, FetchError};
use crate::index::{self, IndexError, Suggestion};
use crate::install::{self, EnvConsent, InstallError, InstallReport, UpgradeReport};
use crate::manifest::{Kind, Manifest, PackageRef};
use crate::paths::{Paths, SkillScope, SkillTarget};
use crate::skill::{self, SkillError, SkillInstallReport};
use crate::state::State;

/// Progress events emitted as [`install_remote`] works through the chain.
#[derive(Debug)]
pub enum Step<'a> {
    /// Starting on a package: about to download (or hit cache) then install.
    Downloading { name: &'a str, version: &'a str },
    /// Download byte progress for the current package.
    Progress { done: u64, total: Option<u64> },
    /// All artifacts are verified and the package is ready to install.
    Installing {
        name: &'a str,
        version: &'a str,
        bytes: u64,
        cache_hit: bool,
    },
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

/// Progress events for one remote skill installation.
#[derive(Debug)]
pub enum SkillStep<'a> {
    Downloading {
        name: &'a str,
        version: &'a str,
    },
    Progress {
        done: u64,
        total: Option<u64>,
    },
    Installing {
        name: &'a str,
        version: &'a str,
        bytes: u64,
        cache_hit: bool,
    },
}

/// Result of installing one skill for one target agent.
#[derive(Debug)]
pub enum SkillRemoteReport {
    Installed(SkillInstallReport),
    Skipped {
        name: String,
        version: String,
        target: SkillTarget,
    },
}

#[derive(Debug)]
pub enum PrefetchStep {
    Queued {
        position: usize,
        total: usize,
        name: String,
    },
    Downloading {
        position: usize,
        total: usize,
        name: String,
        version: String,
    },
    Progress {
        position: usize,
        total: usize,
        done: u64,
        length: Option<u64>,
    },
    Prepared {
        position: usize,
        total: usize,
        name: String,
        bytes: u64,
        cache_hit: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Install(#[from] InstallError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Skill(#[from] SkillError),
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
    #[error("skill package '{0}' has no universal source in the index")]
    NoUniversalSource(String),
}

/// Resolve, download, and install one signed skill archive for an agent.
pub fn install_skill_remote(
    name: &str,
    version: Option<&str>,
    target: SkillTarget,
    home: &Path,
    root: &Path,
    on_step: &mut dyn FnMut(SkillStep),
) -> Result<SkillRemoteReport, RemoteError> {
    Ok(install_skill_remote_many(
        name,
        version,
        &[target],
        SkillScope::Global,
        home,
        Path::new("."),
        root,
        on_step,
    )?
    .pop()
    .expect("one target produces one report"))
}

#[allow(clippy::too_many_arguments)]
pub fn install_skill_remote_many(
    name: &str,
    version: Option<&str>,
    targets: &[SkillTarget],
    scope: SkillScope,
    home: &Path,
    project: &Path,
    root: &Path,
    on_step: &mut dyn FnMut(SkillStep),
) -> Result<Vec<SkillRemoteReport>, RemoteError> {
    let package = PackageRef {
        kind: Kind::Skill,
        name: name.to_string(),
    };
    let manifest = match version {
        Some(version) => index::manifest_at_ref(root, &package, version)?,
        None => index::info_ref(root, &package)?,
    }
    .ok_or_else(|| RemoteError::NotFound {
        name: format!("skill/{name}"),
        suggestions: index::did_you_mean_ref(root, &package).unwrap_or_default(),
    })?;

    let state = State::open(&Paths::at(root).state_db())
        .map_err(|error| RemoteError::Skill(SkillError::Sqlite(error)))?;
    let mut pending = Vec::new();
    let mut skipped = Vec::new();
    for target in targets {
        if let Some(installed) = state
            .installed_skill(target.as_str(), scope.as_str(), name)
            .map_err(|error| RemoteError::Skill(SkillError::Sqlite(error)))?
        {
            if !installed.install_dir.exists() {
                return Err(RemoteError::Skill(SkillError::IncompleteInstall {
                    target: target.as_str().to_string(),
                    name: installed.name,
                }));
            }
            if installed.version == manifest.version {
                skipped.push(SkillRemoteReport::Skipped {
                    name: installed.name,
                    version: installed.version,
                    target: *target,
                });
                continue;
            }
            return Err(RemoteError::Skill(SkillError::VersionConflict {
                target: target.as_str().to_string(),
                name: installed.name,
                installed: installed.version,
                requested: manifest.version,
            }));
        }
        pending.push(*target);
    }
    drop(state);
    if pending.is_empty() {
        return Ok(skipped);
    }

    let source = manifest
        .source
        .any
        .as_ref()
        .ok_or_else(|| RemoteError::NoUniversalSource(name.to_string()))?;
    on_step(SkillStep::Downloading {
        name: &manifest.name,
        version: &manifest.version,
    });
    let archive = fetch::download_with_status(
        &source.url,
        source.hash(),
        &Paths::at(root).cache(),
        &mut |done, total| on_step(SkillStep::Progress { done, total }),
    )?;
    on_step(SkillStep::Installing {
        name: &manifest.name,
        version: &manifest.version,
        bytes: archive.size,
        cache_hit: archive.cache_hit,
    });
    let reports = skill::install_skill_archive_many(
        &manifest,
        &archive.path,
        &pending,
        scope,
        home,
        project,
        root,
    )?;
    let mut results = reports
        .into_iter()
        .map(SkillRemoteReport::Installed)
        .collect::<Vec<_>>();
    results.append(&mut skipped);
    Ok(results)
}

/// Download all artifacts for several requested packages concurrently.
///
/// Only cache files are written here. Package installation, environment
/// changes, shims, and state updates remain sequential in [`install_remote`].
pub fn prefetch_remote(
    packages: &[(String, Option<String>)],
    root: &Path,
    on_step: &mut dyn FnMut(PrefetchStep),
) -> Result<(), RemoteError> {
    #[derive(Debug)]
    struct Job {
        package: String,
        version: String,
        url: String,
        hash: String,
    }

    let state = State::open(&Paths::at(root).state_db())
        .map_err(|error| RemoteError::Install(InstallError::Sqlite(error)))?;
    let mut seen_packages = HashSet::new();
    let mut seen_hashes = HashSet::new();
    let mut plans: Vec<Vec<Job>> = (0..packages.len()).map(|_| Vec::new()).collect();

    for (position, (name, version)) in packages.iter().enumerate() {
        on_step(PrefetchStep::Queued {
            position: position + 1,
            total: packages.len(),
            name: name.clone(),
        });
        for manifest in resolve_chain(root, name, version.as_deref())? {
            if !seen_packages.insert(manifest.name.clone())
                || state
                    .is_installed(&manifest.name)
                    .map_err(|error| RemoteError::Install(InstallError::Sqlite(error)))?
            {
                continue;
            }
            let source = manifest
                .source
                .x64
                .as_ref()
                .ok_or_else(|| RemoteError::NoArch(manifest.name.clone()))?;
            let hash = source.hash().to_string();
            if seen_hashes.insert(hash.clone()) {
                plans[position].push(Job {
                    package: manifest.name.clone(),
                    version: manifest.version.clone(),
                    url: source.url.clone(),
                    hash,
                });
            }
            for extra in &source.extra {
                if seen_hashes.insert(extra.sha256.clone()) {
                    plans[position].push(Job {
                        package: manifest.name.clone(),
                        version: manifest.version.clone(),
                        url: extra.url.clone(),
                        hash: extra.sha256.clone(),
                    });
                }
            }
        }
    }
    drop(state);

    let cache = Paths::at(root).cache();
    let workers = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2)
        .clamp(1, 4);

    for chunk_start in (0..plans.len()).step_by(workers) {
        let chunk_end = (chunk_start + workers).min(plans.len());
        let (tx, rx) = mpsc::channel();
        let results = thread::scope(|scope| {
            let handles: Vec<_> = plans[chunk_start..chunk_end]
                .iter()
                .enumerate()
                .map(|(offset, jobs)| {
                    let tx = tx.clone();
                    let cache = &cache;
                    let position = chunk_start + offset + 1;
                    let total = packages.len();
                    let requested = packages[position - 1].0.clone();
                    scope.spawn(move || -> Result<(), RemoteError> {
                        let mut bytes = 0u64;
                        let mut cache_hit = true;
                        for job in jobs {
                            let _ = tx.send(PrefetchStep::Downloading {
                                position,
                                total,
                                name: job.package.clone(),
                                version: job.version.clone(),
                            });
                            let outcome = fetch::download_with_status(
                                &job.url,
                                &job.hash,
                                cache,
                                &mut |done, length| {
                                    let _ = tx.send(PrefetchStep::Progress {
                                        position,
                                        total,
                                        done,
                                        length,
                                    });
                                },
                            )?;
                            bytes = bytes.saturating_add(outcome.size);
                            cache_hit &= outcome.cache_hit;
                        }
                        let _ = tx.send(PrefetchStep::Prepared {
                            position,
                            total,
                            name: requested,
                            bytes,
                            cache_hit: !jobs.is_empty() && cache_hit,
                        });
                        Ok(())
                    })
                })
                .collect();
            drop(tx);
            for event in rx {
                on_step(event);
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().map_err(|_| {
                        RemoteError::Install(InstallError::Io(std::io::Error::other(
                            "parallel download worker stopped unexpectedly",
                        )))
                    })?
                })
                .collect::<Vec<_>>()
        });
        for result in results {
            result?;
        }
    }
    Ok(())
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
        let archive =
            fetch::download_with_status(&source.url, source.hash(), &cache, &mut |done, total| {
                on_step(Step::Progress { done, total })
            })?;
        let mut artifact_bytes = archive.size;
        let mut cache_hit = archive.cache_hit;

        // Download extra archives (multi-URL sources).
        let mut extras: Vec<(std::path::PathBuf, String)> = Vec::new();
        for ex in &source.extra {
            let extra =
                fetch::download_with_status(&ex.url, &ex.sha256, &cache, &mut |done, total| {
                    on_step(Step::Progress { done, total })
                })?;
            artifact_bytes += extra.size;
            cache_hit &= extra.cache_hit;
            extras.push((extra.path, ex.extract_to.clone()));
        }

        on_step(Step::Installing {
            name: &manifest.name,
            version: &manifest.version,
            bytes: artifact_bytes,
            cache_hit,
        });
        let installed =
            install::install_manifest(manifest, &archive.path, &extras, root, env_subkey, consent)?;
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
    let archive =
        fetch::download_with_status(&source.url, source.hash(), &cache, &mut |done, total| {
            on_step(Step::Progress { done, total })
        })?;
    let mut artifact_bytes = archive.size;
    let mut cache_hit = archive.cache_hit;

    // Download extra archives (multi-URL sources).
    let mut extras: Vec<(std::path::PathBuf, String)> = Vec::new();
    for ex in &source.extra {
        let extra =
            fetch::download_with_status(&ex.url, &ex.sha256, &cache, &mut |done, total| {
                on_step(Step::Progress { done, total })
            })?;
        artifact_bytes += extra.size;
        cache_hit &= extra.cache_hit;
        extras.push((extra.path, ex.extract_to.clone()));
    }

    on_step(Step::Installing {
        name: &latest.name,
        version: &latest.version,
        bytes: artifact_bytes,
        cache_hit,
    });
    let report = install::upgrade_install(&latest, &archive.path, &extras, root)?;
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
