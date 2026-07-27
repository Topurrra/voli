//! Transactional local install / uninstall engine (spec §3, §11 step 3).
//!
//! The engine is all-or-nothing. Every filesystem mutation is appended to an
//! in-memory [`Action`] list as it happens; on any failure the list is replayed
//! backwards to undo the partial install, and nothing is written to the state
//! ledger. Only on full success is the whole action list persisted to
//! `state.sqlite` in a single transaction — so a failed install leaves both the
//! filesystem and the state DB byte-identical to before it started.
//!
//! Uninstall reads that ledger back and replays it in reverse, which is the
//! uninstall guarantee: we never guess at cleanup.
//!
//! ponytail: we build the action list in memory and commit it to the ledger
//! atomically at the end, rather than appending to sqlite mid-install. This is a
//! deliberate deviation from "record in the ledger as you go" — it is strictly
//! better for the byte-identical-on-failure guarantee (the DB file is never
//! touched on a failed install) and avoids holding a write transaction open
//! across slow extraction. Crash-mid-install recovery (a journal replayed on
//! next run) is a later step; in-process rollback covers every failure the
//! engine can observe.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::manifest::{Manifest, ManifestError, SourceKind};
use crate::paths::Paths;
use crate::state::State;

/// Role of a created directory, so uninstall knows whether it survives (persist)
/// or is removed (version dir), and rollback knows what to delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirRole {
    /// `apps\<name>` — the package's top-level directory.
    AppRoot,
    /// `apps\<name>\<version>` — a version payload directory.
    Version,
    /// `apps\<name>\persist` — the persist container.
    PersistRoot,
    /// `apps\<name>\persist\<d>` — user data that survives uninstall.
    Persist,
}

/// A single recorded, reversible mutation. Serialized into the state ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    DirCreated {
        path: PathBuf,
        role: DirRole,
    },
    JunctionCreated {
        path: PathBuf,
    },
    ShimWritten {
        shim: PathBuf,
        exe: PathBuf,
    },
    /// A user env var we set (spec §8). `value` is what we wrote (so `voli env`
    /// and doctor's drift check can compare against the live registry); `prior`
    /// is the value to restore on uninstall (`None` = the key was unset, so
    /// uninstall deletes it — the zero-trace guarantee).
    EnvSet {
        key: String,
        value: String,
        prior: Option<String>,
    },
    /// A PATH segment we prepended (spec §8). Uninstall removes exactly this
    /// segment; `value` doubles as what `voli env` reports.
    PathAdded {
        segment: String,
    },
    /// A Start Menu shortcut we created.
    ShortcutCreated {
        path: PathBuf,
    },
    /// An Apps & Features Uninstall registry key we created.
    UninstallKeyCreated {
        name: String,
    },
}

impl Action {
    /// The `action_kind` column value (the serde tag).
    pub fn kind_str(&self) -> &'static str {
        match self {
            Action::DirCreated { .. } => "dir_created",
            Action::JunctionCreated { .. } => "junction_created",
            Action::ShimWritten { .. } => "shim_written",
            Action::EnvSet { .. } => "env_set",
            Action::PathAdded { .. } => "path_added",
            Action::ShortcutCreated { .. } => "shortcut_created",
            Action::UninstallKeyCreated { .. } => "uninstall_key_created",
        }
    }
}

/// Per-package env consent (spec §8): given the package name and the resolved
/// `(key, value)` pairs it wants to set, return `true` to apply, `false` to skip.
/// The CLI supplies the `[Y/n]` prompt / `--yes` / non-TTY / `--no-env` logic.
pub type EnvConsent<'a> = dyn FnMut(&str, &[(String, String)]) -> bool + 'a;

/// A consent closure that always skips `[env]` (used by [`install_local`] and by
/// tests whose fixtures carry no env).
pub fn skip_env(_name: &str, _resolved: &[(String, String)]) -> bool {
    false
}

/// What an install produced.
#[derive(Debug, Clone)]
pub struct InstallReport {
    pub name: String,
    pub version: String,
    pub version_dir: PathBuf,
    /// Absolute paths of the `.exe` shims written under `shims\`.
    pub shims: Vec<PathBuf>,
    /// Env vars the manifest requested, `{dir}`-resolved (regardless of consent).
    pub env_requested: Vec<(String, String)>,
    /// Env vars actually applied (empty when skipped/declined). Resolved values.
    pub env_applied: Vec<(String, String)>,
}

/// What an upgrade produced (spec §3 junction-flip model).
#[derive(Debug, Clone)]
pub struct UpgradeReport {
    pub name: String,
    pub from_version: String,
    pub to_version: String,
    pub new_version_dir: PathBuf,
    /// The old version dir, left on disk until `voli cleanup` (running exes keep
    /// working — the §3 promise).
    pub old_version_dir: PathBuf,
    pub shims: Vec<PathBuf>,
}

/// What an uninstall did.
#[derive(Debug, Clone)]
pub struct UninstallReport {
    pub name: String,
    pub version: String,
    /// True if persist dirs were kept (i.e. not `--purge`).
    pub kept_persist: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("state db error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("7z error: {0}")]
    SevenZ(String),
    #[error("archive hash mismatch: manifest expected {expected}, archive is {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("no source for the current architecture (x64) in the manifest")]
    NoArchSource,
    #[error("unsafe archive entry (absolute path or '..'): {0}")]
    ZipSlip(String),
    #[error("unsupported archive type: {0} (expected .zip, .tar.gz, or .7z)")]
    UnsupportedArchive(String),
    #[error(
        "7-Zip not found — required to extract installer archives (.exe/.msi). Install 7-Zip or add it to PATH."
    )]
    SevenZipNotFound,
    #[error("extract_dir '{0}' not found in archive after extraction")]
    ExtractDirMissing(String),
    #[error("package '{0}' is already installed; delete it first")]
    AlreadyInstalled(String),
    #[error("package '{0}' is not installed")]
    NotInstalled(String),
    #[error("shim stub not found at {0}; build voli-shim or set VOLI_SHIM_STUB")]
    StubMissing(PathBuf),
}

type Result<T> = std::result::Result<T, InstallError>;

/// Install a package from a local manifest + local archive (spec §11 step 3).
///
/// Verifies the archive hash before any mutation, extracts to a staging dir,
/// atomically moves it into place, creates the `current` junction, wires up
/// persist dirs, and writes shims — recording every step. On any failure the
/// filesystem is rolled back and the error returned; the staging dir is always
/// cleaned up.
pub fn install_local(
    manifest_path: &Path,
    archive_path: &Path,
    root: &Path,
) -> Result<InstallReport> {
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest = Manifest::from_toml_str(&manifest_text)?;
    // The bare local path skips `[env]` (no consent context); the CLI drives the
    // env-consent flow explicitly via [`install_manifest`].
    install_manifest(
        &manifest,
        archive_path,
        &[],
        root,
        crate::env::ENVIRONMENT,
        &mut skip_env,
    )
}

/// Install from an already-parsed [`Manifest`] + local archive.
///
/// Same engine as [`install_local`], but the manifest is supplied directly (e.g.
/// from the downloaded index by [`crate::remote::install_remote`]) rather than
/// read from a `.toml` file. The archive is still hash-verified against the
/// manifest before any mutation — the security gate never moves.
pub fn install_manifest(
    manifest: &Manifest,
    archive_path: &Path,
    extras: &[(PathBuf, String)],
    root: &Path,
    env_subkey: &str,
    consent: &mut EnvConsent,
) -> Result<InstallReport> {
    let paths = Paths::at(root);
    paths.ensure()?;

    let mut state = State::open(&paths.state_db())?;
    if state.is_installed(&manifest.name)? {
        return Err(InstallError::AlreadyInstalled(manifest.name.clone()));
    }

    // Hash check first — hard fail before touching anything.
    let source = manifest
        .source
        .x64
        .as_ref()
        .ok_or(InstallError::NoArchSource)?;
    let actual = hash_file(archive_path, source.is_sha512())?;
    if !actual.eq_ignore_ascii_case(source.hash()) {
        return Err(InstallError::HashMismatch {
            expected: source.hash().to_string(),
            actual,
        });
    }

    // Perform every filesystem mutation, rolling those back internally on error.
    let (mut actions, mut report) =
        do_install_fs(&paths, manifest, source.kind, archive_path, extras)?;

    // Env consent flow (spec §8): resolve `{dir}` -> apps\<name>\current, prompt
    // (via `consent`), and — if applied — append EnvSet/PathAdded to the SAME
    // action list so it lands in the install transaction and uninstall replays
    // it. A failure here rolls back both env and filesystem.
    let resolved = resolve_env(manifest, &paths);
    report.env_requested = resolved.clone();
    if !resolved.is_empty() && consent(&manifest.name, &resolved) {
        if let Err(e) = apply_env(env_subkey, &resolved, &mut actions) {
            rollback(env_subkey, &actions);
            return Err(e.into());
        }
        crate::env::broadcast_change();
        report.env_applied = resolved;
    }

    // Apps & Features registration: write the Uninstall key so the package
    // appears in Windows Settings → Apps.
    {
        let base = crate::uninstall_reg::uninstall_base();
        let current = paths.current(&manifest.name);
        let icon = manifest
            .bin
            .first()
            .map(|b| current.join(b.path()).to_string_lossy().into_owned())
            .unwrap_or_else(|| current.to_string_lossy().into_owned());
        let voli_exe = paths.root.join("bin").join("voli.exe");
        let size_kb = dir_size(&report.version_dir) / 1024;
        if let Err(e) = crate::uninstall_reg::write_key(
            &base,
            &manifest.name,
            &manifest.version,
            &current,
            &icon,
            &voli_exe,
            size_kb,
        ) {
            rollback(env_subkey, &actions);
            return Err(e.into());
        }
        actions.push(Action::UninstallKeyCreated {
            name: manifest.name.clone(),
        });
    }

    // Persist the ledger + installed marker atomically. If this fails, undo
    // everything (filesystem AND env) so the machine is byte-identical.
    let manifest_json = serde_json::to_string(manifest)?;
    if let Err(e) =
        state.record_install(&manifest.name, &manifest.version, &manifest_json, &actions)
    {
        rollback(env_subkey, &actions);
        return Err(e.into());
    }

    Ok(report)
}

/// Resolve a manifest's `[env]` values, substituting `{dir}` with the package's
/// `current` junction path (spec §8). Returns `(key, resolved_value)` pairs in
/// manifest order.
fn resolve_env(manifest: &Manifest, paths: &Paths) -> Vec<(String, String)> {
    if manifest.env.is_empty() {
        return Vec::new();
    }
    let current = paths.current(&manifest.name);
    let current_str = current.to_string_lossy().into_owned();
    manifest
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.replace("{dir}", &current_str)))
        .collect()
}

/// Apply resolved env vars to `subkey`, appending an [`Action`] per var so the
/// ledger can restore prior state exactly. PATH-type keys prepend (tracked
/// segment); everything else is a plain set that records the prior value.
fn apply_env(
    subkey: &str,
    resolved: &[(String, String)],
    actions: &mut Vec<Action>,
) -> io::Result<()> {
    for (key, value) in resolved {
        if key.eq_ignore_ascii_case("PATH") {
            crate::env::add_to_path(subkey, value)?;
            actions.push(Action::PathAdded {
                segment: value.clone(),
            });
        } else {
            let prior = crate::env::set(subkey, key, value)?;
            actions.push(Action::EnvSet {
                key: key.clone(),
                value: value.clone(),
                prior,
            });
        }
    }
    Ok(())
}

/// Run all filesystem mutations, undoing them if any step fails.
fn do_install_fs(
    paths: &Paths,
    manifest: &Manifest,
    source_kind: SourceKind,
    archive_path: &Path,
    extras: &[(PathBuf, String)],
) -> Result<(Vec<Action>, InstallReport)> {
    let mut actions: Vec<Action> = Vec::new();
    match install_fs_inner(
        paths,
        manifest,
        source_kind,
        archive_path,
        extras,
        &mut actions,
    ) {
        Ok(report) => Ok((actions, report)),
        Err(e) => {
            // Only filesystem actions exist at this point (env is applied later,
            // in install_manifest), so the subkey is irrelevant here.
            rollback("", &actions);
            Err(e)
        }
    }
}

fn install_fs_inner(
    paths: &Paths,
    manifest: &Manifest,
    source_kind: SourceKind,
    archive_path: &Path,
    extras: &[(PathBuf, String)],
    actions: &mut Vec<Action>,
) -> Result<InstallReport> {
    let name = &manifest.name;
    let version = &manifest.version;

    // 1. Extract into a staging dir under cache\ (same volume as apps\, so the
    //    later move is a real atomic rename). TempDir cleans itself up on drop,
    //    including on early return or panic.
    let staging = tempfile::Builder::new()
        .prefix("staging-")
        .tempdir_in(paths.cache())?;
    let extract_root = staging.path().join("x");
    fs::create_dir_all(&extract_root)?;
    if source_kind == SourceKind::InstallerArchive {
        extract_installer(archive_path, &extract_root)?;
    } else {
        extract_archive(archive_path, &extract_root)?;
    }

    // 2. Apply extract_dir stripping.
    let move_src = match &manifest.extract_dir {
        Some(d) => extract_root.join(d),
        None => extract_root.clone(),
    };
    if !move_src.is_dir() {
        return Err(InstallError::ExtractDirMissing(
            manifest.extract_dir.clone().unwrap_or_default(),
        ));
    }

    // 3. apps\<name>\ (record only if we create it).
    let app_dir = paths.app_dir(name);
    if !app_dir.exists() {
        fs::create_dir_all(&app_dir)?;
        actions.push(Action::DirCreated {
            path: app_dir.clone(),
            role: DirRole::AppRoot,
        });
    }

    // 4. Atomic move staging payload -> apps\<name>\<version>\.
    let version_dir = paths.version_dir(name, version);
    fs::rename(&move_src, &version_dir)?;
    actions.push(Action::DirCreated {
        path: version_dir.clone(),
        role: DirRole::Version,
    });

    // 5. persist dirs: move any extracted data out into apps\<name>\persist\<d>
    //    and junction it back into the version dir so upgrades don't eat it.
    // ponytail: persist names are treated as single directory names (the spec's
    // examples are flat); nested persist paths are out of scope for v1.
    if !manifest.persist.is_empty() {
        let persist_root = paths.persist_root(name);
        if !persist_root.exists() {
            fs::create_dir_all(&persist_root)?;
            actions.push(Action::DirCreated {
                path: persist_root.clone(),
                role: DirRole::PersistRoot,
            });
        }
        for d in &manifest.persist {
            let persist_dir = persist_root.join(d);
            let link = version_dir.join(d);
            if !persist_dir.exists() {
                if link.exists() {
                    fs::rename(&link, &persist_dir)?;
                } else {
                    fs::create_dir_all(&persist_dir)?;
                }
                actions.push(Action::DirCreated {
                    path: persist_dir.clone(),
                    role: DirRole::Persist,
                });
            } else if link.exists() {
                // persist already holds data from a prior install; drop the
                // freshly extracted copy so the junction can take its place.
                fs::remove_dir_all(&link)?;
            }
            junction::create(&persist_dir, &link)?;
            actions.push(Action::JunctionCreated { path: link });
        }
    }

    // 6. current junction -> the version dir.
    let current = paths.current(name);
    junction::create(&version_dir, &current)?;
    actions.push(Action::JunctionCreated {
        path: current.clone(),
    });

    // 7. shims: one <base>.shim + <base>.exe per bin entry.
    let stub = resolve_stub()?;
    let mut shims = Vec::new();
    for b in &manifest.bin {
        let base = b.shim_name();
        let shim_file = paths.shims().join(format!("{base}.shim"));
        let shim_exe = paths.shims().join(format!("{base}.exe"));
        // Target points through `current` so upgrades only flip the junction.
        let target = current.join(b.path());
        let mut body = target.to_string_lossy().into_owned();
        body.push('\n');
        if let Some(args) = b.args() {
            body.push_str(args);
            body.push('\n');
        }
        fs::write(&shim_file, body)?;
        fs::copy(&stub, &shim_exe)?;
        // Give the shim the target app's own icon instead of voli's bear stub
        // icon (spec §6). Best-effort and never fatal: on any error, or when the
        // target carries no icon, the working stub-icon shim is left in place.
        let _ = crate::shim_icon::copy_exe_icon(&target, &shim_exe);
        actions.push(Action::ShimWritten {
            shim: shim_file,
            exe: shim_exe.clone(),
        });
        shims.push(shim_exe);
    }

    // 8. Extra archives: extract into subdirectories of the version dir.
    for (extra_archive, extract_to) in extras {
        let dest = version_dir.join(extract_to);
        fs::create_dir_all(&dest)?;
        extract_archive(extra_archive, &dest)?;
    }

    // 9. Declarative write_file: static files written into the version dir.
    for wf in &manifest.write_file {
        let target = version_dir.join(&wf.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &wf.content)?;
    }

    // 10. Start Menu shortcuts (.lnk via COM IShellLink).
    for sc in &manifest.shortcuts {
        let link_dir = shortcut_dir()?;
        fs::create_dir_all(&link_dir)?;
        let link_path = link_dir.join(format!("{}.lnk", sc.link_name()));
        let target = current.join(sc.target());
        create_shortcut(&link_path, &target, &current)?;
        actions.push(Action::ShortcutCreated { path: link_path });
    }

    Ok(InstallReport {
        name: name.clone(),
        version: version.clone(),
        version_dir,
        shims,
        // Filled in (resolved + consent-gated) by install_manifest.
        env_requested: Vec::new(),
        env_applied: Vec::new(),
    })
}

/// Undo a partial install, best-effort. Replayed in reverse so junctions are
/// deleted before the version dir that contains them (otherwise a recursive
/// delete could follow a junction into real persist data) and env vars are
/// restored to their prior state. `subkey` is the registry env subkey the env
/// actions were applied to (unused when there are no env actions).
fn rollback(subkey: &str, actions: &[Action]) {
    let mut touched_env = false;
    for a in actions.iter().rev() {
        match a {
            Action::ShimWritten { shim, exe } => {
                let _ = fs::remove_file(shim);
                let _ = fs::remove_file(exe);
            }
            Action::JunctionCreated { path } => {
                let _ = junction::delete(path);
                let _ = fs::remove_dir(path);
            }
            // A failed install is undone completely, persist included, so the
            // root is byte-identical to before.
            Action::DirCreated { path, .. } => {
                let _ = fs::remove_dir_all(path);
            }
            Action::EnvSet { key, prior, .. } => {
                restore_env(subkey, key, prior.as_deref());
                touched_env = true;
            }
            Action::PathAdded { segment } => {
                let _ = crate::env::remove_from_path(subkey, segment);
                touched_env = true;
            }
            Action::ShortcutCreated { path } => {
                let _ = fs::remove_file(path);
            }
            Action::UninstallKeyCreated { name } => {
                let base = crate::uninstall_reg::uninstall_base();
                let _ = crate::uninstall_reg::delete_key(&base, name);
            }
        }
    }
    if touched_env {
        crate::env::broadcast_change();
    }
}

/// Restore one env var to its prior state: set it back if it existed, delete it
/// if it did not (the zero-trace guarantee, spec §1/§8).
fn restore_env(subkey: &str, key: &str, prior: Option<&str>) {
    match prior {
        Some(v) => {
            let _ = crate::env::set(subkey, key, v);
        }
        None => {
            let _ = crate::env::delete(subkey, key);
        }
    }
}

/// Uninstall a package by replaying its ledger backwards (spec §3, §11 step 3).
///
/// Persist dirs survive unless `purge` is set. After this returns, the only
/// remaining trace of the package is `apps\<name>\persist\` (and only when not
/// purging); the state rows are removed in one transaction.
pub fn uninstall(name: &str, root: &Path, purge: bool) -> Result<UninstallReport> {
    uninstall_env(name, root, purge, &crate::env::env_subkey())
}

/// Like [`uninstall`], but with an explicit registry env subkey (spec §8). The
/// bare [`uninstall`] resolves it from [`crate::env::env_subkey`]; tests pass a
/// scratch subkey so they never touch the real user Environment.
///
/// After an upgrade the package's ledger carries every version's `dir_created`
/// entry (see [`upgrade_install`]), so this removes ALL version dirs, leaving
/// zero trace (spec §3).
pub fn uninstall_env(
    name: &str,
    root: &Path,
    purge: bool,
    env_subkey: &str,
) -> Result<UninstallReport> {
    let paths = Paths::at(root);
    let mut state = State::open(&paths.state_db())?;

    let version = match state.installed_version(name)? {
        Some(v) => v,
        None => return Err(InstallError::NotInstalled(name.to_string())),
    };
    let actions = state.actions_for(name)?;

    let mut kept_persist = false;
    let mut touched_env = false;
    for a in actions.iter().rev() {
        match a {
            Action::ShimWritten { shim, exe } => {
                let _ = fs::remove_file(shim);
                let _ = fs::remove_file(exe);
            }
            Action::JunctionCreated { path } => {
                let _ = junction::delete(path);
                let _ = fs::remove_dir(path);
            }
            Action::DirCreated { path, role } => match role {
                DirRole::Version => {
                    let _ = fs::remove_dir_all(path);
                }
                DirRole::Persist | DirRole::PersistRoot => {
                    if purge {
                        let _ = fs::remove_dir_all(path);
                    } else {
                        kept_persist = true;
                    }
                }
                DirRole::AppRoot => {
                    if purge {
                        let _ = fs::remove_dir_all(path);
                    } else {
                        // Removes it only if empty; if persist survives, it stays.
                        let _ = fs::remove_dir(path);
                    }
                }
            },
            Action::EnvSet { key, prior, .. } => {
                restore_env(env_subkey, key, prior.as_deref());
                touched_env = true;
            }
            Action::PathAdded { segment } => {
                let _ = crate::env::remove_from_path(env_subkey, segment);
                touched_env = true;
            }
            Action::ShortcutCreated { path } => {
                let _ = fs::remove_file(path);
            }
            Action::UninstallKeyCreated { name } => {
                let base = crate::uninstall_reg::uninstall_base();
                let _ = crate::uninstall_reg::delete_key(&base, name);
            }
        }
    }
    if touched_env {
        crate::env::broadcast_change();
    }

    state.remove_package(name)?;

    Ok(UninstallReport {
        name: name.to_string(),
        version,
        kept_persist,
    })
}

/// Upgrade an installed package to `manifest_new` via the §3 junction-flip model.
///
/// The new version dir is installed alongside the old, the `current` junction is
/// flipped to it, shims are rewritten (added/removed as the bin set changed), and
/// env values (which reference `{dir}` = the stable `current` path) are carried
/// forward with their ORIGINAL priors.
///
/// ## Ledger transition (the design decision, spec §3)
///
/// The package's action ledger is rewritten so that a later `uninstall` removes
/// EVERY version dir and restores the ORIGINAL pre-install env. Concretely the
/// new ledger is built as:
///
/// 1. the OLD ledger's structural actions — app-root, persist-root/dirs, the old
///    version's `dir_created`, and the old version's persist junctions — are
///    **carried forward verbatim** (so the old version dir survives for
///    `cleanup`, and is still removed on `uninstall`);
/// 2. the OLD `current` junction action and OLD shim actions are **dropped**
///    (the junction is flipped, the shims are rewritten);
/// 3. the NEW version's actions (its `dir_created`, persist junctions, the new
///    `current` junction, the new shims) are appended;
/// 4. the OLD env actions are appended LAST, **unchanged** — preserving the
///    original `prior` values so uninstall restores the pre-install state, not
///    an intermediate one. `{dir}` resolves to `current` either way, so the
///    applied value is identical across versions (spec §8: "usually a no-op").
///
/// Env value *changes* across versions (rare — only if a manifest hard-codes a
/// non-`{dir}` env value that differs) and env vars newly *added* by the new
/// version are out of scope for v1: env is carried forward as-is.
pub fn upgrade_install(
    manifest_new: &Manifest,
    archive_path: &Path,
    extras: &[(PathBuf, String)],
    root: &Path,
) -> Result<UpgradeReport> {
    let paths = Paths::at(root);
    let name = &manifest_new.name;
    let new_version = &manifest_new.version;

    let mut state = State::open(&paths.state_db())?;
    let old_version = match state.installed_version(name)? {
        Some(v) => v,
        None => return Err(InstallError::NotInstalled(name.clone())),
    };

    // Hash gate first (same as install) — no mutation before it passes.
    let source = manifest_new
        .source
        .x64
        .as_ref()
        .ok_or(InstallError::NoArchSource)?;
    let actual = hash_file(archive_path, source.is_sha512())?;
    if !actual.eq_ignore_ascii_case(source.hash()) {
        return Err(InstallError::HashMismatch {
            expected: source.hash().to_string(),
            actual,
        });
    }

    let old_actions = state.actions_for(name)?;
    let old_current = paths.current(name);
    let old_version_dir = paths.version_dir(name, &old_version);

    // Flip prep: drop the old `current` junction so the new install can recreate
    // it. (Brief window where `current` is absent; the new junction is recreated
    // within the same call. On failure we restore it, below.)
    let _ = junction::delete(&old_current);
    let _ = fs::remove_dir(&old_current);

    // Install the new version's filesystem payload (version dir, persist
    // junctions, current junction -> new, shims). Reuses the install engine.
    let mut new_actions: Vec<Action> = Vec::new();
    let new_report = match install_fs_inner(
        &paths,
        manifest_new,
        source.kind,
        archive_path,
        extras,
        &mut new_actions,
    ) {
        Ok(r) => r,
        Err(e) => {
            // Undo the partial new install and put `current` back on the old
            // version so running tools (and shims) keep resolving.
            rollback("", &new_actions);
            let _ = junction::create(&old_version_dir, &old_current);
            return Err(e);
        }
    };

    // Remove shims for bins that vanished in the new version (bin-set change).
    let new_bases: std::collections::HashSet<String> =
        manifest_new.bin.iter().map(|b| b.shim_name()).collect();
    for a in &old_actions {
        if let Action::ShimWritten { exe, .. } = a
            && let Some(base) = exe.file_stem().and_then(|s| s.to_str())
            && !new_bases.contains(base)
        {
            let _ = fs::remove_file(paths.shims().join(format!("{base}.shim")));
            let _ = fs::remove_file(exe);
        }
    }

    // Build the transitioned ledger (see the doc comment above).
    let mut structural: Vec<Action> = Vec::new();
    let mut old_env: Vec<Action> = Vec::new();
    for a in old_actions {
        match &a {
            Action::JunctionCreated { path } if *path == old_current => {} // old current: dropped
            Action::ShimWritten { .. } => {}                               // rewritten
            Action::UninstallKeyCreated { .. } => {}                       // rewritten below
            Action::EnvSet { .. } | Action::PathAdded { .. } => old_env.push(a),
            _ => structural.push(a),
        }
    }

    // Rewrite the Apps & Features key with the new version + size.
    {
        let base = crate::uninstall_reg::uninstall_base();
        let current = paths.current(name);
        let icon = manifest_new
            .bin
            .first()
            .map(|b| current.join(b.path()).to_string_lossy().into_owned())
            .unwrap_or_else(|| current.to_string_lossy().into_owned());
        let voli_exe = paths.root.join("bin").join("voli.exe");
        let size_kb = dir_size(&new_report.version_dir) / 1024;
        let _ = crate::uninstall_reg::write_key(
            &base,
            name,
            new_version,
            &current,
            &icon,
            &voli_exe,
            size_kb,
        );
    }

    let mut combined = structural;
    // Clone: `new_actions` is retained for the failure-rollback path below.
    combined.extend(new_actions.clone());
    combined.push(Action::UninstallKeyCreated { name: name.clone() });
    combined.extend(old_env);

    // Swap the installed row (version bump, ledger replaced) preserving the pin.
    let manifest_json = serde_json::to_string(manifest_new)?;
    if let Err(e) = state.replace_install(name, new_version, &manifest_json, &combined) {
        // Best-effort: undo the new install and restore `current` to old. The old
        // ledger row is intact (replace_install failed before committing).
        rollback("", &new_actions);
        let _ = junction::create(&old_version_dir, &old_current);
        return Err(e.into());
    }

    Ok(UpgradeReport {
        name: name.clone(),
        from_version: old_version,
        to_version: new_version.clone(),
        new_version_dir: new_report.version_dir,
        old_version_dir,
        shims: new_report.shims,
    })
}

/// Remove every version dir of `name` that is not `keep_version` (spec §11
/// cleanup). Junctions inside a version dir (persist links) are deleted before
/// the dir so a recursive delete never follows one into real persist data.
/// Returns the paths removed and total bytes freed. `dry_run` reports only.
///
/// `persist` and the `current` junction are never touched.
pub fn cleanup_versions(
    root: &Path,
    name: &str,
    keep_version: &str,
    dry_run: bool,
) -> io::Result<(Vec<PathBuf>, u64)> {
    let paths = Paths::at(root);
    let app_dir = paths.app_dir(name);
    let mut removed = Vec::new();
    let mut freed = 0u64;
    let entries = match fs::read_dir(&app_dir) {
        Ok(e) => e,
        Err(_) => return Ok((removed, freed)),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let base = file_name.to_string_lossy();
        // Skip the kept version, the current junction, and persist.
        if base == keep_version || base == "current" || base == "persist" {
            continue;
        }
        if !path.is_dir() || junction::exists(&path).unwrap_or(false) {
            continue; // only real version dirs
        }
        freed += dir_size(&path);
        removed.push(path.clone());
        if !dry_run {
            remove_version_dir_safe(&path);
        }
    }
    Ok((removed, freed))
}

/// Remove a version dir after deleting any junctions it directly contains
/// (persist links), so the recursive delete can't follow a junction into
/// persist. ponytail: persist junctions are top-level in the version dir (the
/// schema is flat), so immediate children suffice.
fn remove_version_dir_safe(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if junction::exists(&p).unwrap_or(false) {
                let _ = junction::delete(&p);
                let _ = fs::remove_dir(&p);
            }
        }
    }
    let _ = fs::remove_dir_all(dir);
}

/// Recursively sum the byte size of a directory tree (best-effort; unreadable
/// entries count as zero).
pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() && !junction::exists(entry.path()).unwrap_or(false) {
            total += dir_size(&entry.path());
        } else if let Ok(meta) = entry.metadata() {
            total += meta.len();
        }
    }
    total
}

/// Locate the shim stub exe: `VOLI_SHIM_STUB` override, else `voli-shim.exe`
/// next to the running binary.
fn resolve_stub() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("VOLI_SHIM_STUB") {
        let p = PathBuf::from(p);
        return if p.exists() {
            Ok(p)
        } else {
            Err(InstallError::StubMissing(p))
        };
    }
    let exe = std::env::current_exe()?;
    let cand = exe.with_file_name("voli-shim.exe");
    if cand.exists() {
        Ok(cand)
    } else {
        Err(InstallError::StubMissing(cand))
    }
}

fn hash_file(path: &Path, sha512: bool) -> Result<String> {
    let mut f = File::open(path)?;
    if sha512 {
        let mut hasher = Sha512::new();
        io::copy(&mut f, &mut hasher)?;
        Ok(hex(&hasher.finalize()))
    } else {
        let mut hasher = Sha256::new();
        io::copy(&mut f, &mut hasher)?;
        Ok(hex(&hasher.finalize()))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---- Start Menu shortcuts (COM IShellLink) --------------------------------

/// `%APPDATA%\Microsoft\Windows\Start Menu\Programs\voli\`
/// Override with `VOLI_SHORTCUT_DIR` for tests.
fn shortcut_dir() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("VOLI_SHORTCUT_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let appdata = std::env::var_os("APPDATA")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "APPDATA is not set"))?;
    Ok(PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("voli"))
}

/// Create a `.lnk` shortcut via the WScript.Shell COM object (real .lnk, not .url).
fn create_shortcut(link_path: &Path, target: &Path, working_dir: &Path) -> io::Result<()> {
    let script = format!(
        "$ws = New-Object -ComObject WScript.Shell\n\
         $sc = $ws.CreateShortcut(\"{}\")\n\
         $sc.TargetPath = \"{}\"\n\
         $sc.WorkingDirectory = \"{}\"\n\
         $sc.Save()",
        link_path.display().to_string().replace('"', "`\""),
        target.display().to_string().replace('"', "`\""),
        working_dir.display().to_string().replace('"', "`\""),
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "shortcut creation failed: {stderr}"
        )));
    }
    Ok(())
}

// ---- archive extraction (zip-slip safe) ----------------------------------

/// Find 7z.exe: PATH, then common install locations.
fn find_7z() -> Option<PathBuf> {
    // PATH lookup.
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("7z.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    // Common install locations.
    for dir in [r"C:\Program Files\7-Zip", r"C:\Program Files (x86)\7-Zip"] {
        let candidate = Path::new(dir).join("7z.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Extract an installer (.exe/.msi) using 7-Zip — pure-read, no execution.
/// 7z opens NSIS, Inno Setup, and MSI containers as archives.
fn extract_installer(installer: &Path, dest: &Path) -> Result<()> {
    let sz = find_7z().ok_or(InstallError::SevenZipNotFound)?;

    // Match the built-in extractors' containment rule before writing anything.
    let listing = std::process::Command::new(&sz)
        .args(["l", "-slt", "-ba", "-sccUTF-8"])
        .arg(installer)
        .output()?;
    if !listing.status.success() {
        return Err(InstallError::Io(io::Error::other(format!(
            "7z listing failed: {}{}",
            String::from_utf8_lossy(&listing.stderr),
            String::from_utf8_lossy(&listing.stdout)
        ))));
    }
    validate_installer_listing(&String::from_utf8_lossy(&listing.stdout))?;

    let mut output_dir = std::ffi::OsString::from("-o");
    output_dir.push(dest);
    let output = std::process::Command::new(&sz)
        .arg("x")
        .arg(output_dir)
        .arg("-y")
        .arg(installer)
        .output()?;
    if !output.status.success() {
        return Err(InstallError::Io(io::Error::other(format!(
            "7z extraction failed: {}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ))));
    }
    Ok(())
}

fn validate_installer_listing(listing: &str) -> Result<()> {
    let mut found = false;
    for raw in listing
        .lines()
        .filter_map(|line| line.strip_prefix("Path = "))
    {
        found = true;
        if safe_rel(raw).is_none() {
            return Err(InstallError::ZipSlip(raw.to_string()));
        }
    }
    if !found {
        return Err(InstallError::Io(io::Error::other(
            "7z listing returned no archive entries",
        )));
    }
    Ok(())
}

fn extract_archive(archive: &Path, dest: &Path) -> Result<()> {
    let lower = archive
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.ends_with(".zip") {
        extract_zip(archive, dest)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_tar_gz(archive, dest)
    } else if lower.ends_with(".7z") {
        extract_7z(archive, dest)
    } else {
        Err(InstallError::UnsupportedArchive(lower))
    }
}

fn extract_zip(archive: &Path, dest: &Path) -> Result<()> {
    let file = File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let raw = entry.name().to_string();
        let rel = safe_rel(&raw).ok_or(InstallError::ZipSlip(raw))?;
        let out = dest.join(&rel);
        if entry.is_dir() {
            fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = File::create(&out)?;
            io::copy(&mut entry, &mut f)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(archive: &Path, dest: &Path) -> Result<()> {
    let file = File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut ar = tar::Archive::new(gz);
    for entry in ar.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.to_string_lossy().into_owned();
        let rel = safe_rel(&raw).ok_or(InstallError::ZipSlip(raw))?;
        let out = dest.join(&rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        entry.unpack(&out)?;
    }
    Ok(())
}

fn extract_7z(archive: &Path, dest: &Path) -> Result<()> {
    let file = File::open(archive)?;
    let offset = embedded_7z_offset(file.try_clone()?)?;
    let source = OffsetReader::new(file, offset)?;
    let mut reader = sevenz_rust2::ArchiveReader::new(source, sevenz_rust2::Password::empty())
        .map_err(|e| InstallError::SevenZ(e.to_string()))?;

    // Validate every entry name before extracting anything (zip-slip, §10).
    for entry in &reader.archive().files {
        let raw = entry.name();
        safe_rel(raw).ok_or_else(|| InstallError::ZipSlip(raw.to_string()))?;
    }

    reader
        .for_each_entries(|entry, data| {
            let rel = safe_rel(entry.name()).expect("all entries validated above");
            let out = dest.join(&rel);
            if entry.is_directory() {
                fs::create_dir_all(&out)?;
            } else {
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut f = File::create(&out)?;
                io::copy(data, &mut f)?;
            }
            Ok(true)
        })
        .map_err(|e| InstallError::SevenZ(e.to_string()))?;

    Ok(())
}

const SEVEN_Z_SIGNATURE: [u8; 6] = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];

fn embedded_7z_offset(mut file: File) -> Result<u64> {
    let mut head = [0; 6];
    file.read_exact(&mut head)?;
    if head == SEVEN_Z_SIGNATURE {
        return Ok(0);
    }
    if !head.starts_with(b"MZ") {
        return Ok(0);
    }

    file.seek(SeekFrom::Start(0))?;
    let mut window = [0; 6];
    for (position, byte) in BufReader::new(file).bytes().enumerate() {
        window.rotate_left(1);
        window[5] = byte?;
        if window == SEVEN_Z_SIGNATURE {
            return Ok(position.saturating_sub(5) as u64);
        }
    }
    Err(InstallError::SevenZ(
        "self-extracting archive contains no 7z payload".to_string(),
    ))
}

struct OffsetReader<R> {
    inner: R,
    offset: u64,
}

impl<R: Seek> OffsetReader<R> {
    fn new(mut inner: R, offset: u64) -> io::Result<Self> {
        inner.seek(SeekFrom::Start(offset))?;
        Ok(Self { inner, offset })
    }
}

impl<R: Read> Read for OffsetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Seek> Seek for OffsetReader<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let absolute = match position {
            SeekFrom::Start(position) => SeekFrom::Start(
                self.offset
                    .checked_add(position)
                    .ok_or_else(|| io::Error::other("embedded archive seek overflow"))?,
            ),
            other => other,
        };
        self.inner
            .seek(absolute)?
            .checked_sub(self.offset)
            .ok_or_else(|| io::Error::other("seek before embedded archive"))
    }
}

/// Validate an archive entry name and return it as a safe relative path.
/// Rejects absolute paths and any `..` component (zip-slip protection, §10).
fn safe_rel(raw: &str) -> Option<PathBuf> {
    let normalized = raw.replace('\\', "/");
    if normalized.starts_with('/') {
        return None;
    }
    let mut out = PathBuf::new();
    for c in Path::new(&normalized).components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn safe_rel_accepts_nested() {
        assert_eq!(safe_rel("a/b/c.txt"), Some(PathBuf::from("a/b/c.txt")));
        assert_eq!(safe_rel("a\\b.txt"), Some(PathBuf::from("a/b.txt")));
    }

    #[test]
    fn safe_rel_rejects_traversal_and_absolute() {
        assert_eq!(safe_rel("../evil"), None);
        assert_eq!(safe_rel("a/../../evil"), None);
        assert_eq!(safe_rel("/etc/passwd"), None);
        assert_eq!(safe_rel("C:\\windows\\x"), None);
        assert_eq!(safe_rel(""), None);
    }

    #[test]
    fn installer_listing_rejects_unsafe_paths() {
        validate_installer_listing("Path = app/app.exe\n").unwrap();
        let err = validate_installer_listing("Path = ..\\escape.exe\n").unwrap_err();
        assert!(matches!(err, InstallError::ZipSlip(_)));
    }

    #[test]
    fn reads_7z_payload_after_self_extracting_header() {
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        archive.write_all(b"MZstub").unwrap();
        archive.write_all(&SEVEN_Z_SIGNATURE).unwrap();

        let offset = embedded_7z_offset(archive.reopen().unwrap()).unwrap();
        assert_eq!(offset, 6);

        let mut reader = OffsetReader::new(archive.reopen().unwrap(), offset).unwrap();
        let mut signature = [0; 6];
        reader.read_exact(&mut signature).unwrap();
        assert_eq!(signature, SEVEN_Z_SIGNATURE);
        assert_eq!(reader.seek(SeekFrom::Start(0)).unwrap(), 0);
    }
}
