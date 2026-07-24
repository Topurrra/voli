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
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::{Manifest, ManifestError};
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
    /// Reserved for the env feature (spec §8), not emitted in this step.
    EnvSet {
        key: String,
        prior: Option<String>,
    },
    /// Reserved for PATH-segment tracking (spec §8), not emitted in this step.
    PathAdded {
        segment: String,
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
        }
    }
}

/// What an install produced.
#[derive(Debug, Clone)]
pub struct InstallReport {
    pub name: String,
    pub version: String,
    pub version_dir: PathBuf,
    /// Absolute paths of the `.exe` shims written under `shims\`.
    pub shims: Vec<PathBuf>,
    /// Env vars the manifest requested (not applied in this step; spec §8).
    pub env_requested: Vec<(String, String)>,
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
    #[error("archive hash mismatch: manifest expected {expected}, archive is {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("no source for the current architecture (x64) in the manifest")]
    NoArchSource,
    #[error("unsafe archive entry (absolute path or '..'): {0}")]
    ZipSlip(String),
    #[error("unsupported archive type: {0} (expected .zip or .tar.gz)")]
    UnsupportedArchive(String),
    #[error("extract_dir '{0}' not found in archive after extraction")]
    ExtractDirMissing(String),
    #[error("package '{0}' is already installed; uninstall it first")]
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
    install_manifest(&manifest, archive_path, root)
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
    root: &Path,
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
    let actual = sha256_file(archive_path)?;
    if !actual.eq_ignore_ascii_case(&source.sha256) {
        return Err(InstallError::HashMismatch {
            expected: source.sha256.clone(),
            actual,
        });
    }

    // Perform every filesystem mutation, rolling those back internally on error.
    let (actions, report) = do_install_fs(&paths, manifest, archive_path)?;

    // Persist the ledger + installed marker atomically. If this fails, undo FS.
    let manifest_json = serde_json::to_string(manifest)?;
    if let Err(e) =
        state.record_install(&manifest.name, &manifest.version, &manifest_json, &actions)
    {
        rollback_fs(&actions);
        return Err(e.into());
    }

    Ok(report)
}

/// Run all filesystem mutations, undoing them if any step fails.
fn do_install_fs(
    paths: &Paths,
    manifest: &Manifest,
    archive_path: &Path,
) -> Result<(Vec<Action>, InstallReport)> {
    let mut actions: Vec<Action> = Vec::new();
    match install_fs_inner(paths, manifest, archive_path, &mut actions) {
        Ok(report) => Ok((actions, report)),
        Err(e) => {
            rollback_fs(&actions);
            Err(e)
        }
    }
}

fn install_fs_inner(
    paths: &Paths,
    manifest: &Manifest,
    archive_path: &Path,
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
    extract_archive(archive_path, &extract_root)?;

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
        actions.push(Action::ShimWritten {
            shim: shim_file,
            exe: shim_exe.clone(),
        });
        shims.push(shim_exe);
    }

    Ok(InstallReport {
        name: name.clone(),
        version: version.clone(),
        version_dir,
        shims,
        env_requested: manifest
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    })
}

/// Undo a partial install, best-effort. Replayed in reverse so junctions are
/// deleted before the version dir that contains them (otherwise a recursive
/// delete could follow a junction into real persist data).
fn rollback_fs(actions: &[Action]) {
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
            Action::EnvSet { .. } | Action::PathAdded { .. } => {}
        }
    }
}

/// Uninstall a package by replaying its ledger backwards (spec §3, §11 step 3).
///
/// Persist dirs survive unless `purge` is set. After this returns, the only
/// remaining trace of the package is `apps\<name>\persist\` (and only when not
/// purging); the state rows are removed in one transaction.
pub fn uninstall(name: &str, root: &Path, purge: bool) -> Result<UninstallReport> {
    let paths = Paths::at(root);
    let mut state = State::open(&paths.state_db())?;

    let version = match state.installed_version(name)? {
        Some(v) => v,
        None => return Err(InstallError::NotInstalled(name.to_string())),
    };
    let actions = state.actions_for(name)?;

    let mut kept_persist = false;
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
            Action::EnvSet { .. } | Action::PathAdded { .. } => {}
        }
    }

    state.remove_package(name)?;

    Ok(UninstallReport {
        name: name.to_string(),
        version,
        kept_persist,
    })
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

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut f, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---- archive extraction (zip-slip safe) ----------------------------------

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
}
