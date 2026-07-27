//! Safe global installation for Agent Skills archives.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};

use crate::manifest::{Kind, Manifest};
use crate::paths::{Paths, SkillTarget};
use crate::state::{SkillAction, State};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInstallReport {
    pub target: SkillTarget,
    pub name: String,
    pub version: String,
    pub description: String,
    pub install_dir: PathBuf,
    pub files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillUninstallReport {
    pub target: SkillTarget,
    pub name: String,
    pub install_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SkillError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("state db error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported skill archive: {0} (expected .zip, .tar.gz, or .tgz)")]
    UnsupportedArchive(String),
    #[error("unsafe archive entry: {0}")]
    UnsafeArchiveEntry(String),
    #[error("duplicate archive entry after path normalization: {0}")]
    DuplicateEntry(String),
    #[error("skill archive contains more than 10000 entries")]
    TooManyEntries,
    #[error("skill archive expands beyond 256 MiB")]
    ArchiveTooLarge,
    #[error("skill archives may contain only regular files and directories: {0}")]
    UnsupportedEntry(String),
    #[error("skill archive must contain exactly one skill root with SKILL.md")]
    InvalidLayout,
    #[error("manifest '{0}' is not a skill package")]
    WrongKind(String),
    #[error("no universal source in skill manifest")]
    NoUniversalSource,
    #[error("archive hash mismatch: manifest expected {expected}, archive is {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("SKILL.md name '{skill}' does not match manifest name '{manifest}'")]
    ManifestNameMismatch { manifest: String, skill: String },
    #[error("invalid SKILL.md: {0}")]
    InvalidSkill(String),
    #[error("skill directory '{directory}' does not match frontmatter name '{name}'")]
    NameMismatch { directory: String, name: String },
    #[error("skill '{name}' is already installed for {target}")]
    AlreadyInstalled { target: String, name: String },
    #[error(
        "skill '{name}' {installed} is already installed for {target}; delete it before installing {requested}"
    )]
    VersionConflict {
        target: String,
        name: String,
        installed: String,
        requested: String,
    },
    #[error(
        "skill '{name}' has an incomplete installation for {target}; delete it before retrying"
    )]
    IncompleteInstall { target: String, name: String },
    #[error("destination already exists and is not owned by Voli: {0}")]
    DestinationExists(PathBuf),
    #[error("skill '{name}' is not installed for {target}")]
    NotInstalled { target: String, name: String },
    #[error("installed skill has unexpected user changes at {0}; nothing was removed")]
    Changed(PathBuf),
    #[error("skill ledger path does not match the selected target: {0}")]
    StatePathMismatch(PathBuf),
}

type Result<T> = std::result::Result<T, SkillError>;

const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_EXTRACTED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SKILL_MD_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_DEPTH: usize = 64;
const MAX_ARCHIVE_PATH_BYTES: usize = 4096;

/// Install one skill archive directly into an agent's global skills directory.
///
/// `home` and `voli_root` are explicit so callers and tests never depend on
/// process-global environment variables.
pub fn install_skill_archive(
    manifest: &Manifest,
    archive: &Path,
    target: SkillTarget,
    home: &Path,
    voli_root: &Path,
) -> Result<SkillInstallReport> {
    if manifest.kind != Kind::Skill {
        return Err(SkillError::WrongKind(manifest.name.clone()));
    }
    let source = manifest
        .source
        .any
        .as_ref()
        .ok_or(SkillError::NoUniversalSource)?;
    let actual_hash = hash_file(archive, source.is_sha512())?;
    if !actual_hash.eq_ignore_ascii_case(source.hash()) {
        return Err(SkillError::HashMismatch {
            expected: source.hash().to_string(),
            actual: actual_hash,
        });
    }

    let paths = Paths::at(voli_root);
    let mut state = State::open(&paths.state_db())?;
    let skills_dir = target.global_skills_dir(home);
    fs::create_dir_all(&skills_dir)?;

    let stage = tempfile::Builder::new()
        .prefix(".voli-skill-")
        .tempdir_in(&skills_dir)?;
    let unpacked = stage.path().join("unpacked");
    fs::create_dir(&unpacked)?;
    extract_archive(archive, &unpacked)?;

    let (skill_root, wrapped) = find_skill_root(&unpacked)?;
    let metadata = validate_skill(&skill_root)?;
    if metadata.name != manifest.name {
        return Err(SkillError::ManifestNameMismatch {
            manifest: manifest.name.clone(),
            skill: metadata.name,
        });
    }
    if wrapped {
        let directory = skill_root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SkillError::InvalidLayout)?;
        if directory != metadata.name {
            return Err(SkillError::NameMismatch {
                directory: directory.to_string(),
                name: metadata.name,
            });
        }
    }

    let target_name = target.as_str();
    if let Some(installed) = state.installed_skill(target_name, &metadata.name)? {
        return if installed.install_dir.exists() {
            Err(SkillError::AlreadyInstalled {
                target: target_name.to_string(),
                name: metadata.name,
            })
        } else {
            Err(SkillError::IncompleteInstall {
                target: target_name.to_string(),
                name: metadata.name,
            })
        };
    }

    let install_dir = skills_dir.join(&metadata.name);
    if install_dir.exists() {
        return Err(SkillError::DestinationExists(install_dir));
    }

    let actions = collect_actions(&skill_root, &install_dir)?;
    let files = actions
        .iter()
        .filter(|action| matches!(action, SkillAction::FileWritten { .. }))
        .count();
    let publish = stage.path().join("publish");
    fs::rename(&skill_root, &publish)?;

    let manifest_json = serde_json::to_string(manifest)?;
    state.record_skill_install(
        target_name,
        &metadata.name,
        &manifest.version,
        &metadata.description,
        &manifest_json,
        &install_dir,
        &actions,
    )?;
    if let Err(error) = fs::rename(&publish, &install_dir) {
        let _ = state.remove_skill(target_name, &metadata.name);
        return Err(error.into());
    }

    Ok(SkillInstallReport {
        target,
        name: metadata.name,
        version: manifest.version.clone(),
        description: metadata.description,
        install_dir,
        files,
    })
}

/// Remove a target-scoped skill only when every recorded entry is unchanged.
pub fn uninstall_skill(
    name: &str,
    target: SkillTarget,
    home: &Path,
    voli_root: &Path,
) -> Result<SkillUninstallReport> {
    let paths = Paths::at(voli_root);
    let mut state = State::open(&paths.state_db())?;
    let target_name = target.as_str();
    let installed =
        state
            .installed_skill(target_name, name)?
            .ok_or_else(|| SkillError::NotInstalled {
                target: target_name.to_string(),
                name: name.to_string(),
            })?;
    let expected_dir = target.global_skills_dir(home).join(name);
    if installed.install_dir != expected_dir {
        return Err(SkillError::StatePathMismatch(installed.install_dir));
    }

    let actions = state.skill_actions_for(target_name, name)?;
    let parent = installed
        .install_dir
        .parent()
        .ok_or_else(|| SkillError::StatePathMismatch(installed.install_dir.clone()))?
        .to_path_buf();
    let quarantined = parent.join(format!(".voli-removing-{name}"));
    if installed.install_dir.exists() {
        if quarantined.exists() {
            return Err(SkillError::Changed(quarantined));
        }
        verify_unchanged(&installed.install_dir, &installed.install_dir, &actions)?;
        fs::rename(&installed.install_dir, &quarantined)?;
    } else if !quarantined.exists() {
        state.remove_skill(target_name, name)?;
        prune_empty_skill_dirs(&parent, home);
        return Ok(SkillUninstallReport {
            target,
            name: name.to_string(),
            install_dir: installed.install_dir,
        });
    }

    verify_unchanged(&quarantined, &installed.install_dir, &actions)?;
    fs::remove_dir_all(&quarantined)?;
    state.remove_skill(target_name, name)?;
    // Zero-trace (§2): remove the agent skills-dir scaffolding voli created
    // when the agent wasn't already present. `remove_dir` only deletes EMPTY
    // dirs, so any agent- or user-owned content stops the walk — we never
    // touch a populated directory, and never `home` itself.
    prune_empty_skill_dirs(&parent, home);

    Ok(SkillUninstallReport {
        target,
        name: name.to_string(),
        install_dir: installed.install_dir,
    })
}

/// Remove `start` and each ancestor up to (but never including) `home`, while
/// each is empty. `fs::remove_dir` fails on a non-empty dir, which safely halts
/// the walk without inspecting contents. A no-op when `start` isn't under
/// `home` (e.g. a custom target dir elsewhere).
fn prune_empty_skill_dirs(start: &Path, home: &Path) {
    let mut current = start.to_path_buf();
    while current != *home && current.starts_with(home) {
        if fs::remove_dir(&current).is_err() {
            break;
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => break,
        }
    }
}

struct SkillMetadata {
    name: String,
    description: String,
}

#[derive(Deserialize)]
struct SkillFrontmatter {
    name: String,
    description: String,
}

fn find_skill_root(unpacked: &Path) -> Result<(PathBuf, bool)> {
    if regular_file(&unpacked.join("SKILL.md")) {
        return Ok((unpacked.to_path_buf(), false));
    }
    let mut entries = fs::read_dir(unpacked)?.collect::<io::Result<Vec<_>>>()?;
    if entries.len() != 1 {
        return Err(SkillError::InvalidLayout);
    }
    let entry = entries.pop().expect("length checked");
    if !entry.file_type()?.is_dir() || !regular_file(&entry.path().join("SKILL.md")) {
        return Err(SkillError::InvalidLayout);
    }
    Ok((entry.path(), true))
}

fn validate_skill(root: &Path) -> Result<SkillMetadata> {
    let skill_file = root.join("SKILL.md");
    if fs::metadata(&skill_file)?.len() > MAX_SKILL_MD_BYTES {
        return Err(SkillError::InvalidSkill(
            "SKILL.md exceeds 1 MiB".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    File::open(skill_file)?
        .take(MAX_SKILL_MD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SKILL_MD_BYTES {
        return Err(SkillError::InvalidSkill(
            "SKILL.md exceeds 1 MiB".to_string(),
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| SkillError::InvalidSkill("SKILL.md must be UTF-8".to_string()))?;
    let content = text
        .strip_prefix("---\r\n")
        .or_else(|| text.strip_prefix("---\n"))
        .ok_or_else(|| {
            SkillError::InvalidSkill("YAML frontmatter must start with '---'".to_string())
        })?;
    let (frontmatter, markdown) = content
        .split_once("\n---\r\n")
        .or_else(|| content.split_once("\n---\n"))
        .ok_or_else(|| SkillError::InvalidSkill("YAML frontmatter is not closed".to_string()))?;
    if frontmatter.len() > 16 * 1024 {
        return Err(SkillError::InvalidSkill(
            "YAML frontmatter exceeds 16 KiB".to_string(),
        ));
    }
    if markdown.trim().is_empty() {
        return Err(SkillError::InvalidSkill(
            "Markdown body is required".to_string(),
        ));
    }

    let parsed: SkillFrontmatter = serde_saphyr::from_str(frontmatter)
        .map_err(|error| SkillError::InvalidSkill(error.to_string()))?;
    let name = parsed.name;
    validate_name(&name)?;
    let description = parsed.description;
    let description_len = description.chars().count();
    if !(1..=1024).contains(&description_len) {
        return Err(SkillError::InvalidSkill(
            "description must be 1 to 1024 characters".to_string(),
        ));
    }

    Ok(SkillMetadata { name, description })
}

fn validate_name(name: &str) -> Result<()> {
    let valid = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--");
    if valid {
        Ok(())
    } else {
        Err(SkillError::InvalidSkill(
            "name must be 1 to 64 lowercase ASCII letters, digits, or hyphens, with no leading, trailing, or consecutive hyphens".to_string(),
        ))
    }
}

fn extract_archive(archive: &Path, destination: &Path) -> Result<()> {
    let name = archive
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".zip") {
        extract_zip(archive, destination)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        extract_tar_gz(archive, destination)
    } else {
        Err(SkillError::UnsupportedArchive(name))
    }
}

fn extract_zip(archive: &Path, destination: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(File::open(archive)?)?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(SkillError::TooManyEntries);
    }
    let mut seen = BTreeSet::new();
    let mut extracted = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let raw = entry.name().to_string();
        let relative =
            safe_relative(&raw).ok_or_else(|| SkillError::UnsafeArchiveEntry(raw.clone()))?;
        if !seen.insert(relative.to_string_lossy().to_lowercase()) {
            return Err(SkillError::DuplicateEntry(raw));
        }
        let expected_mode = if entry.is_dir() { 0o040000 } else { 0o100000 };
        if entry.unix_mode().is_some_and(|mode| {
            let kind = mode & 0o170000;
            kind != 0 && kind != expected_mode
        }) {
            return Err(SkillError::UnsupportedEntry(raw));
        }
        let output = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(output)?;
        } else {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_bounded(&mut entry, &mut File::create(output)?, &mut extracted)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(archive: &Path, destination: &Path) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(File::open(archive)?);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    let mut extracted = 0u64;
    for entry in archive.entries()? {
        count += 1;
        if count > MAX_ARCHIVE_ENTRIES {
            return Err(SkillError::TooManyEntries);
        }
        let mut entry = entry?;
        let raw = entry.path()?.to_string_lossy().into_owned();
        let relative =
            safe_relative(&raw).ok_or_else(|| SkillError::UnsafeArchiveEntry(raw.clone()))?;
        if !seen.insert(relative.to_string_lossy().to_lowercase()) {
            return Err(SkillError::DuplicateEntry(raw));
        }
        let output = destination.join(relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(output)?;
        } else if kind.is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_bounded(&mut entry, &mut File::create(output)?, &mut extracted)?;
        } else {
            return Err(SkillError::UnsupportedEntry(raw));
        }
    }
    Ok(())
}

fn safe_relative(raw: &str) -> Option<PathBuf> {
    let normalized = raw.replace('\\', "/");
    if normalized.starts_with('/') || normalized.len() > MAX_ARCHIVE_PATH_BYTES {
        return None;
    }
    let mut output = PathBuf::new();
    let mut depth = 0usize;
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(value) if safe_windows_component(value.to_str()?) => {
                depth += 1;
                if depth > MAX_ARCHIVE_DEPTH {
                    return None;
                }
                output.push(value)
            }
            Component::CurDir => {}
            Component::Normal(_)
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => return None,
        }
    }
    (!output.as_os_str().is_empty()).then_some(output)
}

fn safe_windows_component(value: &str) -> bool {
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

fn copy_bounded(
    reader: &mut impl Read,
    writer: &mut impl Write,
    extracted: &mut u64,
) -> Result<()> {
    copy_with_limit(reader, writer, extracted, MAX_EXTRACTED_BYTES)
}

fn copy_with_limit(
    reader: &mut impl Read,
    writer: &mut impl Write,
    extracted: &mut u64,
    limit: u64,
) -> Result<()> {
    let remaining = limit.saturating_sub(*extracted);
    let copied = io::copy(&mut reader.take(remaining + 1), writer)?;
    if copied > remaining {
        return Err(SkillError::ArchiveTooLarge);
    }
    *extracted += copied;
    Ok(())
}

fn collect_actions(source: &Path, destination: &Path) -> Result<Vec<SkillAction>> {
    let mut actions = vec![SkillAction::DirectoryCreated {
        path: destination.to_path_buf(),
    }];
    collect_children(source, source, destination, &mut actions)?;
    Ok(actions)
}

fn collect_children(
    root: &Path,
    directory: &Path,
    destination: &Path,
    actions: &mut Vec<SkillAction>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let relative = source_path
            .strip_prefix(root)
            .map_err(|_| SkillError::UnsafeArchiveEntry(source_path.display().to_string()))?;
        let target_path = destination.join(relative);
        let kind = fs::symlink_metadata(&source_path)?.file_type();
        if kind.is_symlink() {
            return Err(SkillError::UnsupportedEntry(relative.display().to_string()));
        }
        if kind.is_dir() {
            actions.push(SkillAction::DirectoryCreated { path: target_path });
            collect_children(root, &source_path, destination, actions)?;
        } else if kind.is_file() {
            actions.push(SkillAction::FileWritten {
                path: target_path,
                sha256: sha256_file(&source_path)?,
            });
        } else {
            return Err(SkillError::UnsupportedEntry(relative.display().to_string()));
        }
    }
    Ok(())
}

fn verify_unchanged(
    current_root: &Path,
    recorded_root: &Path,
    actions: &[SkillAction],
) -> Result<()> {
    let expected = action_map(recorded_root, actions)?;
    let actual = tree_map(current_root)?;
    if expected.keys().ne(actual.keys()) {
        let changed = expected
            .keys()
            .find(|path| !actual.contains_key(*path))
            .or_else(|| actual.keys().find(|path| !expected.contains_key(*path)))
            .cloned()
            .unwrap_or_default();
        return Err(SkillError::Changed(recorded_root.join(changed)));
    }
    for (relative, hash) in expected {
        if let Some(expected_hash) = hash {
            let path = current_root.join(&relative);
            if sha256_file(&path)? != expected_hash {
                return Err(SkillError::Changed(recorded_root.join(relative)));
            }
        }
    }
    Ok(())
}

fn action_map(
    recorded_root: &Path,
    actions: &[SkillAction],
) -> Result<BTreeMap<PathBuf, Option<String>>> {
    let mut entries = BTreeMap::new();
    for action in actions {
        let (path, hash) = match action {
            SkillAction::DirectoryCreated { path } => (path, None),
            SkillAction::FileWritten { path, sha256 } => (path, Some(sha256.clone())),
        };
        let relative = path
            .strip_prefix(recorded_root)
            .map_err(|_| SkillError::StatePathMismatch(path.clone()))?
            .to_path_buf();
        if entries.insert(relative, hash).is_some() {
            return Err(SkillError::StatePathMismatch(path.clone()));
        }
    }
    Ok(entries)
}

fn tree_map(root: &Path) -> Result<BTreeMap<PathBuf, Option<String>>> {
    if !root.exists() {
        return Ok(BTreeMap::new());
    }
    let mut entries = BTreeMap::from([(PathBuf::new(), None)]);
    tree_children(root, root, &mut entries, 0)?;
    Ok(entries)
}

fn tree_children(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<PathBuf, Option<String>>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_ARCHIVE_DEPTH {
        return Err(SkillError::Changed(directory.to_path_buf()));
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| SkillError::Changed(path.clone()))?
            .to_path_buf();
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_symlink() {
            return Err(SkillError::Changed(path));
        }
        if kind.is_dir() {
            entries.insert(relative, None);
            tree_children(root, &path, entries, depth + 1)?;
        } else if kind.is_file() {
            entries.insert(relative, Some(String::new()));
        } else {
            return Err(SkillError::Changed(path));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_file(path: &Path, sha512: bool) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    if sha512 {
        let mut hasher = Sha512::new();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                return Ok(hex::encode(hasher.finalize()));
            }
            hasher.update(&buffer[..read]);
        }
    }
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hex::encode(hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_copy_rejects_one_byte_over_the_limit() {
        let mut input = &b"12345"[..];
        let mut output = Vec::new();
        let mut extracted = 0;
        assert!(matches!(
            copy_with_limit(&mut input, &mut output, &mut extracted, 4),
            Err(SkillError::ArchiveTooLarge)
        ));
    }
}
