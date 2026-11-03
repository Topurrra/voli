//! Shim shadowing rules (supply-chain review item 2).
//!
//! voli's shims dir is first on PATH, so a shim silently wins over any
//! same-named system command — that is the "lookalike on PATH" attack: one
//! bad manifest getting through review replaces `sudo` or `ssh` for everyone
//! who installs it. Install-time consent therefore treats three situations as
//! a conflict the caller must explicitly approve:
//!
//! 1. the shim name is on a fixed reserved list (`sudo`, `ssh`, `git`, …);
//! 2. the name already resolves on PATH — outside the shims dir — to
//!    something else;
//! 3. another installed package already owns a shim with that name.
//!
//! Everything here is pure and PATH is passed in as a string, so the logic is
//! testable without touching the process environment.

use std::path::{Path, PathBuf};

/// Shim names a package may never claim without explicit consent: core
/// system tools, shells, and credential-bearing CLIs. A lookalike shim here
/// is indistinguishable from a compromise of the machine.
pub const RESERVED_NAMES: &[&str] = &[
    "sudo",
    "su",
    "ssh",
    "scp",
    "sftp",
    "git",
    "gpg",
    "python",
    "python3",
    "py",
    "pip",
    "pip3",
    "node",
    "npm",
    "npx",
    "bash",
    "sh",
    "zsh",
    "pwsh",
    "powershell",
    "cmd",
    "curl",
    "wget",
    "docker",
    "kubectl",
    "aws",
    "az",
    "gcloud",
    "gh",
    "pyenv",
    "brew",
    "java",
    "code",
    "openssl",
];

/// Case-insensitive on Windows (shims are `name.exe`), exact elsewhere.
pub fn is_reserved(name: &str) -> bool {
    #[cfg(windows)]
    {
        RESERVED_NAMES.iter().any(|r| r.eq_ignore_ascii_case(name))
    }
    #[cfg(not(windows))]
    {
        RESERVED_NAMES.contains(&name)
    }
}

/// One shim-name conflict the installer must surface to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimConflict {
    /// The shim base name (without extension) the package wants to claim.
    pub shim: String,
    /// The name is on [`RESERVED_NAMES`].
    pub reserved: bool,
    /// The command the shim would shadow: the first PATH hit outside the
    /// shims dir, if any.
    pub shadows: Option<PathBuf>,
    /// Package that already owns a same-named shim in the shims dir, if any.
    pub held_by: Option<String>,
}

impl ShimConflict {
    /// Human-readable one-liner for prompts and error messages.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.reserved {
            parts.push("reserved name".to_string());
        }
        if let Some(path) = &self.shadows {
            parts.push(format!("shadows {}", path.display()));
        }
        if let Some(owner) = &self.held_by {
            parts.push(format!("already provided by package {owner}"));
        }
        format!("shim '{}': {}", self.shim, parts.join("; "))
    }
}

/// Whether `path` (one PATH segment) is the shims dir itself — the shim's own
/// directory never counts as the shadowed command.
#[cfg(windows)]
fn same_dir(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(b.to_string_lossy().trim_end_matches(['\\', '/']))
}

#[cfg(not(windows))]
fn same_dir(a: &Path, b: &Path) -> bool {
    a == b
}

/// Executable extensions tried when resolving `name` on a Windows PATH;
/// unix PATH resolution is exact-name only.
#[cfg(windows)]
const PATHEXT: &[&str] = &["", ".exe", ".cmd", ".bat", ".com", ".ps1"];

/// First command named `name` (or `name.exe`/… on Windows) found on
/// `path_var`, ignoring any hit inside `shims_dir`. `None` when the name is
/// free. Pure: `path_var` is passed in, never read from the environment.
pub fn path_shadow(name: &str, shims_dir: &Path, path_var: &str) -> Option<PathBuf> {
    let sep = if cfg!(windows) { ';' } else { ':' };
    for dir in path_var.split(sep) {
        if dir.trim().is_empty() {
            continue;
        }
        let dir_path = Path::new(dir);
        if same_dir(dir_path, shims_dir) {
            continue;
        }
        #[cfg(windows)]
        {
            for ext in PATHEXT {
                let candidate = dir_path.join(format!("{name}{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let candidate = dir_path.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Owning package of an existing `.shim` file, parsed from its target path
/// (`<root>/apps/<name>/current/…` on line 1). `None` when unparseable —
/// callers treat that as "unknown owner" and still prompt.
pub fn shim_owner(shim_file: &Path) -> Option<String> {
    let body = std::fs::read_to_string(shim_file).ok()?;
    let first = body.lines().next()?.trim();
    let path = Path::new(first);
    let mut comps = path.components();
    while let Some(comp) = comps.next() {
        if comp.as_os_str() == "apps" {
            if let Some(owner) = comps.next() {
                if comps.next().is_some_and(|c| c.as_os_str() == "current") {
                    return Some(owner.as_os_str().to_string_lossy().into_owned());
                }
            }
            return None;
        }
    }
    None
}

/// Collect every conflict for the shim names a package wants to write.
///
/// * `bases` — shim base names (from `Manifest::bin` via `shim_name()`).
/// * `shims_dir` — `<root>/shims`, where the shims land.
/// * `path_var` — the PATH to resolve against.
/// * `self_pkg` — the package being installed; its own existing shims
///   (an upgrade reinstalling itself) are not conflicts.
pub fn collect_conflicts(
    bases: &[String],
    shims_dir: &Path,
    path_var: &str,
    self_pkg: &str,
) -> Vec<ShimConflict> {
    let mut out = Vec::new();
    for base in bases {
        let mut conflict = ShimConflict {
            shim: base.clone(),
            reserved: is_reserved(base),
            shadows: path_shadow(base, shims_dir, path_var),
            held_by: None,
        };
        let shim_file = shims_dir.join(format!("{base}.shim"));
        if let Some(owner) = shim_owner(&shim_file) {
            if !owner.eq_ignore_ascii_case(self_pkg) {
                conflict.held_by = Some(owner);
            }
        }
        if conflict.reserved || conflict.shadows.is_some() || conflict.held_by.is_some() {
            out.push(conflict);
        }
    }
    out
}

/// Every shim currently installed that shadows a same-named command on PATH
/// — the `voli doctor` report (review item 2.3). Returns
/// `(shim base name, shadowed command path)` pairs.
pub fn doctor_shadow_report(shims_dir: &Path, path_var: &str) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(shims_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // shims are `name.exe` (Windows) or `name` (unix); `.shim` files are
        // metadata, not executables.
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name.ends_with(".shim") {
            continue;
        }
        #[cfg(windows)]
        let base = name.strip_suffix(".exe").unwrap_or(&name).to_string();
        #[cfg(not(windows))]
        let base = name;
        if let Some(shadowed) = path_shadow(&base, shims_dir, path_var) {
            out.push((base, shadowed));
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path) {
        fs::write(path, b"stub").unwrap();
    }

    fn fake_path(root: &Path, dir: &str) -> String {
        let dir = root.join(dir);
        fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn reserved_list_matches_the_review_list() {
        for name in ["sudo", "ssh", "git", "gpg", "curl", "gh", "code", "openssl"] {
            assert!(is_reserved(name), "{name} must be reserved");
        }
        assert!(!is_reserved("rg"));
        assert!(!is_reserved("7zip"));
    }

    #[test]
    fn path_shadow_finds_command_outside_shims_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let shims = tmp.path().join("shims");
        fs::create_dir_all(&shims).unwrap();
        let bin = fake_path(tmp.path(), "usr-bin");
        touch(&Path::new(&bin).join("rg"));

        let path_var = format!(
            "{}{}{}",
            shims.display(),
            if cfg!(windows) { ';' } else { ':' },
            bin
        );
        let hit = path_shadow("rg", &shims, &path_var).expect("must resolve");
        assert!(hit.to_string_lossy().contains("usr-bin"));
        // A name with no hit anywhere: free.
        assert!(path_shadow("definitely-not-a-command", &shims, &path_var).is_none());
        // A hit *inside* the shims dir does not count as shadowing.
        touch(&shims.join(if cfg!(windows) { "sudo.exe" } else { "sudo" }));
        assert!(path_shadow("sudo", &shims, &path_var).is_none());
    }

    #[test]
    fn shim_owner_parses_apps_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let shim = tmp.path().join("x.shim");
        let root = tmp.path().join("root");
        fs::write(
            &shim,
            format!(
                "{}\n",
                root.join("apps")
                    .join("psutils")
                    .join("current")
                    .join("sudo.ps1")
                    .display()
            ),
        )
        .unwrap();
        assert_eq!(shim_owner(&shim).as_deref(), Some("psutils"));
        // garbage body
        fs::write(&shim, "not a path\n").unwrap();
        assert_eq!(shim_owner(&shim), None);
        // missing file
        assert_eq!(shim_owner(&tmp.path().join("nope.shim")), None);
    }

    #[test]
    fn collect_conflicts_flags_reserved_path_and_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let shims = tmp.path().join("shims");
        fs::create_dir_all(&shims).unwrap();
        // an existing shim owned by another package
        fs::write(
            &shims.join("scp.shim"),
            format!(
                "{}\n",
                tmp.path().join("apps/openssh/current/scp").display()
            ),
        )
        .unwrap();
        let bin = fake_path(tmp.path(), "usr-bin");
        touch(&Path::new(&bin).join("curl"));

        let path_var = format!(
            "{}{}{}",
            shims.display(),
            if cfg!(windows) { ';' } else { ':' },
            bin
        );
        let conflicts = collect_conflicts(
            &["sudo".into(), "scp".into(), "curl".into(), "7zip".into()],
            &shims,
            &path_var,
            "somepkg",
        );
        let mut names: Vec<&str> = conflicts.iter().map(|c| c.shim.as_str()).collect();
        names.sort();
        assert_eq!(names, ["curl", "scp", "sudo"]);
        assert!(
            conflicts
                .iter()
                .find(|c| c.shim == "sudo")
                .unwrap()
                .reserved
        );
        assert_eq!(
            conflicts
                .iter()
                .find(|c| c.shim == "scp")
                .unwrap()
                .held_by
                .as_deref(),
            Some("openssh")
        );
        assert!(
            conflicts
                .iter()
                .find(|c| c.shim == "curl")
                .unwrap()
                .shadows
                .is_some()
        );
        // clean name: no conflict listed at all
        assert!(!conflicts.iter().any(|c| c.shim == "7zip"));
    }

    #[test]
    fn collect_conflicts_ignores_own_shims_on_upgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let shims = tmp.path().join("shims");
        fs::create_dir_all(&shims).unwrap();
        fs::write(
            &shims.join("sudo.shim"),
            format!(
                "{}\n",
                tmp.path().join("apps/psutils/current/sudo.ps1").display()
            ),
        )
        .unwrap();
        let conflicts = collect_conflicts(&["sudo".into()], &shims, "", "psutils");
        // reserved is still flagged (an upgrade is exactly when the user
        // should re-confirm), but the owner check must not fire.
        assert!(conflicts.iter().all(|c| c.held_by.is_none()));
        assert!(conflicts.iter().any(|c| c.reserved && c.shim == "sudo"));
    }

    #[test]
    fn doctor_report_lists_only_shadowing_shims() {
        let tmp = tempfile::tempdir().unwrap();
        let shims = tmp.path().join("shims");
        fs::create_dir_all(&shims).unwrap();
        let bin = fake_path(tmp.path(), "usr-bin");
        touch(&Path::new(&bin).join("git"));
        touch(&shims.join(if cfg!(windows) { "git.exe" } else { "git" }));
        touch(&shims.join(if cfg!(windows) { "free.exe" } else { "free" }));

        let path_var = format!(
            "{}{}{}",
            shims.display(),
            if cfg!(windows) { ';' } else { ':' },
            bin
        );
        let report = doctor_shadow_report(&shims, &path_var);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].0, "git");
        assert!(report[0].1.to_string_lossy().contains("usr-bin"));
    }
}
