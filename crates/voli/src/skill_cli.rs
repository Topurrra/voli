use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use voli_core::{SkillScope, SkillTarget};

pub(crate) struct Selection {
    pub targets: Vec<SkillTarget>,
    pub scope: SkillScope,
    pub project: PathBuf,
}

pub(crate) fn resolve(
    requested: &[String],
    project_scope: bool,
    global_scope: bool,
    noninteractive: bool,
    home: &Path,
    root: &Path,
) -> Result<Selection, String> {
    let targets = if requested.is_empty() {
        if noninteractive || !std::io::stdin().is_terminal() {
            return Err(
                "skill packages require --for <agent>, --for detected, or --for all".to_string(),
            );
        }
        interactive_targets(home, root)?
    } else {
        expand_targets(requested, home)?
    };
    if targets.is_empty() {
        return Err("no installed agents were detected".to_string());
    }

    let scope = if project_scope {
        SkillScope::Project
    } else if global_scope || noninteractive || !std::io::stdin().is_terminal() {
        SkillScope::Global
    } else {
        prompt_scope()?
    };
    let project = std::env::current_dir()
        .map_err(|error| format!("cannot resolve current project directory: {error}"))?;
    Ok(Selection {
        targets,
        scope,
        project,
    })
}

fn expand_targets(requested: &[String], home: &Path) -> Result<Vec<SkillTarget>, String> {
    let mut selected = Vec::new();
    for value in requested {
        match value.as_str() {
            "all" => selected.extend_from_slice(SkillTarget::all()),
            "detected" => selected.extend(
                SkillTarget::all()
                    .iter()
                    .copied()
                    .filter(|target| target.is_detected(home)),
            ),
            value => selected.push(
                value
                    .parse::<SkillTarget>()
                    .map_err(|error| error.to_string())?,
            ),
        }
    }
    let mut seen = BTreeSet::new();
    selected.retain(|target| seen.insert(target.as_str()));
    Ok(selected)
}

fn interactive_targets(home: &Path, root: &Path) -> Result<Vec<SkillTarget>, String> {
    let previous = read_previous(root);
    let detected = SkillTarget::all()
        .iter()
        .copied()
        .filter(|target| target.is_detected(home))
        .collect::<Vec<_>>();
    loop {
        print!("Search agents (Enter for detected): ");
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        let query = read_line()?.to_ascii_lowercase();
        let matches = SkillTarget::all()
            .iter()
            .copied()
            .filter(|target| query.is_empty() || target.as_str().contains(&query))
            .collect::<Vec<_>>();
        if matches.is_empty() {
            println!("No matching agents. Try another search.");
            continue;
        }
        for (index, target) in matches.iter().enumerate() {
            let selected = previous.iter().any(|value| value == target.as_str())
                || (previous.is_empty() && detected.contains(target));
            println!(
                "  {:>2}. [{}] {}",
                index + 1,
                if selected { "x" } else { " " },
                target.as_str()
            );
        }
        print!("Select numbers or agent names, comma-separated (Enter keeps checks): ");
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        let answer = read_line()?;
        if answer.is_empty() {
            // Keep only remembered ids that still exist in the target table; a
            // stale id (agent dropped from a later table) is filtered out
            // rather than hard-erroring the "keep previous" default.
            let defaults = if previous.is_empty() {
                detected.clone()
            } else {
                SkillTarget::all()
                    .iter()
                    .copied()
                    .filter(|target| previous.iter().any(|value| value == target.as_str()))
                    .collect::<Vec<_>>()
            };
            if !defaults.is_empty() {
                return Ok(defaults);
            }
            println!("Select at least one agent.");
            continue;
        }
        let mut values = Vec::new();
        for part in answer
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            if let Ok(index) = part.parse::<usize>() {
                // Displayed numbering is 1-based; reject 0 rather than aliasing
                // it to the first item via a saturating subtraction.
                if index == 0 {
                    return Err("selection number 0 is out of range".to_string());
                }
                let Some(target) = matches.get(index - 1) else {
                    return Err(format!("selection number {index} is out of range"));
                };
                values.push(target.as_str().to_string());
            } else {
                values.push(part.to_string());
            }
        }
        return expand_targets(&values, home);
    }
}

fn prompt_scope() -> Result<SkillScope, String> {
    print!("Install scope [G]lobal/[p]roject: ");
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;
    match read_line()?.to_ascii_lowercase().as_str() {
        "" | "g" | "global" => Ok(SkillScope::Global),
        "p" | "project" => Ok(SkillScope::Project),
        value => Err(format!("unknown scope '{value}': choose global or project")),
    }
}

fn read_line() -> Result<String, String> {
    let mut line = String::new();
    let read = std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| format!("cannot read selection: {error}"))?;
    // 0 bytes == EOF (closed stdin / Ctrl+Z). Distinguish it from a blank Enter
    // ("\n") so callers abort instead of looping on a perpetually-empty read.
    if read == 0 {
        return Err("input closed".to_string());
    }
    Ok(line.trim().to_string())
}

/// Confirm the plan before mutating. Auto-approves on `--yes`, `--json`, or a
/// non-interactive stdin; otherwise asks and treats anything but y/yes
/// (including EOF) as a decline.
pub(crate) fn confirm(auto_yes: bool, json: bool) -> bool {
    if auto_yes || json || !std::io::stdin().is_terminal() {
        return true;
    }
    print!("Proceed? [y/N] ");
    let _ = std::io::stdout().flush();
    matches!(
        read_line()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    )
}

pub(crate) fn print_plan(packages: &[String], selection: &Selection, home: &Path, json: bool) {
    let output = packages
        .iter()
        .map(|name| format!("skill/{name}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut lines = vec![
        format!("Plan: {output}"),
        format!("  scope: {}", selection.scope.as_str()),
        "  method: copy".to_string(),
    ];
    let mut paths = BTreeSet::new();
    for target in &selection.targets {
        let path = target.skills_dir(selection.scope, home, &selection.project);
        let shared = !paths.insert(path.clone());
        lines.push(format!(
            "  {} -> {}{}",
            target.as_str(),
            path.display(),
            if shared { " (shared)" } else { "" }
        ));
    }
    for line in lines {
        if json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

pub(crate) fn remember(selection: &Selection, root: &Path) {
    let path = root.join("db").join("skill-targets.json");
    let _ = std::fs::create_dir_all(path.parent().expect("preference file has parent"));
    let values = selection
        .targets
        .iter()
        .map(|target| target.as_str())
        .collect::<Vec<_>>();
    if let Ok(json) = serde_json::to_vec(&values) {
        let _ = std::fs::write(path, json);
    }
}

fn read_previous(root: &Path) -> Vec<String> {
    std::fs::read(root.join("db").join("skill-targets.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_auto_approves_without_prompting() {
        // --yes and --json bypass the gate; and under `cargo test` stdin is not
        // a terminal, so the plain path also auto-approves — none of these read.
        assert!(confirm(true, false));
        assert!(confirm(false, true));
        assert!(confirm(false, false));
    }

    #[test]
    fn noninteractive_selection_is_explicit_and_defaults_to_global_scope() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join(".cursor")).unwrap();

        assert!(resolve(&[], false, false, true, &home, temp.path()).is_err());
        let explicit = resolve(
            &["codex".to_string()],
            false,
            false,
            true,
            &home,
            temp.path(),
        )
        .unwrap();
        assert_eq!(explicit.scope, SkillScope::Global);
        assert_eq!(explicit.targets[0].as_str(), "codex");

        let detected = resolve(
            &["detected".to_string()],
            false,
            false,
            true,
            &home,
            temp.path(),
        )
        .unwrap();
        assert!(
            detected
                .targets
                .iter()
                .any(|target| target.as_str() == "cursor")
        );
        assert!(
            !detected
                .targets
                .iter()
                .any(|target| target.as_str() == "codex")
        );

        let all = resolve(&["all".to_string()], false, true, true, &home, temp.path()).unwrap();
        assert_eq!(all.targets.len(), SkillTarget::all().len());
    }
}
