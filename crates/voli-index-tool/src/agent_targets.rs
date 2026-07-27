use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;

const SOURCE_URL: &str = "https://github.com/vercel-labs/skills/blob/main/src/agents.ts";

#[derive(Debug, PartialEq, Eq)]
struct TargetPaths {
    project: String,
    global: String,
    marker: String,
    appdata_marker: Option<String>,
}

type ParsedTargets = (BTreeMap<String, TargetPaths>, Vec<(String, String)>);

#[derive(Debug, PartialEq, Eq)]
pub struct AgentTargetSync {
    pub imported: usize,
    pub excluded: Vec<(String, String)>,
}

pub fn sync_agent_targets(source: &Path, out: &Path, revision: &str) -> Result<AgentTargetSync> {
    let source_text =
        std::fs::read_to_string(source).with_context(|| format!("reading {}", source.display()))?;
    let (targets, excluded) = parse_agent_targets(&source_text)?;
    let generated = emit_agent_targets(&targets, revision)?;
    std::fs::write(out, generated).with_context(|| format!("writing {}", out.display()))?;
    Ok(AgentTargetSync {
        imported: targets.len(),
        excluded,
    })
}

fn parse_agent_targets(source: &str) -> Result<ParsedTargets> {
    let records = Regex::new(r"(?ms)^  (?:(?:'([^']+)')|([a-z][a-z0-9-]*)): \{\r?\n(.*?)^  \},")?;
    let project = Regex::new(r"(?m)^\s{4}skillsDir:\s*'([^']+)',\s*$")?;
    let global = Regex::new(r"(?m)^\s{4}globalSkillsDir:\s*(.+),\s*$")?;
    let join = Regex::new(
        r"^join\((home|claudeHome|codexHome|vibeHome|hermesHome|autohandHome|grokHome),\s*(.+)\)$",
    )?;
    let quoted = Regex::new(r"'([^']+)'")?;
    let bases = [
        ("home", ""),
        ("claudeHome", ".claude"),
        // Vendor-verified override: Codex reads user skills from ~/.agents/skills.
        ("codexHome", ".agents"),
        ("vibeHome", ".vibe"),
        ("hermesHome", ".hermes"),
        ("autohandHome", ".autohand"),
        ("grokHome", ".grok"),
    ];

    let mut targets = BTreeMap::new();
    let mut excluded = Vec::new();
    for record in records.captures_iter(source) {
        let id = record
            .get(1)
            .or_else(|| record.get(2))
            .expect("agent id capture")
            .as_str();
        let body = record.get(3).expect("agent body capture").as_str();
        let Some(project_path) = project
            .captures(body)
            .and_then(|capture| capture.get(1))
            .map(|value| value.as_str().to_string())
        else {
            excluded.push((id.to_string(), "no-project-directory".to_string()));
            continue;
        };
        if !safe_relative(&project_path) {
            bail!("agent '{id}' produced unsafe project path '{project_path}'");
        }
        let Some(global_expr) = global.captures(body).and_then(|capture| capture.get(1)) else {
            excluded.push((id.to_string(), "no-global-directory".to_string()));
            continue;
        };
        let expression = global_expr.as_str().trim();
        if expression == "undefined" {
            excluded.push((id.to_string(), "project-only".to_string()));
            continue;
        }
        let Some(parts) = join.captures(expression) else {
            excluded.push((id.to_string(), "runtime-dependent".to_string()));
            continue;
        };
        let base_name = parts.get(1).expect("join base capture").as_str();
        let base = bases
            .iter()
            .find_map(|(name, path)| (*name == base_name).then_some(*path))
            .expect("join regex accepts known bases only");
        let mut path = base.to_string();
        for segment in quoted.captures_iter(parts.get(2).expect("join args capture").as_str()) {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(segment.get(1).expect("quoted path capture").as_str());
        }
        if !safe_relative(&path) {
            bail!("agent '{id}' produced unsafe global path '{path}'");
        }
        let marker = marker_path(id, body, &path)?;
        if targets
            .insert(
                id.to_string(),
                TargetPaths {
                    project: project_path,
                    global: path,
                    marker,
                    appdata_marker: (id == "zed").then(|| "Zed".to_string()),
                },
            )
            .is_some()
        {
            bail!("duplicate agent id '{id}'");
        }
    }
    if targets.is_empty() {
        bail!("no stable global agent targets found");
    }
    excluded.sort();
    Ok((targets, excluded))
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !Path::new(path).is_absolute()
        && !path.starts_with(['/', '\\'])
        && !path
            .split(['/', '\\'])
            .any(|part| part == ".." || part.contains(':'))
}

fn marker_path(id: &str, body: &str, global: &str) -> Result<String> {
    let overrides = [
        ("codex", ".codex"),
        ("kimchi", ".config/kimchi"),
        ("zcode", ".zcode"),
        ("zed", ".config/zed"),
    ];
    if let Some((_, marker)) = overrides.iter().find(|(target, _)| *target == id) {
        return Ok((*marker).to_string());
    }

    let joined = Regex::new(r"existsSync\(join\((home|configHome),\s*((?:'[^']+'\s*,?\s*)+)\)\)")?;
    let quoted = Regex::new(r"'([^']+)'")?;
    if let Some(parts) = joined.captures(body) {
        let mut marker = if parts.get(1).expect("marker base").as_str() == "configHome" {
            ".config".to_string()
        } else {
            String::new()
        };
        for segment in quoted.captures_iter(parts.get(2).expect("marker args").as_str()) {
            if !marker.is_empty() {
                marker.push('/');
            }
            marker.push_str(segment.get(1).expect("marker segment").as_str());
        }
        if !marker.is_empty() {
            return Ok(marker);
        }
    }

    for (home, marker) in [
        ("claudeHome", ".claude"),
        ("vibeHome", ".vibe"),
        ("hermesHome", ".hermes"),
        ("autohandHome", ".autohand"),
        ("grokHome", ".grok"),
    ] {
        if body.contains(&format!("existsSync({home})")) {
            return Ok(marker.to_string());
        }
    }

    let marker = global.strip_suffix("/skills").unwrap_or(global).to_string();
    if marker.is_empty() || Path::new(&marker).is_absolute() {
        bail!("agent '{id}' produced unsafe marker path '{marker}'");
    }
    Ok(marker)
}

fn emit_agent_targets(targets: &BTreeMap<String, TargetPaths>, revision: &str) -> Result<String> {
    if revision.is_empty()
        || !revision
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!("revision must be a non-empty hexadecimal git commit");
    }
    let mut output = format!(
        "// @generated by `voli-index-tool sync-agent-targets`; do not edit.\n\
         // Source: {SOURCE_URL}\n\
         // Revision: {revision}\n\
         // Mapping data is MIT licensed by vercel-labs/skills.\n\n\
         pub const SKILL_TARGET_IDS: &[&str] = &[\n"
    );
    for id in targets.keys() {
        writeln!(output, "    {id:?},")?;
    }
    output.push_str("];\n\npub(crate) const GENERATED_SKILL_TARGETS: &[SkillTarget] = &[\n");
    for (id, paths) in targets {
        match &paths.appdata_marker {
            Some(marker) => writeln!(
                output,
                "    SkillTarget::new_full_with_appdata({id:?}, {:?}, {:?}, {:?}, {marker:?}),",
                paths.project, paths.global, paths.marker
            )?,
            None => writeln!(
                output,
                "    SkillTarget::new_full({id:?}, {:?}, {:?}, {:?}),",
                paths.project, paths.global, paths.marker
            )?,
        }
    }
    output.push_str("];\n");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/agents.ts");

    #[test]
    fn imports_stable_targets_and_reports_the_rest() {
        let (targets, excluded) = parse_agent_targets(FIXTURE).unwrap();
        assert_eq!(targets["claude-code"].global, ".claude/skills");
        assert_eq!(targets["claude-code"].project, ".claude/skills");
        assert_eq!(targets["claude-code"].marker, ".claude");
        assert_eq!(targets["codex"].global, ".agents/skills");
        assert_eq!(targets["codex"].project, ".agents/skills");
        assert_eq!(targets["codex"].marker, ".codex");
        assert_eq!(targets["zed"].marker, ".config/zed");
        assert_eq!(targets["zed"].appdata_marker.as_deref(), Some("Zed"));
        assert_eq!(
            excluded,
            [
                ("amp".to_string(), "runtime-dependent".to_string()),
                ("eve".to_string(), "project-only".to_string())
            ]
        );
    }

    #[test]
    fn generated_output_is_deterministic() {
        let (targets, _) = parse_agent_targets(FIXTURE).unwrap();
        let first = emit_agent_targets(&targets, "abc123").unwrap();
        let second = emit_agent_targets(&targets, "abc123").unwrap();
        assert_eq!(first, second);
        assert!(first.contains(
            "SkillTarget::new_full(\"codex\", \".agents/skills\", \".agents/skills\", \".codex\")"
        ));
        assert!(first.contains(
            "SkillTarget::new_full_with_appdata(\"zed\", \".agents/skills\", \".agents/skills\", \".config/zed\", \"Zed\")"
        ));
    }

    #[test]
    fn rejects_unsafe_project_paths() {
        for unsafe_path in ["../escape", r"C:\escape"] {
            let source = FIXTURE.replacen(".claude/skills", unsafe_path, 1);
            let error = parse_agent_targets(&source).unwrap_err().to_string();
            assert!(error.contains("unsafe project path"), "{error}");
        }
    }
}
