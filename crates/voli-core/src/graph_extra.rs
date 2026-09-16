//! Non-AST extractors for `voli graph`: markdown links, package manifests,
//! MCP configs, SQL schemas, Dockerfiles, Terraform blocks.
//!
//! All deterministic and offline. Semantic content inside docs/PDFs/images
//! (what graphify spends LLM calls on) is out of scope for the local engine:
//! such files become file nodes with `contains` edges only, and the REPORT
//! says so honestly.

use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

fn re(pat: &str) -> Regex { Regex::new(pat).unwrap() }
macro_rules! static_re { ($cell:ident, $n:ident, $pat:expr) => { #[allow(non_upper_case_globals)] static $cell: OnceLock<Regex> = OnceLock::new(); let $n: &Regex = $cell.get_or_init(|| re($pat)); } }

// ---------------------------------------------------------------------------
// Markdown: `[text](./other.md)` links + `[[wikilinks]]` → references edges
// ---------------------------------------------------------------------------

/// (target, line) pairs. Targets are raw link destinations as written.
pub fn md_links(text: &str) -> Vec<(String, u32)> {
    static_re!(C_re_link, re_link, r"\[[^\]]*\]\(([^)\s]+)\)");
    static_re!(C_re_wiki, re_wiki, r"\[\[([^\]]+)\]\]");
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let no = (i + 1) as u32;
        for cap in re_link.captures_iter(line) {
            let t = cap[1].trim().to_string();
            if t.starts_with("http://") || t.starts_with("https://") || t.starts_with("mailto:") || t.starts_with('#') {
                continue;
            }
            let t = t.split('#').next().unwrap_or("").split('?').next().unwrap_or("").to_string();
            if !t.is_empty() {
                out.push((t, no));
            }
        }
        for cap in re_wiki.captures_iter(line) {
            let t = cap[1].trim().to_string();
            if !t.is_empty() {
                out.push((t, no));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Manifests: one canonical package node per name + depends_on edges
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ManifestDeps {
    /// (package name, version req or "")
    pub deps: Vec<(String, String)>,
}

/// Parse dependencies from a manifest by file name. Returns None for unknown.
pub fn manifest_deps(file_name: &str, text: &str) -> Option<ManifestDeps> {
    match file_name {
        "package.json" => {
            let v: serde_json::Value = serde_json::from_str(text).ok()?;
            let mut deps = Vec::new();
            for section in ["dependencies", "devDependencies", "peerDependencies"] {
                if let Some(map) = v.get(section).and_then(|m| m.as_object()) {
                    for (k, ver) in map {
                        deps.push((k.clone(), ver.as_str().unwrap_or("").to_string()));
                    }
                }
            }
            Some(ManifestDeps { deps })
        }
        "pyproject.toml" => {
            let v: toml::Value = text.parse().ok()?;
            let mut deps = Vec::new();
            if let Some(arr) = v.get("project").and_then(|p| p.get("dependencies")).and_then(|d| d.as_array()) {
                for d in arr {
                    if let Some(s) = d.as_str() {
                        let name: String = s.chars().take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
                        if !name.is_empty() {
                            deps.push((name, s.to_string()));
                        }
                    }
                }
            }
            // poetry / pdm sections
            for section in ["tool.poetry.dependencies", "tool.pdm.dependencies"] {
                let mut cur: Option<&toml::Value> = Some(&v);
                for key in section.split('.') {
                    cur = cur.and_then(|c| c.get(key));
                }
                match cur {
                    Some(toml::Value::Table(t)) => {
                        for (k, _) in t {
                            if k != "python" {
                                deps.push((k.clone(), String::new()));
                            }
                        }
                    }
                    Some(toml::Value::Array(a)) => {
                        for d in a {
                            if let Some(s) = d.as_str() {
                                deps.push((s.to_string(), String::new()));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Some(ManifestDeps { deps })
        }
        "go.mod" => {
            static_re!(C_re, re, r"^\s*([A-Za-z0-9_./~+-]+\.[A-Za-z]{2,}[A-Za-z0-9_./~+-]*)\s+v[0-9]");
            let mut deps = Vec::new();
            for line in text.lines() {
                if let Some(c) = re.captures(line) {
                    deps.push((c[1].to_string(), String::new()));
                }
            }
            Some(ManifestDeps { deps })
        }
        "pom.xml" => {
            // groupId:artifactId pairs inside <dependencies>
            static_re!(C_re_dep, re_dep, r"(?s)<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>");
            let mut deps = Vec::new();
            for cap in re_dep.captures_iter(text) {
                deps.push((format!("{}:{}", cap[1].trim(), cap[2].trim()), String::new()));
            }
            Some(ManifestDeps { deps })
        }
        name if name.ends_with(".csproj") || name.ends_with(".fsproj") || name.ends_with(".vbproj") => {
            static_re!(C_re, re, r#"<PackageReference\s+Include="([^"]+)"\s+Version="([^"]*)""#);
            static_re!(C_re2, re2, r#"<PackageReference[^>]*Include="([^"]+)"[^>]*>"#);
            let mut deps = Vec::new();
            for cap in re.captures_iter(text) {
                deps.push((cap[1].to_string(), cap[2].to_string()));
            }
            if deps.is_empty() {
                for cap in re2.captures_iter(text) {
                    deps.push((cap[1].to_string(), String::new()));
                }
            }
            Some(ManifestDeps { deps })
        }
        _ => None,
    }
}

/// Crate/package identity for well-known manifests (node label source).
pub fn manifest_identity(file_name: &str, text: &str) -> Option<String> {
    match file_name {
        "package.json" => serde_json::from_str::<serde_json::Value>(text)
            .ok()?
            .get("name")?
            .as_str()
            .map(|s| s.to_string()),
        "pyproject.toml" => text
            .parse::<toml::Value>()
            .ok()?
            .get("project")?
            .get("name")?
            .as_str()
            .map(|s| s.to_string()),
        "go.mod" => text
            .lines()
            .find_map(|l| l.strip_prefix("module "))
            .map(|s| s.trim().to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// MCP configs: server nodes + package refs
// ---------------------------------------------------------------------------

const MCP_FILES: &[&str] = &[".mcp.json", "mcp.json", "mcp_servers.json", "claude_desktop_config.json"];

pub fn is_mcp_config(name: &str) -> bool {
    MCP_FILES.contains(&name)
}

/// (server name, command/package refs)
pub fn mcp_servers(text: &str) -> Vec<(String, Vec<String>)> {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let servers = v.get("mcpServers").or_else(|| v.get("servers"));
    let map = match servers.and_then(|s| s.as_object()) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (name, cfg) in map {
        let mut refs = Vec::new();
        if let Some(cmd) = cfg.get("command").and_then(|c| c.as_str()) {
            refs.push(cmd.to_string());
        }
        if let Some(args) = cfg.get("args").and_then(|a| a.as_array()) {
            for a in args.iter().filter_map(|a| a.as_str()) {
                if a.contains('/') || a.starts_with('@') || a.ends_with(".js") || a.contains("mcp") {
                    refs.push(a.to_string());
                }
            }
        }
        out.push((name.clone(), refs));
    }
    out
}

// ---------------------------------------------------------------------------
// SQL: CREATE TABLE + REFERENCES → table nodes + edges
// ---------------------------------------------------------------------------

/// (table name, referenced tables)
pub fn sql_tables(text: &str) -> Vec<(String, Vec<String>)> {
    static_re!(C_re_table, re_table, r"(?i)\bCREATE\s+(?:TEMPORARY\s+|TEMP\s+|UNLOGGED\s+|OR\s+REPLACE\s+)*TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_.]*)");
    static_re!(C_re_ref, re_ref, r"(?i)\bREFERENCES\s+([A-Za-z_][A-Za-z0-9_.]*)");
    let mut tables: Vec<(String, usize)> = Vec::new();
    for cap in re_table.captures_iter(text) {
        let m = cap.get(0).unwrap();
        tables.push((cap[1].to_string(), m.start()));
    }
    let mut out = Vec::new();
    for (i, (name, start)) in tables.iter().enumerate() {
        let end = tables.get(i + 1).map(|t| t.1).unwrap_or(text.len());
        let body = &text[*start..end];
        let mut refs = Vec::new();
        for cap in re_ref.captures_iter(body) {
            refs.push(cap[1].to_string());
        }
        out.push((short_table(name), refs.into_iter().map(|r| short_table(&r)).collect()));
    }
    out
}

fn short_table(s: &str) -> String {
    s.rsplit('.').next().unwrap_or(s).trim_matches('"').to_string()
}

// ---------------------------------------------------------------------------
// Dockerfile: FROM image → uses edge
// ---------------------------------------------------------------------------

/// Base images referenced by FROM (stages included).
pub fn docker_bases(text: &str) -> Vec<String> {
    static_re!(C_re, re, r"(?i)^\s*FROM\s+(?:--[A-Za-z0-9_=.-]+\s+)*([A-Za-z0-9_./:@-]+)");
    text.lines()
        .filter_map(|l| re.captures(l).map(|c| c[1].to_string()))
        .filter(|s| s.to_lowercase() != "scratch")
        .collect()
}

pub fn is_dockerfile(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n == "Dockerfile" || n.starts_with("Dockerfile.") || n.ends_with(".dockerfile"),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Terraform: module blocks (source) + resources
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct TfModule {
    pub name: String,
    pub source: Option<String>,
    pub line: u32,
}

#[derive(Debug)]
pub struct TfResource {
    pub rtype: String,
    pub name: String,
    pub line: u32,
}

/// Line-oriented HCL scan: module blocks with literal sources, resources.
/// (A full HCL grammar has no 0.24 release; blocks are regular enough that
/// regex is exact for the literal-source cases we link.)
pub fn terraform(text: &str) -> (Vec<TfModule>, Vec<TfResource>) {
    static_re!(C_re_mod, re_mod, r#"^\s*module\s+"([^"]+)"\s*\{?"#);
    static_re!(C_re_source, re_source, r#"^\s*source\s*=\s*"([^"]+)""#);
    static_re!(C_re_res, re_res, r#"^\s*resource\s+"([^"]+)"\s+"([^"]+)""#);
    let mut modules = Vec::new();
    let mut resources = Vec::new();
    let mut cur: Option<(String, u32, Option<String>)> = None;
    let mut depth = 0i32;
    for (i, line) in text.lines().enumerate() {
        let no = (i + 1) as u32;
        if let Some(c) = re_mod.captures(line) {
            if cur.is_some() {
                let (n, l, s) = cur.take().unwrap();
                modules.push(TfModule { name: n, source: s, line: l });
            }
            cur = Some((c[1].to_string(), no, None));
            depth = 0;
        } else if let Some(c) = re_res.captures(line) {
            resources.push(TfResource { rtype: c[1].to_string(), name: c[2].to_string(), line: no });
        } else if let Some(c) = re_source.captures(line) {
            if let Some(m) = cur.as_mut() {
                m.2 = Some(c[1].to_string());
            }
        }
        depth += line.chars().filter(|&c| c == '{').count() as i32
            - line.chars().filter(|&c| c == '}').count() as i32;
        if cur.is_some() && depth <= 0 && line.contains('}') {
            let (n, l, s) = cur.take().unwrap();
            modules.push(TfModule { name: n, source: s, line: l });
        }
    }
    if let Some((n, l, s)) = cur.take() {
        modules.push(TfModule { name: n, source: s, line: l });
    }
    (modules, resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md_links_and_wiki() {
        let l = md_links("see [a](./b.md) and [[c]] plus [x](https://e.com)");
        assert!(l.iter().any(|(t, _)| t == "./b.md"));
        assert!(l.iter().any(|(t, _)| t == "c"));
        assert!(!l.iter().any(|(t, _)| t.contains("https")));
    }

    #[test]
    fn package_json_deps() {
        let d = manifest_deps("package.json", r#"{"dependencies":{"a":"^1.0"},"devDependencies":{"b":"2.0"}}"#).unwrap();
        assert_eq!(d.deps.len(), 2);
    }

    #[test]
    fn sql_tables_and_refs() {
        let t = sql_tables("CREATE TABLE orders (id INT PRIMARY KEY, user_id INT REFERENCES users(id));\nCREATE TABLE users (id INT);");
        assert!(t.iter().any(|(n, r)| n == "orders" && r.contains(&"users".to_string())), "{t:?}");
    }

    #[test]
    fn tf_modules() {
        let (m, r) = terraform("module \"app\" {\n  source = \"./modules/app\"\n}\nresource \"aws_s3_bucket\" \"b\" {}\n");
        assert!(m.iter().any(|x| x.name == "app" && x.source.as_deref() == Some("./modules/app")), "{m:?}");
        assert!(r.iter().any(|x| x.rtype == "aws_s3_bucket"), "{r:?}");
    }
}
