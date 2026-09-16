//! `voli graph`: native code-knowledge graph (Rust port of the graphify idea,
//! rebuilt for voli).
//!
//! Differences from graphify (deliberate):
//! - **Typed nodes.** Every node has a `kind`: file, mod, struct, enum, trait,
//!   fn, method, const, test. No `label.endswith("()")` heuristics downstream.
//! - **Tests indexed but quarantined.** `*/tests/*` and `#[test]` fns are
//!   `kind = test` and excluded from god-node rankings by default.
//! - **Cargo-aware.** `Cargo.toml` files always produce crate nodes + `depends_on`
//!   edges (graphify needed `--cargo` and warned `zero nodes` without it).
//! - **Directed path with automatic undirected fallback.** Callers never pass
//!   `--undirected`; we try directed first, then retry ignoring direction and
//!   say so.
//! - **Offline HTML.** The report page is vanilla JS + inline JSON. No CDN, so
//!   an air-gapped checkout still renders.
//! - **Memory-ready IDs.** Stable `path::Symbol` IDs double as
//!   `voli memory note --tags graph:<id>` citations.
//!
//! Storage: `<root>/.voli-graph/graph.json` + `manifest.json` (incremental) +
//! `REPORT.md` + `graph.html`. The dir is local-only (never committed by
//! default); commit it only to share a prebuilt map with a team.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Node kind — the single biggest fix vs graphify's untyped labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    File,
    Crate,
    Mod,
    Struct,
    Enum,
    Trait,
    Fn,
    Method,
    Const,
    Test,
    Style,
    Table,
    Other,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::File => "file",
            NodeKind::Crate => "crate",
            NodeKind::Mod => "mod",
            NodeKind::Struct => "struct",
            NodeKind::Enum => "enum",
            NodeKind::Trait => "trait",
            NodeKind::Fn => "fn",
            NodeKind::Method => "method",
            NodeKind::Const => "const",
            NodeKind::Test => "test",
            NodeKind::Style => "style",
            NodeKind::Table => "table",
            NodeKind::Other => "other",
        }
    }
}

/// Edge confidence. `extracted` = written literally in the source (a `use`,
/// an `impl X for Y`, a `contains`); `inferred` = resolved by name matching
/// (a `foo()` call textually matching a known `fn foo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Extracted,
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    pub file: String,
    pub line: u32,
    /// File-relative community (one community per file — deterministic and
    /// honest; Leiden-style clustering is a future step, not a placeholder).
    pub community: String,
    pub is_test: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph {
    pub version: u32,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(default)]
    pub built_at_commit: String,
}

impl Graph {
    pub fn node_index(&self) -> HashMap<&str, usize> {
        let mut m = HashMap::with_capacity(self.nodes.len());
        for (i, n) in self.nodes.iter().enumerate() {
            m.insert(n.id.as_str(), i);
        }
        m
    }

    pub fn degree(&self) -> HashMap<&str, usize> {
        let mut d: HashMap<&str, usize> = HashMap::new();
        for e in &self.edges {
            *d.entry(e.from.as_str()).or_default() += 1;
            *d.entry(e.to.as_str()).or_default() += 1;
        }
        d
    }

    /// Most-connected nodes. Test nodes are excluded unless `include_tests`,
    /// and bare `file` nodes are excluded — they always win by construction
    /// (`contains` fans out) and carry no architectural signal.
    pub fn god_nodes(&self, top: usize, include_tests: bool) -> Vec<(&GraphNode, usize)> {
        let deg = self.degree();
        let mut v: Vec<(&GraphNode, usize)> = self
            .nodes
            .iter()
            .filter(|n| {
                (include_tests || !n.is_test)
                    && !matches!(n.kind, NodeKind::File | NodeKind::Crate)
            })
            .map(|n| (n, deg.get(n.id.as_str()).copied().unwrap_or(0)))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.id.cmp(&b.0.id)));
        v.truncate(top);
        v
    }

    pub fn neighbors(&self, id: &str) -> Vec<(&GraphEdge, &GraphNode)> {
        let idx = self.node_index();
        let mut out = Vec::new();
        for e in &self.edges {
            if e.from == id {
                if let Some(&i) = idx.get(e.to.as_str()) {
                    out.push((e, &self.nodes[i]));
                }
            } else if e.to == id {
                if let Some(&i) = idx.get(e.from.as_str()) {
                    out.push((e, &self.nodes[i]));
                }
            }
        }
        out
    }

    /// Directed BFS; on failure automatically retries undirected and reports
    /// which mode succeeded. Callers never pass a direction flag.
    pub fn shortest_path(&self, a: &str, b: &str) -> Option<(Vec<String>, bool)> {
        if let Some(p) = self.bfs(a, b, true) {
            return Some((p, true));
        }
        self.bfs(a, b, false).map(|p| (p, false))
    }

    fn adjacency(&self, directed: bool) -> HashMap<&str, Vec<&str>> {
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for e in &self.edges {
            // `uses` edges point at external `use::...` pseudo-targets with no
            // node record — they make paths hop through meaningless hubs, so
            // pathfinding ignores them (they still show in explain/query).
            if e.relation == "uses" {
                continue;
            }
            adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
            if !directed {
                adj.entry(e.to.as_str()).or_default().push(e.from.as_str());
            }
        }
        adj
    }

    fn bfs(&self, a: &str, b: &str, directed: bool) -> Option<Vec<String>> {
        let adj = self.adjacency(directed);
        let mut prev: HashMap<&str, &str> = HashMap::new();
        let mut seen: HashSet<&str> = HashSet::from([a]);
        let mut q: VecDeque<&str> = VecDeque::from([a]);
        while let Some(cur) = q.pop_front() {
            if cur == b {
                let mut path = vec![b.to_string()];
                let mut c = b;
                while let Some(&p) = prev.get(c) {
                    path.push(p.to_string());
                    c = p;
                }
                path.reverse();
                return Some(path);
            }
            if let Some(nexts) = adj.get(cur) {
                for &n in nexts {
                    if seen.insert(n) {
                        prev.insert(n, cur);
                        q.push_back(n);
                    }
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Paths / storage layout
// ---------------------------------------------------------------------------

pub fn graph_dir(root: &Path) -> PathBuf {
    root.join(".voli-graph")
}

pub fn graph_path(root: &Path) -> PathBuf {
    graph_dir(root).join("graph.json")
}

pub fn manifest_path(root: &Path) -> PathBuf {
    graph_dir(root).join("manifest.json")
}

pub fn report_path(root: &Path) -> PathBuf {
    graph_dir(root).join("REPORT.md")
}

pub fn html_path(root: &Path) -> PathBuf {
    graph_dir(root).join("graph.html")
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    ".voli",
    ".voli-graph",
    "graphify-out",
    "node_modules",
    "dist",
];

fn stable_id(file: &str, symbol: &str) -> String {
    let f = file
        .trim_end_matches(".rs")
        .replace(['/', '\\', '.', '-'], "_")
        .replace(' ', "_");
    format!("{f}__{symbol}")
}

fn is_test_file(rel: &str) -> bool {
    let r = rel.replace('\\', "/");
    r.contains("/tests/")
        || r.contains("/test/")
        || r.contains("/__tests__/")
        || r.ends_with("/tests.rs")
        || r.starts_with("tests/")
        || r.starts_with("test/")
        || r.contains(".test.")
        || r.contains(".spec.")
        || r.ends_with("_test.rs")
        || r.ends_with("_test.go")
        || r.ends_with("_test.py")
}

fn read_crate_name(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).ok()?;
    // Minimal TOML sniff: first [package] name = "..." (no full parser needed).
    let mut in_pkg = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_pkg = t == "[package]";
            continue;
        }
        if in_pkg && t.starts_with("name") {
            if let Some(v) = t.split('=').nth(1) {
                let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Extensions never indexed (binary / media / archives). Everything else gets
/// at least a file node; code-likes get symbols.
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "webp", "gif", "ico", "bmp", "svg", "pdf", "mp4", "mov", "webm",
    "mp3", "wav", "ogg", "flac", "zip", "tar", "gz", "xz", "zst", "7z", "rar", "exe",
    "dll", "so", "dylib", "bin", "o", "a", "class", "pyc", "pyo", "wasm", "ttf",
    "otf", "woff", "woff2", "eot", "lock", "node",
];

/// Files bigger than this get a file node only (never parsed).
const PARSE_CAP: u64 = 512 * 1024;

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if SKIP_DIRS.contains(&name) {
                        continue;
                    }
                    // Skip dot-dirs (venvs, caches, ide state) but keep .github.
                    if name.starts_with('.') && name != ".github" {
                        continue;
                    }
                }
                stack.push(p);
            } else if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    if SKIP_EXTS.contains(&ext.to_lowercase().as_str()) {
                        continue;
                    }
                }
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn file_name_of(p: &Path) -> String {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string()
}

fn ext_of(p: &Path) -> String {
    // Dockerfile / Makefile style names have no useful extension.
    p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase()
}

/// One file's intermediate work: symbols first, edges after every file's
/// symbols are known (two passes, so cross-file calls resolve in any order).
struct WorkItem {
    id: String,
    label: String,
    short: String,
    kind: NodeKind,
    line: u32,
    start_byte: usize,
    end_byte: usize,
    parent: Option<String>,
    bases: Vec<String>,
    is_test: bool,
}

struct WorkCall {
    start_byte: usize,
    qualifier: Option<String>,
    name: String,
}

struct WorkFile {
    rel: String,
    file_id: String,
    items: Vec<WorkItem>,
    calls: Vec<WorkCall>,
    imports: Vec<String>,
    impls: Vec<(String, String)>,
    /// Markdown link targets (resolved in pass 2, when all files are known).
    md_targets: Vec<String>,
    /// Terraform local-source dirs to link (resolved in pass 2).
    tf_source_dirs: Vec<(String, String)>,
}

/// Normalize an import/use/include statement into a stable target string.
fn clean_import(s: &str) -> String {
    let mut t = s.trim().to_string();
    for prefix in ["use ", "from ", "import ", "require ", "require_relative ", "load "] {
        if let Some(rest) = t.strip_prefix(prefix) {
            t = rest.trim().to_string();
            break;
        }
    }
    t = t.trim().trim_matches(|c| c == '"' || c == '\'' || c == '<' || c == '>' || c == ';').to_string();
    // `use a::b::{C, D}` → keep whole; trailing commas/semicolons trimmed.
    t.trim_matches([',', ';', ' ']).to_string()
}

/// Mark `#[test]` functions in Rust sources (inline tests live next to code,
/// so the file heuristic is not enough). Lines are 1-based.
fn rust_test_lines(text: &str) -> HashSet<u32> {
    let mut out = HashSet::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("#[test") || t.starts_with("#[cfg(test)]") {
            // attribute block above the fn: mark fns starting within 6 lines
            for k in 1..=6 {
                if let Some(nl) = lines.get(i + k) {
                    let nt = nl.trim_start();
                    if nt.starts_with("fn ") || nt.starts_with("pub ") && nt.contains(" fn ") || nt.starts_with("async fn") {
                        out.insert((i + k + 1) as u32);
                        break;
                    }
                    if nt.starts_with('}') || (nt.starts_with('#') && !nt.starts_with("#[")) {
                        break;
                    }
                }
            }
        }
    }
    out
}

/// Extract `<script>` blocks (vue/svelte/astro): (lang, code, line_offset).
fn script_blocks(text: &str) -> Vec<(bool, String, u32)> {
    let re = Regex::new(r"(?s)<script([^>]*)>(.*?)</script>").unwrap();
    let mut out = Vec::new();
    let mut line_starts: Vec<usize> = vec![0];
    for (i, ch) in text.char_indices() {
        if ch == '\n' {
            line_starts.push(i + 1);
        }
    }
    for cap in re.captures_iter(text) {
        let m = cap.get(0).unwrap();
        let attrs = cap[1].to_string();
        let code = cap[2].to_string();
        if code.trim().is_empty() {
            continue;
        }
        let off = line_starts.iter().filter(|s| **s <= m.start()).count() as u32;
        out.push((attrs.contains("ts"), code, off));
    }
    out
}

/// Build (or rebuild) the graph for `root`. Deterministic, offline, no network.
///
/// Two passes: every file's symbols first (order-independent cross-file
/// resolution), then edges. Tree-sitter AST where a grammar exists, regex
/// fallback for the rest, deterministic local extractors for docs, manifests,
/// SQL, Docker, Terraform.
pub fn build(root: &Path) -> Graph {
    use crate::graph_extra as extra;
    use crate::graph_fallback as fallback;
    use crate::graph_ts as ts;

    let paths = collect_files(root);

    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();
    // qualified name -> ids (Type::method), short name -> ids (free fns),
    // short method name -> ids (receiver heuristic), type short -> type ids.
    let mut by_qual: HashMap<String, Vec<String>> = HashMap::new();
    let mut by_short: HashMap<String, Vec<String>> = HashMap::new();
    let mut methods_by_short: HashMap<String, Vec<String>> = HashMap::new();
    let mut types_by_short: HashMap<String, Vec<String>> = HashMap::new();
    // canonical package nodes shared across manifests
    let mut pkg_ids: HashMap<String, String> = HashMap::new();
    let mut file_ids: HashMap<String, String> = HashMap::new();
    let mut works: Vec<WorkFile> = Vec::new();

    let ensure_pkg = |nodes: &mut Vec<GraphNode>, pkg_ids: &mut HashMap<String, String>, name: &str, file: &str| -> String {
        if let Some(id) = pkg_ids.get(name) {
            return id.clone();
        }
        let id = format!("pkg::{name}");
        nodes.push(GraphNode {
            id: id.clone(),
            label: name.to_string(),
            kind: NodeKind::Crate,
            file: file.to_string(),
            line: 1,
            community: file.to_string(),
            is_test: false,
        });
        pkg_ids.insert(name.to_string(), id.clone());
        id
    };

    // ---------------- pass 1: nodes ----------------
    for path in &paths {
        let rel = rel_path(root, path);
        let fname = file_name_of(path);
        let ext = ext_of(path);
        let test_file = is_test_file(&rel);
        let file_id = stable_id(&rel, "file");
        file_ids.insert(rel.clone(), file_id.clone());
        nodes.push(GraphNode {
            id: file_id.clone(),
            label: rel.clone(),
            kind: NodeKind::File,
            file: rel.clone(),
            line: 1,
            community: rel.clone(),
            is_test: test_file,
        });

        let big = std::fs::metadata(path).map(|m| m.len() > PARSE_CAP).unwrap_or(false);
        let text = if big { None } else { std::fs::read_to_string(path).ok() };
        let Some(text) = text else { continue };
        if text.trim().is_empty() {
            continue;
        }

        let mut wf = WorkFile {
            rel: rel.clone(),
            file_id: file_id.clone(),
            items: Vec::new(),
            calls: Vec::new(),
            imports: Vec::new(),
            impls: Vec::new(),
            md_targets: Vec::new(),
            tf_source_dirs: Vec::new(),
        };

        // package / crate identity nodes
        if fname == "Cargo.toml" {
            let name = read_crate_name(path).unwrap_or_else(|| "unknown".to_string());
            let id = format!("crate::{name}");
            nodes.push(GraphNode {
                id: id.clone(),
                label: name.clone(),
                kind: NodeKind::Crate,
                file: rel.clone(),
                line: 1,
                community: rel.clone(),
                is_test: false,
            });
            edges.push(GraphEdge {
                from: file_id.clone(),
                to: id,
                relation: "defines".to_string(),
                confidence: Confidence::Extracted,
            });
            works.push(wf);
            continue;
        }
        if ["package.json", "pyproject.toml", "go.mod", "pom.xml"].contains(&fname.as_str())
            || fname.ends_with(".csproj")
            || fname.ends_with(".fsproj")
            || fname.ends_with(".vbproj")
        {
            if let Some(deps) = extra::manifest_deps(&fname, &text) {
                let ident = extra::manifest_identity(&fname, &text)
                    .or_else(|| read_crate_name(path))
                    .unwrap_or_else(|| fname.clone());
                let me = ensure_pkg(&mut nodes, &mut pkg_ids, &ident, &rel);
                edges.push(GraphEdge {
                    from: file_id.clone(),
                    to: me.clone(),
                    relation: "defines".to_string(),
                    confidence: Confidence::Extracted,
                });
                for (dep, _ver) in deps.deps {
                    let target = ensure_pkg(&mut nodes, &mut pkg_ids, &dep, &rel);
                    edges.push(GraphEdge {
                        from: me.clone(),
                        to: target,
                        relation: "depends_on".to_string(),
                        confidence: Confidence::Extracted,
                    });
                }
            }
            works.push(wf);
            continue;
        }
        if extra::is_mcp_config(&fname) {
            for (server, refs) in extra::mcp_servers(&text) {
                let id = format!("mcp::{server}");
                nodes.push(GraphNode {
                    id: id.clone(),
                    label: server.clone(),
                    kind: NodeKind::Mod,
                    file: rel.clone(),
                    line: 1,
                    community: rel.clone(),
                    is_test: false,
                });
                edges.push(GraphEdge {
                    from: file_id.clone(),
                    to: id.clone(),
                    relation: "contains".to_string(),
                    confidence: Confidence::Extracted,
                });
                for r in refs {
                    edges.push(GraphEdge {
                        from: id.clone(),
                        to: format!("use::{}", clean_import(&r)),
                        relation: "uses".to_string(),
                        confidence: Confidence::Extracted,
                    });
                }
            }
            works.push(wf);
            continue;
        }
        if matches!(ext.as_str(), "md" | "mdx" | "qmd" | "txt" | "rst") {
            for (target, _line) in extra::md_links(&text) {
                wf.md_targets.push(target);
            }
            works.push(wf);
            continue;
        }
        if ext == "sql" {
            for (table, _refs) in extra::sql_tables(&text) {
                let id = format!("table::{table}");
                nodes.push(GraphNode {
                    id: id.clone(),
                    label: table.clone(),
                    kind: NodeKind::Table,
                    file: rel.clone(),
                    line: 1,
                    community: rel.clone(),
                    is_test: false,
                });
                edges.push(GraphEdge {
                    from: file_id.clone(),
                    to: id.clone(),
                    relation: "contains".to_string(),
                    confidence: Confidence::Extracted,
                });
                for r in _refs {
                    edges.push(GraphEdge {
                        from: id.clone(),
                        to: format!("table::{r}"),
                        relation: "references".to_string(),
                        confidence: Confidence::Extracted,
                    });
                }
            }
            works.push(wf);
            continue;
        }
        if extra::is_dockerfile(path) {
            for base in extra::docker_bases(&text) {
                edges.push(GraphEdge {
                    from: file_id.clone(),
                    to: format!("docker::{base}"),
                    relation: "uses".to_string(),
                    confidence: Confidence::Extracted,
                });
            }
            works.push(wf);
            continue;
        }
        if matches!(ext.as_str(), "tf" | "tfvars" | "hcl") {
            let (modules, resources) = extra::terraform(&text);
            for m in modules {
                let id = format!("tfmod::{}::{}", rel, m.name);
                nodes.push(GraphNode {
                    id: id.clone(),
                    label: m.name.clone(),
                    kind: NodeKind::Mod,
                    file: rel.clone(),
                    line: m.line,
                    community: rel.clone(),
                    is_test: false,
                });
                edges.push(GraphEdge {
                    from: file_id.clone(),
                    to: id.clone(),
                    relation: "contains".to_string(),
                    confidence: Confidence::Extracted,
                });
                if let Some(src) = m.source {
                    if src.starts_with("./") || src.starts_with("../") {
                        wf.tf_source_dirs.push((id, src));
                    } else {
                        edges.push(GraphEdge {
                            from: id,
                            to: format!("modsrc::{src}"),
                            relation: "module_source".to_string(),
                            confidence: Confidence::Extracted,
                        });
                    }
                }
            }
            for r in resources {
                let id = format!("tfres::{}::{}.{}", rel, r.rtype, r.name);
                nodes.push(GraphNode {
                    id: id.clone(),
                    label: format!("{}.{}", r.rtype, r.name),
                    kind: NodeKind::Other,
                    file: rel.clone(),
                    line: r.line,
                    community: rel.clone(),
                    is_test: false,
                });
                edges.push(GraphEdge {
                    from: file_id.clone(),
                    to: id,
                    relation: "contains".to_string(),
                    confidence: Confidence::Extracted,
                });
            }
            works.push(wf);
            continue;
        }

        // ---- code: tree-sitter AST, fallback, or script blocks ----
        let mut emitted = false;
        if ext == "vue" || ext == "svelte" || ext == "astro" {
            for (is_ts, code, off) in script_blocks(&text) {
                let lang = if is_ts { ts::TsLang::TypeScript } else { ts::TsLang::JavaScript };
                if let Some(tf) = ts::extract(lang, &code) {
                    emit_ts(&mut wf, &rel, tf, off, test_file, &text);
                    emitted = true;
                }
            }
            if !emitted {
                let tf = fallback::extract_for_ext(&text, &ext);
                emit_ts(&mut wf, &rel, tf, 0, test_file, &text);
            }
            works.push(wf);
            continue;
        }
        if let Some(lang) = ts::lang_for_ext(&ext) {
            if let Some(tf) = ts::extract(lang, &text) {
                if !tf.items.is_empty() || !tf.broken {
                    emit_ts(&mut wf, &rel, tf, 0, test_file, &text);
                    emitted = true;
                }
            }
            if !emitted && fallback::handles(&ext) {
                let tf = fallback::extract_for_ext(&text, &ext);
                emit_ts(&mut wf, &rel, tf, 0, test_file, &text);
                emitted = true;
            }
            let _ = emitted;
            works.push(wf);
            continue;
        }
        if fallback::handles(&ext) {
            let tf = fallback::extract_for_ext(&text, &ext);
            emit_ts(&mut wf, &rel, tf, 0, test_file, &text);
            works.push(wf);
            continue;
        }
        // anything else: file node only
        works.push(wf);
    }

    // register symbols (order-independent: every file saw every other)
    for wf in &works {
        for it in &wf.items {
            by_qual.entry(it.label.clone()).or_default().push(it.id.clone());
            if it.kind == NodeKind::Method {
                methods_by_short.entry(it.short.clone()).or_default().push(it.id.clone());
            } else {
                by_short.entry(it.short.clone()).or_default().push(it.id.clone());
            }
            if matches!(it.kind, NodeKind::Struct | NodeKind::Enum | NodeKind::Trait) {
                types_by_short.entry(it.short.clone()).or_default().push(it.id.clone());
            }
        }
    }

    // ---------------- pass 2: edges ----------------
    for wf in &works {
        // calls
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for c in &wf.calls {
            let targets: Vec<String> = match c.qualifier.as_deref() {
                Some("self") | Some("Self") | Some("crate") | Some("super") | Some("this") => {
                    enclosing_type(&wf.items, c.start_byte)
                        .and_then(|t| by_qual.get(&format!("{t}::{}", c.name)))
                        .cloned()
                        .unwrap_or_default()
                }
                Some(q) => by_qual
                    .get(&format!("{}::{}", short_ty(q), c.name))
                    .cloned()
                    .unwrap_or_else(|| {
                        // Qualified miss: an Uppercase qualifier is a *type* —
                        // miss means external (Vec::new, String::new), so no
                        // edge. A lowercase qualifier is a *variable* of
                        // unknown type — same-named methods, INFERRED.
                        let first = q.chars().next().unwrap_or('?');
                        if first.is_uppercase() {
                            Vec::new()
                        } else {
                            methods_by_short.get(&c.name).cloned().unwrap_or_default()
                        }
                    }),
                None => by_short.get(&c.name).cloned().unwrap_or_default(),
            };
            for t in targets {
                if let Some(caller) = enclosing_item(&wf.items, c.start_byte) {
                    if caller.id != t && seen.insert((caller.id.clone(), t.clone())) {
                        edges.push(GraphEdge {
                            from: caller.id.clone(),
                            to: t.clone(),
                            relation: "calls".to_string(),
                            confidence: Confidence::Inferred,
                        });
                    }
                }
                if seen.insert((wf.file_id.clone(), t.clone())) {
                    edges.push(GraphEdge {
                        from: wf.file_id.clone(),
                        to: t.clone(),
                        relation: "calls".to_string(),
                        confidence: Confidence::Inferred,
                    });
                }
            }
        }
        // imports → uses
        for imp in &wf.imports {
            let target = clean_import(imp);
            if target.is_empty() {
                continue;
            }
            edges.push(GraphEdge {
                from: wf.file_id.clone(),
                to: format!("use::{target}"),
                relation: "uses".to_string(),
                confidence: Confidence::Extracted,
            });
        }
        // markdown references (only to indexed files — no dangling ids)
        for target in &wf.md_targets {
            if let Some(fid) = resolve_doc_target(&wf.rel, target, &file_ids) {
                if fid != wf.file_id {
                    edges.push(GraphEdge {
                        from: wf.file_id.clone(),
                        to: fid,
                        relation: "references".to_string(),
                        confidence: Confidence::Extracted,
                    });
                }
            }
        }
        // terraform local sources → directory node + member files
        for (from, src) in &wf.tf_source_dirs {
            let dir = normalize_doc_dir(&wf.rel, src);
            let dir_id = format!("dir::{dir}");
            edges.push(GraphEdge {
                from: from.clone(),
                to: dir_id,
                relation: "module_source".to_string(),
                confidence: Confidence::Extracted,
            });
        }
    }
    // dir nodes for terraform targets (pass 2b: after all file ids known)
    {
        let mut dirs: HashSet<String> = HashSet::new();
        for e in &edges {
            if e.relation == "module_source" && e.to.starts_with("dir::") {
                dirs.insert(e.to.clone());
            }
        }
        for d in dirs {
            let path = d.strip_prefix("dir::").unwrap_or("").to_string();
            nodes.push(GraphNode {
                id: d.clone(),
                label: path.clone(),
                kind: NodeKind::Mod,
                file: path.clone(),
                line: 1,
                community: path.clone(),
                is_test: false,
            });
            // link member files
            for (rel, fid) in &file_ids {
                if rel.starts_with(&format!("{path}/")) {
                    edges.push(GraphEdge {
                        from: d.clone(),
                        to: fid.clone(),
                        relation: "contains".to_string(),
                        confidence: Confidence::Extracted,
                    });
                }
            }
        }
    }

    // method_of + inherits + implements (symbol tables complete)
    let mut tail: Vec<GraphEdge> = Vec::new();
    for wf in &works {
        for it in &wf.items {
            if it.kind == NodeKind::Method {
                if let Some(parent) = &it.parent {
                    if let Some(cands) = types_by_short.get(parent) {
                        if let Some(ty) = cands.first() {
                            tail.push(GraphEdge {
                                from: it.id.clone(),
                                to: ty.clone(),
                                relation: "method_of".to_string(),
                                confidence: Confidence::Extracted,
                            });
                        }
                    }
                }
            }
            for b in &it.bases {
                if let Some(cands) = types_by_short.get(b) {
                    if let Some(ty) = cands.first() {
                        tail.push(GraphEdge {
                            from: it.id.clone(),
                            to: ty.clone(),
                            relation: "inherits".to_string(),
                            confidence: Confidence::Extracted,
                        });
                    }
                }
            }
        }
        for (ty, tr) in &wf.impls {
            let tys = types_by_short.get(ty).and_then(|c| c.first()).cloned();
            let trs = types_by_short
                .get(tr)
                .and_then(|c| c.first())
                .cloned()
                .or_else(|| by_short.get(tr).and_then(|c| c.first()).cloned());
            if let (Some(a), Some(b)) = (tys, trs) {
                tail.push(GraphEdge {
                    from: a,
                    to: b,
                    relation: "implements".to_string(),
                    confidence: Confidence::Extracted,
                });
            }
        }
    }
    edges.extend(tail);

    // item nodes (emitted here so contains/method edges above see final ids)
    for wf in &works {
        for it in &wf.items {
            nodes.push(GraphNode {
                id: it.id.clone(),
                label: it.label.clone(),
                kind: it.kind,
                file: wf.rel.clone(),
                line: it.line,
                community: wf.rel.clone(),
                is_test: it.is_test,
            });
            edges.push(GraphEdge {
                from: wf.file_id.clone(),
                to: it.id.clone(),
                relation: "contains".to_string(),
                confidence: Confidence::Extracted,
            });
        }
    }

    // dedupe edges
    let mut seen = HashSet::new();
    edges.retain(|e| seen.insert((e.from.clone(), e.to.clone(), e.relation.clone())));

    let commit = current_commit(root);
    Graph { version: 1, nodes, edges, built_at_commit: commit }
}

/// Shared item/call/import emission from a TsFile (AST or fallback).
/// `line_off` shifts display lines (vue/svelte script blocks).
#[allow(clippy::too_many_arguments)]
fn emit_ts(
    wf: &mut WorkFile,
    rel: &str,
    tf: crate::graph_ts::TsFile,
    line_off: u32,
    test_file: bool,
    srctext: &str,
) {
    let is_rs = rel.ends_with(".rs");
    let test_lines: HashSet<u32> = if is_rs { rust_test_lines(srctext) } else { HashSet::new() };
    for it in tf.items {
        let mut kind = it.kind;
        let mut is_test = test_file;
        if is_rs && matches!(kind, NodeKind::Fn | NodeKind::Method) && test_lines.contains(&it.line) {
            kind = NodeKind::Test;
            is_test = true;
        }
        if test_file && matches!(kind, NodeKind::Fn | NodeKind::Method) {
            kind = NodeKind::Test;
            is_test = true;
        }
        // python/js `test_*` free functions are tests even outside test files
        if matches!(kind, NodeKind::Fn) && it.name.starts_with("test_") {
            kind = NodeKind::Test;
            is_test = true;
        }
        let id = stable_id(rel, &it.qualified);
        wf.items.push(WorkItem {
            id,
            label: it.qualified.clone(),
            short: it.name.clone(),
            kind,
            line: it.line + line_off,
            start_byte: it.start_byte,
            end_byte: it.end_byte,
            parent: it.parent.clone(),
            bases: it.bases.clone(),
            is_test,
        });
    }
    for c in tf.calls {
        wf.calls.push(WorkCall { start_byte: c.start_byte, qualifier: c.qualifier, name: c.name });
    }
    for i in tf.imports {
        if !i.trim().is_empty() {
            wf.imports.push(i);
        }
    }
    for e in tf.impls {
        wf.impls.push((e.ty, e.tr));
    }
}

/// Enclosing item id for a byte offset (smallest containing def).
fn enclosing_item<'a>(items: &'a [WorkItem], byte: usize) -> Option<&'a WorkItem> {
    let mut best: Option<&WorkItem> = None;
    let mut best_size = usize::MAX;
    for it in items {
        if it.start_byte <= byte && byte < it.end_byte {
            let size = it.end_byte.saturating_sub(it.start_byte);
            if size < best_size {
                best_size = size;
                best = Some(it);
            }
        }
    }
    best
}

/// Enclosing *type* short name (for self/Self calls).
fn enclosing_type(items: &[WorkItem], byte: usize) -> Option<String> {
    let mut best: Option<&WorkItem> = None;
    let mut best_size = usize::MAX;
    for it in items {
        if !matches!(it.kind, NodeKind::Struct | NodeKind::Enum | NodeKind::Trait) {
            continue;
        }
        if it.start_byte <= byte && byte < it.end_byte {
            let size = it.end_byte.saturating_sub(it.start_byte);
            if size < best_size {
                best_size = size;
                best = Some(it);
            }
        }
    }
    best.map(|i| i.short.clone())
}

/// Last-segment qualifier (`a.b.C` / `a::b` → `C` / `b`).
fn short_ty(s: &str) -> String {
    let s = s.split('<').next().unwrap_or(s).trim();
    s.rsplit("::").next().unwrap_or(s).rsplit('.').next().unwrap_or(s).trim().to_string()
}

/// Resolve a markdown link target to an indexed file id, if any.
fn resolve_doc_target(from_rel: &str, target: &str, file_ids: &HashMap<String, String>) -> Option<String> {
    let base = std::path::Path::new(from_rel).parent();
    let joined = base.map(|b| b.join(target)).unwrap_or_else(|| std::path::PathBuf::from(target));
    let norm = normalize_rel(&joined);
    if let Some(id) = file_ids.get(&norm) {
        return Some(id.clone());
    }
    // wikilink or bare name: match by basename
    let base_name = norm.rsplit('/').next().unwrap_or(&norm);
    let mut hits: Vec<&String> = file_ids
        .iter()
        .filter(|(k, _)| k.rsplit('/').next() == Some(base_name) || *k == base_name)
        .map(|(_, v)| v)
        .collect();
    hits.sort();
    hits.first().cloned().cloned()
}

/// Resolve a `./` / `../` terraform source to a repo-relative dir path.
fn normalize_doc_dir(from_rel: &str, src: &str) -> String {
    let base = std::path::Path::new(from_rel).parent();
    let joined = base.map(|b| b.join(src)).unwrap_or_else(|| std::path::PathBuf::from(src));
    normalize_rel(&joined)
}

fn normalize_rel(p: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in p.components() {
        use std::path::Component;
        match c {
            Component::ParentDir => {
                parts.pop();
            }
            Component::CurDir | Component::Prefix(_) | Component::RootDir => {}
            Component::Normal(s) => parts.push(s.to_string_lossy().to_string()),
        }
    }
    parts.join("/")
}

fn rel_path(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .map(|s| s.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| p.to_string_lossy().to_string())
}

fn current_commit(root: &Path) -> String {
    let head = root.join(".git/HEAD");
    let Ok(content) = std::fs::read_to_string(&head) else {
        return String::new();
    };
    let content = content.trim();
    if let Some(refpath) = content.strip_prefix("ref: ") {
        let ref_file = root.join(".git").join(refpath);
        if let Ok(sha) = std::fs::read_to_string(ref_file) {
            return sha.trim().chars().take(8).collect();
        }
    }
    content.chars().take(8).collect()
}

// ---------------------------------------------------------------------------
// Incremental manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    files: HashMap<String, (u64, u64)>,
}

fn file_sig(p: &Path) -> Option<(u64, u64)> {
    let m = std::fs::metadata(p).ok()?;
    let mt = m
        .modified()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((mt, m.len()))
}

/// Returns true when the on-disk corpus changed since the last build.
pub fn needs_rebuild(root: &Path) -> bool {
    let mp = manifest_path(root);
    let Ok(data) = std::fs::read_to_string(&mp) else {
        return true;
    };
    let man: Manifest = match serde_json::from_str(&data) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let files = collect_files(root);
    if files.len() != man.files.len() {
        return true;
    }
    for p in &files {
        let rel = rel_path(root, p);
        match (man.files.get(&rel), file_sig(p)) {
            (Some(&old), Some(new)) if old == new => {}
            _ => return true,
        }
    }
    if !graph_path(root).exists() {
        return true;
    }
    false
}

pub fn write_manifest(root: &Path) {
    let files = collect_files(root);
    let mut m = Manifest::default();
    for p in &files {
        if let Some(sig) = file_sig(p) {
            m.files.insert(rel_path(root, p), sig);
        }
    }
    if let Ok(json) = serde_json::to_string_pretty(&m) {
        let _ = std::fs::write(manifest_path(root), json);
    }
}

// ---------------------------------------------------------------------------
// Persistence + report + offline HTML
// ---------------------------------------------------------------------------

pub fn save(root: &Path, g: &Graph) -> std::io::Result<()> {
    let dir = graph_dir(root);
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(g).unwrap_or_else(|_| "{}".to_string());
    std::fs::write(graph_path(root), json)?;
    write_manifest(root);
    std::fs::write(report_path(root), report(g))?;
    std::fs::write(html_path(root), html(g))?;
    Ok(())
}

pub fn load(root: &Path) -> Result<Graph, String> {
    let data =
        std::fs::read_to_string(graph_path(root)).map_err(|_| "no graph yet — run `voli graph build`".to_string())?;
    serde_json::from_str(&data).map_err(|e| format!("cannot parse graph.json: {e}"))
}

fn report(g: &Graph) -> String {
    let gods = g.god_nodes(10, false);
    let mut communities: HashMap<&str, usize> = HashMap::new();
    for n in &g.nodes {
        *communities.entry(n.community.as_str()).or_default() += 1;
    }
    let mut comms: Vec<(&str, usize)> = communities.into_iter().collect();
    comms.sort_by(|a, b| b.1.cmp(&a.1));
    let extracted = g
        .edges
        .iter()
        .filter(|e| e.confidence == Confidence::Extracted)
        .count();
    let inferred = g.edges.len().saturating_sub(extracted);
    let mut out = format!(
        "# Voli Graph Report\n\n- {} nodes · {} edges · {} files\n- Extraction: {} EXTRACTED · {} INFERRED\n- Commit: {}\n\n## God nodes (tests + files excluded)\n",
        g.nodes.len(),
        g.edges.len(),
        comms.len(),
        extracted,
        inferred,
        if g.built_at_commit.is_empty() {
            "(unknown)"
        } else {
            &g.built_at_commit
        }
    );
    for (i, (n, d)) in gods.iter().enumerate() {
        out.push_str(&format!(
            "{}. `{}` [{}] — {} edges ({}:{})\n",
            i + 1,
            n.label,
            n.kind.as_str(),
            d,
            n.file,
            n.line
        ));
    }
    out.push_str("\n## Largest files\n");
    for (c, n) in comms.iter().take(15) {
        out.push_str(&format!("- `{c}` — {n} symbols\n"));
    }
    out.push_str(
        "\n## Memory hooks\nEach symbol has a stable id (`file::Symbol`) usable as `voli memory note --tags graph:<id>`.\n",
    );
    out
}

/// Offline report page: no CDN, no fetch — JSON inlined, vanilla JS filter.
fn html(g: &Graph) -> String {
    let deg = g.degree();
    let mut rows: Vec<(&GraphNode, usize)> = g.nodes.iter().map(|n| (n, deg.get(n.id.as_str()).copied().unwrap_or(0))).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));
    let mut trs = String::new();
    for (n, d) in rows.iter().take(2000) {
        trs.push_str(&format!(
            "<tr data-q=\"{} {} {} {}\"><td>{}</td><td>{}</td><td>{}:{}</td><td>{}</td><td>{}</td></tr>\n",
            n.label.to_lowercase(),
            n.kind.as_str(),
            n.file.to_lowercase(),
            n.id.to_lowercase(),
            html_esc(&n.label),
            n.kind.as_str(),
            html_esc(&n.file),
            n.line,
            d,
            html_esc(&n.id),
        ));
    }
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
        <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
        <title>voli graph — {nn} nodes</title>\
        <style>body{{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:16px}}\
        input{{width:100%;padding:10px;font-size:15px;margin:12px 0}}\
        table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #333;padding:6px 8px;text-align:left;font-size:13px}}\
        th{{color:#9cf}}.meta{{color:#999}}</style></head><body>\
        <h1>voli graph</h1><p class=\"meta\">{nn} nodes · {ne} edges · commit {cm} · offline, no CDN</p>\
        <input id=\"q\" placeholder=\"filter: type a symbol, file, kind (struct/fn/test)…\" autofocus>\
        <table><thead><tr><th>symbol</th><th>kind</th><th>file:line</th><th>edges</th><th>id (memory tag)</th></tr></thead>\
        <tbody>{trs}</tbody></table>\
        <script>var q=document.getElementById('q');q.addEventListener('input',function(){{\
        var s=q.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(function(r){{\
        r.style.display=r.getAttribute('data-q').includes(s)?'':'none';}});}});</script></body></html>",
        nn = g.nodes.len(),
        ne = g.edges.len(),
        cm = if g.built_at_commit.is_empty() {
            "unknown"
        } else {
            &g.built_at_commit
        },
        trs = trs,
    )
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// Query layer (joins with voli memory via stable ids)
// ---------------------------------------------------------------------------

fn tokens(q: &str) -> Vec<String> {
    q.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| s.len() > 2)
        .map(|s| s.to_string())
        .collect()
}

/// Keyword search + 1-hop expansion, ranked (exact label > file > degree).
/// Test nodes rank last so architecture answers first.
pub fn query<'a>(g: &'a Graph, question: &str, budget: usize) -> Vec<&'a GraphNode> {
    let toks = tokens(question);
    if toks.is_empty() {
        return Vec::new();
    }
    let deg = g.degree();
    let idx = g.node_index();
    let mut score: HashMap<&str, i64> = HashMap::new();
    for n in &g.nodes {
        let label = n.label.to_lowercase();
        let file = n.file.to_lowercase();
        let mut s = 0i64;
        for t in &toks {
            if label == *t || label == format!("{t}()") {
                s += 100;
            } else if label.contains(t) {
                s += 30;
            }
            if file.contains(t) {
                s += 10;
            }
        }
        if s > 0 {
            if n.is_test {
                s -= 25;
            }
            s += (deg.get(n.id.as_str()).copied().unwrap_or(0) as i64).min(20);
            score.insert(n.id.as_str(), s);
        }
    }
    let mut seeds: Vec<&str> = score.keys().copied().collect();
    seeds.sort_by(|a, b| score[b].cmp(&score[a]));
    seeds.truncate(8);
    // 1-hop expansion
    let mut out_ids: Vec<&str> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for s in seeds {
        if seen.insert(s) {
            out_ids.push(s);
        }
        for (e, _) in g.neighbors(s) {
            let other = if e.from == s { e.to.as_str() } else { e.from.as_str() };
            if seen.insert(other) {
                out_ids.push(other);
            }
        }
    }
    let mut out: Vec<&GraphNode> = out_ids
        .iter()
        .filter_map(|id| idx.get(id).map(|&i| &g.nodes[i]))
        .collect();
    out.sort_by(|a, b| score.get(b.id.as_str()).unwrap_or(&0).cmp(score.get(a.id.as_str()).unwrap_or(&0)));
    out.truncate(budget.max(1));
    out
}

pub fn resolve<'a>(g: &'a Graph, symbol: &str) -> Vec<&'a GraphNode> {
    let s = symbol.trim();
    // exact id
    if let Some(n) = g.nodes.iter().find(|n| n.id == s) {
        return vec![n];
    }
    // file::Symbol
    if let Some((f, sym)) = s.split_once("::") {
        let hits: Vec<&GraphNode> = g
            .nodes
            .iter()
            .filter(|n| n.file.contains(f) && (n.label == sym || n.label.ends_with(&format!("::{sym}"))))
            .collect();
        if !hits.is_empty() {
            return hits;
        }
    }
    // bare symbol
    let mut hits: Vec<&GraphNode> = g
        .nodes
        .iter()
        .filter(|n| n.label == s || n.label.ends_with(&format!("::{s}")))
        .collect();
    if hits.is_empty() {
        let lo = s.to_lowercase();
        hits = g
            .nodes
            .iter()
            .filter(|n| n.label.to_lowercase().contains(&lo))
            .collect();
    }
    hits.sort_by(|a, b| {
        (b.is_test.cmp(&a.is_test))
            .then(a.file.cmp(&b.file))
            .then(a.label.cmp(&b.label))
    });
    hits.truncate(12);
    hits
}

/// Stable memory tag for a node, e.g. `graph:crates_voli_core_src_install__install_fs_inner`.
pub fn memory_tag(n: &GraphNode) -> String {
    format!("graph:{}", n.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("voli-graph-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(
            d.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            d.join("src/main.rs"),
            "pub struct Store;\nimpl Store {\n  pub fn fresh() -> Store { Store }\n}\npub fn setup() { let _ = Store::fresh(); }\n",
        )
        .unwrap();
        d
    }

    #[test]
    fn extracts_typed_nodes_and_calls() {
        let root = fixture_root("extract");
        let g = build(&root);
        let labels: Vec<(&str, NodeKind)> =
            g.nodes.iter().map(|n| (n.label.as_str(), n.kind)).collect();
        assert!(labels.contains(&("Store", NodeKind::Struct)));
        assert!(labels.iter().any(|(l, k)| *k == NodeKind::Method && l.contains("fresh")));
        assert!(labels.contains(&("setup", NodeKind::Fn)));
        assert!(g.nodes.iter().any(|n| n.kind == NodeKind::Crate && n.label == "demo"));
        assert!(g.edges.iter().any(|e| e.relation == "calls"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn god_nodes_exclude_files_and_tests_by_default() {
        let root = fixture_root("gods");
        let g = build(&root);
        for (n, _) in g.god_nodes(10, false) {
            assert!(!matches!(n.kind, NodeKind::File | NodeKind::Crate));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn path_falls_back_to_undirected() {
        let root = fixture_root("path");
        let g = build(&root);
        let setup = g.nodes.iter().find(|n| n.label == "setup").unwrap().id.clone();
        let store = g.nodes.iter().find(|n| n.label == "Store").unwrap().id.clone();
        assert!(g.shortest_path(&setup, &store).is_some());
        let _ = std::fs::remove_dir_all(&root);
    }
}
