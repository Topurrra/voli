//! Regex fallback extractor for languages without a tree-sitter grammar in
//! `voli graph` (swift, kotlin, elixir, haskell, lua, apex, robot, dreammaker,
//! plus degraded-tree fallback for any AST language).
//!
//! Deliberately weaker than the AST path: definitions by keyword, calls by
//! bare `name(` attributed to the enclosing def. Every edge from here is
//! `INFERRED` except `contains`. When a grammar lands, the language moves to
//! graph_ts and this file shrinks.

use std::sync::OnceLock;

use regex::Regex;

use super::graph::NodeKind;
use super::graph_ts::{TsCall, TsFile, TsItem};

/// Extensions handled here (ts/extra modules route here on parse failure too).
pub fn handles(ext: &str) -> bool {
    matches!(
        ext,
        "swift"
            | "kt"
            | "kts"
            | "ex"
            | "exs"
            | "hs"
            | "lhs"
            | "lua"
            | "luau"
            | "toc"
            | "vue"
            | "svelte"
            | "astro"
            | "cls"
            | "trigger"
            | "robot"
            | "resource"
            | "dm"
            | "dme"
            | "dmi"
            | "dmm"
            | "dmf"
            | "r"
            | "pl"
            | "pm"
            | "elm"
            | "erl"
            | "hrl"
            | "groovy" // groovy has AST; listed for degraded-tree fallback
            | "rs" // rust AST fallback when the tree is broken
            | "py"
            | "js"
            | "ts"
            | "go"
            | "java"
            | "c"
            | "cpp"
    )
}

struct Pats {
    class: Regex,
    func: Regex,
    haskell_sig: Regex,
    erlang_clause: Regex,
    r_assign: Regex,
    trigger: Regex,
    robot_header: Regex,
    robot_case: Regex,
    call: Regex,
}

fn pats() -> &'static Pats {
    static PATS: OnceLock<Pats> = OnceLock::new();
    PATS.get_or_init(|| Pats {
        class: Regex::new(
            r"^\s*(?:pub(?:\([^)]*\))?\s+|local\s+|export\s+|open\s+|global\s+|private\s+|protected\s+|shared\s+)*(?:class|interface|trait|struct|enum|object|module|type|data|newtype)\s+([A-Za-z_][A-Za-z0-9_.]*)",
        )
        .unwrap(),
        // Def keywords are MANDATORY — a bare `foo(` line is a call, not a def.
        func: Regex::new(
            r"^\s*(?:pub(?:\([^)]*\))?\s+|local\s+|static\s+|async\s+|export\s+|open\s+|override\s+|global\s+|private\s+|protected\s+)*(?:function|fun|fn|def|sub|procedure|macro)\s+([A-Za-z_][A-Za-z0-9_.:?!]*)",
        )
        .unwrap(),
        haskell_sig: Regex::new(r"^([a-z_][A-Za-z0-9_']*)\s*::").unwrap(),
        erlang_clause: Regex::new(r"^([a-z_][A-Za-z0-9_]*)\s*\(").unwrap(),
        r_assign: Regex::new(r"^\s*([A-Za-z_.][A-Za-z0-9_.]*)\s*<-\s*function").unwrap(),
        trigger: Regex::new(r"^\s*trigger\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
        robot_header: Regex::new(r"^\s*\*\*\*\s*(.+?)\s*\*\*\*\s*$").unwrap(),
        robot_case: Regex::new(r"^([A-Z][A-Za-z0-9_ ][^:]*)$").unwrap(),
        call: Regex::new(r"\b([A-Za-z_][A-Za-z0-9_?!]*)\s*\(").unwrap(),
    })
}

/// Extract defs + calls from `text`. Byte ranges are derived from line
/// offsets so the shared edge emitter works unchanged.
pub fn extract(text: &str) -> TsFile {
    extract_for_ext(text, "")
}

/// Same, with extension-specific shapes (`ext` may be empty).
pub fn extract_for_ext(text: &str, ext: &str) -> TsFile {
    let p = pats();
    let mut out = TsFile::default();
    // line start offsets for byte conversion
    let mut starts: Vec<usize> = vec![0];
    for (i, ch) in text.char_indices() {
        if ch == '\n' {
            starts.push(i + 1);
        }
    }
    let offset = |line: usize| -> usize { starts.get(line).copied().unwrap_or(text.len()) };

    struct Raw {
        name: String,
        kind: NodeKind,
        line0: usize,
    }
    let mut raws: Vec<Raw> = Vec::new();
    let mut in_robot_cases = false;
    for (i, line) in text.lines().enumerate() {
        if ext == "robot" || ext == "resource" {
            if let Some(h) = p.robot_header.captures(line) {
                in_robot_cases = h[1].to_lowercase().contains("test case");
                continue;
            }
            if in_robot_cases && p.robot_case.is_match(line) && !line.starts_with(' ') && !line.starts_with('\t') {
                raws.push(Raw { name: line.trim().to_string(), kind: NodeKind::Test, line0: i });
                continue;
            }
        }
        if let Some(c) = p.class.captures(line) {
            raws.push(Raw { name: c[1].to_string(), kind: NodeKind::Struct, line0: i });
        } else if let Some(c) = p.func.captures(line) {
            let name = c[1].to_string();
            if !name.is_empty() && name.len() < 80 {
                raws.push(Raw { name, kind: NodeKind::Fn, line0: i });
            }
        } else if let Some(c) = p.trigger.captures(line) {
            raws.push(Raw { name: c[1].to_string(), kind: NodeKind::Struct, line0: i });
        } else if (ext == "hs" || ext == "lhs") && p.haskell_sig.captures(line).is_some() {
            let c = p.haskell_sig.captures(line).unwrap();
            raws.push(Raw { name: c[1].to_string(), kind: NodeKind::Fn, line0: i });
        } else if (ext == "erl" || ext == "hrl") && p.erlang_clause.captures(line).is_some() {
            let c = p.erlang_clause.captures(line).unwrap();
            raws.push(Raw { name: c[1].to_string(), kind: NodeKind::Fn, line0: i });
        } else if ext == "r" && p.r_assign.captures(line).is_some() {
            let c = p.r_assign.captures(line).unwrap();
            raws.push(Raw { name: c[1].to_string(), kind: NodeKind::Fn, line0: i });
        }
    }
    // fn inside class range → method (same rule as the AST path)
    for (idx, r) in raws.iter().enumerate() {
        let mut parent: Option<String> = None;
        if r.kind == NodeKind::Fn {
            let indent_of = |l: usize| -> usize {
                text.lines().nth(l).map(|s| s.len() - s.trim_start().len()).unwrap_or(0)
            };
            let my_indent = indent_of(r.line0);
            for prev in raws[..idx].iter().rev() {
                if prev.kind == NodeKind::Struct && indent_of(prev.line0) < my_indent {
                    parent = Some(short(&prev.name));
                    break;
                }
            }
        }
        let (kind, qualified) = match &parent {
            Some(pn) => (NodeKind::Method, format!("{pn}::{}", r.name)),
            None => (r.kind, r.name.clone()),
        };
        let end_line = raws
            .get(idx + 1)
            .map(|n| n.line0)
            .unwrap_or_else(|| text.lines().count());
        out.items.push(TsItem {
            kind,
            name: r.name.clone(),
            qualified,
            start_byte: offset(r.line0),
            end_byte: offset(end_line),
            line: (r.line0 + 1) as u32,
            parent,
            bases: Vec::new(),
            is_test: false,
        });
    }

    // calls attributed to enclosing item by byte
    for (i, line) in text.lines().enumerate() {
        // skip the def line's own name
        let defined = raws.iter().find(|r| r.line0 == i).map(|r| r.name.clone());
        for cap in p.call.captures_iter(line) {
            let name = cap[1].to_string();
            if defined.as_deref() == Some(name.as_str()) {
                continue;
            }
            if name.len() > 80 {
                continue;
            }
            out.calls.push(TsCall {
                start_byte: offset(i),
                qualifier: None,
                name,
            });
        }
    }
    out
}

fn short(s: &str) -> String {
    s.rsplit('.').next().unwrap_or(s).rsplit("::").next().unwrap_or(s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kotlin_class_and_fun() {
        let f = extract_for_ext("class Store {\n  fun fresh(): Store = Store()\n}\n", "kt");
        assert!(f.items.iter().any(|i| i.name == "Store"), "{:?}", f.items);
        assert!(f.items.iter().any(|i| i.qualified == "Store::fresh"), "{:?}", f.items);
    }

    #[test]
    fn swift_struct_func() {
        let f = extract_for_ext("struct Store {\n  func fresh() {}\n}\n", "swift");
        assert!(f.items.iter().any(|i| i.name == "Store"), "{:?}", f.items);
    }

    #[test]
    fn lua_local_function() {
        let f = extract_for_ext("local function fresh()\nend\n", "lua");
        assert!(f.items.iter().any(|i| i.name == "fresh"), "{:?}", f.items);
    }

    #[test]
    fn calls_are_not_defs() {
        let f = extract_for_ext("x = foo(1)\nbar(2)\n", "r");
        assert!(f.items.is_empty(), "{:?}", f.items);
        assert_eq!(f.calls.len(), 2);
    }

    #[test]
    fn robot_cases_are_tests() {
        let f = extract_for_ext("*** Test Cases ***\nLogin works\n  Click  ok\n", "robot");
        assert!(f.items.iter().any(|i| i.name == "Login works" && i.kind == NodeKind::Test), "{:?}", f.items);
    }
}
