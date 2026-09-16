//! `voli graph ...`: native code-knowledge graph.
//!
//! Better than graphify's code-only mode on purpose: typed nodes, tests
//! quarantined from god-nodes, Cargo crates always indexed, directed path
//! with automatic undirected fallback, offline HTML, and stable
//! `graph:<id>` tags for `voli memory note`.

use std::path::PathBuf;

use clap::Subcommand;
use voli_core::graph;

#[derive(Subcommand)]
pub enum GraphCmd {
    /// Build (or rebuild) the graph for a codebase.
    Build {
        /// Corpus root (default: current directory).
        path: Option<PathBuf>,
    },
    /// Show node/edge counts, freshness vs git HEAD, and output paths.
    Status {
        /// Corpus root (default: current directory).
        path: Option<PathBuf>,
    },
    /// Keyword search + 1-hop expansion, ranked (tests last).
    Query {
        /// Plain-language question or keywords ("how does install flow work?").
        question: String,
        /// Corpus root (default: current directory).
        #[arg(long)]
        path: Option<PathBuf>,
        /// Max nodes to print.
        #[arg(long, default_value_t = 40)]
        budget: usize,
    },
    /// Shortest path between two symbols (directed first, then undirected).
    Path {
        /// From symbol (id, file::Symbol, or bare name).
        from: String,
        /// To symbol.
        to: String,
        /// Corpus root (default: current directory).
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Explain one symbol: kind, location, neighbors, memory tag.
    Explain {
        /// Symbol (id, file::Symbol, or bare name).
        symbol: String,
        /// Corpus root (default: current directory).
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Most-connected symbols (files, crates, tests excluded by default).
    Gods {
        /// Corpus root (default: current directory).
        #[arg(long)]
        path: Option<PathBuf>,
        /// How many to show.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Include test nodes in the ranking.
        #[arg(long)]
        include_tests: bool,
    },
}

fn root_of(arg: Option<PathBuf>) -> PathBuf {
    arg.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

pub fn run(cmd: &GraphCmd, json: bool) -> i32 {
    match cmd {
        GraphCmd::Build { path } => {
            let root = root_of(path.clone());
            if !graph::needs_rebuild(&root) && graph::graph_path(&root).exists() {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"ok": true, "cached": true, "dir": graph::graph_dir(&root)})
                    );
                } else {
                    println!("graph is fresh — nothing to rebuild");
                    println!("  dir: {}", graph::graph_dir(&root).display());
                }
                return 0;
            }
            let g = graph::build(&root);
            match graph::save(&root, &g) {
                Ok(()) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "ok": true, "cached": false,
                                "nodes": g.nodes.len(), "edges": g.edges.len(),
                                "dir": graph::graph_dir(&root),
                            })
                        );
                    } else {
                        println!(
                            "built graph: {} nodes · {} edges",
                            g.nodes.len(),
                            g.edges.len()
                        );
                        println!("  graph:  {}", graph::graph_path(&root).display());
                        println!("  report: {}", graph::report_path(&root).display());
                        println!("  html:   {}", graph::html_path(&root).display());
                        println!("  open the html in a browser — fully offline, no CDN.");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("error: cannot save graph: {e}");
                    1
                }
            }
        }
        GraphCmd::Status { path } => {
            let root = root_of(path.clone());
            match graph::load(&root) {
                Ok(g) => {
                    let stale = graph::needs_rebuild(&root);
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "nodes": g.nodes.len(), "edges": g.edges.len(),
                                "commit": g.built_at_commit,
                                "stale": stale,
                                "dir": graph::graph_dir(&root),
                            })
                        );
                    } else {
                        println!(
                            "graph: {} nodes · {} edges · commit {}",
                            g.nodes.len(),
                            g.edges.len(),
                            if g.built_at_commit.is_empty() {
                                "(unknown)"
                            } else {
                                &g.built_at_commit
                            }
                        );
                        println!(
                            "  {}",
                            if stale {
                                "stale — run `voli graph build`"
                            } else {
                                "fresh"
                            }
                        );
                        println!("  dir: {}", graph::graph_dir(&root).display());
                    }
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        GraphCmd::Query {
            question,
            path,
            budget,
        } => {
            let root = root_of(path.clone());
            let g = match graph::load(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let hits = graph::query(&g, question, *budget);
            if json {
                let arr: Vec<_> = hits
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "id": n.id, "label": n.label, "kind": n.kind.as_str(),
                            "file": n.file, "line": n.line,
                            "memory_tag": graph::memory_tag(n),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
            } else if hits.is_empty() {
                println!("no matches — try fewer keywords or run `voli graph build` first");
            } else {
                for n in &hits {
                    println!(
                        "{} [{}] {}:{}  {}",
                        n.label,
                        n.kind.as_str(),
                        n.file,
                        n.line,
                        graph::memory_tag(n)
                    );
                }
            }
            0
        }
        GraphCmd::Path { from, to, path } => {
            let root = root_of(path.clone());
            let g = match graph::load(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let af = graph::resolve(&g, from);
            let bf = graph::resolve(&g, to);
            if af.is_empty() || bf.is_empty() {
                eprintln!("error: symbol not found (try `voli graph explain <name>`)");
                return 1;
            }
            // best pair: first hit each (resolve already ranks exact > fuzzy,
            // non-test first).
            let (a, b) = (af[0], bf[0]);
            match g.shortest_path(&a.id, &b.id) {
                Some((ids, directed)) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "from": a.id, "to": b.id,
                                "directed": directed, "path": ids,
                            })
                        );
                    } else {
                        println!(
                            "path ({} hops, {}):",
                            ids.len().saturating_sub(1),
                            if directed { "directed" } else { "undirected fallback" }
                        );
                        for id in &ids {
                            if let Some(n) = g.nodes.iter().find(|n| &n.id == id) {
                                println!("  {} [{}] {}:{}", n.label, n.kind.as_str(), n.file, n.line);
                            } else {
                                println!("  {id}");
                            }
                        }
                    }
                    0
                }
                None => {
                    eprintln!("error: no path between '{}' and '{}'", a.label, b.label);
                    1
                }
            }
        }
        GraphCmd::Explain { symbol, path } => {
            let root = root_of(path.clone());
            let g = match graph::load(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let hits = graph::resolve(&g, symbol);
            if hits.is_empty() {
                eprintln!("error: no symbol matching '{symbol}'");
                return 1;
            }
            if hits.len() > 1 && hits.iter().all(|n| n.id != *symbol) {
                // ambiguous bare name — list candidates, then explain the best.
                if !json {
                    println!("{} candidates — showing best, refine with file::Symbol:\n", hits.len());
                    for n in &hits {
                        println!("  {} [{}] {}:{}", n.label, n.kind.as_str(), n.file, n.line);
                    }
                    println!();
                }
            }
            let n = hits[0];
            let nb = g.neighbors(&n.id);
            if json {
                let arr: Vec<_> = nb
                    .iter()
                    .map(|(e, m)| {
                        serde_json::json!({
                            "relation": e.relation, "confidence": e.confidence,
                            "label": m.label, "kind": m.kind.as_str(),
                            "file": m.file, "line": m.line, "id": m.id,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "id": n.id, "label": n.label, "kind": n.kind.as_str(),
                        "file": n.file, "line": n.line,
                        "memory_tag": graph::memory_tag(n),
                        "degree": nb.len(), "neighbors": arr,
                    }))
                    .unwrap()
                );
            } else {
                println!("{} [{}] {}:{}", n.label, n.kind.as_str(), n.file, n.line);
                println!("  id: {}", n.id);
                println!("  memory: voli memory note \"...\" --tags {}", graph::memory_tag(n));
                println!("  {} neighbor(s):", nb.len());
                for (e, m) in nb.iter().take(30) {
                    let dir = if e.from == n.id { "-->" } else { "<--" };
                    println!(
                        "  {dir} {} [{}] {}:{} {:?}",
                        m.label,
                        m.kind.as_str(),
                        m.file,
                        m.line,
                        e.relation
                    );
                }
                if nb.len() > 30 {
                    println!("  ... and {} more (use --json)", nb.len() - 30);
                }
            }
            0
        }
        GraphCmd::Gods {
            path,
            top,
            include_tests,
        } => {
            let root = root_of(path.clone());
            let g = match graph::load(&root) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            };
            let gods = g.god_nodes(*top, *include_tests);
            if json {
                let arr: Vec<_> = gods
                    .iter()
                    .map(|(n, d)| {
                        serde_json::json!({
                            "label": n.label, "kind": n.kind.as_str(),
                            "file": n.file, "line": n.line,
                            "degree": d, "id": n.id,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
            } else {
                for (i, (n, d)) in gods.iter().enumerate() {
                    println!(
                        "{}. {} [{}] — {} edges ({}:{})",
                        i + 1,
                        n.label,
                        n.kind.as_str(),
                        d,
                        n.file,
                        n.line
                    );
                }
            }
            0
        }
    }
}
