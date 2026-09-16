//! Louvain community detection for `voli graph`.
//!
//! Deterministic by construction: nodes visit in index order, ties break by
//! lowest community id, no RNG anywhere. Same graph → same clusters, so
//! `REPORT.md` diffs stay meaningful and tests can pin results.
//!
//! Runs on the undirected projection, ignoring dangling pseudo-targets
//! (`use::…`, `docker::…`) — hubs with no node record would otherwise glue
//! unrelated subsystems together.

use std::collections::HashMap;

/// Detect communities. `n` nodes, `edges` undirected pairs (may repeat;
/// multiplicities become weights). Returns community id per node index —
/// ids are compacted 0..k in first-seen order.
pub fn louvain(n: usize, edges: &[(usize, usize)]) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    // adjacency: node -> (neighbor -> weight)
    let mut adj: Vec<HashMap<usize, f64>> = (0..n).map(|_| HashMap::new()).collect();
    let mut degree = vec![0.0f64; n];
    let mut total = 0.0;
    for &(a, b) in edges {
        if a >= n || b >= n || a == b {
            continue;
        }
        *adj[a].entry(b).or_default() += 1.0;
        if a != b {
            *adj[b].entry(a).or_default() += 1.0;
        }
        degree[a] += 1.0;
        degree[b] += 1.0;
        total += 2.0;
    }
    if total == 0.0 {
        return (0..n).collect(); // edgeless: every node its own community
    }

    let mut comm: Vec<usize> = (0..n).collect();
    let mut comm_deg = degree.clone();

    // Phase 1 passes until no move (cap: deterministic, still terminates).
    for _ in 0..20 {
        let mut moved = false;
        for v in 0..n {
            // weight to each neighboring community (incl. own)
            let mut to_comm: HashMap<usize, f64> = HashMap::new();
            for (&u, &w) in &adj[v] {
                *to_comm.entry(comm[u]).or_default() += w;
            }
            let cur = comm[v];
            let kv = degree[v];
            // gain of moving v from cur to c:
            // ΔQ = (k(v→c) - k(v→cur∖v)) / m - kv * (Σc - Σcur + kv) / m²
            // (m = total/2; use 2m = total consistently)
            let mut best_c = cur;
            let mut best_gain = 0.0;
            let mut cands: Vec<usize> = to_comm.keys().copied().collect();
            cands.sort_unstable();
            for c in cands {
                if c == cur {
                    continue;
                }
                let kin_c = to_comm[&c];
                let kin_cur = to_comm.get(&cur).copied().unwrap_or(0.0);
                let gain = (kin_c - kin_cur) / total
                    - kv * (comm_deg[c] - comm_deg[cur] + kv) / (total * total);
                if gain > best_gain + 1e-12 {
                    best_gain = gain;
                    best_c = c;
                }
            }
            if best_c != cur {
                comm_deg[cur] -= kv;
                comm_deg[best_c] += kv;
                comm[v] = best_c;
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }

    // Compact ids in first-seen order.
    let mut remap: HashMap<usize, usize> = HashMap::new();
    let mut next = 0;
    comm.iter()
        .map(|c| {
            *remap.entry(*c).or_insert_with(|| {
                let id = next;
                next += 1;
                id
            })
        })
        .collect()
}

/// Hierarchical Louvain: one round of aggregation + a second phase-1 pass on
/// the contracted graph, for coarser clusters on large graphs. Returns final
/// labels; deterministic like [`louvain`].
pub fn louvain2(n: usize, edges: &[(usize, usize)]) -> Vec<usize> {
    let first = louvain(n, edges);
    let k = first.iter().copied().max().map(|m| m + 1).unwrap_or(0);
    if k <= 1 || k == n {
        return first;
    }
    // contract: super-edge weights between first-level communities
    let mut super_edges: Vec<(usize, usize)> = Vec::new();
    for &(a, b) in edges {
        if a < n && b < n {
            super_edges.push((first[a], first[b]));
        }
    }
    let second = louvain(k, &super_edges);
    first.iter().map(|c| second[*c]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_cliques_split() {
        // two triangles joined by one edge → two communities
        let edges = vec![(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3), (2, 3)];
        let c = louvain(6, &edges);
        assert_eq!(c[0], c[1]);
        assert_eq!(c[1], c[2]);
        assert_eq!(c[3], c[4]);
        assert_eq!(c[4], c[5]);
        assert_ne!(c[0], c[3]);
    }

    #[test]
    fn deterministic_and_edgeless() {
        let edges = vec![(0, 1), (1, 2), (2, 0)];
        assert_eq!(louvain(3, &edges), louvain(3, &edges));
        assert_eq!(louvain(3, &[]), vec![0, 1, 2]);
    }

    #[test]
    fn hierarchy_coarsens() {
        let edges = vec![(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3), (2, 3)];
        let c = louvain2(6, &edges);
        assert_eq!(c[0], c[2]);
        assert_eq!(c[3], c[5]);
    }
}
