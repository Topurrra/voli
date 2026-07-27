//! Offline contradiction detection — PROPOSE, never destroy.
//!
//! Ported from the KeepItLocal memory engine (`contradiction.rs`), with the one
//! key adaptation for stela: candidates are blocked with **BM25** (stela's
//! retrieval), not embedding cosine — stela has no embeddings. On a new `note`,
//! the [`HeuristicClassifier`] runs against the BM25-nearest live memories, and a
//! [`Relation::Contradiction`] is surfaced to the user (advisory + reversible: the
//! note is still saved; the user decides whether to `--supersedes` the conflict).
//!
//! ## Temporal gating (why item 3 comes first)
//!
//! Two facts with DISJOINT validity windows are *history*, not a contradiction —
//! "lived in Lisbon `[2019, 2022)`" then "lives in Berlin `[2022, ∞)`" were each
//! true in their own era. [`windows_overlap`] gates them out, so the classifier
//! only ever judges facts that claim to be true at the same time.
//!
//! The classifier is intentionally crude (lexical, not semantic) — deterministic,
//! no model, no network, runs in CI. A real NLI model would be the upgrade behind
//! the same seam, unchanged otherwise.
//
// ponytail: a single free `classify` + `HeuristicClassifier` unit struct, not the
// `trait ContradictionClassifier` seam the source carries. One implementation ⇒ no
// trait; add the seam when a real NLI plugin actually arrives.

use std::collections::HashSet;

/// NLI-style relation between two statements `a` (the new fact) and `b` (an
/// existing neighbor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// `a` implies / restates `b` (they agree).
    Entailment,
    /// No strong logical relation.
    Neutral,
    /// `a` and `b` cannot both be true (a conflict).
    Contradiction,
}

// --- heuristic tunables ----------------------------------------------------
/// Subject overlap (Jaccard of content tokens) below this ⇒ the two statements
/// aren't about the same thing, so neither entailment nor contradiction applies.
const MIN_SUBJECT_OVERLAP: f64 = 0.2;
/// Token overlap at/above this with NO conflict cue ⇒ entailment (a restatement).
const ENTAIL_OVERLAP: f64 = 0.6;

/// Negation cues; presence in exactly ONE side flips an otherwise-agreeing pair.
const NEGATIONS: &[&str] = &["not", "never", "no", "none", "n't", "cannot", "false"];

/// Antonym / mutually-exclusive pairs. One side carries one, the other the other.
const ANTONYMS: &[(&str, &str)] = &[
    ("likes", "hates"),
    ("likes", "dislikes"),
    ("loves", "hates"),
    ("love", "hate"),
    ("on", "off"),
    ("open", "closed"),
    ("true", "false"),
    ("yes", "no"),
    ("married", "single"),
    ("alive", "dead"),
];

/// The built-in offline classifier — no model, no network, deterministic.
pub struct HeuristicClassifier;

impl HeuristicClassifier {
    /// Classify the relation between `a` (new fact) and `b` (existing neighbor).
    pub fn classify(&self, a: &str, b: &str) -> Relation {
        classify(a, b)
    }
}

/// Lowercase alphanumeric tokens, length ≥ 2 (drops "a"/"i"/punctuation noise).
fn tokens(s: &str) -> HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// Jaccard overlap of two token sets (0.0 when either is empty).
fn overlap(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    inter as f64 / union as f64
}

/// Does the lowercased text carry a negation cue? Short cues are matched on word
/// boundaries so "now"/"nope" don't count as "no"; "n't"/"cannot" are substrings.
fn has_negation(lower: &str) -> bool {
    NEGATIONS.iter().any(|n| match *n {
        "no" | "not" | "none" | "never" | "false" => {
            lower.split(|c: char| !c.is_alphanumeric()).any(|w| w == *n)
        }
        other => lower.contains(other),
    })
}

/// The heuristic. Same subject (enough token overlap) is required first; then a
/// negation-in-exactly-one-side, an antonym across the two sides, or a
/// changed-salient-value (high-but-partial overlap, each side with a private
/// token) ⇒ [`Relation::Contradiction`]; high overlap with no cue ⇒
/// [`Relation::Entailment`]; low overlap ⇒ [`Relation::Neutral`].
pub fn classify(a: &str, b: &str) -> Relation {
    let (la, lb) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    let (ta, tb) = (tokens(a), tokens(b));
    let ov = overlap(&ta, &tb);

    if ov < MIN_SUBJECT_OVERLAP {
        return Relation::Neutral; // different subjects
    }
    // Polarity conflict: negation present in exactly one side.
    if has_negation(&la) != has_negation(&lb) {
        return Relation::Contradiction;
    }
    // Antonym across the two sides.
    for (x, y) in ANTONYMS {
        let a_has = ta.contains(*x) || ta.contains(*y);
        let b_has = tb.contains(*x) || tb.contains(*y);
        let opposite = (ta.contains(*x) && tb.contains(*y)) || (ta.contains(*y) && tb.contains(*x));
        if a_has && b_has && opposite {
            return Relation::Contradiction;
        }
    }
    // Same subject, no negation/antonym: changed value? High-but-partial overlap
    // with each side carrying a distinct salient token ("berlin" vs "lisbon").
    let only_a = ta.difference(&tb).count();
    let only_b = tb.difference(&ta).count();
    if only_a >= 1 && only_b >= 1 && ov < ENTAIL_OVERLAP {
        return Relation::Contradiction;
    }
    if ov >= ENTAIL_OVERLAP {
        Relation::Entailment
    } else {
        Relation::Neutral
    }
}

/// Do two validity windows `[valid_from, valid_until)` OVERLAP? Disjoint windows
/// are history (each fact true in its own era), not a contradiction. `None`
/// `valid_until` = still valid (open-ended → +∞). Half-open, so touching at a
/// point (`a_until == b_from`) does NOT overlap.
pub fn windows_overlap(
    a_from: i64,
    a_until: Option<i64>,
    b_from: i64,
    b_until: Option<i64>,
) -> bool {
    let a_ends_first = a_until.is_some_and(|u| u <= b_from);
    let b_ends_first = b_until.is_some_and(|u| u <= a_from);
    !(a_ends_first || b_ends_first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negation_one_side_is_contradiction() {
        assert_eq!(
            classify("I eat meat", "I do not eat meat"),
            Relation::Contradiction
        );
    }

    #[test]
    fn changed_value_same_subject_is_contradiction() {
        assert_eq!(
            classify("I live in Berlin", "I live in Lisbon"),
            Relation::Contradiction
        );
        assert_eq!(
            classify("I prefer tabs", "I prefer spaces"),
            Relation::Contradiction
        );
    }

    #[test]
    fn antonym_is_contradiction() {
        assert_eq!(
            classify("she likes coffee", "she hates coffee"),
            Relation::Contradiction
        );
    }

    #[test]
    fn restatement_is_entailment() {
        assert_eq!(
            classify("I live in Berlin now", "I live in Berlin"),
            Relation::Entailment
        );
    }

    #[test]
    fn unrelated_is_neutral() {
        assert_eq!(
            classify("I live in Berlin", "the weather is cold"),
            Relation::Neutral
        );
    }

    #[test]
    fn disjoint_windows_do_not_overlap() {
        // [0, 100) and [100, ∞) touch at a point → disjoint (half-open).
        assert!(!windows_overlap(0, Some(100), 100, None));
        // [0, 100) and [50, ∞) overlap on [50, 100).
        assert!(windows_overlap(0, Some(100), 50, None));
        // Both open-ended → always overlap.
        assert!(windows_overlap(0, None, 5, None));
    }
}
