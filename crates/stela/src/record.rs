//! Fixed-width plaintext log records: pack, unpack, the blake2b hash chain, and
//! BM25 retrieval.
//!
//! One record is a fixed-width line:
//!
//! ```text
//! seq(8) ts(20) kind(4) conf(3) sup(20) src(16) method(12) tags(32) hash(16) text…
//! ```
//!
//! then ASCII-space padding and one `\n` to exactly [`LOG_P`] bytes. Padding is
//! pure ASCII, so a record boundary never splits a multi-byte codepoint. `src`
//! and `method` are the **provenance** fields (added over STELA).
//!
//! The hash chains each record to the previous one, so any edit to any past
//! record breaks every hash after it. To fix STELA's tag-truncation false-tamper
//! bug, tags are capped on **token boundaries** ([`join_capped`]) so the stored
//! field never has a dangling comma, and [`recompute_hash`] hashes the **stored
//! body bytes** verbatim rather than a reconstruction.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use blake2::digest::consts::U8;
use blake2::{Blake2b, Digest};
use regex::Regex;

use crate::{
    ENTRY_BYTES, LOG_P, Result, W_CONF, W_HASH, W_KIND, W_METHOD, W_SEQ, W_SRC, W_SUP, W_TAGS,
    W_TS, W_VFROM, W_VUNTIL, msg,
};

type Blake2b8 = Blake2b<U8>;

// Byte offsets, derived from the field widths (single-space separators).
const O_SEQ: usize = 0;
const O_TS: usize = O_SEQ + W_SEQ + 1;
const O_KIND: usize = O_TS + W_TS + 1;
const O_CONF: usize = O_KIND + W_KIND + 1;
const O_SUP: usize = O_CONF + W_CONF + 1;
const O_SRC: usize = O_SUP + W_SUP + 1;
const O_METHOD: usize = O_SRC + W_SRC + 1;
const O_TAGS: usize = O_METHOD + W_METHOD + 1;
const O_VFROM: usize = O_TAGS + W_TAGS + 1;
const O_VUNTIL: usize = O_VFROM + W_VFROM + 1;
/// The body region `[0, BODY_LEN)` — everything the hash covers except `text`.
const BODY_LEN: usize = O_VUNTIL + W_VUNTIL;
const O_HASH: usize = BODY_LEN + 1;
const O_TEXT: usize = O_HASH + W_HASH + 1;

/// One parsed memory. `stale` is filled by supersession resolution, not the file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Record {
    pub dev: String,
    pub seq: u64,
    pub ts: String,
    pub kind: String,
    pub conf: u32,
    /// The memory this one supersedes (`"dev:seq"`), or `"-"`.
    pub sup: String,
    /// Provenance: where the memory came from (e.g. `user`, `agent`, `import`).
    pub src: String,
    /// Provenance: how it was captured (e.g. `note`, `retract`).
    pub method: String,
    pub tags: Vec<String>,
    /// Valid-time lower bound (unix millis). `0` = unbounded (true since forever).
    pub valid_from: i64,
    /// Valid-time upper bound (unix millis, half-open). `None` = still valid.
    pub valid_until: Option<i64>,
    pub hash: String,
    pub text: String,
    pub stale: bool,
}

impl Record {
    /// The global id `"dev:seq"`.
    pub fn id(&self) -> String {
        format!("{}:{}", self.dev, self.seq)
    }
}

/// Truncate `s` to at most `width` bytes on a char boundary, then pad with ASCII
/// spaces to exactly `width` bytes. The result is always valid UTF-8.
pub(crate) fn fixed_field(s: &str, width: usize) -> String {
    let mut end = s.len().min(width);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(width);
    out.push_str(&s[..end]);
    while out.len() < width {
        out.push(' ');
    }
    out
}

/// Join tags with commas while they fit `width` bytes, dropping the rest. Never
/// leaves a partial token or a trailing comma — the fix for the false-tamper bug.
pub(crate) fn join_capped(tags: &[String], width: usize) -> String {
    let mut acc = String::new();
    for tag in tags {
        let piece_len = tag.len() + usize::from(!acc.is_empty());
        if acc.len() + piece_len > width {
            break;
        }
        if !acc.is_empty() {
            acc.push(',');
        }
        acc.push_str(tag);
    }
    acc
}

/// Encode and pad `text` to exactly `rec` bytes: UTF-8 bytes, ASCII spaces, `\n`.
pub(crate) fn pad(text: &str, rec: usize) -> Result<Vec<u8>> {
    let b = text.as_bytes();
    if b.len() > rec - 1 {
        return msg(format!(
            "record too long: {} bytes, max {}",
            b.len(),
            rec - 1
        ));
    }
    let mut out = Vec::with_capacity(rec);
    out.extend_from_slice(b);
    out.resize(rec - 1, b' ');
    out.push(b'\n');
    Ok(out)
}

fn chain_hash(prev_hash: &str, body: &[u8], text: &[u8]) -> String {
    let mut h = Blake2b8::new();
    h.update(prev_hash.as_bytes());
    h.update(body);
    h.update(text);
    hex::encode(h.finalize())
}

/// Build one fixed-width plaintext log record (`LOG_P` bytes). `text` must be
/// pre-sanitized and within [`ENTRY_BYTES`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn pack_log(
    seq: u64,
    ts: &str,
    kind: &str,
    conf: u32,
    tags: &[String],
    sup: &str,
    src: &str,
    method: &str,
    valid_from: i64,
    valid_until: Option<i64>,
    prev_hash: &str,
    text: &str,
) -> Result<Vec<u8>> {
    if text.len() > ENTRY_BYTES {
        return msg(format!(
            "memory is {} bytes; the limit is {ENTRY_BYTES}. Compress it.",
            text.len()
        ));
    }
    let ts_f = fixed_field(ts, W_TS);
    let kind_f = fixed_field(kind, W_KIND);
    let sup_f = fixed_field(sup, W_SUP);
    let src_f = fixed_field(src, W_SRC);
    let method_f = fixed_field(method, W_METHOD);
    let tags_f = fixed_field(&join_capped(tags, W_TAGS), W_TAGS);
    let vfrom_f = fixed_field(&valid_from.max(0).to_string(), W_VFROM);
    let vuntil_f = fixed_field(
        &valid_until
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        W_VUNTIL,
    );
    let conf = conf.min(100);
    let body = format!(
        "{seq:08} {ts_f} {kind_f} {conf:03} {sup_f} {src_f} {method_f} {tags_f} {vfrom_f} {vuntil_f}"
    );
    debug_assert_eq!(body.len(), BODY_LEN, "record body width drifted");
    let hash = chain_hash(prev_hash, body.as_bytes(), text.as_bytes());
    let line = format!("{body} {hash} {text}");
    pad(&line, LOG_P)
}

/// Parse one plaintext record. Returns `None` for a blank/torn record rather than
/// erroring: a damaged tail must never take down a whole session.
pub(crate) fn unpack_log(p: &[u8], dev: &str) -> Option<Record> {
    if p.len() != LOG_P {
        return None;
    }
    let field = |a: usize, b: usize| -> Option<String> {
        Some(
            std::str::from_utf8(p.get(a..b)?)
                .ok()?
                .trim_end()
                .to_string(),
        )
    };
    let seq_s = field(O_SEQ, O_SEQ + W_SEQ)?;
    if seq_s.trim().is_empty() {
        return None; // blank record
    }
    let seq = seq_s.trim().parse::<u64>().ok()?;
    let conf = field(O_CONF, O_CONF + W_CONF)?.trim().parse::<u32>().ok()?;
    let tags_raw = field(O_TAGS, O_TAGS + W_TAGS)?;
    let tags = tags_raw
        .split(',')
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    // Valid-time fields. A pre-valid-time (legacy-layout) record has hash/text
    // bytes here instead, so the `vfrom` integer parse fails → `None`: the record
    // is skipped and `verify` flags it, rather than being silently misread.
    let vfrom_s = field(O_VFROM, O_VFROM + W_VFROM)?;
    let valid_from = vfrom_s.trim().parse::<i64>().ok()?;
    let vuntil_s = field(O_VUNTIL, O_VUNTIL + W_VUNTIL)?;
    let vuntil_t = vuntil_s.trim();
    let valid_until = if vuntil_t == "-" || vuntil_t.is_empty() {
        None
    } else {
        Some(vuntil_t.parse::<i64>().ok()?)
    };
    let text = std::str::from_utf8(p.get(O_TEXT..)?)
        .ok()?
        .trim_end()
        .to_string();
    Some(Record {
        dev: dev.to_string(),
        seq,
        ts: field(O_TS, O_TS + W_TS)?,
        kind: field(O_KIND, O_KIND + W_KIND)?,
        conf,
        sup: field(O_SUP, O_SUP + W_SUP)?,
        src: field(O_SRC, O_SRC + W_SRC)?,
        method: field(O_METHOD, O_METHOD + W_METHOD)?,
        tags,
        valid_from,
        valid_until,
        hash: field(O_HASH, O_HASH + W_HASH)?,
        text,
        stale: false,
    })
}

/// Recompute the hash a record *should* carry, from the previous hash and the
/// **stored body+text bytes** (not a reconstruction). Used by `verify`.
pub(crate) fn recompute_hash(prev_hash: &str, p: &[u8]) -> Option<String> {
    if p.len() != LOG_P {
        return None;
    }
    let text = std::str::from_utf8(p.get(O_TEXT..)?).ok()?.trim_end();
    Some(chain_hash(prev_hash, &p[..BODY_LEN], text.as_bytes()))
}

// ---------------------------------------------------------------- retrieval

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z0-9]+").expect("static token regex"))
}

fn stopwords() -> &'static HashSet<&'static str> {
    static SW: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SW.get_or_init(|| {
        "a an the and or but if then than that this these those of in on at to for from by with \
         without as is are was were be been being do does did done have has had having i me my mine \
         you your yours he him his she her it its we us our they them their what which who whom when \
         where why how all any both each few more most other some such no nor not only own same so \
         too very can will just don should now about into over after before again once"
            .split_whitespace()
            .collect()
    })
}

/// Lowercase alphanumeric tokens, stopwords dropped, light suffix stripping so
/// `deployed` and `deploy` meet.
pub fn tokens(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    for m in token_re().find_iter(&lower) {
        let w = m.as_str();
        if w.len() < 2 || stopwords().contains(w) {
            continue;
        }
        let mut w = w.to_string();
        for suf in ["ing", "ed", "es", "s"] {
            if w.len() > suf.len() + 2 && w.ends_with(suf) {
                w.truncate(w.len() - suf.len());
                break;
            }
        }
        out.push(w);
    }
    out
}

/// Rank memories against a natural-language query (BM25). A one-pass scan, not a
/// persisted index — the log is the only truth. Confidence and CORE pinning are
/// relevance signals, matching STELA.
pub fn bm25<'a>(recs: &'a [Record], query: &str, k: usize) -> Vec<(f64, &'a Record)> {
    let q = tokens(query);
    if q.is_empty() || recs.is_empty() {
        return vec![];
    }
    let docs: Vec<Vec<String>> = recs
        .iter()
        .map(|r| tokens(&format!("{} {}", r.text, r.tags.join(" "))))
        .collect();
    let n = docs.len() as f64;
    let avgdl = docs.iter().map(Vec::len).sum::<usize>() as f64 / n.max(1.0);
    let mut df: HashMap<&str, f64> = HashMap::new();
    for d in &docs {
        for t in d.iter().collect::<HashSet<_>>() {
            *df.entry(t.as_str()).or_insert(0.0) += 1.0;
        }
    }
    let (k1, b) = (1.5f64, 0.75f64);
    let mut scored: Vec<(f64, &Record)> = Vec::new();
    for (r, d) in recs.iter().zip(&docs) {
        if d.is_empty() {
            continue;
        }
        let mut tf: HashMap<&str, f64> = HashMap::new();
        for t in d {
            *tf.entry(t.as_str()).or_insert(0.0) += 1.0;
        }
        let mut s = 0.0;
        for t in &q {
            if let Some(&f) = tf.get(t.as_str()) {
                let dfi = df.get(t.as_str()).copied().unwrap_or(0.0);
                let idf = (1.0 + (n - dfi + 0.5) / (dfi + 0.5)).ln();
                s += idf * (f * (k1 + 1.0)) / (f + k1 * (1.0 - b + b * d.len() as f64 / avgdl));
            }
        }
        if s <= 0.0 {
            continue;
        }
        s *= 0.6 + 0.4 * (f64::from(r.conf) / 100.0);
        if r.kind == "core" {
            s *= 1.35;
        }
        scored.push((s, r));
    }
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.ts.cmp(&b.1.ts))
    });
    scored.truncate(k);
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_round_trips_and_hash_matches() {
        let tags = vec!["deploy".to_string(), "prod".to_string()];
        let p = pack_log(
            0,
            "2026-07-27T00:00:00Z",
            "fact",
            80,
            &tags,
            "-",
            "user",
            "note",
            1_600_000_000_000,
            Some(1_700_000_000_000),
            &"0".repeat(16),
            "hello world",
        )
        .unwrap();
        assert_eq!(p.len(), LOG_P);
        let r = unpack_log(&p, "abc123").unwrap();
        assert_eq!(r.seq, 0);
        assert_eq!(r.text, "hello world");
        assert_eq!(r.tags, tags);
        assert_eq!(r.src, "user");
        assert_eq!(r.method, "note");
        // Valid-time round-trips through the fixed-width fields.
        assert_eq!(r.valid_from, 1_600_000_000_000);
        assert_eq!(r.valid_until, Some(1_700_000_000_000));
        // The stored hash recomputes from the stored bytes (bug #3 fixed).
        assert_eq!(recompute_hash(&"0".repeat(16), &p).unwrap(), r.hash);
    }

    #[test]
    fn tags_capped_on_boundary_round_trip() {
        // Many tags overflow 32 bytes; the stored field must never end mid-token
        // or with a trailing comma, and must round-trip through the hash.
        let tags: Vec<String> = (0..20).map(|i| format!("tag{i:02}")).collect();
        let p = pack_log(
            1,
            "2026-07-27T00:00:00Z",
            "fact",
            50,
            &tags,
            "-",
            "agent",
            "note",
            0,
            None,
            &"0".repeat(16),
            "x",
        )
        .unwrap();
        let r = unpack_log(&p, "dev").unwrap();
        // Re-capping the parsed tags reproduces the stored field exactly.
        assert_eq!(join_capped(&r.tags, W_TAGS), join_capped(&tags, W_TAGS));
        // Unbounded valid-time round-trips: 0 → 0, "-" → None.
        assert_eq!(r.valid_from, 0);
        assert_eq!(r.valid_until, None);
        assert_eq!(recompute_hash(&"0".repeat(16), &p).unwrap(), r.hash);
    }

    #[test]
    fn bm25_ranks_relevant_first() {
        let mk = |seq: u64, text: &str, kind: &str| Record {
            dev: "d".into(),
            seq,
            ts: "2026-07-27T00:00:00Z".into(),
            kind: kind.into(),
            conf: 80,
            sup: "-".into(),
            src: "user".into(),
            method: "note".into(),
            tags: vec![],
            valid_from: 0,
            valid_until: None,
            hash: "0".repeat(16),
            text: text.into(),
            stale: false,
        };
        let recs = vec![
            mk(0, "the deployment pipeline uses github actions", "fact"),
            mk(1, "lunch was good", "evnt"),
            mk(2, "we deploy on fridays", "dcsn"),
        ];
        let hits = bm25(&recs, "deploy pipeline", 8);
        assert!(!hits.is_empty());
        assert!(hits[0].1.text.contains("deploy"));
        assert!(hits.iter().all(|(_, r)| !r.text.contains("lunch")));
    }
}
