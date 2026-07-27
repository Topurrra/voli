//! STELA — permanent, verifiable, **encrypted** memory for AI agents.
//!
//! A stele is an inscribed stone: append-only, provably unaltered. This crate is
//! a Rust port of the Python STELA design (see `reference/stela.py`) onto a
//! crash-safe, cross-platform, fixed-width record engine (the hardened OptMem
//! storage core), with **encryption at rest** and **provenance** folded in.
//!
//! What it keeps from STELA:
//!
//! 1. **CORE** memories — pinned facts, never compressed away.
//! 2. **Supersession** — the log is append-only, but truth is current.
//! 3. **Tamper-evidence** — a blake2b hash chain; [`Store::verify`] proves it.
//! 4. **Semantic retrieval** — BM25 ranking, not just regex.
//! 5. **Task-focused read** — load what this task needs.
//! 6. **Injection containment** — memories are DATA, fenced and [`sanitize`]d.
//! 7. **Conflict-free sync** — per-device shards (`LOG.<dev>.txt`).
//! 8. **Graceful degradation** — a missing summary never bricks a session.
//!
//! What it adds (ported from the KeepItLocal memory engine):
//!
//! * **Encryption at rest** — every on-disk record is XChaCha20-Poly1305 sealed
//!   (`E = 24-byte nonce + P + 16-byte tag`), still fixed width, with `AAD = seq`
//!   binding a record to its slot (anti-splice / anti-reorder). See [`crypto`].
//! * **Key custody** — Argon2id passphrase custody with a cleartext verifier
//!   (wrong passphrase rejected before any read), plus an OS-keychain fallback on
//!   Windows and a passphrase-wrapped recovery blob. See [`key`].
//! * **Provenance** — short `src` + `method` fields on every record.
//!
//! ## The three STELA bugs fixed en route
//!
//! 1. `fcntl` / `os.uname()` were Unix-only. We use `std::fs::File::lock`
//!    (cross-platform) and derive the device id from the OS RNG — no `uname`.
//! 2. **Torn-tail append corruption:** the Python code appended after a torn
//!    partial record, misaligning the log. We *repair* (truncate to a record
//!    boundary) before every append. See `store::repair`.
//! 3. **Tag-truncation false integrity:** the Python code truncated joined tags
//!    mid-token, so the reconstructed field differed from the hashed one and
//!    `verify` cried tamper. We store tags capped on token boundaries and, on
//!    verify, hash the *stored body bytes* — never a reconstruction.
//!
//! What it adds beyond STELA (ported from the KeepItLocal memory engine):
//!
//! * **Disclosure Firewall** — deterministic (no-LLM) secret redaction enforced
//!   at recall. Every rendered egress is re-scanned and masked on the way out,
//!   routed through the [`Disclosed`] newtype (minted only by [`fence`]). A
//!   `--private` note is withheld entirely. See [`firewall`].
//! * **Bitemporal valid-time** — each record carries `[valid_from, valid_until)`;
//!   a memory is "current" only when now falls inside its window, so "was true
//!   THEN, false NOW" is history (a closed window), not an error. See [`record`].
//! * **Contradiction detection** — on `note`, an offline heuristic classifier
//!   runs against the BM25-nearest live memories (time-disjoint pairs gated out)
//!   and flags a conflict for the user. Kill-switchable via `$STELA_CONTRADICT`.

pub mod contradiction;
pub mod crypto;
pub mod firewall;
pub mod key;
pub mod record;
pub mod store;

pub use firewall::Disclosed;

pub use key::{
    CustodyMode, create_passphrase_custody, custody_mode, default_memory_dir,
    derive_master_for_open, recover_master, recovery_blob_path, write_recovery_blob,
};
pub use record::{Record, bm25, tokens};
pub use store::{NoteOutcome, Stats, Store, VerifyReport, prompt};

use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- layout
//
// Records are FIXED WIDTH so memory `i` is one seek away. Width is counted in
// BYTES so non-ASCII text can never misalign the file. The PLAINTEXT record is
// `LOG_P` bytes; on disk it is sealed to `LOG_E = 24 + LOG_P + 16` bytes, still
// constant width, so `seek(seq * LOG_E)` and torn-tail repair are unchanged.

/// Plaintext bytes per log record.
pub const LOG_P: usize = 768;
/// Plaintext bytes per tree (summary) record.
pub const TREE_P: usize = 512;

/// Blocks up to this many memories compress straight from the raw log.
pub const RAW_MAX: u64 = 16;
/// Default read budget, in lines.
pub const READ_LINES: u64 = 120;
/// Default hits for a focused/`task` read.
pub const SEARCH_K: usize = 8;

// Header field widths (bytes). Fixed so a record parses by byte offset.
pub(crate) const W_SEQ: usize = 8;
pub(crate) const W_TS: usize = 20;
pub(crate) const W_KIND: usize = 4;
pub(crate) const W_CONF: usize = 3;
pub(crate) const W_SUP: usize = 20;
pub(crate) const W_SRC: usize = 16;
pub(crate) const W_METHOD: usize = 12;
pub(crate) const W_TAGS: usize = 32;
/// Valid-time window bounds (unix millis, decimal). Added over STELA for
/// bitemporal validity; `0`/`-` = unbounded. See the format-bump note below.
pub(crate) const W_VFROM: usize = 20;
pub(crate) const W_VUNTIL: usize = 20;
pub(crate) const W_HASH: usize = 16;

/// Longest memory text, in bytes: the log record minus its header and newline.
//
// FORMAT BUMP (valid-time): the record gained two fixed-width millis fields
// (`vfrom`, `vuntil`) between `tags` and `hash`, so the header grew 42 bytes
// (140 → 182) and `ENTRY_BYTES` shrank 627 → 585. Crucially, `LOG_P` is
// UNCHANGED, so the sealed width `LOG_E`, `seek(seq * LOG_E)`, torn-tail repair
// and the `AAD = seq` anti-splice binding are all byte-identical — no re-seal, no
// migration of the encrypted envelope. Only the plaintext header LAYOUT changed:
// a pre-valid-time record read by this code fails to parse its `vfrom`/`vuntil`
// integers and is skipped (and flagged by `verify`) rather than silently
// misread. stela stores had no valid-time data before this, so that loud
// skip — not a silent break — is the whole compatibility story.
// header = seq +sp +ts +sp +kind +sp +conf +sp +sup +sp +src +sp +method +sp
//          +tags +sp +vfrom +sp +vuntil +sp +hash +sp
//        = 164 (body) + 1 + 16 + 1 = 182
pub const ENTRY_BYTES: usize = LOG_P - 182 - 1;

/// The memory kinds. `core` is never compressed; `rtrc` is a retraction.
pub const KINDS: [&str; 6] = ["core", "fact", "evnt", "dcsn", "pref", "rtrc"];

/// One-line help per kind (for `stats`).
pub fn kind_help(kind: &str) -> &'static str {
    match kind {
        "core" => "identity-critical; never compressed, always shown",
        "fact" => "a durable fact",
        "evnt" => "something that happened",
        "dcsn" => "a decision and its reason",
        "pref" => "how the principal likes things done",
        "rtrc" => "a retraction of an earlier memory",
        _ => "unknown",
    }
}

/// The fence the model is told never to treat as instructions. Any occurrence of
/// these tokens inside memory text is neutralised at write time by [`sanitize`],
/// so a memory can never close the fence and smuggle in instructions.
pub const FENCE_OPEN: &str = "<<<VOLI_MEMORY_DATA>>>";
/// The closing fence token.
pub const FENCE_CLOSE: &str = "<<<END_VOLI_MEMORY_DATA>>>";

// ---------------------------------------------------------------- errors

/// Either an I/O / crypto failure, or a clean, actionable user-facing message.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A filesystem error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// A JSON (custody sidecar) error.
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// An actionable message for the user/agent (the analogue of STELA's `die`).
    #[error("{0}")]
    Msg(String),
    /// Key derivation failed (Argon2, keychain).
    #[error("key derivation error: {0}")]
    KeyDerivation(String),
    /// The passphrase was wrong (rejected by the custody verifier before any read).
    #[error("wrong passphrase")]
    BadPassphrase,
    /// A cryptographic failure (AEAD auth, malformed blob).
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// The crate result type.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn msg<T>(s: impl Into<String>) -> Result<T> {
    Err(Error::Msg(s.into()))
}

// ---------------------------------------------------------------- sanitize / fence

/// Memory text is DATA. Strip anything that could break the fence or the record:
/// the fence tokens, control chars, and newlines; collapse runs of whitespace.
pub fn sanitize(text: &str) -> String {
    let replaced = text
        .replace(FENCE_OPEN, "[fence]")
        .replace(FENCE_CLOSE, "[fence]");
    let cleaned: String = replaced
        .chars()
        .map(|c| {
            if (c as u32) < 32 || c as u32 == 127 {
                ' '
            } else {
                c
            }
        })
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The reserved tag that marks a memory `--private`: at recall its text is
/// withheld (`••• (private, withheld)`) instead of rendered. Detection is at
/// write (the tag is recorded, hash-chained); enforcement is at recall ([`fmt`]).
pub const PRIVATE_TAG: &str = "private";

/// Wrap rendered lines in the data fence and seal them as a [`Disclosed`] — the
/// single egress chokepoint. Secret spans are masked here (unless the human
/// `$STELA_SHOW_SECRETS` escape hatch is set), so no rendered path can hand an
/// agent an un-redacted secret without minting a `Disclosed` through this seam.
pub fn fence(lines: &[String]) -> Disclosed {
    let mut out = String::new();
    out.push_str(FENCE_OPEN);
    out.push('\n');
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(FENCE_CLOSE);
    firewall::disclose_block(out)
}

// ---------------------------------------------------------------- blocks (cover)
//
// A BLOCK is an aligned power-of-two range `[lo, hi)` of the live timeline,
// compressed into one line. Blocks form a binary merge tree. `cover` is OptMem's
// detail-decay tiling: recent memories stay verbatim, ancient ones collapse, all
// inside a fixed line budget. (Lifted from the verified optmem-rs engine.)

fn cover_alpha(t: u64, alpha: f64) -> Vec<(u64, u64)> {
    let mut root = 1u64;
    while root < t {
        root *= 2;
    }
    let mut out = Vec::new();
    let mut stack = vec![(0u64, root)];
    while let Some((lo, hi)) = stack.pop() {
        if lo >= t {
            continue;
        }
        let size = hi - lo;
        if size > 1 && (hi > t || (size as f64) > alpha * ((t - lo) as f64)) {
            let mid = (lo + hi) / 2;
            stack.push((mid, hi));
            stack.push((lo, mid));
        } else {
            out.push((lo, hi));
        }
    }
    out.sort_unstable();
    out
}

/// At most `budget` blocks, finest near the present. If everything fits, nothing
/// is compressed.
pub fn cover(t: u64, budget: u64) -> Vec<(u64, u64)> {
    if t == 0 {
        return vec![];
    }
    if t <= budget {
        return (0..t).map(|i| (i, i + 1)).collect();
    }
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    for _ in 0..60 {
        let mid = (lo + hi) / 2.0;
        if cover_alpha(t, mid).len() as u64 > budget {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let mut out = cover_alpha(t, hi);
    while (out.len() as u64) < budget {
        let idx = out
            .iter()
            .enumerate()
            .filter(|(_, b)| b.1 - b.0 > 1)
            .map(|(i, _)| i)
            .max();
        match idx {
            None => break,
            Some(i) => {
                let (a, b) = out[i];
                let mid = (a + b) / 2;
                out.splice(i..i + 1, [(a, mid), (mid, b)]);
            }
        }
    }
    out
}

/// Parse `<lo>-<hi>` (inclusive both ends, as read prints it) into a half-open
/// aligned power-of-two block `[lo, hi)`.
pub fn parse_block_id(s: &str) -> Result<(u64, u64)> {
    let s = s.trim().trim_start_matches('#');
    let not_block = || Error::Msg(format!("'{s}' is not a block id (they look like 16-31)."));
    let (a, b) = s.split_once('-').ok_or_else(not_block)?;
    let lo: u64 = a.trim().parse().map_err(|_| not_block())?;
    let hi_inclusive: u64 = b.trim().parse().map_err(|_| not_block())?;
    let hi = hi_inclusive + 1;
    if hi <= lo {
        return Err(not_block());
    }
    let n = hi - lo;
    if n < 2 || !n.is_power_of_two() || !lo.is_multiple_of(n) {
        return Err(not_block());
    }
    Ok((lo, hi))
}

// ---------------------------------------------------------------- time / device

/// UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` (exactly 20 bytes), from the system clock.
///
/// ponytail: UTC from the raw clock rather than a `chrono`/`time` dependency for
/// one display string. Swap in `time` here if local-date fidelity ever matters.
pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let day_secs = secs % 86_400;
    let (hh, mm, ss) = (day_secs / 3600, (day_secs % 3600) / 60, day_secs % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Milliseconds since the Unix epoch, from the system clock. The clock for
/// bitemporal valid-time (`valid_from` / `valid_until`).
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Unix millis at `00:00:00Z` on the given proleptic-Gregorian date. The inverse
/// of [`civil_from_days`], for parsing `--valid-from` / `--valid-until` dates.
pub fn millis_from_civil(y: i64, m: u32, d: u32) -> i64 {
    days_from_civil(y, m, d) * 86_400 * 1000
}

/// Howard Hinnant's days-from-civil: `(year, month, day)` → days since the Unix
/// epoch. Proleptic Gregorian, exact; the inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Howard Hinnant's days-from-civil, inverted: days since the Unix epoch to
/// `(year, month, day)`. Proleptic Gregorian, exact.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// Fill `buf` from the OS RNG (BCryptGenRandom on Windows, getrandom elsewhere).
pub(crate) fn os_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::Crypto(format!("OS RNG unavailable: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_neutralises_fence_and_control() {
        let s = sanitize(&format!("hi{FENCE_OPEN}\nthere\tworld  "));
        assert!(!s.contains(FENCE_OPEN));
        assert!(!s.contains('\n') && !s.contains('\t'));
        assert_eq!(s, "hi[fence] there world");
    }

    #[test]
    fn entry_bytes_leaves_room() {
        // After the valid-time format bump the header is 182 bytes, so 585 bytes
        // of text fit a 768-byte record. LOG_P (and thus the sealed width) is
        // unchanged — only the plaintext header grew.
        assert_eq!(ENTRY_BYTES, 585);
    }

    #[test]
    fn days_from_civil_roundtrips() {
        for &(y, m, d) in &[(1970, 1, 1), (2020, 2, 29), (2026, 7, 27), (1999, 12, 31)] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d));
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(millis_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn block_id_shape() {
        assert_eq!(parse_block_id("16-31").unwrap(), (16, 32));
        assert_eq!(parse_block_id("0-1").unwrap(), (0, 2));
        assert!(parse_block_id("5-6").is_err()); // not aligned
        assert!(parse_block_id("0-2").is_err()); // size 3, not power of two
        assert!(parse_block_id("nope").is_err());
    }

    #[test]
    fn now_iso_is_20_bytes() {
        let ts = now_iso();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z') && ts.contains('T'));
    }

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
    }

    #[test]
    fn cover_is_within_budget_for_large_t() {
        for &t in &[121u64, 1_000, 12_345] {
            assert!(cover(t, 120).len() as u64 <= 120, "over budget at t={t}");
        }
        assert_eq!(cover(50, 120).len(), 50); // all singletons under budget
    }
}
