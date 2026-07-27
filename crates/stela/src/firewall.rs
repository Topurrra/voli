//! Disclosure firewall — deterministic secret redaction at recall.
//!
//! Ported from the KeepItLocal memory engine (`firewall/`), trimmed to the
//! HIGH-tier secret set plus Luhn-validated cards and structural SSNs. **No
//! model, no network, no LLM** — a compile-time-constant `regex::RegexSet` (the
//! `regex` crate is linear-time, so ReDoS-free) plus a handful of checksum
//! validators. Findings carry only `(kind, span)`; the raw secret value never
//! leaves this module.
//!
//! Enforcement is at **recall**: every rendered egress is re-scanned and masked
//! on the way out (stela already does a full O(n) scan per recall, so this is the
//! same cost class — and there is NO stored-spans column and NO write-path change,
//! matching stela's "an index that can desync is a bug" stance). Spans are applied
//! **back-to-front** so byte offsets stay valid, with an overlap guard.
//!
//! ## The one-place invariant
//!
//! [`Disclosed`] is the SOLE egress type for rendered memory content. Its inner
//! `String` is private and its only mint is [`disclose_block`] here, so
//! "un-redacted text reaches the agent" is unrepresentable without calling this
//! module by name — a greppable red flag. [`crate::fence`] is the chokepoint: it
//! is the only producer of a `Disclosed`, and it always redacts first.
//!
//! A human escape hatch (`$STELA_SHOW_SECRETS` truthy) disables masking; redaction
//! is the privacy-by-default.

use std::fmt;
use std::ops::Deref;
use std::sync::OnceLock;

use regex::{Regex, RegexSet};

// ---------------------------------------------------------------- Disclosed

/// The sole egress type for rendered memory content leaving stela toward an agent.
///
/// The inner `String` is private and is minted ONLY by [`disclose_block`] (via
/// [`crate::fence`]), so no code elsewhere can fabricate a `Disclosed` around a
/// raw, un-redacted String. `Deref<Target = str>` and `Display` make it print and
/// read like a string at the call sites, but its construction is sealed.
#[derive(Debug, Clone)]
pub struct Disclosed(String);

impl Disclosed {
    /// Borrow the redacted text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Consume into the owned redacted String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for Disclosed {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Disclosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redact secrets in `block` (unless the human escape hatch is on) and seal the
/// result as a [`Disclosed`]. THE mint. [`crate::fence`] is its only caller.
pub(crate) fn disclose_block(block: String) -> Disclosed {
    if show_secrets() {
        return Disclosed(block);
    }
    Disclosed(redact_secrets(&block))
}

/// The human kill switch: `$VOLI_MEMORY_SHOW_SECRETS` truthy disables redaction
/// (`$STELA_SHOW_SECRETS` is accepted as a legacy alias).
///
// ponytail: one env-var escape hatch (global, greppable) rather than threading a
// `--show-secrets` bool through every render method. Promote to a threaded flag if
// per-invocation control is ever needed.
pub fn show_secrets() -> bool {
    ["VOLI_MEMORY_SHOW_SECRETS", "STELA_SHOW_SECRETS"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .any(|v| matches!(v.trim(), "1" | "true" | "on" | "yes"))
}

// ---------------------------------------------------------------- findings

/// One sensitive-content finding: a byte-range into the scanned text pointing at
/// the SECRET itself, plus its `kind` (drives the masker). No raw value is held.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    kind: &'static str,
    start: usize,
    end: usize,
}

// ─── HIGH-tier patterns ────────────────────────────────────────────
//
// Prefixed / structured tokens that no ordinary memory text produces by accident:
// provider API keys, PEM/PGP private-key headers, JWTs, DB-URLs-with-password, and
// crypto wallet addresses. One RegexSet scans for all of them in a single O(n)
// pass; only patterns that hit get re-scanned to pull spans. Anthropic BEFORE
// OpenAI so the more specific `sk-ant-` prefix wins when both would match.
const HIGH_PATTERNS: &[(&str, &str)] = &[
    ("aws_access_key", r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("github_token", r"\bgh[opusr]_[A-Za-z0-9]{36,}"),
    ("github_fine_grained_pat", r"\bgithub_pat_[A-Za-z0-9_]{30,}"),
    ("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    (
        "slack_webhook",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
    ),
    (
        "stripe_secret_key",
        r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{24,}",
    ),
    (
        "jwt_token",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    ),
    (
        "private_key_pem",
        r"-----BEGIN ([A-Z]+ )*PRIVATE KEY( BLOCK)?-----",
    ),
    ("pgp_private_key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    (
        "database_url_with_password",
        r"\b(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp)://[^\s:/]+:[^\s@]+@[^\s/]+",
    ),
    ("ethereum_private_key", r"\b0x[a-fA-F0-9]{64}\b"),
    // Anthropic BEFORE OpenAI — the more specific prefix wins.
    ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai_api_key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36,}"),
    // Crypto wallets — deterministic prefix/length, near-zero false positives.
    ("bitcoin_address", r"\b[13][1-9A-HJ-NP-Za-km-z]{24,33}\b"),
    ("bitcoin_bech32", r"\bbc1[ac-hj-np-z02-9]{39,59}\b"),
    ("ethereum_address", r"\b0x[a-fA-F0-9]{40}\b"),
    ("solana_address", r"\b[1-9A-HJ-NP-Za-km-z]{44}\b"),
];

struct HighEngine {
    set: RegexSet,
    individual: Vec<Regex>,
}

fn high() -> &'static HighEngine {
    static HIGH: OnceLock<HighEngine> = OnceLock::new();
    HIGH.get_or_init(|| {
        let set =
            RegexSet::new(HIGH_PATTERNS.iter().map(|(_, p)| *p)).expect("HIGH RegexSet compile");
        let individual = HIGH_PATTERNS
            .iter()
            .map(|(_, p)| Regex::new(p).expect("HIGH Regex compile"))
            .collect();
        HighEngine { set, individual }
    })
}

// ─── MEDIUM-tier: credit cards (Luhn) + SSN (structural) ───────────

fn card_shape() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d[ -]?){11,18}\d\b").expect("card shape compile"))
}

fn ssn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").expect("ssn compile"))
}

/// Luhn checksum over a digits-only string of plausible card length (12..=19).
/// Rules out ~90% of the false positives a bare 16-digit shape would surface.
fn is_valid_card(digits: &str) -> bool {
    let len = digits.len();
    if !(12..=19).contains(&len) || digits.bytes().any(|b| !b.is_ascii_digit()) {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for ch in digits.bytes().rev() {
        let d = (ch - b'0') as u32;
        let v = if double { d * 2 } else { d };
        sum += if v > 9 { v - 9 } else { v };
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// SSA structural rules: no 000/666/9xx area, no 00 group, no 0000 serial. Drops
/// the obvious non-SSNs a bare `NNN-NN-NNNN` shape would otherwise flag.
fn is_valid_ssn(area: &str, group: &str, serial: &str) -> bool {
    !(area == "000" || area == "666" || area.starts_with('9') || group == "00" || serial == "0000")
}

// ---------------------------------------------------------------- scan / mask

/// Scan `text` for secret findings (HIGH tokens, Luhn cards, structural SSNs).
fn scan(text: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    // HIGH: RegexSet says which patterns hit, then per-pattern spans.
    let engine = high();
    for idx in engine.set.matches(text).iter() {
        let (kind, _) = HIGH_PATTERNS[idx];
        for m in engine.individual[idx].find_iter(text) {
            out.push(Finding {
                kind,
                start: m.start(),
                end: m.end(),
            });
        }
    }

    // MEDIUM: credit cards (Luhn-validated → rejects random 16-digit runs).
    for m in card_shape().find_iter(text) {
        let digits: String = text[m.start()..m.end()]
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        if is_valid_card(&digits) {
            out.push(Finding {
                kind: "credit_card",
                start: m.start(),
                end: m.end(),
            });
        }
    }

    // MEDIUM: SSN (structurally validated).
    for caps in ssn_re().captures_iter(text) {
        let whole = caps.get(0).expect("group 0 always present");
        let area = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let group = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let serial = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        if is_valid_ssn(area, group, serial) {
            out.push(Finding {
                kind: "ssn",
                start: whole.start(),
                end: whole.end(),
            });
        }
    }

    out
}

/// Turn a raw matched secret into a preview: enough to identify it, never the
/// value. Cards keep the last 4; private-key/JWT/webhook previews are fully
/// obscured (no useful sub-string); the rest keep a short prefix + tail.
fn mask_value(kind: &str, raw: &str) -> String {
    match kind {
        "credit_card" => {
            let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() < 4 {
                "****".into()
            } else {
                format!("**** **** **** {}", &digits[digits.len() - 4..])
            }
        }
        "jwt_token" | "slack_webhook" => "[REDACTED]".into(),
        "private_key_pem" | "pgp_private_key" => "[PRIVATE KEY]".into(),
        "aws_access_key"
        | "github_token"
        | "github_fine_grained_pat"
        | "slack_token"
        | "stripe_secret_key"
        | "openai_api_key"
        | "anthropic_api_key"
        | "npm_token"
        | "database_url_with_password"
        | "ethereum_private_key" => mask_prefix_tail(raw, 4, 4),
        _ => mask_prefix_tail(raw, 2, 2),
    }
}

fn mask_prefix_tail(raw: &str, head: usize, tail: usize) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= head + tail {
        return "*".repeat(chars.len().max(4));
    }
    let prefix: String = chars.iter().take(head).collect();
    let suffix: String = chars[chars.len() - tail..].iter().collect();
    format!("{prefix}***{suffix}")
}

/// Replace every secret span with its masked preview. Applies **back-to-front** so
/// earlier byte offsets stay valid, guarding against overlaps (a span that starts
/// before the previously-applied one ended is skipped).
pub(crate) fn redact_secrets(content: &str) -> String {
    let mut findings = scan(content);
    if findings.is_empty() {
        return content.to_string();
    }
    findings.sort_by_key(|f| f.start);

    let mut text = content.to_string();
    let mut last_start = text.len();
    for f in findings.iter().rev() {
        if f.end > last_start || f.end > text.len() || f.start >= f.end {
            continue; // overlap or out-of-range — skip
        }
        let preview = mask_value(f.kind, &content[f.start..f.end]);
        text.replace_range(f.start..f.end, &preview);
        last_start = f.start;
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_real_card_rejects_random_16_digits() {
        assert!(is_valid_card("4242424242424242")); // Visa test number
        assert!(!is_valid_card("1234567890123456")); // not Luhn-valid
        assert!(!is_valid_card("4242")); // too short
    }

    #[test]
    fn masks_aws_key_and_hides_the_raw_value() {
        let out = redact_secrets("key is AKIAIOSFODNN7EXAMPLE here");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("AKIA***MPLE"));
    }

    #[test]
    fn masks_card_but_not_a_random_number() {
        let carded = redact_secrets("card 4242 4242 4242 4242 ok");
        assert!(!carded.contains("4242 4242 4242 4242"));
        assert!(carded.contains("4242")); // last-four preview only
        // A non-Luhn 16-digit number is left alone (false-positive guard).
        let plain = "ref 1234567890123456 end";
        assert_eq!(redact_secrets(plain), plain);
    }

    #[test]
    fn masks_ssn_but_not_placeholder() {
        let out = redact_secrets("ssn 123-45-6789 on file");
        assert!(!out.contains("123-45-6789"));
        // 000 area is structurally invalid → not flagged.
        let placeholder = "ssn 000-12-3456 test";
        assert_eq!(redact_secrets(placeholder), placeholder);
    }

    #[test]
    fn back_to_front_multiple_secrets() {
        let raw = "a AKIAIOSFODNN7EXAMPLE b sk-ant-abcdefghijklmnopqrstuvwxyz c";
        let out = redact_secrets(raw);
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!out.contains("sk-ant-abcdefghijklmnopqrstuvwxyz"));
        assert!(out.starts_with("a AKIA***"));
    }

    #[test]
    fn show_secrets_escape_hatch_passes_through() {
        // disclose_block honours the env kill switch.
        unsafe { std::env::set_var("STELA_SHOW_SECRETS", "1") };
        let d = disclose_block("AKIAIOSFODNN7EXAMPLE".to_string());
        assert_eq!(d.as_str(), "AKIAIOSFODNN7EXAMPLE");
        unsafe { std::env::remove_var("STELA_SHOW_SECRETS") };
        let d2 = disclose_block("AKIAIOSFODNN7EXAMPLE".to_string());
        assert!(!d2.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
