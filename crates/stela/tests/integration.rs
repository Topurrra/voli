//! Integration tests proving the STELA guarantees. Each uses its own tempdir and
//! a fixed test key (so CI needs no keychain); the wrong-passphrase test drives
//! the real Argon2id custody under the fast profile.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::thread;

use stela::store::LOG_E;
use stela::{Store, create_passphrase_custody, derive_master_for_open};

const KEY: [u8; 32] = [7u8; 32];

/// A fresh store in a tempdir, opened with the fixed test key.
fn fresh() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let (store, was_fresh) = Store::init_with_key(dir.path().join("mem"), KEY).unwrap();
    assert!(was_fresh);
    (dir, store)
}

/// A plain `fact` note from `user`.
fn note(store: &Store, text: &str) -> String {
    store
        .note(text, "fact", 80, &[], None, "user", "note")
        .unwrap()
        .id
}

fn shard_path(store: &Store) -> std::path::PathBuf {
    let dev = store.device().unwrap();
    store.dir().join(format!("LOG.{dev}.txt"))
}

// ---------------------------------------------------------------- encryption

#[test]
fn encryption_round_trip_and_at_rest() {
    let (_d, store) = fresh();
    let secret = "the quick brown fox jumps over the lazy dog";
    let id = note(&store, secret);
    let (dev, seq) = id.split_once(':').unwrap();
    // Round-trips through decryption.
    let r = store.log_get(dev, seq.parse().unwrap()).unwrap().unwrap();
    assert_eq!(r.text, secret);

    // At rest: the shard is a whole number of sealed records and does NOT contain
    // the plaintext anywhere.
    let bytes = fs::read(shard_path(&store)).unwrap();
    assert_eq!(
        bytes.len() % LOG_E,
        0,
        "not a whole number of sealed records"
    );
    assert_eq!(bytes.len(), LOG_E, "one record => exactly one sealed width");
    assert!(
        !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "plaintext leaked into the on-disk record"
    );
}

#[test]
fn wrong_passphrase_rejected_before_any_read_even_empty() {
    // Fast Argon2 so CI never runs a full-cost KDF.
    unsafe { std::env::set_var("STELA_ARGON2_TEST_FAST", "1") };

    // A brand-new, still-EMPTY store: the verifier alone must reject a wrong
    // passphrase, with no record to AEAD-fail on.
    let empty = tempfile::tempdir().unwrap();
    let _created = create_passphrase_custody(empty.path(), "correct horse").unwrap();
    assert!(matches!(
        derive_master_for_open(empty.path(), "wrong horse"),
        Err(stela::Error::BadPassphrase)
    ));

    // And a populated store: right passphrase opens, wrong is rejected.
    let dir = tempfile::tempdir().unwrap();
    let key = create_passphrase_custody(dir.path(), "correct horse").unwrap();
    let (store, _) = Store::init_with_key(dir.path(), *key).unwrap();
    note(&store, "a real memory");
    let opened = derive_master_for_open(dir.path(), "correct horse").unwrap();
    assert_eq!(*opened, *key);
    assert!(matches!(
        derive_master_for_open(dir.path(), "nope"),
        Err(stela::Error::BadPassphrase)
    ));
}

#[test]
fn anti_splice_copying_a_record_to_another_slot_fails() {
    let (_d, store) = fresh();
    let id0 = note(&store, "record zero");
    let _id1 = note(&store, "record one");
    let (dev, _) = id0.split_once(':').unwrap();

    // Copy slot 1's ciphertext over slot 0. AAD = seq, so it can no longer open
    // as slot 0.
    let path = shard_path(&store);
    let mut bytes = fs::read(&path).unwrap();
    let (a, b) = bytes.split_at_mut(LOG_E);
    a.copy_from_slice(&b[..LOG_E]);
    fs::write(&path, &bytes).unwrap();

    assert!(
        store.log_get(dev, 0).is_err(),
        "spliced record must fail to open"
    );
    let report = store.verify().unwrap();
    assert!(!report.ok());
    assert!(
        report.bad.iter().any(|b| b.contains(":0")),
        "verify must name slot 0: {:?}",
        report.bad
    );
}

// ---------------------------------------------------------------- key recovery

#[test]
fn recovery_blob_restores_access_after_keychain_wipe() {
    // Fast Argon2 so CI never runs a full-cost KDF (the blob wrap derives a key).
    unsafe { std::env::set_var("STELA_ARGON2_TEST_FAST", "1") };
    let dir = tempfile::tempdir().unwrap();
    let mem = dir.path().join("mem");
    let (store, _) = Store::init_with_key(&mem, KEY).unwrap();
    note(&store, "a recoverable memory");

    // Save a recovery blob for the master key under a recovery passphrase.
    stela::write_recovery_blob(&mem, &KEY, "rescue phrase").unwrap();
    assert!(stela::recovery_blob_path(&mem).exists());

    // Simulate a wiped keychain: we no longer "have" the key. Recover it from the
    // blob — the whole point of item 1.
    let recovered = stela::recover_master(&mem, "rescue phrase").unwrap();
    assert_eq!(
        recovered, KEY,
        "recovered key must equal the original master key"
    );

    // A wrong recovery passphrase fails closed.
    assert!(stela::recover_master(&mem, "wrong phrase").is_err());
    // No blob at all is an actionable error, not a panic.
    let empty = tempfile::tempdir().unwrap();
    assert!(stela::recover_master(empty.path(), "rescue phrase").is_err());

    // Access is genuinely restored: the store opens with the recovered key and
    // read returns the memory (this is what `recover` re-enables via the keychain).
    let store2 = Store::open_with_key(&mem, recovered).unwrap();
    assert!(
        store2
            .render_read(120, None, 8)
            .unwrap()
            .contains("recoverable memory")
    );
}

// ---------------------------------------------------------------- crash recovery

#[test]
fn torn_tail_is_tolerated_then_repaired() {
    let (_d, store) = fresh();
    note(&store, "alpha");
    note(&store, "bravo");
    let path = shard_path(&store);
    let before = fs::metadata(&path).unwrap().len();

    // Simulate a crash mid-append: a partial sealed record on the tail.
    {
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0u8; LOG_E / 2]).unwrap();
    }
    assert_ne!(fs::metadata(&path).unwrap().len() % LOG_E as u64, 0);

    // Readers floor the torn tail: the two committed records are unaffected.
    let dev = store.device().unwrap();
    assert_eq!(store.log_get(&dev, 1).unwrap().unwrap().text, "bravo");
    assert_eq!(store.timeline().unwrap().len(), 2);

    // The next note repairs the tail and lands at the correct contiguous slot.
    let id = note(&store, "charlie");
    assert_eq!(id, format!("{dev}:2"));
    assert_eq!(fs::metadata(&path).unwrap().len(), before + LOG_E as u64);
    let all = store.timeline().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
}

// ---------------------------------------------------------------- utf-8

#[test]
fn utf8_multibyte_at_the_byte_limit() {
    let (_d, store) = fresh();
    let limit = stela::ENTRY_BYTES; // 585 bytes after the valid-time header bump

    // Exactly at the limit: 292 two-byte chars + 1 ascii = 585 bytes.
    let text = format!("{}{}", "é".repeat(limit / 2), "x");
    assert_eq!(text.len(), limit);
    let id = note(&store, &text);
    let (dev, seq) = id.split_once(':').unwrap();
    assert_eq!(
        store
            .log_get(dev, seq.parse().unwrap())
            .unwrap()
            .unwrap()
            .text,
        text
    );

    // A 4-byte char ending exactly at the limit round-trips too.
    let text4 = format!("{}{}", "a".repeat(limit - 4), "😀");
    assert_eq!(text4.len(), limit);
    let id = note(&store, &text4);
    let (dev, seq) = id.split_once(':').unwrap();
    assert_eq!(
        store
            .log_get(dev, seq.parse().unwrap())
            .unwrap()
            .unwrap()
            .text,
        text4
    );

    // One byte over the limit is rejected; nothing is written.
    let over = format!("{}xx", "é".repeat(limit / 2));
    assert!(over.len() > limit);
    assert!(
        store
            .note(&over, "fact", 80, &[], None, "user", "note")
            .is_err()
    );
    assert_eq!(store.timeline().unwrap().len(), 2);
}

// ---------------------------------------------------------------- concurrency

#[test]
fn concurrent_notes_assign_distinct_contiguous_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mem");
    Store::init_with_key(&path, KEY).unwrap();

    let path = Arc::new(path);
    const WRITERS: u64 = 4;
    const EACH: u64 = 20;
    let mut handles = Vec::new();
    for w in 0..WRITERS {
        let path = Arc::clone(&path);
        handles.push(thread::spawn(move || {
            let store = Store::open_with_key(&*path, KEY).unwrap();
            for i in 0..EACH {
                note(&store, &format!("writer {w} note {i}"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let store = Store::open_with_key(&*path, KEY).unwrap();
    let total = WRITERS * EACH;
    let recs = store.timeline().unwrap();
    assert_eq!(recs.len() as u64, total);
    // Every record is in the single home shard, position == stored seq, unique.
    let dev = store.device().unwrap();
    let mut seqs: Vec<u64> = recs
        .iter()
        .map(|r| {
            assert_eq!(r.dev, dev);
            r.seq
        })
        .collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len() as u64, total, "duplicate or missing ids");
    assert_eq!(seqs, (0..total).collect::<Vec<_>>());
}

// ---------------------------------------------------------------- supersession

#[test]
fn supersession_hidden_from_wake_shown_in_history() {
    let (_d, store) = fresh();
    let old = store
        .note(
            "old fact: staging url is a.example",
            "fact",
            80,
            &[],
            None,
            "user",
            "note",
        )
        .unwrap()
        .id;
    let out = store
        .note(
            "new fact: staging url is b.example",
            "fact",
            90,
            &[],
            Some(&old),
            "user",
            "note",
        )
        .unwrap();
    assert_eq!(out.superseded.as_deref(), Some(old.as_str()));

    // read hides the superseded memory, shows the current one.
    let read = store.render_read(120, None, 8).unwrap();
    assert!(
        read.contains("b.example"),
        "current memory missing from read"
    );
    assert!(
        !read.contains("a.example"),
        "superseded memory leaked into read"
    );
    assert!(read.contains("1 superseded"));

    // history shows the full audit trail.
    let hist = store.history(Some(&old)).unwrap();
    assert!(hist.contains("a.example") && hist.contains("b.example"));

    assert_eq!(store.stats().unwrap().superseded, 1);
}

// ---------------------------------------------------------------- core / degrade

#[test]
fn core_is_never_compressed() {
    let (_d, store) = fresh();
    store
        .note(
            "ALLERGIC to penicillin",
            "core",
            100,
            &[],
            None,
            "user",
            "note",
        )
        .unwrap();
    for i in 0..40 {
        note(&store, &format!("routine event number {i}"));
    }
    // A tight budget forces the non-core timeline to compress, but CORE stays
    // verbatim under its own section, never inside a block.
    let read = store.render_read(8, None, 8).unwrap();
    assert!(read.contains("## Core (never compressed)"));
    assert!(
        read.contains("ALLERGIC to penicillin"),
        "core memory was compressed away"
    );
}

#[test]
fn graceful_degradation_missing_summary_shows_raw_not_crash() {
    let (_d, store) = fresh();
    for i in 0..20 {
        note(&store, &format!("memory {i}"));
    }
    // Summaries are NOT built. A tight budget needs them; render must degrade to
    // raw memories / a hint, never error.
    let read = store.render_read(8, None, 8).unwrap();
    assert!(read.contains("memory 19"), "most recent raw memory missing");
    assert!(
        read.contains("not yet compressed") || read.contains("memory 1"),
        "expected raw fallback or a compression hint:\n{read}"
    );
}

// ---------------------------------------------------------------- verify

#[test]
fn verify_catches_a_flipped_byte_and_names_the_record() {
    let (_d, store) = fresh();
    for i in 0..4 {
        note(&store, &format!("memory {i}"));
    }
    assert!(store.verify().unwrap().ok());

    // Flip one byte inside record 1's sealed region.
    let path = shard_path(&store);
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let pos = (LOG_E as u64) + 40;
        f.seek(SeekFrom::Start(pos)).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Start(pos)).unwrap();
        f.write_all(&[b[0] ^ 0x01]).unwrap();
    }

    let report = store.verify().unwrap();
    assert!(!report.ok());
    assert!(
        report.bad.iter().any(|b| b.contains(":1")),
        "verify must name record 1: {:?}",
        report.bad
    );
}

// ---------------------------------------------------------------- retrieval

#[test]
fn bm25_focus_ranks_and_provenance_round_trips() {
    let (_d, store) = fresh();
    store
        .note(
            "the deployment pipeline runs on github actions",
            "fact",
            80,
            &["ci".into()],
            None,
            "import",
            "manual",
        )
        .unwrap();
    note(&store, "we had pizza for lunch");
    store
        .note(
            "deploy only on tuesdays",
            "dcsn",
            90,
            &[],
            None,
            "user",
            "note",
        )
        .unwrap();

    let hits = store.search("deployment pipeline", 8).unwrap();
    assert!(hits.contains("github actions"), "top hit missing:\n{hits}");
    assert!(!hits.contains("pizza"), "irrelevant memory ranked");

    // Provenance round-trips through the encrypted record and the hash chain.
    let r = store.log_get(&store.device().unwrap(), 0).unwrap().unwrap();
    assert_eq!(r.src, "import");
    assert_eq!(r.method, "manual");
    assert_eq!(r.tags, vec!["ci".to_string()]);
    assert!(
        store.verify().unwrap().ok(),
        "hash chain must cover provenance"
    );
}

// ---------------------------------------------------------------- disclosure firewall

#[test]
fn secrets_masked_in_wake_focus_recall_never_raw() {
    // Redaction is the default (the escape hatch env var is expected unset in CI);
    // this binary never mutates that process-global env, to avoid a concurrent race.
    let (_d, store) = fresh();
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let ssn = "123-45-6789";
    let card = "4242 4242 4242 4242";
    note(&store, &format!("prod deploy key is {aws} keep it safe"));
    note(&store, &format!("customer ssn on file {ssn}"));
    note(&store, &format!("test card {card} expires soon"));

    // Every recall surface masks the raw secret.
    let read = store.render_read(120, None, 8).unwrap();
    let search = store.search("deploy key", 8).unwrap();
    let recall = store.recall("ssn|key|card", true).unwrap();
    for out in [read.as_str(), search.as_str(), recall.as_str()] {
        assert!(!out.contains(aws), "raw AWS key leaked:\n{out}");
        assert!(!out.contains(ssn), "raw SSN leaked:\n{out}");
        assert!(!out.contains(card), "raw card leaked:\n{out}");
    }
    // ...but the masked previews ARE present (the memory is still legible).
    assert!(
        read.contains("AKIA***MPLE"),
        "expected masked AWS key:\n{}",
        &*read
    );

    // A non-Luhn 16-digit number is NOT a card (false-positive guard).
    note(&store, "order ref 1234567890123456 shipped");
    let r = store.recall("order ref", true).unwrap();
    assert!(
        r.contains("1234567890123456"),
        "false-positive card mask:\n{}",
        &*r
    );
}

#[test]
fn private_note_is_withheld_at_recall() {
    let (_d, store) = fresh();
    // The `--private` marker rides as the reserved PRIVATE_TAG (what the CLI adds).
    store
        .note(
            "my luggage code is 7431",
            "fact",
            80,
            &[stela::PRIVATE_TAG.to_string()],
            None,
            "user",
            "note",
        )
        .unwrap();
    note(&store, "a normal visible memory");

    let read = store.render_read(120, None, 8).unwrap();
    assert!(
        read.contains("••• (private, withheld)"),
        "private not withheld:\n{}",
        &*read
    );
    assert!(
        !read.contains("7431"),
        "private text leaked into read:\n{}",
        &*read
    );
    assert!(
        read.contains("a normal visible memory"),
        "non-private hidden"
    );

    // Even an exact recall of the withheld content renders the placeholder, not it.
    let recall = store.recall("luggage", true).unwrap();
    assert!(
        !recall.contains("7431"),
        "private text leaked into recall:\n{}",
        &*recall
    );
}

// The `$STELA_SHOW_SECRETS` escape hatch is unit-tested in `firewall.rs`; it is
// process-global env state, so it is deliberately NOT toggled here where it would
// race the concurrent masking tests above.

// ---------------------------------------------------------------- bitemporal valid-time

#[test]
fn window_closed_fact_is_history_not_current() {
    let (_d, mut store) = fresh();
    store.set_contradiction_detection(true); // independent of the dev's env
    let now = stela::now_millis();
    let yr: i64 = 365 * 24 * 3600 * 1000;

    // Lived in Lisbon [now-7yr, now-4yr): the window has CLOSED.
    store
        .note_valid(
            "I lived in Lisbon",
            "fact",
            80,
            &[],
            None,
            "user",
            "note",
            Some(now - 7 * yr),
            Some(now - 4 * yr),
        )
        .unwrap();
    // Lives in Berlin [now-4yr, ∞): CURRENT. Same predicate as Lisbon, so it WOULD
    // classify as a contradiction if the windows overlapped — they don't.
    let out = store
        .note_valid(
            "I lived in Berlin",
            "fact",
            80,
            &[],
            None,
            "user",
            "note",
            Some(now - 4 * yr),
            None,
        )
        .unwrap();
    assert!(
        out.contradicts.is_empty(),
        "time-disjoint facts must NOT be flagged as a contradiction: {:?}",
        out.contradicts
    );

    // read (the CURRENT view) shows only Berlin.
    let read = store.render_read(120, None, 8).unwrap();
    assert!(
        read.contains("Berlin"),
        "current fact missing from read:\n{}",
        &*read
    );
    assert!(
        !read.contains("Lisbon"),
        "closed-window fact leaked into the current view:\n{}",
        &*read
    );
    assert!(
        read.contains("1 live memories"),
        "live count wrong:\n{}",
        &*read
    );

    // ...but BOTH remain on record — history is preserved (recall shows every one).
    let recall = store.recall("lived in", true).unwrap();
    assert!(
        recall.contains("Lisbon") && recall.contains("Berlin"),
        "history lost a fact:\n{}",
        &*recall
    );
    assert_eq!(
        store.stats().unwrap().live,
        1,
        "only the current fact is live"
    );
}

// ---------------------------------------------------------------- contradiction detection

#[test]
fn contradiction_flagged_for_overlapping_validity() {
    let (_d, mut store) = fresh();
    store.set_contradiction_detection(true);
    note(&store, "I prefer tabs");
    // Same subject, overlapping (default) validity, changed value ⇒ flagged.
    let out = store
        .note("I prefer spaces", "pref", 80, &[], None, "user", "note")
        .unwrap();
    assert!(
        out.contradicts.iter().any(|(_, t)| t.contains("tabs")),
        "overlapping-validity contradiction not flagged: {:?}",
        out.contradicts
    );
    // The note is still saved (advisory, non-destructive).
    assert_eq!(store.timeline().unwrap().len(), 2);
}

#[test]
fn contradiction_kill_switch_disables_detection() {
    let (_d, mut store) = fresh();
    store.set_contradiction_detection(false); // the config half of the kill switch
    note(&store, "I prefer tabs");
    let out = store
        .note("I prefer spaces", "pref", 80, &[], None, "user", "note")
        .unwrap();
    assert!(
        out.contradicts.is_empty(),
        "kill switch must disable detection: {:?}",
        out.contradicts
    );
}

/// The contradiction warning quotes an older memory back at the user, and that
/// quote is a disclosure like any other. It used to return raw text, so the one
/// place the firewall did not reach was the one place it printed a stored
/// secret verbatim.
#[test]
fn a_contradiction_warning_masks_secrets_in_the_memory_it_quotes() {
    let (_d, mut store) = fresh();
    store.set_contradiction_detection(true);
    note(
        &store,
        "jenkins token AKIAIOSFODNN7EXAMPLE works everywhere",
    );
    let out = store
        .note(
            "jenkins token never works everywhere",
            "fact",
            80,
            &[],
            None,
            "user",
            "note",
        )
        .unwrap();
    let quoted = out
        .contradicts
        .iter()
        .map(|(_, t)| t.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        !quoted.contains("AKIAIOSFODNN7EXAMPLE"),
        "the raw key must never come back in a warning: {quoted}"
    );
    assert!(
        quoted.contains("AKIA***MPLE"),
        "expected the same masking `read` applies: {quoted}"
    );
}

/// A `--private` memory is withheld everywhere it is rendered. A warning that
/// quotes it in full is a rendering, and was withholding nothing.
#[test]
fn a_contradiction_warning_withholds_a_private_memory_entirely() {
    let (_d, mut store) = fresh();
    store.set_contradiction_detection(true);
    store
        .note(
            "office wifi password bluebird77 works everywhere",
            "fact",
            80,
            &[stela::PRIVATE_TAG.to_string()],
            None,
            "user",
            "note",
        )
        .unwrap();
    let out = store
        .note(
            "office wifi password never works everywhere",
            "fact",
            80,
            &[],
            None,
            "user",
            "note",
        )
        .unwrap();
    let quoted = out
        .contradicts
        .iter()
        .map(|(_, t)| t.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        !quoted.contains("bluebird77"),
        "private text must never be quoted back: {quoted}"
    );
    assert!(
        quoted.contains("(private, withheld)"),
        "expected the withheld marker: {quoted}"
    );
}

/// A record that cannot be decrypted is skipped by every read path on purpose --
/// one bad record must not blind the whole store. But the skip is silent, so
/// `read`, `search` and `stats` all under-report while `verify` counts the full
/// set. `stats.unreadable` is what turns that silence into a number.
#[test]
fn stats_counts_records_it_could_not_read() {
    let (_dir, store) = fresh();
    note(&store, "one");
    note(&store, "two");
    assert_eq!(store.stats().unwrap().unreadable, 0, "clean store");

    // Append one full-width record of garbage: the right size to be counted on
    // disk, the wrong bytes to authenticate.
    let dev = store.device().unwrap();
    let log = store.dir().join(format!("LOG.{dev}.txt"));
    let mut bytes = std::fs::read(&log).unwrap();
    bytes.extend(std::iter::repeat_n(0xAB, stela::store::LOG_E));
    std::fs::write(&log, bytes).unwrap();

    let stats = store.stats().unwrap();
    assert_eq!(stats.unreadable, 1, "the unreadable record was not counted");
    assert_eq!(stats.total, 2, "readable records are unaffected");

    // And doctor, which exists to report exactly this kind of drift, says so.
    let issues = store.doctor().unwrap();
    assert!(
        issues.iter().any(|i| i.contains("cannot be decrypted")),
        "doctor stayed quiet: {issues:?}"
    );
}

// ---------------------------------------------------------------- tree / compact

/// Drive every compression the given budget asks for. Returns the blocks built.
fn compact_all(store: &Store, t: u64, budget: u64) -> Vec<(u64, u64)> {
    let mut built = Vec::new();
    loop {
        let todo = store.pending(t, budget, Some(1));
        let Some(&(lo, hi)) = todo.first() else { break };
        assert!(
            store
                .tree_put(lo, hi, &format!("summary of {}-{}", lo, hi - 1))
                .unwrap(),
            "tree_put refused {lo}-{}",
            hi - 1
        );
        built.push((lo, hi));
        assert!(built.len() < 500, "compaction is not converging");
    }
    built
}

#[test]
fn nap_builds_summaries_and_verify_stays_green() {
    let (_d, store) = fresh();
    const T: u64 = 20; // > the 8-line render floor, so summaries are actually used
    for i in 0..T {
        note(&store, &format!("memory {i}"));
    }
    let built = compact_all(&store, T, 8);
    assert!(!built.is_empty(), "a tight budget must demand summaries");
    assert!(store.pending(T, 8, None).is_empty());
    // Every block built reads back, and a tight-budget read uses them.
    for &(lo, hi) in &built {
        assert_eq!(
            store.tree_get(lo, hi).unwrap().as_deref(),
            Some(format!("summary of {}-{}", lo, hi - 1).as_str()),
            "block {lo}-{} should read back",
            hi - 1
        );
    }
    let read = store.render_read(8, None, 8).unwrap();
    assert!(
        read.contains("summary of"),
        "read should surface a summary:\n{read}"
    );
    assert!(store.verify().unwrap().ok());
}

#[test]
fn nothing_is_pending_while_the_whole_timeline_fits_the_budget() {
    // The compaction nag used to fire from the second memory onward and never
    // stop, asking for ~t summaries that `cover` would never render. Below the
    // budget every memory is shown in full, so nothing is owed.
    let (_d, store) = fresh();
    const T: u64 = 40;
    for i in 0..T {
        note(&store, &format!("memory {i}"));
    }
    assert_eq!(
        store.pending_count(T),
        0,
        "no summary can be shown while the timeline fits the read budget"
    );
    let read = store.render_read(stela::READ_LINES, None, 8).unwrap();
    assert!(
        !read.contains("await compression"),
        "a read within budget must not ask for compression:\n{read}"
    );
}

#[test]
fn summary_stops_reading_back_when_a_memory_it_covers_is_retracted() {
    // Blocks index the live, non-core timeline by position. Retracting an early
    // memory shifts every later one, so a summary that is still believed would
    // describe memories it no longer covers.
    let (_d, store) = fresh();
    const T: u64 = 20;
    let ids: Vec<String> = (0..T)
        .map(|i| note(&store, &format!("memory {i}")))
        .collect();
    let built = compact_all(&store, T, 8);
    let &(lo, hi) = built.first().unwrap();
    assert!(store.tree_get(lo, hi).unwrap().is_some());

    store.retract(&ids[0], Some("wrong")).unwrap();

    let t = T - 1; // the retracted memory left the live timeline
    assert_eq!(
        store.tree_get(lo, hi).unwrap(),
        None,
        "a summary whose memories shifted must not be served as fact"
    );
    assert!(
        store.pending(t, 8, None).contains(&(lo, hi)),
        "the shifted block must be offered for rebuild"
    );
    assert!(store.verify().unwrap().ok(), "the log itself is untouched");
}

#[test]
fn summaries_survive_memories_appended_after_them() {
    // Only the leaves a block covers may invalidate it. Appending must not.
    let (_d, store) = fresh();
    const T: u64 = 20;
    for i in 0..T {
        note(&store, &format!("memory {i}"));
    }
    let built = compact_all(&store, T, 8);
    let &(lo, hi) = built.first().unwrap();
    let before = store.tree_get(lo, hi).unwrap();
    assert!(before.is_some());
    for i in 0..5 {
        note(&store, &format!("later memory {i}"));
    }
    assert_eq!(
        store.tree_get(lo, hi).unwrap(),
        before,
        "appending must not invalidate an earlier summary"
    );
}

#[test]
fn a_summary_cannot_be_spliced_between_levels() {
    // AAD used to be the slot index alone, and every level has a slot 0, so a
    // narrow summary could be copied into a wider level's file and still open.
    let (_d, store) = fresh();
    const T: u64 = 20;
    for i in 0..T {
        note(&store, &format!("memory {i}"));
    }
    compact_all(&store, T, 8);
    let two = store.dir().join("TREE").join("2");
    let four = store.dir().join("TREE").join("4");
    if !two.exists() || !four.exists() {
        return; // this budget did not build both levels; nothing to splice
    }
    let rec = stela::store::TREE_E;
    let mut buf = vec![0u8; rec];
    let mut f = fs::File::open(&two).unwrap();
    f.read_exact(&mut buf).unwrap();
    let mut g = OpenOptions::new().write(true).open(&four).unwrap();
    g.seek(SeekFrom::Start(0)).unwrap();
    g.write_all(&buf).unwrap();
    g.sync_all().unwrap();
    assert_eq!(
        store.tree_get(0, 4).unwrap(),
        None,
        "a level-2 summary must not authenticate as a level-4 summary"
    );
}

#[test]
fn forget_drops_only_its_own_block_and_its_ancestors() {
    // Dropping one bad summary used to truncate every later block at every
    // level, discarding unrelated work.
    let (_d, store) = fresh();
    const T: u64 = 20;
    for i in 0..T {
        note(&store, &format!("memory {i}"));
    }
    let built = compact_all(&store, T, 8);
    let pairs: Vec<(u64, u64)> = built.iter().copied().filter(|&(l, h)| h - l == 2).collect();
    if pairs.len() < 2 {
        return; // need two sibling blocks at the same level to prove the point
    }
    let (first, later) = (pairs[0], *pairs.last().unwrap());
    store.tree_drop(first.0, first.1).unwrap();
    assert_eq!(
        store.tree_get(first.0, first.1).unwrap(),
        None,
        "the named block is dropped"
    );
    assert!(
        store.tree_get(later.0, later.1).unwrap().is_some(),
        "a later sibling must survive: {later:?}"
    );
}

#[test]
fn rebuilding_a_stale_block_leaves_untouched_blocks_alone() {
    // Dropping/rebuilding used to truncate a level back to the change, throwing
    // away every later summary. Retract late, so blocks below the change keep
    // exactly the same memories and must survive both the staleness check and
    // the in-place rebuild of the blocks above them.
    let (_d, store) = fresh();
    const T: u64 = 20;
    let ids: Vec<String> = (0..T)
        .map(|i| note(&store, &format!("memory {i}")))
        .collect();
    let built = compact_all(&store, T, 8);
    let cut = T - 2; // retract near the end; blocks under `cut` are unaffected
    let early = built
        .iter()
        .copied()
        .find(|&(_, hi)| hi <= cut)
        .expect("need a block entirely below the retraction");
    let early_text = store.tree_get(early.0, early.1).unwrap();
    assert!(early_text.is_some());

    store.retract(&ids[cut as usize], Some("wrong")).unwrap();
    let t = T - 1;

    assert_eq!(
        store.tree_get(early.0, early.1).unwrap(),
        early_text,
        "a block below the change covers the same memories and must survive"
    );
    let todo = store.pending(t, 8, None);
    for &(lo, hi) in &todo {
        assert!(store.tree_put(lo, hi, "rebuilt").unwrap());
    }
    assert!(
        store.pending(t, 8, None).is_empty(),
        "rebuilding must settle every block the read needs"
    );
    assert_eq!(
        store.tree_get(early.0, early.1).unwrap(),
        early_text,
        "rebuilding later blocks in place must not clobber an earlier one"
    );
    assert!(store.verify().unwrap().ok());
}

// ---------------------------------------------------------------- project scope

/// Detection is opt-in: a `.voli/memory` counts only once it exists, so a
/// directory that never ran `init` keeps using the global store and
/// writes are never silently redirected.
#[test]
fn project_store_is_found_from_any_depth_but_only_once_created() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let deep = root.join("crates").join("thing").join("src");
    fs::create_dir_all(&deep).unwrap();

    assert_eq!(
        stela::project_memory_dir(&deep),
        None,
        "an uninitialised project must not claim a store"
    );

    let store_dir = root.join(".voli").join("memory");
    fs::create_dir_all(&store_dir).unwrap();

    for from in [root, deep.as_path()] {
        assert_eq!(
            stela::project_memory_dir(from)
                .unwrap()
                .canonicalize()
                .unwrap(),
            store_dir.canonicalize().unwrap(),
            "walking up from {} should find the project store",
            from.display()
        );
    }
}

/// A repo inside a repo takes the nearest store, not the outermost.
#[test]
fn the_nearest_project_store_wins() {
    let td = tempfile::tempdir().unwrap();
    let outer = td.path();
    let inner = outer.join("vendor").join("nested");
    fs::create_dir_all(inner.join("src")).unwrap();
    fs::create_dir_all(outer.join(".voli").join("memory")).unwrap();
    fs::create_dir_all(inner.join(".voli").join("memory")).unwrap();

    assert_eq!(
        stela::project_memory_dir(&inner.join("src"))
            .unwrap()
            .canonicalize()
            .unwrap(),
        inner.join(".voli").join("memory").canonicalize().unwrap()
    );
}

/// The two prompts must describe different stores. The project one has to name
/// the escape hatch, or an agent has no way to record a fact that is not about
/// this codebase.
#[test]
fn project_and_global_prompts_differ_and_explain_scope() {
    let dir = std::path::Path::new("C:/proj/.voli/memory");
    let global = stela::prompt_for(dir, stela::Scope::Global);
    let project = stela::prompt_for(dir, stela::Scope::Project);

    assert_ne!(global, project);
    assert!(project.contains("--global"), "must name the escape hatch");
    // Match the sentence, not the bare verb: `init` alone now creates a project
    // store, so the word appears in both prompts and only the phrasing separates
    // them.
    assert!(
        project.contains("from the project root"),
        "must say how to create it"
    );
    assert!(project.contains(".gitignore"), "must mention it is ignored");
    assert!(
        !global.contains("from the project root"),
        "the global prompt should not talk about project stores"
    );
    // Both keep the instruction-injection guard.
    for p in [&global, &project] {
        assert!(p.contains("records, not orders"));
    }
}
