//! Integration tests for the index client (spec §5, §11 step 6).
//!
//! Covers the builder + FTS search + did-you-mean, sign/verify, and the full
//! `update` flow against a throwaway in-process HTTP server serving fixtures.

use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;
use std::thread;

use sha2::{Digest, Sha256};
use voli_core::index::{self, UpdateOutcome};
use voli_core::{Kind, Manifest, PackageRef};

// ---- fixtures -------------------------------------------------------------

fn manifest(name: &str, version: &str, desc: &str, bin: &str) -> Manifest {
    let toml = format!(
        r#"
name = "{name}"
version = "{version}"
description = "{desc}"
kind = "app"
bin = ["{bin}"]

[source.x64]
url = "https://example.com/{name}.zip"
sha256 = "{hash}"
"#,
        hash = "a".repeat(64),
    );
    Manifest::from_toml_str(&toml).expect("fixture manifest parses")
}

/// Three packages; ripgrep's only bin (`rg`) differs from its package name.
fn fixtures() -> Vec<Manifest> {
    vec![
        manifest(
            "ripgrep",
            "14.1.1",
            "Recursively search directories with a regex",
            "rg.exe",
        ),
        manifest(
            "fd",
            "10.1.0",
            "A simple, fast alternative to find",
            "fd.exe",
        ),
        manifest(
            "bat",
            "0.24.0",
            "A cat clone with syntax highlighting",
            "bat.exe",
        ),
    ]
}

fn skill_manifest(name: &str, version: &str, desc: &str) -> Manifest {
    let toml = format!(
        r#"
name = "{name}"
version = "{version}"
description = "{desc}"
kind = "skill"

[source.any]
url = "https://example.com/{name}.zip"
sha256 = "{hash}"
"#,
        hash = "b".repeat(64),
    );
    Manifest::from_toml_str(&toml).expect("skill fixture manifest parses")
}

/// Build an index into `<root>\db\index.sqlite` and return it.
fn build_index_at(root: &Path) -> std::path::PathBuf {
    let db = index::index_db_path(root);
    index::build(&fixtures(), &db).expect("build index");
    db
}

// ---- builder + query ------------------------------------------------------

#[test]
fn search_finds_by_name_description_and_bin() {
    let tmp = tempfile::tempdir().unwrap();
    build_index_at(tmp.path());

    // by name
    let by_name = index::search(tmp.path(), "ripgrep").unwrap();
    assert!(by_name.iter().any(|h| h.name == "ripgrep"));
    let hit = by_name.iter().find(|h| h.name == "ripgrep").unwrap();
    assert_eq!(hit.version, "14.1.1");
    assert!(hit.description.as_deref().unwrap().contains("Recursively"));

    // by a word from the description
    let by_desc = index::search(tmp.path(), "highlighting").unwrap();
    assert!(by_desc.iter().any(|h| h.name == "bat"));

    // by bin name that differs from the package name
    let by_bin = index::search(tmp.path(), "rg").unwrap();
    assert!(
        by_bin.iter().any(|h| h.name == "ripgrep"),
        "searching bin 'rg' should surface ripgrep, got {by_bin:?}"
    );

    // Kind is identity metadata, not a term that makes every app match "app".
    assert!(index::search(tmp.path(), "app").unwrap().is_empty());
}

#[test]
fn info_returns_latest_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    // add an older ripgrep version to prove "latest" wins
    let mut m = fixtures();
    m.push(manifest("ripgrep", "13.0.0", "old", "rg.exe"));
    index::build(&m, &index::index_db_path(tmp.path())).unwrap();

    let info = index::info(tmp.path(), "ripgrep").unwrap().unwrap();
    assert_eq!(info.version, "14.1.1");
    assert!(index::info(tmp.path(), "nope").unwrap().is_none());
}

#[test]
fn app_and_skill_with_same_name_coexist() {
    let tmp = tempfile::tempdir().unwrap();
    let mut manifests = vec![
        manifest("shared", "2.0.0", "Shared app", "shared.exe"),
        skill_manifest("shared", "3.0.0", "Shared skill"),
    ];
    manifests.push(skill_manifest("shared", "1.0.0", "Old shared skill"));
    index::build(&manifests, &index::index_db_path(tmp.path())).unwrap();

    let app = index::info(tmp.path(), "shared").unwrap().unwrap();
    assert_eq!(app.kind, Kind::App);
    assert_eq!(app.version, "2.0.0");

    let skill_ref = PackageRef::parse("skill/shared").unwrap();
    let skill = index::info_ref(tmp.path(), &skill_ref).unwrap().unwrap();
    assert_eq!(skill.kind, Kind::Skill);
    assert_eq!(skill.version, "3.0.0");
    assert_eq!(
        index::manifest_at_ref(tmp.path(), &skill_ref, "1.0.0")
            .unwrap()
            .unwrap()
            .description
            .as_deref(),
        Some("Old shared skill")
    );

    let hits = index::search(tmp.path(), "shared").unwrap();
    assert!(hits.iter().any(|hit| hit.kind == Kind::App));
    assert!(hits.iter().any(|hit| hit.kind == Kind::Skill));

    // Released clients read only these legacy tables and must see apps only.
    let connection = rusqlite::Connection::open(index::index_db_path(tmp.path())).unwrap();
    let app_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM packages WHERE name = 'shared'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let app_search_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM packages_fts WHERE name = 'shared'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(app_rows, 1);
    assert_eq!(app_search_rows, 1);
}

#[test]
fn suggestions_are_scoped_to_package_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let manifests = vec![
        manifest("testing", "1.0.0", "Testing app", "testing.exe"),
        skill_manifest("test-driven", "1.0.0", "Testing skill"),
    ];
    index::build(&manifests, &index::index_db_path(tmp.path())).unwrap();

    let skill_ref = PackageRef::parse("skill/test-drivne").unwrap();
    let suggestions = index::did_you_mean_ref(tmp.path(), &skill_ref).unwrap();
    assert_eq!(suggestions[0].kind, Kind::Skill);
    assert_eq!(suggestions[0].name, "test-driven");
    assert!(suggestions.iter().all(|item| item.kind == Kind::Skill));
}

#[test]
fn did_you_mean_ranks_ripgrep_first() {
    let tmp = tempfile::tempdir().unwrap();
    build_index_at(tmp.path());

    let sugg = index::did_you_mean(tmp.path(), "ripgerp").unwrap();
    assert!(!sugg.is_empty(), "expected suggestions for 'ripgerp'");
    assert_eq!(sugg[0].name, "ripgrep");
    assert_eq!(sugg[0].bin.as_deref(), Some("rg"));
}

#[test]
fn queries_without_index_say_run_update() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        index::search(tmp.path(), "x"),
        Err(index::IndexError::NoIndex)
    ));
}

#[test]
fn legacy_app_index_remains_searchable() {
    let tmp = tempfile::tempdir().unwrap();
    let db = build_index_at(tmp.path());
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "DROP TABLE packages_fts;
         CREATE VIRTUAL TABLE packages_fts USING fts5(name, description, bin_names);
         INSERT INTO packages_fts VALUES
           ('ripgrep', 'Recursively search directories with a regex', 'rg'),
           ('fd', 'A simple, fast alternative to find', 'fd'),
           ('bat', 'A cat clone with syntax highlighting', 'bat');",
    )
    .unwrap();
    drop(conn);

    assert_eq!(index::search(tmp.path(), "rg").unwrap()[0].name, "ripgrep");
    assert_eq!(
        index::did_you_mean(tmp.path(), "ripgerp").unwrap()[0].name,
        "ripgrep"
    );
}

// ---- sign / verify --------------------------------------------------------

#[test]
fn sign_verify_round_trip_and_tamper() {
    let secret = [42u8; 32];
    let pk = index::sign::public_key_hex(&secret);
    let sig = index::sign(b"index bytes", &secret);
    assert!(index::verify(b"index bytes", &sig, &pk).is_ok());
    assert!(index::verify(b"tampered bytes", &sig, &pk).is_err());
}

// ---- update flow ----------------------------------------------------------

/// A tiny fixture server; serves the three index files from a map. `Drop` stops
/// it. `flip_sig`/etc. are baked into the bytes passed in.
struct FixtureServer {
    base: String,
    _handle: thread::JoinHandle<()>,
    stop: mpsc::Sender<()>,
}

impl FixtureServer {
    fn start(index_json: Vec<u8>, snapshot_zst: Vec<u8>, sig: Vec<u8>) -> FixtureServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        let (stop, rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            for req in server.incoming_requests() {
                if rx.try_recv().is_ok() {
                    break;
                }
                let (body, ctype): (&[u8], &str) = match req.url() {
                    "/index.json" => (&index_json, "application/json"),
                    "/index.sqlite.zst" => (&snapshot_zst, "application/octet-stream"),
                    "/index.sig" => (&sig, "application/octet-stream"),
                    _ => {
                        let _ = req.respond(tiny_http::Response::empty(404));
                        continue;
                    }
                };
                let header =
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype.as_bytes()).unwrap();
                let resp = tiny_http::Response::from_data(body).with_header(header);
                let _ = req.respond(resp);
            }
        });
        FixtureServer {
            base: format!("http://127.0.0.1:{port}"),
            _handle: handle,
            stop,
        }
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        // Nudge the accept loop so it observes the stop signal.
        let _ = ureq::get(&format!("{}/quit", self.base)).call();
    }
}

/// Fixed, obviously-fake ephemeral test secret — no key material lives in the
/// repo. Verification works because `use_test_pubkey` points the client's
/// `VOLI_INDEX_PUBKEY` override at the matching public key.
fn dev_secret() -> [u8; 32] {
    [42u8; 32]
}

/// Point index verification at the test key (process-wide, set once).
/// Concurrent tests may race here, but they all write the identical value.
fn use_test_pubkey() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let pk = index::sign::public_key_hex(&dev_secret());
        // SAFETY: single value, set before any reader in this test binary cares.
        unsafe { std::env::set_var("VOLI_INDEX_PUBKEY", pk) };
    });
}

/// Build a snapshot + its index.json + a valid test-key signature.
fn make_publishable(epoch: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use_test_pubkey();
    let build_dir = tempfile::tempdir().unwrap();
    let db_path = build_dir.path().join("index.sqlite");
    index::build(&fixtures(), &db_path).unwrap();
    let db_bytes = std::fs::read(&db_path).unwrap();

    let sha = hex::encode(Sha256::digest(&db_bytes));
    let index_json = serde_json::json!({
        "epoch": epoch,
        "sha256": sha,
        "size": db_bytes.len(),
    });
    let index_json = serde_json::to_vec(&index_json).unwrap();
    let snapshot_zst = zstd::stream::encode_all(&db_bytes[..], 3).unwrap();
    let sig = index::sign(&db_bytes, &dev_secret()).to_vec();
    (db_bytes, index_json, snapshot_zst, sig)
}

#[test]
fn update_fresh_fetch_then_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let (db_bytes, index_json, snap, sig) = make_publishable(1);
    let srv = FixtureServer::start(index_json, snap, sig);

    // fresh fetch installs the index
    let out = index::update(tmp.path(), &srv.base).unwrap();
    assert_eq!(
        out,
        UpdateOutcome::Updated {
            epoch: 1,
            size: db_bytes.len() as u64
        }
    );
    assert!(index::index_db_path(tmp.path()).exists());
    // index is now queryable
    assert!(
        index::search(tmp.path(), "ripgrep")
            .unwrap()
            .iter()
            .any(|h| h.name == "ripgrep")
    );

    // same epoch → no-op
    let out2 = index::update(tmp.path(), &srv.base).unwrap();
    assert_eq!(out2, UpdateOutcome::UpToDate { epoch: 1 });
}

#[test]
fn update_rejects_tampered_signature_keeping_old_index() {
    let tmp = tempfile::tempdir().unwrap();

    // First, install a good epoch-1 index.
    let (good_bytes, ij1, snap1, sig1) = make_publishable(1);
    {
        let srv = FixtureServer::start(ij1, snap1, sig1);
        index::update(tmp.path(), &srv.base).unwrap();
    }

    // Now serve epoch-2 with a corrupted signature.
    let (_b2, ij2, snap2, mut sig2) = make_publishable(2);
    sig2[0] ^= 0xff;
    let srv = FixtureServer::start(ij2, snap2, sig2);
    let err = index::update(tmp.path(), &srv.base).unwrap_err();
    assert!(matches!(err, index::IndexError::BadSignature));

    // The old (epoch-1) index must be untouched.
    let on_disk = std::fs::read(index::index_db_path(tmp.path())).unwrap();
    assert_eq!(on_disk, good_bytes);
}

#[test]
fn update_rejects_sha_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let (_bytes, index_json, snap, sig) = make_publishable(1);
    // corrupt the advertised sha256 in index.json
    let mut val: serde_json::Value = serde_json::from_slice(&index_json).unwrap();
    val["sha256"] = serde_json::Value::String("b".repeat(64));
    let bad_json = serde_json::to_vec(&val).unwrap();

    let srv = FixtureServer::start(bad_json, snap, sig);
    let err = index::update(tmp.path(), &srv.base).unwrap_err();
    assert!(
        matches!(err, index::IndexError::Sha256Mismatch { .. }),
        "expected sha mismatch, got {err:?}"
    );
    // nothing was written
    assert!(!index::index_db_path(tmp.path()).exists());
}

#[test]
fn update_offline_reports_local_copy() {
    let tmp = tempfile::tempdir().unwrap();
    // No server: point at a dead port.
    let out = index::update(tmp.path(), "http://127.0.0.1:9").unwrap();
    assert!(matches!(
        out,
        UpdateOutcome::Offline {
            local_epoch: None,
            ..
        }
    ));
}
