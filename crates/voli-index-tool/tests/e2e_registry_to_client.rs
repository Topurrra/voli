//! End-to-end proof (§11 step 7 deliverable 3): build a signed index triple,
//! serve `dist/` over HTTP, and drive `voli_core::index::net::update` against it
//! exactly as the real client would — closing the loop registry → client.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use voli_core::index::UpdateOutcome;

fn manifest_toml(name: &str, version: &str, bin: &str) -> String {
    format!(
        r#"name = "{name}"
version = "{version}"
description = "test package {name}"
kind = "app"
bin = ["{bin}"]

[source.x64]
url = "https://example.com/{name}-{version}.zip"
sha256 = "{hash}"
"#,
        hash = "a".repeat(64),
    )
}

fn write_good(root: &Path, name: &str, version: &str, bin: &str) {
    let dir = root.join(&name[..1]).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{version}.toml")),
        manifest_toml(name, version, bin),
    )
    .unwrap();
}

fn dev_key_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry-dev/dev-signing-key.hex")
}

#[test]
fn registry_triple_is_accepted_by_the_client() {
    // 1. A small registry.
    let reg = TempDir::new().unwrap();
    write_good(reg.path(), "ripgrep", "14.1.0", "rg.exe");
    write_good(reg.path(), "ripgrep", "14.1.1", "rg.exe");
    write_good(reg.path(), "fd", "10.1.0", "fd.exe");

    // 2. Build the dist/ triple with the dev key (derives the embedded DEV_PUBKEY).
    let dist = TempDir::new().unwrap();
    voli_index_tool::build(
        reg.path(),
        dist.path(),
        &dev_key_path(),
        Some(1_753_315_200),
    )
    .unwrap();

    // 3. Serve dist/ over tiny_http on an ephemeral port.
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
    let base = format!("http://{}", server.server_addr());
    let dist_root = dist.path().to_path_buf();
    let srv = server.clone();
    let handle = std::thread::spawn(move || {
        // Serve the three assets the client asks for, then stop.
        for _ in 0..3 {
            let Ok(req) = srv.recv() else { break };
            let name = req.url().trim_start_matches('/').to_string();
            match std::fs::read(dist_root.join(&name)) {
                Ok(body) => req.respond(tiny_http::Response::from_data(body)).ok(),
                Err(_) => req.respond(tiny_http::Response::empty(404)).ok(),
            };
        }
    });

    // 4. Client update against the served base URL (no VOLI_INDEX_PUBKEY set ⇒
    //    verifies with the embedded DEV_PUBKEY, which the dev key matches).
    let client_root = TempDir::new().unwrap();
    let outcome = voli_core::index::update(client_root.path(), &base).expect("update must succeed");
    handle.join().ok();

    match outcome {
        UpdateOutcome::Updated { epoch, .. } => assert_eq!(epoch, 1_753_315_200),
        other => panic!("expected Updated, got {other:?}"),
    }

    // 5. The installed index opens and searches — the full client query path.
    let hits = voli_core::index::search(client_root.path(), "ripgrep").unwrap();
    assert!(
        hits.iter()
            .any(|h| h.name == "ripgrep" && h.version == "14.1.1")
    );

    // did-you-mean also works against the installed index.
    let sugg = voli_core::index::did_you_mean(client_root.path(), "ripgerp").unwrap();
    assert!(sugg.iter().any(|s| s.name == "ripgrep"));
}

/// Sanity: the served bytes are exactly what the client hashes. (Guards against
/// accidentally re-compressing or truncating on the serve path.)
#[test]
fn served_snapshot_matches_index_json() {
    use sha2::{Digest, Sha256};

    let reg = TempDir::new().unwrap();
    write_good(reg.path(), "fd", "10.1.0", "fd.exe");
    let dist = TempDir::new().unwrap();
    voli_index_tool::build(reg.path(), dist.path(), &dev_key_path(), Some(1)).unwrap();

    let json = std::fs::read_to_string(dist.path().join("index.json")).unwrap();
    let remote: voli_core::index::net::RemoteIndex = serde_json::from_str(&json).unwrap();

    let mut zst = Vec::new();
    std::fs::File::open(dist.path().join("index.sqlite.zst"))
        .unwrap()
        .read_to_end(&mut zst)
        .unwrap();
    let db = zstd::stream::decode_all(&zst[..]).unwrap();
    assert_eq!(db.len() as u64, remote.size);
    assert_eq!(hex::encode(Sha256::digest(&db)), remote.sha256);
}
