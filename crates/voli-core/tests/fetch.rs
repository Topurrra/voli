//! Integration tests for the download module (spec §11 step 9 deliverable 4).
//!
//! Each test runs a tiny in-process HTTP server. The server counts requests and
//! implements just enough `Range` handling to exercise resume and the
//! server-ignores-Range fallback.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use sha2::{Digest, Sha256};
use voli_core::download;
use voli_core::fetch::FetchError;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// How the fixture server should treat `Range` request headers.
#[derive(Clone, Copy, PartialEq)]
enum RangeMode {
    /// Honour `Range: bytes=N-` with a 206 + `Content-Range`.
    Honour,
    /// Ignore `Range` and always return the full body with 200.
    Ignore,
}

/// A one-file HTTP server. Serves `body` at `/file.bin`, counting requests.
struct Server {
    base: String,
    hits: Arc<AtomicUsize>,
    stop: mpsc::Sender<()>,
    _handle: thread::JoinHandle<()>,
}

impl Server {
    fn start(body: Vec<u8>, mode: RangeMode) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_thread = hits.clone();
        let (stop, rx) = mpsc::channel::<()>();
        let body = Arc::new(body);
        let handle = thread::spawn(move || {
            for req in server.incoming_requests() {
                if rx.try_recv().is_ok() {
                    break;
                }
                if req.url() == "/quit" {
                    let _ = req.respond(tiny_http::Response::empty(200));
                    break;
                }
                if req.url() != "/file.bin" {
                    let _ = req.respond(tiny_http::Response::empty(404));
                    continue;
                }
                hits_thread.fetch_add(1, Ordering::SeqCst);
                let range_from = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Range"))
                    .and_then(|h| parse_range(h.value.as_str()));

                match (mode, range_from) {
                    (RangeMode::Honour, Some(from)) if (from as usize) < body.len() => {
                        let slice = &body[from as usize..];
                        let cr = format!("bytes {}-{}/{}", from, body.len() - 1, body.len());
                        let resp = tiny_http::Response::from_data(slice.to_vec())
                            .with_status_code(206)
                            .with_header(header("Content-Range", &cr));
                        let _ = req.respond(resp);
                    }
                    _ => {
                        let resp = tiny_http::Response::from_data(body.to_vec());
                        let _ = req.respond(resp);
                    }
                }
            }
        });
        Server {
            base: format!("http://127.0.0.1:{port}"),
            hits,
            stop,
            _handle: handle,
        }
    }

    fn url(&self) -> String {
        format!("{}/file.bin", self.base)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        let _ = ureq::get(&format!("{}/quit", self.base)).call();
    }
}

fn header(name: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

/// Parse `bytes=N-` → N.
fn parse_range(v: &str) -> Option<u64> {
    v.strip_prefix("bytes=")
        .and_then(|r| r.split('-').next())
        .and_then(|n| n.parse().ok())
}

fn body_fixture() -> Vec<u8> {
    // Non-trivial size so a Range split is meaningful.
    (0..5000u32).flat_map(|n| n.to_le_bytes()).collect()
}

#[test]
fn happy_path_downloads_and_verifies() {
    let body = body_fixture();
    let sha = sha256_hex(&body);
    let srv = Server::start(body.clone(), RangeMode::Honour);
    let cache = tempfile::tempdir().unwrap();

    let mut last: Option<(u64, Option<u64>)> = None;
    let path = download(&srv.url(), &sha, cache.path(), &mut |d, t| {
        last = Some((d, t))
    })
    .unwrap();

    assert!(path.exists());
    assert_eq!(std::fs::read(&path).unwrap(), body);
    assert_eq!(sha256_hex(&std::fs::read(&path).unwrap()), sha);
    // Final progress reported the full size.
    assert_eq!(last, Some((body.len() as u64, Some(body.len() as u64))));
    // No stray .part left behind.
    let leftovers: Vec<_> = std::fs::read_dir(cache.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "part file should be gone");
}

#[test]
fn hash_mismatch_removes_artifact_and_errors() {
    let body = body_fixture();
    let wrong_sha = "a".repeat(64);
    let srv = Server::start(body, RangeMode::Honour);
    let cache = tempfile::tempdir().unwrap();

    let err = download(&srv.url(), &wrong_sha, cache.path(), &mut |_, _| {}).unwrap_err();
    assert!(
        matches!(err, FetchError::HashMismatch { .. }),
        "got {err:?}"
    );

    // Nothing left in the cache — no poison.
    let entries: Vec<_> = std::fs::read_dir(cache.path()).unwrap().collect();
    assert!(entries.is_empty(), "cache must be empty after a mismatch");
}

#[test]
fn cache_hit_skips_the_network() {
    let body = body_fixture();
    let sha = sha256_hex(&body);
    let srv = Server::start(body.clone(), RangeMode::Honour);
    let cache = tempfile::tempdir().unwrap();

    let p1 = download(&srv.url(), &sha, cache.path(), &mut |_, _| {}).unwrap();
    assert_eq!(srv.hits(), 1);

    // Second call must be served from cache — no further request.
    let p2 = download(&srv.url(), &sha, cache.path(), &mut |_, _| {}).unwrap();
    assert_eq!(p1, p2);
    assert_eq!(srv.hits(), 1, "cache hit must not touch the network");
}

#[test]
fn resume_continues_from_existing_part() {
    let body = body_fixture();
    let sha = sha256_hex(&body);
    let srv = Server::start(body.clone(), RangeMode::Honour);
    let cache = tempfile::tempdir().unwrap();

    // Pre-seed a correct prefix as the .part (download names it <sha>.bin.part).
    let half = body.len() / 2;
    let part = cache.path().join(format!("{sha}.bin.part"));
    std::fs::write(&part, &body[..half]).unwrap();

    let path = download(&srv.url(), &sha, cache.path(), &mut |_, _| {}).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), body);
    // The server should have received a ranged request (206 path), one hit.
    assert_eq!(srv.hits(), 1);
}

#[test]
fn restarts_when_server_ignores_range() {
    let body = body_fixture();
    let sha = sha256_hex(&body);
    // This server always returns 200 + full body, ignoring Range.
    let srv = Server::start(body.clone(), RangeMode::Ignore);
    let cache = tempfile::tempdir().unwrap();

    // A stale/partial .part is present; the server ignores our Range → we must
    // restart cleanly from zero and still end with the correct file.
    let part = cache.path().join(format!("{sha}.bin.part"));
    std::fs::write(&part, &body[..body.len() / 3]).unwrap();

    let path = download(&srv.url(), &sha, cache.path(), &mut |_, _| {}).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), body);
    assert_eq!(sha256_hex(&std::fs::read(&path).unwrap()), sha);
}
