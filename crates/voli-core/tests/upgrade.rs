//! Upgrade / cleanup tests (spec §3, §11 step 10 deliverable 4).
//!
//! A local HTTP server serves fixture zips at the URLs baked into a
//! locally-built index; we install v1, upgrade to v2 (junction flip), and prove
//! the §3 promises: the junction points at v2, the old dir survives for
//! cleanup, shims track the new bin set, cleanup removes only the old dir, and
//! uninstall-after-upgrade leaves zero trace (all version dirs gone).

#![cfg(windows)]

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Once;
use std::sync::mpsc;
use std::thread;

use sha2::{Digest, Sha256};
use voli_core::{
    State, UpgradeOutcome, cleanup_versions, index, install_remote, uninstall, upgrade,
};
use zip::write::SimpleFileOptions;

static STUB: Once = Once::new();

fn ensure_stub() {
    STUB.call_once(|| {
        let real = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .and_then(|deps| deps.parent().map(|d| d.join("voli-shim.exe")))
            .filter(|p| p.exists());
        let stub = real.unwrap_or_else(|| {
            let p = std::env::temp_dir().join("voli-test-shim-stub.exe");
            fs::write(&p, b"dummy shim stub").unwrap();
            p
        });
        // SAFETY: set once, before any install runs.
        unsafe {
            std::env::set_var("VOLI_SHIM_STUB", stub);
            // Binary-wide scratch registry/shortcut hooks: without these, any
            // in-process install writes to the user REAL Apps & Features
            // registry (found polluted 2026-07-24).
            std::env::set_var(
                "VOLI_UNINSTALL_SUBKEY",
                concat!("Software\\voli-scratch-", env!("CARGO_CRATE_NAME")),
            );
            let sdir =
                std::env::temp_dir().join(concat!("voli-scratch-lnk-", env!("CARGO_CRATE_NAME")));
            let _ = fs::create_dir_all(&sdir);
            std::env::set_var("VOLI_SHORTCUT_DIR", sdir);
        };
    });
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A zip with wrapper dir `app-<version>/` holding the given bins plus a
/// `data/` persist dir carrying a file.
fn app_zip(version: &str, bins: &[&str]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.add_directory(format!("app-{version}/"), opts).unwrap();
        for b in bins {
            w.start_file(format!("app-{version}/{b}"), opts).unwrap();
            w.write_all(format!("bin {b} {version}").as_bytes())
                .unwrap();
        }
        w.add_directory(format!("app-{version}/data/"), opts)
            .unwrap();
        w.start_file(format!("app-{version}/data/seed.txt"), opts)
            .unwrap();
        w.write_all(b"seed").unwrap();
        w.finish().unwrap();
    }
    buf
}

fn manifest_toml(version: &str, url: &str, sha: &str, bins: &[&str]) -> String {
    let bin_list = bins
        .iter()
        .map(|b| format!("\"{b}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
name = "app"
version = "{version}"
description = "app package"
kind = "app"
extract_dir = "app-{version}"
bin = [{bin_list}]
persist = ["data"]

[source.x64]
url = "{url}"
sha256 = "{sha}"
"#
    )
}

/// Minimal request-counting file server (same shape as remote.rs tests).
struct Server {
    base: String,
    stop: mpsc::Sender<()>,
    _handle: thread::JoinHandle<()>,
}

impl Server {
    fn start(files: HashMap<String, Vec<u8>>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        let (stop, rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            for req in server.incoming_requests() {
                if rx.try_recv().is_ok() {
                    break;
                }
                let url = req.url().to_string();
                if url == "/quit" {
                    let _ = req.respond(tiny_http::Response::empty(200));
                    break;
                }
                match files.get(&url) {
                    Some(bytes) => {
                        let _ = req.respond(tiny_http::Response::from_data(bytes.clone()));
                    }
                    None => {
                        let _ = req.respond(tiny_http::Response::empty(404));
                    }
                }
            }
        });
        Server {
            base: format!("http://127.0.0.1:{port}"),
            stop,
            _handle: handle,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        let _ = ureq::get(&format!("{}/quit", self.base)).call();
    }
}

/// Build a two-version index (v1 bins app+old, v2 bins app+new) served by a
/// fresh server. Returns (server, root-owning tempdir).
fn setup(root: &Path) -> Server {
    ensure_stub();
    let z1 = app_zip("1.0.0", &["app.exe", "old.exe"]);
    let z2 = app_zip("2.0.0", &["app.exe", "new.exe"]);
    let mut files = HashMap::new();
    files.insert("/app-1.0.0.zip".to_string(), z1.clone());
    files.insert("/app-2.0.0.zip".to_string(), z2.clone());
    let srv = Server::start(files);

    let m1 = voli_core::Manifest::from_toml_str(&manifest_toml(
        "1.0.0",
        &format!("{}/app-1.0.0.zip", srv.base),
        &sha256_hex(&z1),
        &["app.exe", "old.exe"],
    ))
    .unwrap();
    let m2 = voli_core::Manifest::from_toml_str(&manifest_toml(
        "2.0.0",
        &format!("{}/app-2.0.0.zip", srv.base),
        &sha256_hex(&z2),
        &["app.exe", "new.exe"],
    ))
    .unwrap();
    index::build(&[m1, m2], &index::index_db_path(root)).unwrap();
    srv
}

#[test]
fn upgrade_flips_junction_keeps_old_and_tracks_bins() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let _srv = setup(root);

    // Install v1 explicitly, then write into persist to prove it survives.
    install_remote("app", Some("1.0.0"), root, &mut |_| {}).unwrap();
    assert!(root.join("apps/app/1.0.0/app.exe").is_file());
    fs::write(root.join("apps/app/persist/data/user.txt"), b"mine").unwrap();

    // Upgrade to latest (2.0.0).
    let outcome = upgrade("app", root, &mut |_| {}).unwrap();
    match outcome {
        UpgradeOutcome::Upgraded(r) => {
            assert_eq!(r.from_version, "1.0.0");
            assert_eq!(r.to_version, "2.0.0");
        }
        other => panic!("expected Upgraded, got {other:?}"),
    }

    // Junction now resolves to v2: new.exe (v2-only) is reachable, old.exe isn't.
    let current = root.join("apps/app/current");
    assert!(
        current.join("new.exe").is_file(),
        "current must point at v2"
    );
    assert!(!current.join("old.exe").exists(), "v2 dropped old.exe");

    // Old version dir survives on disk (running exes keep working).
    assert!(
        root.join("apps/app/1.0.0/app.exe").is_file(),
        "old dir kept for cleanup"
    );
    assert!(root.join("apps/app/2.0.0/app.exe").is_file());

    // State shows v2.
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert_eq!(
        state.installed_version("app").unwrap().as_deref(),
        Some("2.0.0")
    );
    drop(state);

    // Bin-set change: new shim added, vanished shim removed, kept shim resolves v2.
    assert!(
        root.join("shims/new.exe").is_file(),
        "added bin gets a shim"
    );
    assert!(
        !root.join("shims/old.exe").exists(),
        "dropped bin's shim removed"
    );
    assert!(!root.join("shims/old.shim").exists());
    let app_shim = fs::read_to_string(root.join("shims/app.shim")).unwrap();
    let target = app_shim.lines().next().unwrap().trim();
    assert!(
        target.ends_with("current\\app.exe"),
        "shim target: {target}"
    );
    assert!(
        Path::new(target).is_file(),
        "shim target must resolve (via current -> v2)"
    );

    // Persist untouched by the upgrade.
    assert_eq!(
        fs::read_to_string(root.join("apps/app/persist/data/user.txt")).unwrap(),
        "mine"
    );
}

#[test]
fn cleanup_removes_only_the_old_version() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let _srv = setup(root);

    install_remote("app", Some("1.0.0"), root, &mut |_| {}).unwrap();
    fs::write(root.join("apps/app/persist/data/user.txt"), b"mine").unwrap();
    upgrade("app", root, &mut |_| {}).unwrap();

    // Dry-run reports the old dir but removes nothing.
    let (dry, _bytes) = cleanup_versions(root, "app", "2.0.0", true).unwrap();
    assert_eq!(dry.len(), 1);
    assert!(root.join("apps/app/1.0.0").exists(), "dry-run preserves");

    // Real cleanup removes only v1; v2, current, and persist stay.
    let (removed, freed) = cleanup_versions(root, "app", "2.0.0", false).unwrap();
    assert_eq!(removed.len(), 1);
    assert!(freed > 0);
    assert!(
        !root.join("apps/app/1.0.0").exists(),
        "old version dir removed"
    );
    assert!(
        root.join("apps/app/2.0.0/app.exe").is_file(),
        "current version kept"
    );
    assert!(root.join("apps/app/current/app.exe").is_file());
    // Persist data must NOT be followed into and deleted via the v1 junction.
    assert_eq!(
        fs::read_to_string(root.join("apps/app/persist/data/user.txt")).unwrap(),
        "mine"
    );
}

#[test]
fn uninstall_after_upgrade_leaves_zero_trace() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let _srv = setup(root);

    install_remote("app", Some("1.0.0"), root, &mut |_| {}).unwrap();
    upgrade("app", root, &mut |_| {}).unwrap();

    // Both version dirs exist before uninstall.
    assert!(root.join("apps/app/1.0.0").exists());
    assert!(root.join("apps/app/2.0.0").exists());

    // Purge uninstall removes the whole package tree — every version dir gone.
    uninstall("app", root, true).unwrap();
    assert!(
        !root.join("apps/app").exists(),
        "no trace after upgrade + purge uninstall"
    );
    assert!(!root.join("shims/app.exe").exists());
    assert!(!root.join("shims/new.exe").exists());

    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(!state.is_installed("app").unwrap());
    assert!(state.actions_for("app").unwrap().is_empty());
}

#[test]
fn upgrade_when_already_latest_is_up_to_date() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let _srv = setup(root);

    // Install latest directly, then an upgrade is a no-op.
    install_remote("app", None, root, &mut |_| {}).unwrap();
    let outcome = upgrade("app", root, &mut |_| {}).unwrap();
    assert!(matches!(outcome, UpgradeOutcome::UpToDate { version } if version == "2.0.0"));
}

/// A renamed package must not be silently "upgraded" into the new name.
///
/// The new name is a different package with its own directory and shims, so
/// following the alias here would install its manifest over the old install --
/// and if the versions happened to match, would instead report "up to date"
/// forever while the package quietly stopped receiving updates.
#[test]
fn upgrade_reports_a_rename_instead_of_following_it() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let srv = setup(root);

    install_remote("app", Some("1.0.0"), root, &mut |_| {}).unwrap();
    assert!(root.join("apps/app/1.0.0/app.exe").is_file());

    // Republish the catalog with `app` renamed to `app-ng`, keeping the old
    // name as an alias -- and offering a NEWER version, which is the case that
    // would otherwise overwrite the old install.
    let z2 = app_zip("2.0.0", &["app.exe", "new.exe"]);
    let renamed = voli_core::Manifest::from_toml_str(
        &manifest_toml(
            "2.0.0",
            &format!("{}/app-2.0.0.zip", srv.base),
            &sha256_hex(&z2),
            &["app.exe", "new.exe"],
        )
        .replace("name = \"app\"", "name = \"app-ng\"\naliases = [\"app\"]"),
    )
    .unwrap();
    index::build(&[renamed], &index::index_db_path(root)).unwrap();

    match upgrade("app", root, &mut |_| {}).unwrap() {
        UpgradeOutcome::Renamed { to, version } => {
            assert_eq!(to, "app-ng");
            assert_eq!(version, "1.0.0");
        }
        other => panic!("expected Renamed, got {other:?}"),
    }

    // The old install is untouched and nothing was written under the new name.
    assert!(root.join("apps/app/1.0.0/app.exe").is_file());
    assert!(!root.join("apps/app-ng").exists());
    assert!(!root.join("apps/app/2.0.0").exists());

    // Installing the new name still works, and reaches it through the alias.
    assert_eq!(index::info(root, "app").unwrap().unwrap().name, "app-ng");
}
