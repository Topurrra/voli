//! End-to-end tests for `install_remote` (spec §11 step 9 deliverable 4).
//!
//! A local HTTP server serves fixture zip archives at the URLs baked into the
//! index manifests; `install_remote` resolves against a locally-built index,
//! downloads from that server, and runs the real local install engine.

#![cfg(windows)]

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use sha2::{Digest, Sha256};
use voli_core::index;
use voli_core::remote::{PrefetchStep, prefetch_remote};
use voli_core::{
    Manifest, RemoteError, SkillError, SkillRemoteReport, SkillTarget, State, Step, install_remote,
    install_skill_remote, uninstall, uninstall_skill,
};
use zip::write::SimpleFileOptions;

// ---- shim stub (shared, set once) -----------------------------------------

use std::sync::Once;
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

// ---- fixtures --------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A zip whose wrapper dir is `<name>-<version>` and whose only bin is `<bin>`.
fn pkg_zip(name: &str, version: &str, bin: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.add_directory(format!("{name}-{version}/"), opts).unwrap();
        w.start_file(format!("{name}-{version}/{bin}"), opts)
            .unwrap();
        w.write_all(format!("fake {name} {version}").as_bytes())
            .unwrap();
        w.finish().unwrap();
    }
    buf
}

fn skill_zip(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.add_directory(format!("{name}/"), options).unwrap();
        writer
            .start_file(format!("{name}/SKILL.md"), options)
            .unwrap();
        writer
            .write_all(
                format!(
                    "---\nname: {name}\ndescription: Remote test skill\n---\n# Test\n\nInstructions.\n"
                )
                .as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
    }
    buf
}

fn manifest_toml(
    name: &str,
    version: &str,
    url: &str,
    sha: &str,
    bin: &str,
    deps: &[&str],
) -> String {
    let mut depends = String::new();
    if !deps.is_empty() {
        depends.push_str("\n[depends]\n");
        for d in deps {
            depends.push_str(&format!("{d} = \"*\"\n"));
        }
    }
    format!(
        r#"
name = "{name}"
version = "{version}"
description = "{name} package"
kind = "app"
extract_dir = "{name}-{version}"
bin = ["{bin}"]

[source.x64]
url = "{url}"
sha256 = "{sha}"
{depends}
"#
    )
}

/// Like [`manifest_toml`] but each dependency carries its own version
/// constraint string (`("lib", ">=1.2")`) instead of the implicit `"*"`.
fn manifest_toml_deps(
    name: &str,
    version: &str,
    url: &str,
    sha: &str,
    bin: &str,
    deps: &[(&str, &str)],
) -> String {
    let mut depends = String::new();
    if !deps.is_empty() {
        depends.push_str("\n[depends]\n");
        for (d, c) in deps {
            depends.push_str(&format!("{d} = \"{c}\"\n"));
        }
    }
    format!(
        r#"
name = "{name}"
version = "{version}"
description = "{name} package"
kind = "app"
extract_dir = "{name}-{version}"
bin = ["{bin}"]

[source.x64]
url = "{url}"
sha256 = "{sha}"
{depends}
"#
    )
}

// ---- fixture server --------------------------------------------------------

/// Serves a map of path → bytes, counting requests per path.
struct Server {
    base: String,
    hits: Arc<Mutex<HashMap<String, AtomicUsize>>>,
    stop: mpsc::Sender<()>,
    _handle: thread::JoinHandle<()>,
}

impl Server {
    fn start(files: HashMap<String, Vec<u8>>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        let hits: Arc<Mutex<HashMap<String, AtomicUsize>>> = Arc::new(Mutex::new(
            files
                .keys()
                .map(|k| (k.clone(), AtomicUsize::new(0)))
                .collect(),
        ));
        let hits_thread = hits.clone();
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
                        if let Some(c) = hits_thread.lock().unwrap().get(&url) {
                            c.fetch_add(1, Ordering::SeqCst);
                        }
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
            hits,
            stop,
            _handle: handle,
        }
    }

    fn hits(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .get(path)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        let _ = ureq::get(&format!("{}/quit", self.base)).call();
    }
}

/// Record just the install/skip order from the step stream.
fn recorder(log: &Mutex<Vec<String>>) -> impl FnMut(Step) + '_ {
    move |step: Step| match step {
        Step::Installed(r) => log
            .lock()
            .unwrap()
            .push(format!("installed {}@{}", r.name, r.version)),
        Step::Skipped { name, version } => log
            .lock()
            .unwrap()
            .push(format!("skipped {name}@{version}")),
        _ => {}
    }
}

fn build_index(root: &Path, manifests: &[Manifest]) {
    index::build(manifests, &index::index_db_path(root)).unwrap();
}

// ---- tests -----------------------------------------------------------------

#[test]
fn remote_skill_installs_and_deletes_for_one_target() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("voli");
    let home = temp.path().join("home");
    let archive = skill_zip("tdd");
    let server = Server::start(HashMap::from([("/tdd.zip".to_string(), archive.clone())]));
    let manifest = Manifest::from_toml_str(&format!(
        r#"name = "tdd"
version = "1.0.0"
kind = "skill"

[source.any]
url = "{}/tdd.zip"
sha256 = "{}"
"#,
        server.base,
        sha256_hex(&archive)
    ))
    .unwrap();
    build_index(&root, &[manifest]);

    let report =
        install_skill_remote("tdd", None, SkillTarget::Codex, &home, &root, &mut |_| {}).unwrap();
    assert!(matches!(report, SkillRemoteReport::Installed(_)));
    assert!(home.join(".agents/skills/tdd/SKILL.md").is_file());
    assert_eq!(server.hits("/tdd.zip"), 1);

    uninstall_skill("tdd", SkillTarget::Codex, &home, &root).unwrap();
    assert!(!home.join(".agents/skills/tdd").exists());
}

#[test]
fn remote_skill_rejects_a_different_installed_version() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("voli");
    let home = temp.path().join("home");
    let archive = skill_zip("tdd");
    let server = Server::start(HashMap::from([("/tdd.zip".to_string(), archive.clone())]));
    let make_manifest = |version: &str| {
        Manifest::from_toml_str(&format!(
            r#"name = "tdd"
version = "{version}"
kind = "skill"

[source.any]
url = "{}/tdd.zip"
sha256 = "{}"
"#,
            server.base,
            sha256_hex(&archive)
        ))
        .unwrap()
    };
    build_index(&root, &[make_manifest("1.0.0")]);
    install_skill_remote("tdd", None, SkillTarget::Codex, &home, &root, &mut |_| {}).unwrap();

    build_index(&root, &[make_manifest("2.0.0")]);
    assert!(matches!(
        install_skill_remote("tdd", None, SkillTarget::Codex, &home, &root, &mut |_| {}),
        Err(RemoteError::Skill(SkillError::VersionConflict {
            installed,
            requested,
            ..
        })) if installed == "1.0.0" && requested == "2.0.0"
    ));
    assert_eq!(server.hits("/tdd.zip"), 1);
}

#[test]
fn install_by_name_resolves_latest() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let z1 = pkg_zip("ripgrep", "1.0.0", "rg.exe");
    let z2 = pkg_zip("ripgrep", "2.0.0", "rg.exe");
    let mut files = HashMap::new();
    files.insert("/rg-1.0.0.zip".to_string(), z1.clone());
    files.insert("/rg-2.0.0.zip".to_string(), z2.clone());
    let srv = Server::start(files);

    let m1 = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "1.0.0",
        &format!("{}/rg-1.0.0.zip", srv.base),
        &sha256_hex(&z1),
        "rg.exe",
        &[],
    ))
    .unwrap();
    let m2 = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "2.0.0",
        &format!("{}/rg-2.0.0.zip", srv.base),
        &sha256_hex(&z2),
        "rg.exe",
        &[],
    ))
    .unwrap();
    build_index(root, &[m1, m2]);

    let report = install_remote("ripgrep", None, root, &mut |_| {}).unwrap();
    assert_eq!(report.installed.len(), 1);
    assert_eq!(report.installed[0].version, "2.0.0");
    assert!(root.join("apps/ripgrep/2.0.0/rg.exe").is_file());
    assert!(root.join("shims/rg.exe").is_file());
}

#[test]
fn at_version_pins_exact() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let z1 = pkg_zip("ripgrep", "1.0.0", "rg.exe");
    let z2 = pkg_zip("ripgrep", "2.0.0", "rg.exe");
    let mut files = HashMap::new();
    files.insert("/rg-1.0.0.zip".to_string(), z1.clone());
    files.insert("/rg-2.0.0.zip".to_string(), z2.clone());
    let srv = Server::start(files);

    let m1 = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "1.0.0",
        &format!("{}/rg-1.0.0.zip", srv.base),
        &sha256_hex(&z1),
        "rg.exe",
        &[],
    ))
    .unwrap();
    let m2 = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "2.0.0",
        &format!("{}/rg-2.0.0.zip", srv.base),
        &sha256_hex(&z2),
        "rg.exe",
        &[],
    ))
    .unwrap();
    build_index(root, &[m1, m2]);

    let report = install_remote("ripgrep", Some("1.0.0"), root, &mut |_| {}).unwrap();
    assert_eq!(report.installed[0].version, "1.0.0");
    assert!(root.join("apps/ripgrep/1.0.0/rg.exe").is_file());
    assert!(!root.join("apps/ripgrep/2.0.0").exists());
}

#[test]
fn dep_chain_installs_dependency_first() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let app = pkg_zip("app", "1.0.0", "app.exe");
    let lib = pkg_zip("lib", "1.0.0", "lib.exe");
    let mut files = HashMap::new();
    files.insert("/app.zip".to_string(), app.clone());
    files.insert("/lib.zip".to_string(), lib.clone());
    let srv = Server::start(files);

    let m_app = Manifest::from_toml_str(&manifest_toml(
        "app",
        "1.0.0",
        &format!("{}/app.zip", srv.base),
        &sha256_hex(&app),
        "app.exe",
        &["lib"],
    ))
    .unwrap();
    let m_lib = Manifest::from_toml_str(&manifest_toml(
        "lib",
        "1.0.0",
        &format!("{}/lib.zip", srv.base),
        &sha256_hex(&lib),
        "lib.exe",
        &[],
    ))
    .unwrap();
    build_index(root, &[m_app, m_lib]);

    let log = Mutex::new(Vec::new());
    let report = install_remote("app", None, root, &mut recorder(&log)).unwrap();

    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "installed lib@1.0.0".to_string(),
            "installed app@1.0.0".to_string()
        ],
        "dependency must install before the dependent",
    );
    assert_eq!(report.installed.len(), 2);
    assert!(root.join("apps/lib/1.0.0/lib.exe").is_file());
    assert!(root.join("apps/app/1.0.0/app.exe").is_file());
}

/// Install `app@1.0.0` (which depends on `lib` at `constraint`) against an index
/// that publishes `lib` at every version in `lib_versions`. Returns the recorded
/// install/skip log and the install result (mapped to `()` on success).
fn run_dep_install(
    constraint: &str,
    lib_versions: &[&str],
) -> (Vec<String>, Result<(), RemoteError>) {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let app = pkg_zip("app", "1.0.0", "app.exe");
    let mut files = HashMap::new();
    files.insert("/app.zip".to_string(), app.clone());
    let mut lib_zips: Vec<(String, Vec<u8>)> = Vec::new();
    for v in lib_versions {
        let z = pkg_zip("lib", v, "lib.exe");
        files.insert(format!("/lib-{v}.zip"), z.clone());
        lib_zips.push(((*v).to_string(), z));
    }
    let srv = Server::start(files);

    let mut manifests = vec![
        Manifest::from_toml_str(&manifest_toml_deps(
            "app",
            "1.0.0",
            &format!("{}/app.zip", srv.base),
            &sha256_hex(&app),
            "app.exe",
            &[("lib", constraint)],
        ))
        .unwrap(),
    ];
    for (v, z) in &lib_zips {
        manifests.push(
            Manifest::from_toml_str(&manifest_toml_deps(
                "lib",
                v,
                &format!("{}/lib-{v}.zip", srv.base),
                &sha256_hex(z),
                "lib.exe",
                &[],
            ))
            .unwrap(),
        );
    }
    build_index(root, &manifests);

    let log = Mutex::new(Vec::new());
    let result = install_remote("app", None, root, &mut recorder(&log)).map(|_| ());
    let out = log.lock().unwrap().clone();
    (out, result)
}

#[test]
fn dep_star_picks_newest() {
    let (log, result) = run_dep_install("*", &["1.0.0", "2.0.0"]);
    result.unwrap();
    assert!(
        log.contains(&"installed lib@2.0.0".to_string()),
        "`*` must resolve to the newest version, got {log:?}",
    );
}

#[test]
fn dep_exact_pin_resolves_that_version() {
    let (log, result) = run_dep_install("1.0.0", &["1.0.0", "2.0.0"]);
    result.unwrap();
    assert!(
        log.contains(&"installed lib@1.0.0".to_string()),
        "exact pin must resolve to 1.0.0 (not the newer 2.0.0), got {log:?}",
    );
}

#[test]
fn dep_range_picks_newest_satisfying() {
    let (log, result) = run_dep_install(">=1.5", &["1.0.0", "1.5.0", "2.0.0"]);
    result.unwrap();
    assert!(
        log.contains(&"installed lib@2.0.0".to_string()),
        ">=1.5 must resolve to the newest satisfying version 2.0.0, got {log:?}",
    );
}

#[test]
fn dep_unsatisfiable_constraint_errors() {
    let (log, result) = run_dep_install(">=9.0", &["1.0.0", "2.0.0"]);
    assert!(
        matches!(&result, Err(RemoteError::Unsatisfiable { dep, constraint })
            if dep == "lib" && constraint == ">=9.0"),
        "got {result:?}",
    );
    assert!(
        log.is_empty(),
        "nothing should install when a dependency constraint is unsatisfiable: {log:?}",
    );
}

#[test]
fn missing_dependency_errors() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let broken = pkg_zip("broken", "1.0.0", "b.exe");
    let mut files = HashMap::new();
    files.insert("/broken.zip".to_string(), broken.clone());
    let srv = Server::start(files);

    let m = Manifest::from_toml_str(&manifest_toml(
        "broken",
        "1.0.0",
        &format!("{}/broken.zip", srv.base),
        &sha256_hex(&broken),
        "b.exe",
        &["ghost"],
    ))
    .unwrap();
    build_index(root, &[m]);

    let err = install_remote("broken", None, root, &mut |_| {}).unwrap_err();
    assert!(
        matches!(&err, RemoteError::UnknownDep { package, dep } if package == "broken" && dep == "ghost"),
        "got {err:?}",
    );
    // Nothing installed.
    assert!(!root.join("apps/broken").exists());
}

#[test]
fn typo_returns_did_you_mean() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let z = pkg_zip("ripgrep", "1.0.0", "rg.exe");
    let mut files = HashMap::new();
    files.insert("/rg.zip".to_string(), z.clone());
    let srv = Server::start(files);

    let m = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "1.0.0",
        &format!("{}/rg.zip", srv.base),
        &sha256_hex(&z),
        "rg.exe",
        &[],
    ))
    .unwrap();
    build_index(root, &[m]);

    let err = install_remote("ripgerp", None, root, &mut |_| {}).unwrap_err();
    match err {
        RemoteError::NotFound { name, suggestions } => {
            assert_eq!(name, "ripgerp");
            assert!(
                suggestions.iter().any(|s| s.name == "ripgrep"),
                "suggestions should include ripgrep, got {suggestions:?}",
            );
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn second_install_skips_cached_download() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let z = pkg_zip("ripgrep", "1.0.0", "rg.exe");
    let mut files = HashMap::new();
    files.insert("/rg.zip".to_string(), z.clone());
    let srv = Server::start(files);

    let m = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "1.0.0",
        &format!("{}/rg.zip", srv.base),
        &sha256_hex(&z),
        "rg.exe",
        &[],
    ))
    .unwrap();
    build_index(root, &[m]);

    install_remote("ripgrep", None, root, &mut |_| {}).unwrap();
    assert_eq!(srv.hits("/rg.zip"), 1);

    // Uninstall removes the app but keeps the hash-keyed cache entry.
    uninstall("ripgrep", root, false).unwrap();

    // Reinstall: download is a cache hit → no new request.
    install_remote("ripgrep", None, root, &mut |_| {}).unwrap();
    assert_eq!(
        srv.hits("/rg.zip"),
        1,
        "reinstall must reuse the cached archive"
    );

    // And it is installed again.
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    assert!(state.is_installed("ripgrep").unwrap());
}

#[test]
fn already_installed_is_skipped() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let z = pkg_zip("ripgrep", "1.0.0", "rg.exe");
    let mut files = HashMap::new();
    files.insert("/rg.zip".to_string(), z.clone());
    let srv = Server::start(files);

    let m = Manifest::from_toml_str(&manifest_toml(
        "ripgrep",
        "1.0.0",
        &format!("{}/rg.zip", srv.base),
        &sha256_hex(&z),
        "rg.exe",
        &[],
    ))
    .unwrap();
    build_index(root, &[m]);

    install_remote("ripgrep", None, root, &mut |_| {}).unwrap();
    let report = install_remote("ripgrep", None, root, &mut |_| {}).unwrap();
    assert!(report.installed.is_empty());
    assert_eq!(
        report.skipped,
        vec![("ripgrep".to_string(), "1.0.0".to_string())]
    );
}

#[test]
fn parallel_prefetch_populates_cache_before_sequential_install() {
    ensure_stub();
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    let ripgrep = pkg_zip("ripgrep", "1.0.0", "rg.exe");
    let fd = pkg_zip("fd", "1.0.0", "fd.exe");
    let srv = Server::start(HashMap::from([
        ("/rg.zip".to_string(), ripgrep.clone()),
        ("/fd.zip".to_string(), fd.clone()),
    ]));
    let manifests = [
        Manifest::from_toml_str(&manifest_toml(
            "ripgrep",
            "1.0.0",
            &format!("{}/rg.zip", srv.base),
            &sha256_hex(&ripgrep),
            "rg.exe",
            &[],
        ))
        .unwrap(),
        Manifest::from_toml_str(&manifest_toml(
            "fd",
            "1.0.0",
            &format!("{}/fd.zip", srv.base),
            &sha256_hex(&fd),
            "fd.exe",
            &[],
        ))
        .unwrap(),
    ];
    build_index(root, &manifests);

    let mut prepared = 0;
    prefetch_remote(
        &[("ripgrep".to_string(), None), ("fd".to_string(), None)],
        root,
        &mut |step| {
            if matches!(step, PrefetchStep::Prepared { .. }) {
                prepared += 1;
            }
        },
    )
    .unwrap();
    assert_eq!(prepared, 2);
    assert_eq!(srv.hits("/rg.zip"), 1);
    assert_eq!(srv.hits("/fd.zip"), 1);

    let mut cache_hits = 0;
    install_remote("ripgrep", None, root, &mut |step| {
        if matches!(
            step,
            Step::Installing {
                cache_hit: true,
                ..
            }
        ) {
            cache_hits += 1;
        }
    })
    .unwrap();
    install_remote("fd", None, root, &mut |_| {}).unwrap();
    assert_eq!(cache_hits, 1);
    assert_eq!(srv.hits("/rg.zip"), 1);
    assert_eq!(srv.hits("/fd.zip"), 1);
}
