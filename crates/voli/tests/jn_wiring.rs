//! The machine interface JN apps use (schema 1): `version --json`,
//! `where --json`, `provides`, `info --summary`, `path`, `which --json`,
//! `delete --json`, and `--progress` events for install/update/delete.
//!
//! Drives the real `voli` binary against a scratch VOLI_ROOT, a test index
//! built in-process, and a local HTTP server for downloads. Registry, Start
//! Menu and env writes go to scratch hooks, never the real ones.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;

use serde_json::Value;
use sha2::{Digest, Sha256};
use voli_core::{Manifest, index};
use zip::write::SimpleFileOptions;

// ---- fixtures ---------------------------------------------------------------

fn shim_stub() -> PathBuf {
    #[cfg(windows)]
    let stub_name = "voli-shim.exe";
    #[cfg(not(windows))]
    let stub_name = "voli-shim";
    let built = std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .and_then(|d| d.parent())
                .map(|d| d.join(stub_name))
        })
        .filter(|p| p.exists());
    built.unwrap_or_else(|| {
        let p = std::env::temp_dir().join(format!("voli-jn-test-stub-{stub_name}"));
        fs::write(&p, b"dummy shim stub").unwrap();
        p
    })
}

/// The scratch registry key for one test root (env + Apps & Features hooks).
fn scratch_key(root: &Path) -> String {
    let tag = root.file_name().and_then(|n| n.to_str()).unwrap_or("x");
    format!("Software\\voli-test-jn-{tag}")
}

/// A temp root that also removes its scratch registry key when dropped, so a
/// test run leaves nothing behind.
struct TestRoot {
    _td: tempfile::TempDir,
    root: PathBuf,
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        #[cfg(windows)]
        let _ = Command::new("reg")
            .args([
                "delete",
                &format!("HKCU\\{}", scratch_key(&self.root)),
                "/f",
            ])
            .output();
    }
}

fn test_root() -> TestRoot {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().to_path_buf();
    TestRoot { _td: td, root }
}

fn voli(root: &Path, args: &[&str]) -> Output {
    let key = scratch_key(root);
    Command::new(env!("CARGO_BIN_EXE_voli"))
        .args(args)
        .env("VOLI_ROOT", root)
        .env("VOLI_SHIM_STUB", shim_stub())
        .env("VOLI_ENV_SUBKEY", format!("{key}\\env"))
        .env("VOLI_UNINSTALL_SUBKEY", format!("{key}\\uninstall"))
        .env("VOLI_SHORTCUT_DIR", root.join(".scratch").join("shortcuts"))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stdout_json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document ({e}):\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Every stdout line must be one JSON event.
fn events(out: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("not a JSON event line ({e}): {l}"))
        })
        .collect()
}

fn kinds(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|e| e["event"].as_str().unwrap_or("?").to_string())
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `tool-<version>/tool.exe` plus `tool-<version>/README.txt`, padded so the
/// download is big enough to report progress.
fn tool_zip(version: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.add_directory(format!("tool-{version}/"), opts).unwrap();
        w.start_file(format!("tool-{version}/tool.exe"), opts)
            .unwrap();
        w.write_all(&vec![b'x'; 256 * 1024]).unwrap();
        w.start_file(format!("tool-{version}/README.txt"), opts)
            .unwrap();
        w.write_all(b"readme").unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Source blocks for every platform (one archive serves the whole CI matrix).
fn all_sources(url: &str, sha: &str, unix_extract: &str) -> String {
    [
        "x64",
        "arm64",
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
    ]
    .into_iter()
    .map(|key| {
        let extra = if key.contains('-') {
            format!("extract_dir = \"{unix_extract}\"\n")
        } else {
            String::new()
        };
        format!("[source.{key}]\nurl = \"{url}\"\nsha256 = \"{sha}\"\n{extra}")
    })
    .collect::<Vec<_>>()
    .join("\n")
}

/// A source block only for an OS this test is NOT running on.
fn other_os_source(url: &str, sha: &str) -> String {
    let key = if cfg!(windows) { "linux-x64" } else { "x64" };
    format!("[source.{key}]\nurl = \"{url}\"\nsha256 = \"{sha}\"\n")
}

fn manifest(name: &str, version: &str, bins: &str, sources: &str) -> Manifest {
    Manifest::from_toml_str(&format!(
        r#"name = "{name}"
version = "{version}"
description = "{name} package"
homepage = "https://example.com/{name}"
license = "MIT"
kind = "app"
extract_dir = "tool-{version}"
bin = {bins}

{sources}
"#
    ))
    .unwrap_or_else(|e| panic!("fixture manifest {name}: {e}"))
}

/// Serves path -> bytes on 127.0.0.1 until the test process ends.
fn serve(files: HashMap<String, Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tiny_http::Server::from_listener(listener, None).unwrap();
    thread::spawn(move || {
        for req in server.incoming_requests() {
            let resp = match files.get(req.url()) {
                Some(bytes) => tiny_http::Response::from_data(bytes.clone()),
                None => tiny_http::Response::from_data(Vec::new()).with_status_code(404),
            };
            let _ = req.respond(resp);
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A root with an index holding `tool` 1.0.0 (served for real) and a few
/// catalog-only packages for the lookup tests.
fn catalog_root() -> TestRoot {
    let test_root = test_root();
    let root = test_root.root.clone();
    let zip = tool_zip("1.0.0");
    let sha = sha256_hex(&zip);
    let base = serve(HashMap::from([("/tool-1.0.0.zip".to_string(), zip)]));
    let url = format!("{base}/tool-1.0.0.zip");
    let fake = "a".repeat(64);
    let manifests = vec![
        // Provides `tool` as a shim; installable for real.
        manifest(
            "tool",
            "1.0.0",
            r#"["tool.exe"]"#,
            &all_sources(&url, &sha, "tool-1.0.0"),
        ),
        // Also ships a `tool` shim: listed after the exact-name package.
        manifest(
            "atoolkit",
            "2.0.0",
            r#"["tool.exe", "kit.exe"]"#,
            &all_sources("https://example.com/atoolkit.zip", &fake, "x"),
        ),
        // Its exe is python.exe but the shim it installs is `py3`: it does
        // NOT provide `python`, whatever the file is called.
        manifest(
            "pyish",
            "3.0.0",
            r#"[{ name = "py3", path = "python.exe" }]"#,
            &all_sources("https://example.com/pyish.zip", &fake, "x"),
        ),
        // Has a `tool` shim but no build for this OS: never offered here.
        manifest(
            "foreign-tool",
            "1.0.0",
            r#"["tool.exe"]"#,
            &other_os_source("https://example.com/foreign.zip", &fake),
        ),
    ];
    index::build(&manifests, &index::index_db_path(&root)).unwrap();
    test_root
}

// ---- tests ------------------------------------------------------------------

#[test]
fn version_json_names_schema_and_features() {
    let td = tempfile::tempdir().unwrap();
    let out = voli(td.path(), &["version", "--json"]);
    assert!(out.status.success());
    let v = stdout_json(&out);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["schema"], 1);
    let features: Vec<&str> = v["features"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for f in ["provides", "info-summary", "progress", "where", "path"] {
        assert!(features.contains(&f), "missing feature {f}: {features:?}");
    }
}

#[test]
fn where_json_follows_voli_root() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let v = stdout_json(&voli(root, &["where", "--json"]));
    assert_eq!(v["schema"], 1);
    assert_eq!(Path::new(v["root"].as_str().unwrap()), root);
    assert_eq!(
        Path::new(v["shims"].as_str().unwrap()),
        voli_core::Paths::at(root).shims()
    );
    assert_eq!(
        Path::new(v["apps"].as_str().unwrap()),
        voli_core::Paths::at(root).apps()
    );
    assert_eq!(
        Path::new(v["cache"].as_str().unwrap()),
        voli_core::Paths::at(root).cache()
    );
}

#[test]
fn provides_orders_exact_name_then_shim_and_skips_what_cannot_run_here() {
    let t = catalog_root();
    let root = t.root.as_path();
    let out = voli(root, &["provides", "tool", "python", "kit.exe", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = stdout_json(&out);
    assert_eq!(v["schema"], 1);
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 3, "one result per command, in order");

    assert_eq!(results[0]["command"], "tool");
    let names: Vec<&str> = results[0]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    // exact package name first, then the shim match; the foreign-OS one never.
    assert_eq!(names, ["tool", "atoolkit"]);
    let tool = &results[0]["packages"][0];
    assert_eq!(tool["version"], "1.0.0");
    assert_eq!(tool["description"], "tool package");
    assert_eq!(tool["bins"], serde_json::json!(["tool"]));
    assert!(tool["installed_version"].is_null());

    // a file stem is not a command: pyish installs `py3`, not `python`.
    assert_eq!(results[1]["command"], "python");
    assert_eq!(results[1]["packages"], serde_json::json!([]));

    // `.exe` is ignored when matching.
    assert_eq!(results[2]["packages"][0]["name"], "atoolkit");
}

#[test]
fn info_summary_lists_found_and_missing_and_plain_info_is_unchanged() {
    let t = catalog_root();
    let root = t.root.as_path();
    let out = voli(
        root,
        &["info", "tool", "nope", "pyish", "--summary", "--json"],
    );
    assert!(out.status.success());
    let v = stdout_json(&out);
    assert_eq!(v["schema"], 1);
    assert_eq!(v["missing"], serde_json::json!(["nope"]));
    let tool = &v["packages"][0];
    assert_eq!(tool["name"], "tool");
    assert_eq!(tool["version"], "1.0.0");
    assert_eq!(tool["homepage"], "https://example.com/tool");
    assert_eq!(tool["license"], "MIT");
    assert_eq!(tool["bins"], serde_json::json!(["tool"]));
    assert!(tool["installed_version"].is_null());
    assert_eq!(v["packages"][1]["bins"], serde_json::json!(["py3"]));

    // Plain `info --json` is still the raw manifest of one package.
    let raw = stdout_json(&voli(root, &["info", "tool", "--json"]));
    assert_eq!(raw["name"], "tool");
    assert!(raw.get("schema").is_none());
    assert!(
        raw.get("source").is_some(),
        "raw manifest keeps its sources"
    );
}

#[test]
fn install_update_delete_stream_progress_events() {
    let t = catalog_root();
    let root = t.root.as_path();

    // install
    let out = voli(root, &["install", "tool", "--yes", "--json", "--progress"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ev = events(&out);
    let k = kinds(&ev);
    assert_eq!(k.first().map(String::as_str), Some("start"), "{k:?}");
    assert_eq!(ev[0]["name"], "tool");
    assert_eq!(ev[0]["version"], "1.0.0");
    let downloads: Vec<&Value> = ev.iter().filter(|e| e["event"] == "download").collect();
    assert!(!downloads.is_empty(), "no download events: {k:?}");
    let last = downloads.last().unwrap();
    assert_eq!(last["name"], "tool");
    assert_eq!(
        last["bytes"], last["total"],
        "the final download event is sent"
    );
    let tail: Vec<&str> = k
        .iter()
        .map(String::as_str)
        .filter(|e| *e != "download")
        .collect();
    assert_eq!(tail, ["start", "verify", "extract", "installed", "done"]);
    let installed = ev.iter().find(|e| e["event"] == "installed").unwrap();
    assert_eq!(installed["version"], "1.0.0");
    assert_eq!(installed["bins"], serde_json::json!(["tool"]));
    assert_eq!(ev.last().unwrap()["ok"], true);

    // already installed: one `installed` with already:true, then done
    let ev = events(&voli(
        root,
        &["install", "tool", "--yes", "--json", "--progress"],
    ));
    assert_eq!(kinds(&ev), ["installed", "done"]);
    assert_eq!(ev[0]["already"], true);
    assert_eq!(ev[0]["bins"], serde_json::json!(["tool"]));

    // update <pkg> upgrades; here it is current
    let ev = events(&voli(
        root,
        &["update", "tool", "--yes", "--json", "--progress"],
    ));
    assert_eq!(kinds(&ev), ["installed", "done"]);
    assert_eq!(ev[0]["version"], "1.0.0");

    // installed_version shows up in the lookups now
    let v = stdout_json(&voli(root, &["provides", "tool", "--json"]));
    assert_eq!(v["results"][0]["packages"][0]["installed_version"], "1.0.0");
    let v = stdout_json(&voli(root, &["info", "tool", "--summary", "--json"]));
    assert_eq!(v["packages"][0]["installed_version"], "1.0.0");

    // path and which point into the package
    let v = stdout_json(&voli(root, &["path", "tool", "README.txt", "--json"]));
    assert_eq!(v["schema"], 1);
    assert_eq!(v["name"], "tool");
    assert_eq!(v["version"], "1.0.0");
    let readme = PathBuf::from(v["path"].as_str().unwrap());
    assert_eq!(fs::read_to_string(&readme).unwrap(), "readme");
    let v = stdout_json(&voli(root, &["which", "tool", "--json"]));
    assert_eq!(v["schema"], 1);
    assert_eq!(v["command"], "tool");
    assert_eq!(v["package"], "tool");
    assert!(v["target"].as_str().unwrap().contains("tool"));

    // delete
    let out = voli(root, &["delete", "tool", "--json", "--progress"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ev = events(&out);
    assert_eq!(kinds(&ev), ["start", "deleted", "done"]);
    assert_eq!(ev[1]["version"], "1.0.0");
    assert_eq!(ev[1]["bins"], serde_json::json!(["tool"]));
}

#[test]
fn progress_reports_errors_and_ends_with_done_false() {
    let t = catalog_root();
    let root = t.root.as_path();
    let out = voli(
        root,
        &["install", "nosuch", "--yes", "--json", "--progress"],
    );
    assert_eq!(out.status.code(), Some(1));
    let ev = events(&out);
    assert_eq!(kinds(&ev), ["error", "done"]);
    assert_eq!(ev[0]["name"], "nosuch");
    assert!(ev[0]["message"].as_str().unwrap().contains("not found"));
    assert!(!ev[0]["hint"].as_str().unwrap().is_empty());
    assert_eq!(ev[1]["ok"], false);

    // A failure before any package is touched still gets a reason and done.
    let out = voli(root, &["install", "Bad Name!", "--yes", "--progress"]);
    assert_eq!(out.status.code(), Some(1));
    let ev = events(&out);
    assert_eq!(kinds(&ev), ["error", "done"]);
    assert_eq!(ev[1]["ok"], false);
}

#[test]
fn path_and_which_fail_with_a_schema_error() {
    let t = catalog_root();
    let root = t.root.as_path();
    for args in [
        &["path", "tool", "tool.exe", "--json"][..],
        &["which", "tool", "--json"][..],
    ] {
        let out = voli(root, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let v = stdout_json(&out);
        assert_eq!(v["schema"], 1);
        assert!(v["error"].as_str().is_some_and(|e| !e.is_empty()), "{v}");
    }
    // Installed, but the file is missing or outside the package.
    assert!(
        voli(root, &["install", "tool", "--yes", "--json"])
            .status
            .success()
    );
    for file in ["missing.txt", "../../escape.txt"] {
        let out = voli(root, &["path", "tool", file, "--json"]);
        assert_eq!(out.status.code(), Some(1), "{file}");
        assert!(stdout_json(&out)["error"].is_string());
    }
}

#[test]
fn delete_json_is_one_document() {
    let t = catalog_root();
    let root = t.root.as_path();
    assert!(
        voli(root, &["install", "tool", "--yes", "--json"])
            .status
            .success()
    );
    let out = voli(root, &["delete", "tool", "nosuch", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let v = stdout_json(&out);
    assert_eq!(v["schema"], 1);
    assert_eq!(v["ok"], false);
    assert_eq!(v["deleted"][0]["name"], "tool");
    assert_eq!(v["deleted"][0]["version"], "1.0.0");
    assert_eq!(v["failed"][0]["name"], "nosuch");
    assert!(
        v["failed"][0]["error"]
            .as_str()
            .unwrap()
            .contains("not installed")
    );
}
