//! Machine-facing queries for apps that drive voli (jnshell and the other JN
//! apps): `version`, `where`, `path`, `provides`, `info --summary`, and
//! `which --json`.
//!
//! Every `--json` answer is ONE document on stdout carrying `"schema": 1`. A
//! new field may be added within a schema; renaming or removing one bumps it.
//! Failures print `{"schema":1,"error":...,"hint":...}` and exit 1.

use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};
use voli_core::index::{self, IndexError};
use voli_core::{Kind, PackageRef, Paths, State};

pub const SCHEMA: u32 = 1;

/// What this voli can do for a caller, so an app can feature-test instead of
/// parsing version numbers.
pub const FEATURES: &[&str] = &["provides", "info-summary", "progress", "where", "path"];

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// `{"schema":1,"error":...,"hint":...}` on stdout (with `--json`), or the
/// usual error lines on stderr; exit code 1 either way.
fn fail(json: bool, message: &str, hint: &str) -> i32 {
    if json {
        print_json(&json!({ "schema": SCHEMA, "error": message, "hint": hint }));
    } else {
        eprintln!("error: {message}");
        if !hint.is_empty() {
            eprintln!("  fix: {hint}");
        }
    }
    EXIT_ERROR
}

fn fail_index(json: bool, action: &str, e: &IndexError) -> i32 {
    let p = crate::index_problem(action, e);
    if json {
        let mut v = json!({ "schema": SCHEMA, "error": p.summary, "hint": p.fix });
        if !p.detail.is_empty() {
            v["detail"] = json!(p.detail);
        }
        print_json(&v);
    } else {
        crate::print_problem(&p.summary, &p.detail, &p.fix);
    }
    EXIT_ERROR
}

/// Installed version of an app, without creating a state database when there
/// is none yet (a query must not write to the root).
fn installed_version(root: &Path, name: &str) -> Option<String> {
    let db = Paths::at(root).state_db();
    if !db.exists() {
        return None;
    }
    State::open(&db).ok()?.installed_version(name).ok()?
}

// ---- voli version ---------------------------------------------------------

pub fn run_version(json: bool) -> i32 {
    let version = env!("CARGO_PKG_VERSION");
    if json {
        print_json(&json!({ "version": version, "schema": SCHEMA, "features": FEATURES }));
    } else {
        println!("voli {version}");
    }
    EXIT_OK
}

// ---- voli where -----------------------------------------------------------

pub fn run_where(root: &Path, json: bool) -> i32 {
    let paths = Paths::at(root);
    if json {
        print_json(&json!({
            "schema": SCHEMA,
            "root": root,
            "shims": paths.shims(),
            "apps": paths.apps(),
            "cache": paths.cache(),
        }));
    } else {
        println!("root:  {}", root.display());
        println!("shims: {}", paths.shims().display());
        println!("apps:  {}", paths.apps().display());
        println!("cache: {}", paths.cache().display());
    }
    EXIT_OK
}

// ---- voli path ------------------------------------------------------------

/// A path inside a package must stay inside it: relative, no `..`, no root.
fn safe_relative(file: &str) -> Option<PathBuf> {
    let p = Path::new(file);
    if file.is_empty() || p.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

pub fn run_path(root: &Path, package: &str, file: &str, json: bool) -> i32 {
    let package_ref = match PackageRef::parse(package) {
        Ok(p) if p.kind == Kind::App => p,
        Ok(_) => return fail(json, "`voli path` works for app packages only", ""),
        Err(e) => return fail(json, &format!("invalid package '{package}': {e}"), ""),
    };
    let name = package_ref.name;
    let Some(version) = installed_version(root, &name) else {
        return fail(
            json,
            &format!("{name} is not installed"),
            &format!("run `voli install {name}`"),
        );
    };
    let Some(rel) = safe_relative(file) else {
        return fail(
            json,
            &format!("'{file}' is not a path inside the package"),
            "pass a relative path such as `rg.exe` or `bin/tool.exe`",
        );
    };
    let dir = Paths::at(root).version_dir(&name, &version);
    let mut path = dir.join(&rel);
    // Manifests name `rg.exe` even where the payload is extensionless, and
    // callers on Windows may leave `.exe` off: accept the one that exists.
    if !path.exists() {
        let alt = match file.strip_suffix(".exe") {
            Some(stem) => safe_relative(stem).map(|r| dir.join(r)),
            None if cfg!(windows) => safe_relative(&format!("{file}.exe")).map(|r| dir.join(r)),
            None => None,
        };
        if let Some(alt) = alt.filter(|a| a.exists()) {
            path = alt;
        }
    }
    if !path.exists() {
        return fail(
            json,
            &format!("{name} {version} has no '{file}'"),
            &format!("look in {}", dir.display()),
        );
    }
    if json {
        print_json(&json!({ "schema": SCHEMA, "name": name, "version": version, "path": path }));
    } else {
        println!("{}", path.display());
    }
    EXIT_OK
}

// ---- voli provides --------------------------------------------------------

pub fn run_provides(root: &Path, commands: &[String], json: bool) -> i32 {
    let found = match index::providers(root, commands) {
        Ok(found) => found,
        Err(e) => return fail_index(json, "look up commands", &e),
    };
    if json {
        let results: Vec<Value> = found
            .iter()
            .map(|(command, packages)| {
                let packages: Vec<Value> = packages
                    .iter()
                    .map(|p| {
                        json!({
                            "name": p.name,
                            "version": p.version,
                            "description": p.description,
                            "bins": p.bins,
                            "installed_version": installed_version(root, &p.name),
                        })
                    })
                    .collect();
                json!({ "command": command, "packages": packages })
            })
            .collect();
        print_json(&json!({ "schema": SCHEMA, "results": results }));
        return EXIT_OK;
    }
    for (command, packages) in &found {
        if packages.is_empty() {
            println!("{command}: no package provides it");
            continue;
        }
        println!("{command}:");
        for p in packages {
            let installed = installed_version(root, &p.name)
                .map(|v| format!("  (installed {v})"))
                .unwrap_or_default();
            let desc = p.description.as_deref().unwrap_or("");
            println!("  {} {}{installed}  {desc}", p.name, p.version);
        }
    }
    EXIT_OK
}

// ---- voli info --summary --------------------------------------------------

pub fn run_info_summary(root: &Path, packages: &[String], json: bool) -> i32 {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for requested in packages {
        let package_ref = match PackageRef::parse(requested) {
            Ok(p) => p,
            Err(_) => {
                missing.push(requested.clone());
                continue;
            }
        };
        match index::info_ref(root, &package_ref) {
            Ok(Some(m)) => {
                let bins: Vec<String> = m.bin.iter().map(|b| b.shim_name()).collect();
                let installed = (m.kind == Kind::App)
                    .then(|| installed_version(root, &m.name))
                    .flatten();
                let mut v = json!({
                    "name": m.name,
                    "version": m.version,
                    "description": m.description,
                    "homepage": m.homepage,
                    "license": m.license,
                    "bins": bins,
                    "installed_version": installed,
                });
                // A rename answers under the new name; say which input it was.
                if m.name != package_ref.name {
                    v["requested"] = json!(requested);
                }
                found.push(v);
            }
            Ok(None) => missing.push(requested.clone()),
            Err(e) => return fail_index(json, "read package information", &e),
        }
    }
    if json {
        print_json(&json!({ "schema": SCHEMA, "packages": found, "missing": missing }));
        return EXIT_OK;
    }
    for v in &found {
        let installed = v["installed_version"]
            .as_str()
            .map(|iv| format!("  (installed {iv})"))
            .unwrap_or_default();
        println!(
            "{} {}{installed}  {}",
            v["name"].as_str().unwrap_or(""),
            v["version"].as_str().unwrap_or(""),
            v["description"].as_str().unwrap_or("")
        );
    }
    for m in &missing {
        println!("{m}: not found");
    }
    EXIT_OK
}

// ---- voli which --json ----------------------------------------------------

/// The app that owns a shim target under `<root>/apps/<name>/...`.
fn owner_of(root: &Path, target: &Path) -> Option<String> {
    let rest = target.strip_prefix(Paths::at(root).apps()).ok()?;
    match rest.components().next()? {
        Component::Normal(name) => name.to_str().map(str::to_string),
        _ => None,
    }
}

pub fn run_which(root: &Path, bin: &str, json: bool) -> i32 {
    // Tolerate a `.exe` suffix on every platform: manifests name `rg.exe`
    // even where the installed shim is extensionless.
    let base = bin.strip_suffix(".exe").unwrap_or(bin);
    let shim = Paths::at(root).shims().join(format!("{base}.shim"));
    let body = match std::fs::read_to_string(&shim) {
        Ok(body) => body,
        Err(_) => {
            return fail(
                json,
                &format!("no shim for '{bin}' (looked for {})", shim.display()),
                &format!("run `voli provides {base}` to find a package for it"),
            );
        }
    };
    // Line 1 of a .shim is the target path (spec §6).
    let Some(target) = body.lines().next().map(str::trim).filter(|t| !t.is_empty()) else {
        return fail(
            json,
            &format!("shim {} is empty or malformed", shim.display()),
            "reinstall the package that owns it",
        );
    };
    if json {
        print_json(&json!({
            "schema": SCHEMA,
            "command": base,
            "target": target,
            "package": owner_of(root, Path::new(target)),
        }));
    } else {
        println!("{target}");
    }
    EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::safe_relative;

    #[test]
    fn package_paths_cannot_escape_the_package() {
        assert!(safe_relative("rg.exe").is_some());
        assert!(safe_relative("bin/tool.exe").is_some());
        assert!(safe_relative("./rg.exe").is_some());
        assert!(safe_relative("").is_none());
        assert!(safe_relative(".").is_none());
        assert!(safe_relative("../other/x.exe").is_none());
        assert!(safe_relative("bin/../../x").is_none());
        #[cfg(windows)]
        {
            assert!(safe_relative(r"C:\Windows\notepad.exe").is_none());
            assert!(safe_relative(r"\Windows").is_none());
        }
        #[cfg(not(windows))]
        assert!(safe_relative("/etc/passwd").is_none());
    }
}
