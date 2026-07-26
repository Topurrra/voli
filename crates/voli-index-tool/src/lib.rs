//! Registry index tooling (Voli.md §5, §11 step 7).
//!
//! Two operations, reusing `voli-core` verbatim so the registry CI and the
//! client can never disagree about the index format:
//!
//! - [`analyze`] / [`validate`] — walk `manifests/`, parse+validate every
//!   `.toml` with [`Manifest::from_toml_str`], check the on-disk layout
//!   (`<letter>/<name>/<version>.toml`), and detect duplicate (name, version)
//!   pairs. Collects *every* error rather than failing fast.
//! - [`build`] — validate, compile the manifests into `index.sqlite` via
//!   [`voli_core::index::build`], compress to `.zst`, Ed25519-sign the
//!   *decompressed* bytes, and write the `index.json` freshness pointer.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use voli_core::Manifest;
use voli_core::index::net::RemoteIndex;

/// Directory name excluded from validation and the index build (spec: fixtures).
const EXAMPLES_DIR: &str = "_examples";

/// Result of a build: the values written into `index.json`.
#[derive(Debug, Clone)]
pub struct BuildMeta {
    pub epoch: u64,
    pub sha256: String,
    pub size: u64,
    /// Number of package rows compiled (one per manifest kept).
    pub manifests: usize,
}

/// Recursively collect every `.toml` under `dir`, skipping any `_examples/`
/// subtree. Returns absolute paths, sorted for stable output.
pub fn collect_toml_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(dir, &mut out).with_context(|| format!("walking {}", dir.display()))?;
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if entry.file_name() == EXAMPLES_DIR {
                continue;
            }
            walk(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            out.push(path);
        }
    }
    Ok(())
}

/// Parse + validate every manifest under `dir`, returning the parsed manifests
/// and a list of every error found (parse, layout, or duplicate). A non-empty
/// error list means the registry is invalid.
pub fn analyze(dir: &Path) -> Result<(Vec<Manifest>, Vec<String>)> {
    let files = collect_toml_files(dir)?;
    let mut manifests = Vec::new();
    let mut errors = Vec::new();
    // (name, version) -> the relative path that first claimed it.
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for abs in &files {
        let rel = abs.strip_prefix(dir).unwrap_or(abs);
        let rel_disp = rel.display().to_string();
        let text = match std::fs::read_to_string(abs) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("{rel_disp}: cannot read file: {e}"));
                continue;
            }
        };
        match Manifest::from_toml_str(&text) {
            Err(e) => errors.push(format!("{rel_disp}: {e}")),
            Ok(m) => {
                errors.extend(layout_errors(rel, &m));
                if !seen.insert((m.name.clone(), m.version.clone())) {
                    errors.push(format!(
                        "{rel_disp}: duplicate package version (name = {}, version = {}) \
                         already defined elsewhere",
                        m.name, m.version
                    ));
                }
                manifests.push(m);
            }
        }
    }
    Ok((manifests, errors))
}

/// Layout check for one manifest: the path must be
/// `<first-letter>/<name>/<version>.toml` relative to the manifests root, with
/// the letter, directory name, and filename matching the manifest fields.
fn layout_errors(rel: &Path, m: &Manifest) -> Vec<String> {
    let rel_disp = rel.display().to_string();
    let comps: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();

    if comps.len() != 3 {
        return vec![format!(
            "{rel_disp}: wrong layout — expected <first-letter>/<name>/<version>.toml"
        )];
    }
    let (letter, name_dir, file) = (&comps[0], &comps[1], &comps[2]);
    let mut errs = Vec::new();

    let expected_letter = m.name.chars().next().unwrap_or('_').to_ascii_lowercase();
    if letter.as_str() != expected_letter.to_string() {
        errs.push(format!(
            "{rel_disp}: first-letter dir '{letter}' does not match package name '{}' \
             (expected '{expected_letter}')",
            m.name
        ));
    }
    if name_dir != &m.name {
        errs.push(format!(
            "{rel_disp}: directory '{name_dir}' does not match manifest name '{}'",
            m.name
        ));
    }
    let stem = file.strip_suffix(".toml").unwrap_or(file);
    if stem != m.version {
        errs.push(format!(
            "{rel_disp}: filename '{file}' does not match manifest version '{}'",
            m.version
        ));
    }
    errs
}

/// Human-readable validate: returns the error list (empty = valid).
pub fn validate(dir: &Path) -> Result<Vec<String>> {
    Ok(analyze(dir)?.1)
}

/// Full build: validate, compile to sqlite, compress, sign, and write the
/// `index.json` pointer. Writes `index.sqlite`, `index.sqlite.zst`,
/// `index.sig`, and `index.json` into `out`.
///
/// `epoch` is taken from `epoch_flag`, else `$SOURCE_DATE_EPOCH`, else the
/// current system time — so CI can produce a reproducible index.
pub fn build(
    dir: &Path,
    out: &Path,
    key_path: &Path,
    epoch_flag: Option<u64>,
) -> Result<BuildMeta> {
    let (manifests, errors) = analyze(dir)?;
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("error: {e}");
        }
        bail!("{} manifest error(s); index not built", errors.len());
    }
    if manifests.is_empty() {
        bail!("no manifests found under {}", dir.display());
    }

    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;

    // ponytail: "latest N per package" == keep all versions in v1 (the index is
    // single-digit MB); add per-name truncation only if snapshot size demands it.
    let db_path = out.join("index.sqlite");
    voli_core::index::build(&manifests, &db_path).context("compiling index.sqlite")?;

    let db_bytes = std::fs::read(&db_path).context("reading compiled index.sqlite")?;
    let size = db_bytes.len() as u64;
    let sha256 = hex::encode(Sha256::digest(&db_bytes));

    // Compress the snapshot. Client verifies the *decompressed* bytes.
    let zst = zstd::encode_all(&db_bytes[..], 19).context("zstd-compressing index")?;
    std::fs::write(out.join("index.sqlite.zst"), &zst).context("writing index.sqlite.zst")?;

    // Sign the decompressed db (matches voli-core net::update verification).
    let key_hex = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading signing key {}", key_path.display()))?;
    let secret = voli_core::index::sign::secret_key_from_hex(&key_hex)
        .map_err(|e| anyhow::anyhow!("bad signing key: {e}"))?;
    let sig = voli_core::index::sign(&db_bytes, &secret);
    std::fs::write(out.join("index.sig"), sig).context("writing index.sig")?;

    let epoch = epoch_flag
        .or_else(|| {
            std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or_else(now_unix_secs);

    // Reuse the client's own struct so the JSON shape can never drift.
    let remote = RemoteIndex {
        epoch,
        sha256: sha256.clone(),
        size,
    };
    let json = serde_json::to_string_pretty(&remote).context("serializing index.json")?;
    std::fs::write(out.join("index.json"), format!("{json}\n")).context("writing index.json")?;

    // Convenience mirror for the website search (NOT signed — the client never
    // uses it; it's a read-only catalog snapshot for volibear.dev).
    {
        use std::collections::BTreeMap;
        let mut latest: BTreeMap<&str, &Manifest> = BTreeMap::new();
        for m in &manifests {
            match latest.get(m.name.as_str()) {
                Some(prev) => {
                    if voli_core::index::cmp_version(&m.version, &prev.version)
                        == std::cmp::Ordering::Greater
                    {
                        latest.insert(&m.name, m);
                    }
                }
                None => {
                    latest.insert(&m.name, m);
                }
            }
        }
        let pkgs: Vec<serde_json::Value> = latest
            .values()
            .map(|m| {
                let bins: Vec<&str> = m.bin.iter().map(|b| b.path()).collect();
                let mut package = serde_json::json!({
                    "n": m.name,
                    "v": m.version,
                    "d": m.description.as_deref().unwrap_or(""),
                    "b": bins,
                });
                if let Some(homepage) = &m.homepage {
                    package["h"] = serde_json::json!(homepage);
                }
                if let Some(icon) = &m.icon {
                    package["i"] = serde_json::json!(icon);
                }
                package
            })
            .collect();
        let minified = serde_json::to_string(&pkgs).context("serializing packages.json")?;
        std::fs::write(out.join("packages.json"), &minified).context("writing packages.json")?;
    }

    Ok(BuildMeta {
        epoch,
        sha256,
        size,
        manifests: manifests.len(),
    })
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- auto-bump -----------------------------------------------------------

/// Outcome of a single package bump attempt.
enum BumpResult {
    Bumped { from: String, to: String },
    UpToDate(String),
    Skipped(String),
}

/// Check GitHub releases for newer versions of packages with `[autoupdate]`
/// and emit updated manifests. Returns a human-readable summary table.
pub fn bump(dir: &Path, limit: usize) -> Result<String> {
    let (manifests, errors) = analyze(dir)?;
    if !errors.is_empty() {
        bail!("{} manifest error(s); fix before bumping", errors.len());
    }

    // Group by name, keep latest version only.
    let mut latest: std::collections::BTreeMap<String, Manifest> =
        std::collections::BTreeMap::new();
    for m in manifests {
        match latest.get(&m.name) {
            Some(prev) => {
                if voli_core::index::cmp_version(&m.version, &prev.version)
                    == std::cmp::Ordering::Greater
                {
                    latest.insert(m.name.clone(), m);
                }
            }
            None => {
                latest.insert(m.name.clone(), m);
            }
        }
    }

    let token = std::env::var("GITHUB_TOKEN").ok();
    let mut results: Vec<(String, BumpResult)> = Vec::new();
    let mut bumped_count = 0;

    for (name, m) in &latest {
        if bumped_count >= limit {
            results.push((name.clone(), BumpResult::Skipped("limit reached".into())));
            continue;
        }

        // Extract GitHub owner/repo from [autoupdate].
        let Some((owner, repo)) = github_repo(m) else {
            continue; // no autoupdate or not GitHub — silently skip
        };

        match bump_one(name, m, &owner, &repo, token.as_deref(), dir) {
            Ok(r) => {
                if matches!(r, BumpResult::Bumped { .. }) {
                    bumped_count += 1;
                }
                results.push((name.clone(), r));
            }
            Err(e) => {
                results.push((name.clone(), BumpResult::Skipped(e.to_string())));
            }
        }
    }

    // Build summary table.
    let mut out = String::new();
    out.push_str("bump summary\n");
    out.push_str("| package | status | detail |\n|---|---|---|\n");
    for (name, r) in &results {
        match r {
            BumpResult::Bumped { from, to } => {
                out.push_str(&format!("| {name} | **bumped** | {from} → {to} |\n"));
            }
            BumpResult::UpToDate(v) => {
                out.push_str(&format!("| {name} | up-to-date | {v} |\n"));
            }
            BumpResult::Skipped(reason) => {
                out.push_str(&format!("| {name} | skipped | {reason} |\n"));
            }
        }
    }
    let bumped = results
        .iter()
        .filter(|(_, r)| matches!(r, BumpResult::Bumped { .. }))
        .count();
    let uptodate = results
        .iter()
        .filter(|(_, r)| matches!(r, BumpResult::UpToDate(_)))
        .count();
    let skipped = results
        .iter()
        .filter(|(_, r)| matches!(r, BumpResult::Skipped(_)))
        .count();
    out.push_str(&format!(
        "\n{bumped} bumped, {uptodate} up-to-date, {skipped} skipped\n"
    ));
    Ok(out)
}

/// Extract `(owner, repo)` from a manifest's `[autoupdate]` if it has a
/// GitHub-style checkver.
fn github_repo(m: &Manifest) -> Option<(String, String)> {
    let au = m.autoupdate.as_ref()?;
    // checkver = { github = "owner/repo" }
    if let Some(cv) = au.get("checkver") {
        if let Some(gh) = cv.get("github").and_then(|v| v.as_str()) {
            let parts: Vec<&str> = gh.splitn(2, '/').collect();
            if parts.len() == 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }
        // checkver = "owner/repo" (bare string form)
        if let Some(s) = cv.as_str() {
            let parts: Vec<&str> = s.splitn(2, '/').collect();
            if parts.len() == 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
        }
    }
    None
}

fn bump_one(
    name: &str,
    m: &Manifest,
    owner: &str,
    repo: &str,
    token: Option<&str>,
    manifests_dir: &Path,
) -> Result<BumpResult> {
    // Query GitHub API.
    let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    let mut req = ureq::get(&url).set("User-Agent", "voli-index-tool");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => {
            return Ok(BumpResult::Skipped("repo not found (404)".into()));
        }
        Err(ureq::Error::Status(403, _)) => {
            return Ok(BumpResult::Skipped("rate limited (403)".into()));
        }
        Err(e) => return Err(anyhow::anyhow!("GitHub API: {e}")),
    };
    let body: serde_json::Value = resp
        .into_string()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or_else(|| anyhow::anyhow!("bad API JSON"))?;

    let tag = body["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no tag_name"))?;
    let new_version = tag.trim_start_matches('v');

    // Compare versions.
    if voli_core::index::cmp_version(new_version, &m.version) != std::cmp::Ordering::Greater {
        return Ok(BumpResult::UpToDate(m.version.clone()));
    }

    // Derive new URL for x64 source.
    let source = m
        .source
        .x64
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no x64 source"))?;
    let new_url = derive_url(&source.url, &m.version, new_version)
        .ok_or_else(|| anyhow::anyhow!("url not derivable"))?;

    // Download and hash.
    let is_sha512 = source.is_sha512();
    let hash = download_and_hash(&new_url, is_sha512)?;

    // Build new manifest TOML.
    let new_toml = emit_bumped(m, new_version, &new_url, &hash, is_sha512);

    // Validate with the real parser.
    Manifest::from_toml_str(&new_toml)
        .map_err(|e| anyhow::anyhow!("emitted manifest invalid: {e}"))?;

    // Write.
    let letter = &name[..1];
    let dest = manifests_dir.join(letter).join(name);
    std::fs::create_dir_all(&dest)?;
    let file = dest.join(format!("{new_version}.toml"));
    std::fs::write(&file, &new_toml)?;

    Ok(BumpResult::Bumped {
        from: m.version.clone(),
        to: new_version.to_string(),
    })
}

/// Derive the new asset URL by substituting the version.
fn derive_url(old_url: &str, old_ver: &str, new_ver: &str) -> Option<String> {
    // Try direct string replacement of old version in the URL.
    if old_url.contains(old_ver) {
        let new = old_url.replace(old_ver, new_ver);
        if new != old_url {
            return Some(new);
        }
    }
    None
}

/// Download a URL and compute its hash (sha256 or sha512).
fn download_and_hash(url: &str, sha512: bool) -> Result<String> {
    use sha2::{Digest, Sha256, Sha512};
    let resp = ureq::get(url)
        .set("User-Agent", "voli-index-tool")
        .call()
        .map_err(|e| anyhow::anyhow!("download {url}: {e}"))?;
    let mut bytes = Vec::new();
    resp.into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow::anyhow!("reading {url}: {e}"))?;
    if sha512 {
        Ok(hex::encode(Sha512::digest(&bytes)))
    } else {
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// Emit a bumped manifest TOML from the old manifest with new version/url/hash.
fn emit_bumped(
    m: &Manifest,
    new_ver: &str,
    new_url: &str,
    new_hash: &str,
    is_sha512: bool,
) -> String {
    let mut o = String::new();
    o.push_str(&format!("name = \"{}\"\n", m.name));
    o.push_str(&format!("version = \"{new_ver}\"\n"));
    if let Some(d) = &m.description {
        o.push_str(&format!("description = \"{}\"\n", d.replace('"', "\\\"")));
    }
    if let Some(h) = &m.homepage {
        o.push_str(&format!("homepage = \"{h}\"\n"));
    }
    if let Some(icon) = &m.icon {
        o.push_str(&format!("icon = \"{icon}\"\n"));
    }
    if let Some(l) = &m.license {
        o.push_str(&format!("license = \"{l}\"\n"));
    }
    o.push_str("kind = \"app\"\n");
    if let Some(ed) = &m.extract_dir {
        let new_ed = ed.replace(&m.version, new_ver);
        o.push_str(&format!("extract_dir = \"{new_ed}\"\n"));
    }
    if !m.bin.is_empty() {
        let bins: Vec<String> = m
            .bin
            .iter()
            .map(|b| match b {
                voli_core::Bin::Path(p) => format!("\"{p}\""),
                voli_core::Bin::Table { name, path, args } => {
                    let mut t = format!("{{ name = \"{name}\", path = \"{path}\"");
                    if let Some(a) = args {
                        t.push_str(&format!(", args = \"{a}\""));
                    }
                    t.push_str(" }");
                    t
                }
            })
            .collect();
        o.push_str(&format!("bin = [{}]\n", bins.join(", ")));
    }
    if !m.persist.is_empty() {
        let items: Vec<String> = m.persist.iter().map(|p| format!("\"{p}\"")).collect();
        o.push_str(&format!("persist = [{}]\n", items.join(", ")));
    }
    if !m.shortcuts.is_empty() {
        let items: Vec<String> = m
            .shortcuts
            .iter()
            .map(|s| match s {
                voli_core::Shortcut::Path(p) => format!("\"{p}\""),
                voli_core::Shortcut::Table { target, name } => {
                    format!("{{ target = \"{target}\", name = \"{name}\" }}")
                }
            })
            .collect();
        o.push_str(&format!("shortcuts = [{}]\n", items.join(", ")));
    }
    if !m.write_file.is_empty() {
        o.push_str("write_file = [\n");
        for wf in &m.write_file {
            o.push_str(&format!(
                "  {{ path = \"{}\", content = \"{}\" }},\n",
                wf.path,
                wf.content.replace('"', "\\\"")
            ));
        }
        o.push_str("]\n");
    }

    o.push_str("\n[source.x64]\n");
    o.push_str(&format!("url = \"{new_url}\"\n"));
    if is_sha512 {
        o.push_str(&format!("sha512 = \"{new_hash}\"\n"));
    } else {
        o.push_str(&format!("sha256 = \"{new_hash}\"\n"));
    }

    if !m.env.is_empty() {
        o.push_str("\n[env]\n");
        for (k, v) in &m.env {
            o.push_str(&format!("{k} = \"{}\"\n", v.replace('"', "\\\"")));
        }
    }

    if !m.depends.is_empty() {
        o.push_str("\n[depends]\n");
        for (k, v) in &m.depends {
            o.push_str(&format!("{k} = \"{v}\"\n"));
        }
    }

    if let Some(au) = &m.autoupdate {
        // A toml::Value table Displays as an inline table (`{ k = v }`), which
        // is invalid as a section body — emit per-key lines instead.
        if let Some(t) = au.as_table() {
            o.push_str("\n[autoupdate]\n");
            for (k, v) in t {
                o.push_str(&format!("{k} = {v}\n"));
            }
        }
    }

    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn manifest_toml(name: &str, version: &str, bin: &str) -> String {
        format!(
            r#"name = "{name}"
version = "{version}"
description = "test package {name}"
homepage = "https://example.com/{name}"
icon = "https://example.com/{name}.svg"
kind = "app"
bin = ["{bin}"]

[source.x64]
url = "https://example.com/{name}-{version}.zip"
sha256 = "{hash}"
"#,
            hash = "a".repeat(64),
        )
    }

    /// Write a manifest at the correct `<letter>/<name>/<version>.toml` layout.
    fn write_good(root: &Path, name: &str, version: &str, bin: &str) {
        let letter = &name[..1];
        let dir = root.join(letter).join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{version}.toml")),
            manifest_toml(name, version, bin),
        )
        .unwrap();
    }

    fn registry_with_examples() -> TempDir {
        let td = TempDir::new().unwrap();
        let root = td.path();
        write_good(root, "ripgrep", "14.1.0", "rg.exe");
        write_good(root, "ripgrep", "14.1.1", "rg.exe");
        write_good(root, "fd", "10.1.0", "fd.exe");
        // Excluded subtree — a deliberately broken manifest that must be ignored.
        let ex = root.join(EXAMPLES_DIR);
        fs::create_dir_all(&ex).unwrap();
        fs::write(ex.join("broken.toml"), "not valid toml at all = = =").unwrap();
        td
    }

    #[test]
    fn valid_registry_has_no_errors() {
        let td = registry_with_examples();
        let (manifests, errors) = analyze(td.path()).unwrap();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert_eq!(manifests.len(), 3, "two ripgrep versions + one fd");
    }

    #[test]
    fn examples_dir_is_excluded() {
        let td = registry_with_examples();
        let files = collect_toml_files(td.path()).unwrap();
        assert!(
            files
                .iter()
                .all(|f| !f.to_string_lossy().contains(EXAMPLES_DIR))
        );
    }

    #[test]
    fn catches_parse_error() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("b").join("bad");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("1.0.0.toml"), "this is not = valid = toml").unwrap();
        let (_, errors) = analyze(td.path()).unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("bad"), "{errors:?}");
    }

    #[test]
    fn catches_wrong_letter_dir() {
        let td = TempDir::new().unwrap();
        // ripgrep placed under z/ instead of r/.
        let dir = td.path().join("z").join("ripgrep");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("14.1.1.toml"),
            manifest_toml("ripgrep", "14.1.1", "rg.exe"),
        )
        .unwrap();
        let (_, errors) = analyze(td.path()).unwrap();
        assert!(
            errors.iter().any(|e| e.contains("first-letter")),
            "{errors:?}"
        );
    }

    #[test]
    fn catches_wrong_name_dir_and_filename() {
        let td = TempDir::new().unwrap();
        // name dir 'rg' != manifest name 'ripgrep'; filename version mismatch.
        let dir = td.path().join("r").join("rg");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("9.9.9.toml"),
            manifest_toml("ripgrep", "14.1.1", "rg.exe"),
        )
        .unwrap();
        let (_, errors) = analyze(td.path()).unwrap();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("does not match manifest name")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("does not match manifest version")),
            "{errors:?}"
        );
    }

    #[test]
    fn catches_duplicate_version() {
        let td = TempDir::new().unwrap();
        // Same (name, version) in two different files.
        write_good(td.path(), "ripgrep", "14.1.1", "rg.exe");
        let dir = td.path().join("r").join("ripgrep");
        fs::write(
            dir.join("dupe.toml"),
            manifest_toml("ripgrep", "14.1.1", "rg.exe"),
        )
        .unwrap();
        let (_, errors) = analyze(td.path()).unwrap();
        // dupe.toml: filename 'dupe' != version + duplicate detection both fire.
        assert!(errors.iter().any(|e| e.contains("duplicate")), "{errors:?}");
    }

    #[test]
    fn does_not_fail_fast() {
        let td = TempDir::new().unwrap();
        // Two independent broken manifests — both must be reported.
        let d1 = td.path().join("a").join("a");
        let d2 = td.path().join("b").join("b");
        fs::create_dir_all(&d1).unwrap();
        fs::create_dir_all(&d2).unwrap();
        fs::write(d1.join("1.0.0.toml"), "bad = = toml").unwrap();
        fs::write(d2.join("1.0.0.toml"), "also = = bad").unwrap();
        let (_, errors) = analyze(td.path()).unwrap();
        assert_eq!(
            errors.len(),
            2,
            "both errors reported, not fail-fast: {errors:?}"
        );
    }

    #[test]
    fn build_produces_verifiable_triple() {
        let reg = registry_with_examples();
        let out = TempDir::new().unwrap();
        // Ephemeral test key written to a temp file — no key material in the repo.
        let keydir = TempDir::new().unwrap();
        let key = keydir.path().join("test-key.hex");
        fs::write(&key, hex::encode([42u8; 32])).unwrap();

        let meta = build(reg.path(), out.path(), &key, Some(1_753_315_200)).unwrap();
        assert_eq!(meta.epoch, 1_753_315_200);
        assert_eq!(meta.manifests, 3);

        // index.json shape matches the client's RemoteIndex.
        let json = fs::read_to_string(out.path().join("index.json")).unwrap();
        let remote: RemoteIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(remote.sha256, meta.sha256);
        assert_eq!(remote.size, meta.size);

        let packages: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.path().join("packages.json")).unwrap())
                .unwrap();
        assert_eq!(packages[0]["i"], "https://example.com/fd.svg");
        assert_eq!(packages[0]["h"], "https://example.com/fd");

        // Decompress .zst → must match sha + size in index.json.
        let zst = fs::read(out.path().join("index.sqlite.zst")).unwrap();
        let db = zstd::stream::decode_all(&zst[..]).unwrap();
        assert_eq!(db.len() as u64, remote.size);
        assert_eq!(hex::encode(Sha256::digest(&db)), remote.sha256);

        // Signature over the decompressed bytes verifies with the matching pubkey.
        let sig = fs::read(out.path().join("index.sig")).unwrap();
        let pk = voli_core::index::sign::public_key_hex(&[42u8; 32]);
        voli_core::index::verify(&db, &sig, &pk)
            .expect("test-signed index must verify with the matching pubkey");
    }

    // ---- bump tests ----

    #[test]
    fn derive_url_replaces_version() {
        let old = "https://github.com/o/r/releases/download/v1.2.3/tool-1.2.3-x64.zip";
        assert_eq!(
            derive_url(old, "1.2.3", "2.0.0"),
            Some("https://github.com/o/r/releases/download/v2.0.0/tool-2.0.0-x64.zip".into())
        );
    }

    #[test]
    fn derive_url_returns_none_when_no_match() {
        let old = "https://example.com/tool.zip";
        assert_eq!(derive_url(old, "1.0.0", "2.0.0"), None);
    }

    #[test]
    fn github_repo_extracts_from_checkver_table() {
        let m = Manifest::from_toml_str(&format!(
            r#"
name = "test"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://x/a.zip"
sha256 = "{}"
[autoupdate]
checkver = {{ github = "BurntSushi/ripgrep" }}
"#,
            "a".repeat(64)
        ))
        .unwrap();
        assert_eq!(
            github_repo(&m),
            Some(("BurntSushi".into(), "ripgrep".into()))
        );
    }

    #[test]
    fn github_repo_returns_none_without_autoupdate() {
        let m = Manifest::from_toml_str(&format!(
            r#"
name = "test"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://x/a.zip"
sha256 = "{}"
"#,
            "a".repeat(64)
        ))
        .unwrap();
        assert_eq!(github_repo(&m), None);
    }
}
