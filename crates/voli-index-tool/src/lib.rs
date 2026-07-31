//! Registry index tooling (Voli.md §5, §11 step 7).
//!
//! Two operations, reusing `voli-core` verbatim so the registry CI and the
//! client can never disagree about the index format:
//!
//! - [`analyze`] / [`validate`] — walk `manifests/`, parse+validate every
//!   `.toml` with [`Manifest::from_toml_str`], check the on-disk layout
//!   (apps use `<letter>/<name>/<version>.toml`; typed packages add a kind
//!   directory), and detect duplicate (kind, name, version)
//!   pairs. Collects *every* error rather than failing fast.
//! - [`build`] — validate, compile the manifests into `index.sqlite` via
//!   [`voli_core::index::build`], compress to `.zst`, Ed25519-sign the
//!   *decompressed* bytes, and write the `index.json` freshness pointer.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use voli_core::index::net::RemoteIndex;
use voli_core::{Kind, Manifest};

mod agent_targets;
pub use agent_targets::{AgentTargetSync, sync_agent_targets};

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
    // (kind, name, version) -> the relative path that first claimed it.
    let mut seen: HashSet<(Kind, String, String)> = HashSet::new();

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
                if !seen.insert((m.kind, m.name.clone(), m.version.clone())) {
                    errors.push(format!(
                        "{rel_disp}: duplicate package version (kind = {}, name = {}, version = {}) \
                         already defined elsewhere",
                        m.kind.as_str(),
                        m.name,
                        m.version
                    ));
                }
                manifests.push(m);
            }
        }
    }
    Ok((manifests, errors))
}

/// Layout check for one manifest. Apps preserve the v1
/// `<first-letter>/<name>/<version>.toml` layout. Typed packages use
/// `<kind>/<first-letter>/<name>/<version>.toml`.
fn layout_errors(rel: &Path, m: &Manifest) -> Vec<String> {
    let rel_disp = rel.display().to_string();
    let comps: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();

    let (offset, expected) = match m.kind {
        Kind::App => (0, "<first-letter>/<name>/<version>.toml"),
        Kind::Mcp => (1, "mcp/<first-letter>/<name>/<version>.toml"),
        Kind::Skill => (1, "skills/<first-letter>/<name>/<version>.toml"),
    };
    if comps.len() != offset + 3 {
        return vec![format!("{rel_disp}: wrong layout - expected {expected}")];
    }
    if offset == 1 {
        let expected_kind = match m.kind {
            Kind::Mcp => "mcp",
            Kind::Skill => "skills",
            Kind::App => unreachable!(),
        };
        if comps[0] != expected_kind {
            return vec![format!(
                "{rel_disp}: package kind directory '{}' does not match '{expected_kind}'",
                comps[0]
            )];
        }
    }
    let (letter, name_dir, file) = (&comps[offset], &comps[offset + 1], &comps[offset + 2]);
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
///
/// Includes canonical-form drift. That was once only a report, because hundreds
/// of legacy files were still in the old expanded shape and failing on them
/// would have blocked every publish. They have all been normalized, so drift is
/// now an error and the one canonical form stays that way instead of eroding a
/// file at a time back into weekly merge conflicts.
///
/// [`build`] deliberately does not go through here — it calls [`analyze`]
/// directly, so a formatting nit can never block publishing an index.
pub fn validate(dir: &Path) -> Result<Vec<String>> {
    let mut errors = analyze(dir)?.1;
    errors.extend(check_format(dir)?);
    Ok(errors)
}

/// Every manifest under `dir` that is not in canonical form, as
/// `<relative path>: not in canonical form (…)` lines.
///
/// Part of [`validate`], and also callable on its own to see drift without the
/// rest of the checks. Unparseable files are validate's problem and are skipped.
pub fn check_format(dir: &Path) -> Result<Vec<String>> {
    let mut drift = Vec::new();
    for abs in collect_toml_files(dir)? {
        let Ok(text) = std::fs::read_to_string(&abs) else {
            continue;
        };
        let Ok(m) = Manifest::from_toml_str(&text) else {
            continue;
        };
        if !m.is_canonical_toml(&text) {
            let rel = abs.strip_prefix(dir).unwrap_or(&abs);
            drift.push(format!("{}: not in canonical form", rel.display()));
        }
    }
    Ok(drift)
}

/// Full build: validate, compile to sqlite, compress, sign, and write the
/// `index.json` pointer. Writes `index.sqlite`, `index.sqlite.zst`,
/// `index.sig`, and `index.json` into `out`.
///
/// `epoch` is taken from `epoch_flag`, else `$SOURCE_DATE_EPOCH`, else the
/// current system time — so CI can produce a reproducible index. It is stamped
/// *into* the snapshot before signing, and also mirrored into `index.json` for
/// older clients.
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
    let epoch = epoch_flag
        .or_else(|| {
            std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or_else(now_unix_secs);
    if epoch > voli_core::index::MAX_EPOCH {
        bail!(
            "epoch {epoch} is beyond the client's accepted range (max {}); \
             no client would install this index",
            voli_core::index::MAX_EPOCH
        );
    }

    let db_path = out.join("index.sqlite");
    voli_core::index::build(&manifests, &db_path).context("compiling index.sqlite")?;
    // The epoch must live inside the bytes we sign — index.json is a hint the
    // client does not trust (see voli_core::index::stamp_epoch).
    voli_core::index::stamp_epoch(&db_path, epoch)
        .map_err(|e| anyhow::anyhow!("stamping index epoch: {e}"))?;

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

    // Still emitted for pre-0.9 clients, which read the epoch from here. Newer
    // clients use it only to decide whether to download the snapshot.
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
        let updated_times = git_updated_times(dir);
        let mut latest: BTreeMap<(Kind, &str), &Manifest> = BTreeMap::new();
        for m in &manifests {
            let identity = (m.kind, m.name.as_str());
            match latest.get(&identity) {
                Some(prev) => {
                    if voli_core::index::cmp_version(&m.version, &prev.version)
                        == std::cmp::Ordering::Greater
                    {
                        latest.insert(identity, m);
                    }
                }
                None => {
                    latest.insert(identity, m);
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
                    "p": "official",
                    "k": m.kind.as_str(),
                });
                if let Some(updated) =
                    updated_times.get(&(m.kind, m.name.clone(), m.version.clone()))
                {
                    package["u"] = serde_json::json!(updated);
                }
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

fn git_updated_times(dir: &Path) -> std::collections::BTreeMap<(Kind, String, String), u64> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["log", "--format=@@%ct", "--name-only", "--", "."])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            parse_git_updated_times(&String::from_utf8_lossy(&output.stdout))
        }
        _ => std::collections::BTreeMap::new(),
    }
}

fn parse_git_updated_times(log: &str) -> std::collections::BTreeMap<(Kind, String, String), u64> {
    let mut updated = std::collections::BTreeMap::new();
    let mut timestamp = None;
    for line in log.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(value) = line.strip_prefix("@@") {
            timestamp = value.parse().ok();
            continue;
        }
        let Some(timestamp) = timestamp else {
            continue;
        };
        let path = Path::new(line);
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let Some(name) = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
        else {
            continue;
        };
        let Some(version) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let kind = if path
            .components()
            .any(|component| component.as_os_str() == "skills")
        {
            Kind::Skill
        } else if path
            .components()
            .any(|component| component.as_os_str() == "mcp")
        {
            Kind::Mcp
        } else {
            Kind::App
        };
        updated
            .entry((kind, name.to_string(), version.to_string()))
            .or_insert(timestamp);
    }
    updated
}

// ---- auto-bump -----------------------------------------------------------

/// Outcome of a single package bump attempt.
enum BumpResult {
    Bumped {
        from: String,
        to: String,
        note: Option<String>,
    },
    UpToDate(String),
    Skipped(String),
}

struct ResolvedUpdate {
    version: String,
    x64_url: Option<String>,
    arm64_url: Option<String>,
}

/// Check supported release endpoints for newer versions of packages with
/// `[autoupdate]` and emit updated manifests. Returns a human-readable summary.
pub fn bump(dir: &Path, limit: usize) -> Result<String> {
    let (manifests, errors) = analyze(dir)?;
    if !errors.is_empty() {
        bail!("{} manifest error(s); fix before bumping", errors.len());
    }

    // Group by name, keep latest version only.
    let mut latest: std::collections::BTreeMap<String, Manifest> =
        std::collections::BTreeMap::new();
    for m in manifests {
        if m.kind != Kind::App {
            continue;
        }
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

        let update = match resolve_update(m, token.as_deref()) {
            Ok(Some(update)) => update,
            Ok(None) => continue,
            Err(e) => {
                results.push((name.clone(), BumpResult::Skipped(e.to_string())));
                continue;
            }
        };

        match bump_one(name, m, update, dir) {
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
            BumpResult::Bumped { from, to, note } => {
                let note = note
                    .as_ref()
                    .map(|value| format!(" ({value})"))
                    .unwrap_or_default();
                out.push_str(&format!("| {name} | **bumped** | {from} → {to}{note} |\n"));
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

fn resolve_update(m: &Manifest, token: Option<&str>) -> Result<Option<ResolvedUpdate>> {
    if let Some((owner, repo)) = github_repo(m) {
        let version = github_version(&owner, &repo, token)?;
        return Ok(Some(ResolvedUpdate {
            x64_url: None,
            arm64_url: None,
            version,
        }));
    }

    let Some(checkver) = m
        .autoupdate
        .as_ref()
        .and_then(|au| au.get("checkver"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(None);
    };

    if checkver.get("vendor").and_then(toml::Value::as_str) == Some("google-chrome") {
        return google_chrome_update(m).map(Some);
    }

    let Some(url) = checkver.get("url").and_then(toml::Value::as_str) else {
        return Ok(None);
    };
    let Some(pattern) = checkver.get("regex").and_then(toml::Value::as_str) else {
        return Ok(None);
    };
    let version = http_checkver(url, pattern)?;
    Ok(Some(ResolvedUpdate {
        x64_url: None,
        arm64_url: None,
        version,
    }))
}

/// Extract `(owner, repo)` from a manifest's `[autoupdate]` if it has a
/// GitHub-style checkver.
fn github_repo(m: &Manifest) -> Option<(String, String)> {
    let au = m.autoupdate.as_ref()?;
    // checkver = { github = "owner/repo" }
    if let Some(cv) = au.get("checkver") {
        if let Some(gh) = cv.get("github").and_then(|v| v.as_str()) {
            return parse_github_repo(gh);
        }
        // checkver = "owner/repo" or legacy JSON containing a GitHub URL.
        if let Some(s) = cv.as_str() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(s) {
                return value
                    .get("github")
                    .and_then(serde_json::Value::as_str)
                    .and_then(parse_github_repo);
            }
            return parse_github_repo(s);
        }
    }
    None
}

fn parse_github_repo(value: &str) -> Option<(String, String)> {
    let value = value.trim().trim_end_matches('/');
    let path = value
        .strip_prefix("https://api.github.com/repos/")
        .or_else(|| value.strip_prefix("https://github.com/"));
    let is_url = path.is_some();
    let path = path.unwrap_or(value);
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?.trim_end_matches(".git");
    if owner.is_empty()
        || repo.is_empty()
        || (!is_url && parts.next().is_some())
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        || !repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

fn github_version(owner: &str, repo: &str, token: Option<&str>) -> Result<String> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    let mut req = ureq::get(&url).set("User-Agent", "voli-index-tool");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => bail!("repo not found (404)"),
        Err(ureq::Error::Status(403, _)) => bail!("rate limited (403)"),
        Err(e) => return Err(anyhow::anyhow!("GitHub API: {e}")),
    };
    let body: serde_json::Value = resp
        .into_string()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or_else(|| anyhow::anyhow!("bad API JSON"))?;

    body["tag_name"]
        .as_str()
        .map(|tag| tag.trim_start_matches('v').to_string())
        .ok_or_else(|| anyhow::anyhow!("no tag_name"))
}

fn http_checkver(url: &str, pattern: &str) -> Result<String> {
    if !url.starts_with("https://") {
        bail!("checkver URL must use HTTPS");
    }
    let body = ureq::get(url)
        .set("User-Agent", "voli-index-tool")
        .call()
        .map_err(|e| anyhow::anyhow!("checkver {url}: {e}"))?
        .into_string()
        .map_err(|e| anyhow::anyhow!("reading checkver {url}: {e}"))?;
    extract_checkver_version(&body, pattern)
}

fn extract_checkver_version(body: &str, pattern: &str) -> Result<String> {
    let re = regex::Regex::new(pattern).context("invalid checkver regex")?;
    let captures = re
        .captures(body)
        .ok_or_else(|| anyhow::anyhow!("checkver regex did not match"))?;
    captures
        .name("version")
        .or_else(|| captures.get(1))
        .or_else(|| captures.get(0))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow::anyhow!("checkver regex captured no version"))
}

fn google_chrome_update(m: &Manifest) -> Result<ResolvedUpdate> {
    let mut version = None;
    let mut resolve_arch = |arch: &str, source: Option<&voli_core::Source>| {
        let Some(source) = source else {
            return Ok(None);
        };
        let (resolved_version, url) = google_chrome_arch(arch)?;
        if let Some(expected) = &version {
            if expected != &resolved_version {
                bail!("Google Chrome architectures returned different versions");
            }
        } else {
            version = Some(resolved_version);
        }
        Ok(Some(copy_fragment(&url, &source.url)))
    };

    let x64_url = resolve_arch("x64", m.source.x64.as_ref())?;
    let arm64_url = match resolve_arch("arm64", m.source.arm64.as_ref()) {
        Ok(url) => url,
        Err(error) if is_http_not_found(&error) => None,
        Err(error) => return Err(error),
    };
    Ok(ResolvedUpdate {
        version: version.ok_or_else(|| anyhow::anyhow!("no Chrome source architecture"))?,
        x64_url,
        arm64_url,
    })
}

fn google_chrome_arch(arch: &str) -> Result<(String, String)> {
    let app_id = "{8A69D345-D564-463C-AFF1-A69D9E530F96}";
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <request protocol=\"3.0\">\
         <os platform=\"win\" version=\"10.0.22000\" arch=\"{arch}\"/>\
         <app appid=\"{app_id}\" ap=\"{arch}-stable\" version=\"\">\
         <updatecheck/>\
         </app>\
         </request>"
    );
    let response = ureq::post("https://update.googleapis.com/service/update2")
        .set("Content-Type", "text/xml")
        .set("User-Agent", "voli-index-tool")
        .send_string(&body)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("Google update endpoint ({arch})"))?
        .into_string()
        .map_err(|e| anyhow::anyhow!("reading Google update response ({arch}): {e}"))?;
    parse_google_update_response(&response)
}

fn parse_google_update_response(xml: &str) -> Result<(String, String)> {
    let document = roxmltree::Document::parse(xml).context("invalid Google update XML")?;
    let version = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "manifest")
        .and_then(|node| node.attribute("version"))
        .ok_or_else(|| anyhow::anyhow!("Google response has no manifest version"))?;
    let codebase = document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "url")
        .filter_map(|node| node.attribute("codebase"))
        .find(|url| url.starts_with("https://dl.google.com/release2/chrome/"))
        .ok_or_else(|| anyhow::anyhow!("Google response has no Chrome download URL"))?;
    let package = document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "package")
        .filter_map(|node| node.attribute("name"))
        .find(|name| name.ends_with("_chrome_installer_uncompressed.exe"))
        .ok_or_else(|| anyhow::anyhow!("Google response has no full Chrome package"))?;
    if package.contains(['/', '\\']) || package.contains("..") {
        bail!("Google response contains an invalid package name");
    }
    let separator = if codebase.ends_with('/') { "" } else { "/" };
    Ok((
        version.to_string(),
        format!("{codebase}{separator}{package}"),
    ))
}

fn copy_fragment(url: &str, old_url: &str) -> String {
    match old_url.split_once('#') {
        Some((_, fragment)) => format!("{url}#{fragment}"),
        None => url.to_string(),
    }
}

fn bump_one(
    name: &str,
    m: &Manifest,
    update: ResolvedUpdate,
    manifests_dir: &Path,
) -> Result<BumpResult> {
    validate_resolved_version(&update.version)?;
    if voli_core::index::cmp_version(&update.version, &m.version) != std::cmp::Ordering::Greater {
        return Ok(BumpResult::UpToDate(m.version.clone()));
    }

    let mut bumped = m.clone();
    bumped.version = update.version.clone();
    if let Some(extract_dir) = &mut bumped.extract_dir {
        *extract_dir = extract_dir.replace(&m.version, &update.version);
    }
    update_source(
        bumped.source.x64.as_mut(),
        update.x64_url,
        url_template(m, "x64"),
        &m.version,
        &update.version,
    )?;
    let note = if bumped.source.x64.is_some() && bumped.source.arm64.is_some() {
        match update_source(
            bumped.source.arm64.as_mut(),
            update.arm64_url,
            url_template(m, "arm64"),
            &m.version,
            &update.version,
        ) {
            Ok(()) => None,
            Err(error) if is_http_not_found(&error) => {
                bumped.source.arm64 = None;
                Some(format!("arm64 dropped: {error}"))
            }
            Err(error) => return Err(error),
        }
    } else {
        update_source(
            bumped.source.arm64.as_mut(),
            update.arm64_url,
            url_template(m, "arm64"),
            &m.version,
            &update.version,
        )?;
        None
    };
    // The ONE canonical form (voli-core). `toml::to_string_pretty` used to be
    // called here and emitted a shape no other tool produced — empty collections,
    // expanded [autoupdate.checkver] tables — which collided with the registry
    // importer's output on every bumped file.
    let new_toml = bumped.to_canonical_toml();
    Manifest::from_toml_str(&new_toml)
        .map_err(|e| anyhow::anyhow!("emitted manifest invalid: {e}"))?;

    let letter = &name[..1];
    let dest = manifests_dir.join(letter).join(name);
    std::fs::create_dir_all(&dest)?;
    let file = dest.join(format!("{}.toml", update.version));
    std::fs::write(&file, &new_toml)?;

    Ok(BumpResult::Bumped {
        from: m.version.clone(),
        to: update.version,
        note,
    })
}

fn validate_resolved_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version.len() > 128
        || version == "."
        || version == ".."
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        bail!("resolved version contains unsafe filename characters");
    }
    Ok(())
}

fn update_source(
    source: Option<&mut voli_core::Source>,
    url: Option<String>,
    url_template: Option<&str>,
    old_version: &str,
    new_version: &str,
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    let url = url
        .or_else(|| url_template.and_then(|template| render_url_template(template, new_version)))
        .or_else(|| derive_url(&source.url, old_version, new_version))
        .ok_or_else(|| anyhow::anyhow!("url not derivable"))?;
    let hash = download_and_hash(&url, source.is_sha512())?;
    source.url = url;
    if source.is_sha512() {
        source.sha512 = Some(hash);
    } else {
        source.sha256 = Some(hash);
    }
    for extra in &mut source.extra {
        if let Some(url) = derive_url(&extra.url, old_version, new_version) {
            extra.sha256 = download_and_hash(&url, false)?;
            extra.url = url;
        }
    }
    Ok(())
}

fn url_template<'a>(manifest: &'a Manifest, arch: &str) -> Option<&'a str> {
    let template = manifest
        .autoupdate
        .as_ref()?
        .as_table()?
        .get("url_template")?;
    template
        .as_str()
        .filter(|_| arch == "x64")
        .or_else(|| template.as_table()?.get(arch)?.as_str())
}

fn render_url_template(template: &str, version: &str) -> Option<String> {
    for placeholder in ["{version}", "$version"] {
        if template.contains(placeholder) {
            return Some(template.replace(placeholder, version));
        }
    }
    None
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
    use sha2::{Sha256, Sha512};
    let download_url = url.split('#').next().unwrap_or(url);
    let resp = ureq::get(download_url)
        .set("User-Agent", "voli-index-tool")
        .call()
        .map_err(anyhow::Error::new)
        .with_context(|| format!("download {download_url}"))?;
    if sha512 {
        digest_reader::<Sha512>(resp.into_reader(), download_url)
    } else {
        digest_reader::<Sha256>(resp.into_reader(), download_url)
    }
}

fn digest_reader<D: Digest + Default>(mut reader: impl std::io::Read, url: &str) -> Result<String> {
    let mut digest = D::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| anyhow::anyhow!("reading {url}: {e}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn is_http_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ureq::Error>(),
            Some(ureq::Error::Status(404, _))
        )
    })
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

    fn skill_manifest_toml(name: &str, version: &str) -> String {
        format!(
            r#"name = "{name}"
version = "{version}"
description = "test skill {name}"
kind = "skill"

[source.any]
url = "https://example.com/{name}-{version}.zip"
sha256 = "{hash}"
"#,
            hash = "b".repeat(64),
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

    fn write_good_skill(root: &Path, name: &str, version: &str) {
        let letter = &name[..1];
        let dir = root.join("skills").join(letter).join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{version}.toml")),
            skill_manifest_toml(name, version),
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

    /// The drift detector, now a validation error. Every legacy file has been
    /// normalized, so canonical form is enforced rather than merely reported --
    /// that is what stops the one canonical form eroding back into the weekly
    /// merge conflicts it was introduced to end.
    #[test]
    fn check_format_drift_is_a_validation_error() {
        let td = registry_with_examples();
        let root = td.path();
        assert!(
            check_format(root).unwrap().is_empty(),
            "the fixtures are already canonical"
        );

        // The exact shape `bump` used to emit: empty collections and an expanded
        // [autoupdate.checkver] table. Semantically identical, textually not.
        let dir = root.join("f").join("fd");
        let old_style = format!(
            r#"name = "fd"
version = "10.1.0"
description = "test package fd"
homepage = "https://example.com/fd"
icon = "https://example.com/fd.svg"
kind = "app"
bin = ["fd.exe"]
persist = []
shortcuts = []
write_file = []

[source.x64]
url = "https://example.com/fd-10.1.0.zip"
sha256 = "{hash}"
extra = []

[env]

[depends]
"#,
            hash = "a".repeat(64)
        );
        fs::write(dir.join("10.1.0.toml"), &old_style).unwrap();

        let drift = check_format(root).unwrap();
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("fd"), "{drift:?}");

        // validate now surfaces it, so a PR that hand-edits a manifest out of
        // canonical form fails the gate instead of landing and drifting.
        let errors = validate(root).unwrap();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("not in canonical form"), "{errors:?}");

        // But publishing is never blocked by formatting: build goes through
        // analyze, which only reports real validation errors.
        let (manifests, analyze_errors) = analyze(root).unwrap();
        assert!(analyze_errors.is_empty(), "{analyze_errors:?}");
        assert_eq!(manifests.len(), 3);
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
    fn app_and_skill_with_same_name_are_distinct() {
        let td = TempDir::new().unwrap();
        write_good(td.path(), "shared", "1.0.0", "shared.exe");
        write_good_skill(td.path(), "shared", "1.0.0");

        let (manifests, errors) = analyze(td.path()).unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(manifests.len(), 2);
        assert!(manifests.iter().any(|m| m.kind == Kind::App));
        assert!(manifests.iter().any(|m| m.kind == Kind::Skill));
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
        write_good_skill(reg.path(), "tdd", "1.0.0");
        let out = TempDir::new().unwrap();
        // Ephemeral test key written to a temp file — no key material in the repo.
        let keydir = TempDir::new().unwrap();
        let key = keydir.path().join("test-key.hex");
        fs::write(&key, hex::encode([42u8; 32])).unwrap();

        let meta = build(reg.path(), out.path(), &key, Some(1_753_315_200)).unwrap();
        assert_eq!(meta.epoch, 1_753_315_200);
        assert_eq!(meta.manifests, 4);

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
        assert_eq!(packages[0]["p"], "official");
        assert_eq!(packages[0]["k"], "app");
        assert_eq!(packages.as_array().unwrap().len(), 3);
        assert!(
            packages
                .as_array()
                .unwrap()
                .iter()
                .any(|package| package["n"] == "tdd" && package["k"] == "skill")
        );

        // The epoch must be stamped *inside* the signed snapshot, not only in
        // the unauthenticated index.json — otherwise it can be replayed.
        assert_eq!(
            voli_core::index::read_epoch(&out.path().join("index.sqlite")).unwrap(),
            Some(1_753_315_200)
        );

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
    fn renders_supported_url_templates() {
        assert_eq!(
            render_url_template("https://example.com/{version}/tool.zip", "2.0.0"),
            Some("https://example.com/2.0.0/tool.zip".into())
        );
        assert_eq!(
            render_url_template("https://example.com/$version/tool.zip", "2.0.0"),
            Some("https://example.com/2.0.0/tool.zip".into())
        );
        assert_eq!(
            render_url_template("https://example.com/latest/tool.zip", "2.0.0"),
            None
        );
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
    fn github_repo_parses_legacy_json_without_guessing_from_slashes() {
        let mut m = Manifest::from_toml_str(&format!(
            r#"
name = "test"
version = "1.0.0"
kind = "app"
[source.x64]
url = "https://x/a.zip"
sha256 = "{}"
[autoupdate]
checkver = '{{"github":"https://api.github.com/repos/BurntSushi/ripgrep/releases"}}'
"#,
            "a".repeat(64)
        ))
        .unwrap();
        assert_eq!(
            github_repo(&m),
            Some(("BurntSushi".into(), "ripgrep".into()))
        );

        m.autoupdate.as_mut().unwrap()["checkver"] =
            toml::Value::String(r#"{"url":"https://example.com/version"}"#.into());
        assert_eq!(github_repo(&m), None);
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

    #[test]
    fn parses_google_chrome_update_response() {
        let xml = r#"
<response protocol="3.0">
  <app appid="{id}" status="ok">
    <updatecheck status="ok">
      <urls><url codebase="https://dl.google.com/release2/chrome/token_151.2/"/></urls>
      <manifest version="151.2">
        <packages>
          <package name="151.2_chrome_installer.exe" />
          <package name="151.2_chrome_installer_uncompressed.exe" />
        </packages>
      </manifest>
    </updatecheck>
  </app>
</response>
"#;
        assert_eq!(
            parse_google_update_response(xml).unwrap(),
            (
                "151.2".into(),
                "https://dl.google.com/release2/chrome/token_151.2/151.2_chrome_installer_uncompressed.exe"
                    .into()
            )
        );
    }

    #[test]
    fn vendor_checkver_bumps_and_preserves_both_architectures() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}", server.server_addr());
        let worker = std::thread::spawn(move || {
            for request in server.incoming_requests().take(3) {
                let body = match request.url() {
                    "/tool-1.1.0-x64.zip" => b"x64".as_slice(),
                    "/tool-1.1.0-arm64.zip" => b"arm64".as_slice(),
                    "/helper-1.1.0.zip" => b"helper".as_slice(),
                    path => panic!("unexpected request: {path}"),
                };
                request
                    .respond(tiny_http::Response::from_data(body))
                    .unwrap();
            }
        });

        let root = TempDir::new().unwrap();
        let manifest_dir = root.path().join("t").join("tool");
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::write(
            manifest_dir.join("1.0.0.toml"),
            format!(
                r#"
name = "tool"
version = "1.0.0"
description = "vendor package"
kind = "app"
bin = ["tool.exe"]

[source.x64]
url = "{base}/tool-1.0.0-x64.zip"
sha256 = "{hash}"
extra = [{{ url = "{base}/helper-1.0.0.zip", sha256 = "{hash}", extract_to = "helper" }}]

[source.arm64]
url = "{base}/tool-1.0.0-arm64.zip"
sha256 = "{hash}"

[autoupdate]
checkver = {{ url = "https://example.com/version", regex = "([\\d.]+)" }}
"#,
                hash = "a".repeat(64)
            ),
        )
        .unwrap();

        let manifest =
            Manifest::from_toml_str(&fs::read_to_string(manifest_dir.join("1.0.0.toml")).unwrap())
                .unwrap();
        let result = bump_one(
            "tool",
            &manifest,
            ResolvedUpdate {
                version: "1.1.0".into(),
                x64_url: None,
                arm64_url: None,
            },
            root.path(),
        )
        .unwrap();
        worker.join().unwrap();
        assert!(matches!(
            result,
            BumpResult::Bumped { from, to, note: None }
                if from == "1.0.0" && to == "1.1.0"
        ));

        let emitted = fs::read_to_string(manifest_dir.join("1.1.0.toml")).unwrap();
        let manifest = Manifest::from_toml_str(&emitted).unwrap();
        // bump emits the one canonical form — not toml::to_string_pretty, whose
        // empty collections and expanded [autoupdate.checkver] conflicted with
        // every manifest the registry importer produced.
        assert_eq!(emitted, manifest.to_canonical_toml());
        assert!(!emitted.contains("extra = []"), "{emitted}");
        assert!(!emitted.contains("[autoupdate.checkver]"), "{emitted}");
        let x64 = manifest.source.x64.unwrap();
        let arm64 = manifest.source.arm64.unwrap();
        assert_eq!(x64.url, format!("{base}/tool-1.1.0-x64.zip"));
        assert_eq!(arm64.url, format!("{base}/tool-1.1.0-arm64.zip"));
        assert_eq!(x64.sha256.unwrap(), hex::encode(Sha256::digest(b"x64")));
        assert_eq!(arm64.sha256.unwrap(), hex::encode(Sha256::digest(b"arm64")));
        assert_eq!(x64.extra[0].url, format!("{base}/helper-1.1.0.zip"));
        assert_eq!(x64.extra[0].sha256, hex::encode(Sha256::digest(b"helper")));
    }

    #[test]
    fn bump_keeps_x64_when_arm64_download_fails() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}", server.server_addr());
        let worker = std::thread::spawn(move || {
            for request in server.incoming_requests().take(2) {
                if request.url().ends_with("-x64.zip") {
                    request
                        .respond(tiny_http::Response::from_data(b"x64"))
                        .unwrap();
                } else {
                    request.respond(tiny_http::Response::empty(404)).unwrap();
                }
            }
        });
        let manifest = Manifest::from_toml_str(&format!(
            r#"
name = "tool"
version = "1.0.0"
kind = "app"
bin = ["tool.exe"]

[source.x64]
url = "{base}/tool-1.0.0-x64.zip"
sha256 = "{hash}"

[source.arm64]
url = "{base}/tool-1.0.0-arm64.zip"
sha256 = "{hash}"
"#,
            hash = "a".repeat(64)
        ))
        .unwrap();
        let root = TempDir::new().unwrap();
        let result = bump_one(
            "tool",
            &manifest,
            ResolvedUpdate {
                version: "1.1.0".into(),
                x64_url: None,
                arm64_url: None,
            },
            root.path(),
        )
        .unwrap();
        worker.join().unwrap();

        assert!(matches!(
            result,
            BumpResult::Bumped {
                note: Some(note),
                ..
            } if note.starts_with("arm64 dropped:")
        ));
        let emitted = fs::read_to_string(root.path().join("t/tool/1.1.0.toml")).unwrap();
        let bumped = Manifest::from_toml_str(&emitted).unwrap();
        assert!(bumped.source.x64.is_some());
        assert!(bumped.source.arm64.is_none());
    }

    #[test]
    fn bump_does_not_drop_arm64_on_transient_failure() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}", server.server_addr());
        let worker = std::thread::spawn(move || {
            for request in server.incoming_requests().take(2) {
                if request.url().ends_with("-x64.zip") {
                    request
                        .respond(tiny_http::Response::from_data(b"x64"))
                        .unwrap();
                } else {
                    request.respond(tiny_http::Response::empty(500)).unwrap();
                }
            }
        });
        let manifest = Manifest::from_toml_str(&format!(
            r#"
name = "tool"
version = "1.0.0"
kind = "app"
bin = ["tool.exe"]

[source.x64]
url = "{base}/tool-1.0.0-x64.zip"
sha256 = "{hash}"

[source.arm64]
url = "{base}/tool-1.0.0-arm64.zip"
sha256 = "{hash}"
"#,
            hash = "a".repeat(64)
        ))
        .unwrap();
        let root = TempDir::new().unwrap();
        let error = match bump_one(
            "tool",
            &manifest,
            ResolvedUpdate {
                version: "1.1.0".into(),
                x64_url: None,
                arm64_url: None,
            },
            root.path(),
        ) {
            Ok(_) => panic!("transient arm64 failure must abort the bump"),
            Err(error) => error,
        };
        worker.join().unwrap();

        assert!(error.to_string().contains("arm64"));
        assert!(!root.path().join("t/tool/1.1.0.toml").exists());
    }

    #[test]
    fn extracts_vendor_version_and_rejects_unsafe_filenames() {
        assert_eq!(
            extract_checkver_version("stable=1.1.0", r"([\d.]+)").unwrap(),
            "1.1.0"
        );
        assert!(validate_resolved_version("1.2.3-beta_1+build").is_ok());
        assert!(validate_resolved_version("../escape").is_err());
        assert!(validate_resolved_version("bad:version").is_err());
    }

    #[test]
    fn parses_latest_git_timestamp_for_package_versions() {
        let updated = parse_git_updated_times(
            "@@200\nmanifests/t/tool/2.0.0.toml\n\
             @@100\nmanifests/t/tool/2.0.0.toml\nmanifests/t/tool/1.0.0.toml\n",
        );
        assert_eq!(
            updated.get(&(Kind::App, "tool".into(), "2.0.0".into())),
            Some(&200)
        );
        assert_eq!(
            updated.get(&(Kind::App, "tool".into(), "1.0.0".into())),
            Some(&100)
        );
    }
}
