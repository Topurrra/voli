//! Archive download with hash-keyed cache and resume (spec §5, §10, §11 step 9).
//!
//! [`download`] fetches an artifact to `cache\<sha256><ext>`, verifying the full
//! sha256 before the file is considered good. The cache is keyed by hash: a
//! present, correctly-hashing file is returned with no network call. Downloads
//! stream to a `<sha256><ext>.part` sidecar while feeding an incremental hasher
//! and a progress callback; only after the hash verifies is the `.part` renamed
//! into place (atomic). A hash mismatch deletes the partial so poison never
//! lingers in the cache.
//!
//! Resume: if a `.part` exists, its bytes are re-hashed and an HTTP `Range`
//! request continues from that offset. If the server ignores `Range` (answers
//! `200` instead of `206`), the download restarts cleanly from zero.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

const USER_AGENT: &str = concat!("voli/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
// Per-read/write timeout, not an overall cap — large archives must not trip it.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const BUF: usize = 64 * 1024;

/// Errors from [`download`].
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("download failed for {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("downloaded artifact hash mismatch for {url}: expected {expected}, got {actual}")]
    HashMismatch {
        url: String,
        expected: String,
        actual: String,
    },
}

type Result<T> = std::result::Result<T, FetchError>;

/// Download `url` into `cache_dir`, verifying it hashes to `expected_sha256`.
///
/// Returns the path to the cached, verified file (`cache_dir\<sha256><ext>`).
/// `progress` is called with `(bytes_done, total_opt)` as bytes arrive — `total`
/// is `None` when the server sends no `Content-Length`. On a cache hit `progress`
/// is invoked once with the final size.
pub fn download(
    url: &str,
    expected_sha256: &str,
    cache_dir: &Path,
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<PathBuf> {
    fs::create_dir_all(cache_dir)?;
    let expected = expected_sha256.trim().to_ascii_lowercase();
    let final_path = cache_dir.join(cache_name(url, &expected));

    // 1. Cache hit: present and hashing correctly → no network.
    if final_path.exists() {
        if hash_file(&final_path)? == expected {
            let total = fs::metadata(&final_path)?.len();
            progress(total, Some(total));
            return Ok(final_path);
        }
        // Corrupt cache entry — never trust or serve it.
        fs::remove_file(&final_path)?;
    }

    let part_path = cache_dir.join(format!("{}.part", cache_name(url, &expected)));

    // 2. Resume: re-hash any existing prefix so we can continue from its length.
    let mut hasher = Sha256::new();
    let mut resume_from = 0u64;
    if part_path.exists() {
        match rehash_prefix(&part_path, &mut hasher) {
            Ok(n) => resume_from = n,
            Err(_) => {
                hasher = Sha256::new();
                resume_from = 0;
            }
        }
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(IO_TIMEOUT)
        .timeout_write(IO_TIMEOUT)
        .build();

    // 3. Request, with a Range header when resuming. A 416 (range unsatisfiable,
    //    e.g. a .part already at/beyond the full length) falls back to a full GET.
    let resp = match request(&agent, url, resume_from) {
        Ok(r) => r,
        Err(FetchError::Http { source, .. }) if is_status(&source, 416) && resume_from > 0 => {
            hasher = Sha256::new();
            resume_from = 0;
            request(&agent, url, 0)?
        }
        Err(e) => return Err(e),
    };

    // 4. Decide append-vs-restart from the actual status. Only a 206 honours our
    //    Range; anything else (200) means restart from zero.
    let resumed = resume_from > 0 && resp.status() == 206;
    let (mut file, mut done, total) = if resumed {
        let remaining = content_length(&resp);
        let total = remaining.map(|r| resume_from + r);
        let f = OpenOptions::new().append(true).open(&part_path)?;
        (f, resume_from, total)
    } else {
        hasher = Sha256::new();
        let total = content_length(&resp);
        let f = File::create(&part_path)?;
        (f, 0u64, total)
    };

    // 5. Stream: hash + write + report as we go.
    progress(done, total);
    let mut reader = resp.into_reader();
    let mut buf = vec![0u8; BUF];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
        done += n as u64;
        progress(done, total);
    }
    file.flush()?;
    drop(file);

    // 6. Verify the whole file before it may enter the cache.
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        let _ = fs::remove_file(&part_path);
        return Err(FetchError::HashMismatch {
            url: url.to_string(),
            expected,
            actual,
        });
    }

    // 7. Atomic publish into the cache.
    fs::rename(&part_path, &final_path)?;
    Ok(final_path)
}

/// GET `url`, adding a `Range: bytes=<from>-` header when `from > 0`.
fn request(agent: &ureq::Agent, url: &str, from: u64) -> Result<ureq::Response> {
    let mut req = agent.get(url).set("User-Agent", USER_AGENT);
    if from > 0 {
        req = req.set("Range", &format!("bytes={from}-"));
    }
    req.call().map_err(|e| FetchError::Http {
        url: url.to_string(),
        source: Box::new(e),
    })
}

/// True if the ureq error is a non-2xx HTTP status equal to `code`.
fn is_status(e: &ureq::Error, code: u16) -> bool {
    matches!(e, ureq::Error::Status(s, _) if *s == code)
}

/// Response body length from `Content-Length`, if present and parseable.
fn content_length(resp: &ureq::Response) -> Option<u64> {
    resp.header("Content-Length").and_then(|v| v.parse().ok())
}

/// Cache filename: `<sha256>` plus the archive extension inferred from the URL,
/// so the extractor (which dispatches on extension) sees a real `.zip`/`.tar.gz`.
fn cache_name(url: &str, sha: &str) -> String {
    format!("{sha}{}", archive_ext(url))
}

/// Recognised archive suffix of `url`'s path (`.zip`, `.tar.gz`, …), else empty.
fn archive_ext(url: &str) -> &'static str {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    const EXTS: &[&str] = &[".tar.gz", ".tar.xz", ".tgz", ".zip", ".7z"];
    for ext in EXTS {
        if path.ends_with(ext) {
            return ext;
        }
    }
    ""
}

fn rehash_prefix(path: &Path, hasher: &mut Sha256) -> io::Result<u64> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; BUF];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok(total)
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut f, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_ext_recognises_common_suffixes() {
        assert_eq!(archive_ext("https://x/y/rg-1.0.0.zip"), ".zip");
        assert_eq!(archive_ext("https://x/y/a.tar.gz?token=1"), ".tar.gz");
        assert_eq!(archive_ext("https://x/y/a.tgz"), ".tgz");
        assert_eq!(archive_ext("https://x/y/a"), "");
    }

    #[test]
    fn cache_name_keys_on_sha_with_ext() {
        assert_eq!(cache_name("https://x/a.zip", "deadbeef"), "deadbeef.zip");
        assert_eq!(cache_name("https://x/a", "deadbeef"), "deadbeef");
    }
}
