//! `voli web <bang> <query>`: resolve a search shortcut to a URL and open it.
//!
//! The whole point of this command is what it does *not* do: **voli never
//! fetches anything here.** It builds a URL from a table and hands that URL to
//! the shell, so the request is made by the user's own already-logged-in
//! browser. That buys, for free and permanently: no API key, no quota, no cost,
//! no scraping to maintain when an engine changes its HTML, and no way to be
//! bot-blocked. Adding a search engine is one row in [`BANGS`].
//!
//! Injection safety: the query never becomes part of a command line. It is
//! percent-encoded down to the RFC 3986 unreserved set (so `&`, `|`, `"`, `^`,
//! `%`, `$`, a backtick or a newline can only survive as `%XX`), and the
//! resulting URL is passed as a single `lpFile` argument to `ShellExecuteW`.
//! There is no shell, no `cmd /c start`, and no argv splitting anywhere in the
//! path -- see `no_shell_interpreter_in_this_module` in the tests below, which
//! fails if anyone ever reintroduces one.

/// One search shortcut. `aliases` are what the user types; `url_template` has a
/// single `{}` placeholder that receives the percent-encoded query.
pub struct Bang {
    pub aliases: &'static [&'static str],
    pub name: &'static str,
    pub url_template: &'static str,
}

/// The shortcut table. Adding a row is the only change a new engine needs.
///
/// `rustfmt::skip` keeps it one row per line: exploded to five lines each this is
/// 135 lines of noise instead of a table you can read down.
#[rustfmt::skip]
const BANGS: &[Bang] = &[
    // General-purpose search
    Bang { aliases: &["g", "google"], name: "Google", url_template: "https://www.google.com/search?q={}" },
    Bang { aliases: &["ddg", "d", "?"], name: "DuckDuckGo", url_template: "https://duckduckgo.com/?q={}" },
    Bang { aliases: &["bing", "b"], name: "Bing", url_template: "https://www.bing.com/search?q={}" },
    Bang { aliases: &["brave"], name: "Brave Search", url_template: "https://search.brave.com/search?q={}" },
    Bang { aliases: &["kagi", "k"], name: "Kagi", url_template: "https://kagi.com/search?q={}" },
    Bang { aliases: &["sp", "startpage"], name: "Startpage", url_template: "https://www.startpage.com/sp/search?q={}" },
    // Reference
    Bang { aliases: &["w", "wiki", "wikipedia"], name: "Wikipedia", url_template: "https://en.wikipedia.org/w/index.php?search={}" },
    Bang { aliases: &["tr", "translate"], name: "Google Translate", url_template: "https://translate.google.com/?op=translate&text={}" },
    Bang { aliases: &["maps"], name: "Google Maps", url_template: "https://www.google.com/maps/search/{}" },
    Bang { aliases: &["img", "images"], name: "Google Images", url_template: "https://www.google.com/search?tbm=isch&q={}" },
    // Code hosts and package registries
    Bang { aliases: &["gh", "github"], name: "GitHub", url_template: "https://github.com/search?type=repositories&q={}" },
    Bang { aliases: &["ghc", "code"], name: "GitHub code search", url_template: "https://github.com/search?type=code&q={}" },
    Bang { aliases: &["cr", "crates"], name: "crates.io", url_template: "https://crates.io/search?q={}" },
    Bang { aliases: &["rs", "docsrs"], name: "docs.rs", url_template: "https://docs.rs/releases/search?query={}" },
    Bang { aliases: &["std"], name: "Rust std docs", url_template: "https://doc.rust-lang.org/std/index.html?search={}" },
    Bang { aliases: &["npm"], name: "npm", url_template: "https://www.npmjs.com/search?q={}" },
    Bang { aliases: &["pypi"], name: "PyPI", url_template: "https://pypi.org/search/?q={}" },
    Bang { aliases: &["go", "pkggo"], name: "pkg.go.dev", url_template: "https://pkg.go.dev/search?q={}" },
    // Developer reference
    Bang { aliases: &["so", "stackoverflow"], name: "Stack Overflow", url_template: "https://stackoverflow.com/search?q={}" },
    Bang { aliases: &["mdn"], name: "MDN", url_template: "https://developer.mozilla.org/en-US/search?q={}" },
    Bang { aliases: &["ciu", "caniuse"], name: "Can I use", url_template: "https://caniuse.com/?search={}" },
    Bang { aliases: &["aw", "archwiki"], name: "Arch Wiki", url_template: "https://wiki.archlinux.org/index.php?search={}" },
    Bang { aliases: &["man"], name: "man pages", url_template: "https://man.archlinux.org/search?q={}" },
    Bang { aliases: &["cve"], name: "CVE", url_template: "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={}" },
    // Community and media
    Bang { aliases: &["hn"], name: "Hacker News", url_template: "https://hn.algolia.com/?q={}" },
    Bang { aliases: &["r", "reddit"], name: "Reddit", url_template: "https://www.reddit.com/search/?q={}" },
    Bang { aliases: &["yt", "youtube"], name: "YouTube", url_template: "https://www.youtube.com/results?search_query={}" },
];

/// Percent-encode `q` down to the RFC 3986 unreserved set.
///
/// Deliberately stricter than a query-string encoder: **everything** outside
/// `A-Za-z0-9 - . _ ~` becomes `%XX`, including characters that are legal in a
/// URL (`&`, `=`, `+`, `/`). That is what makes the resulting URL's query
/// portion a closed alphabet -- a hostile query cannot add a parameter, escape
/// the placeholder, or contribute a character any downstream consumer could
/// read as syntax.
fn encode(q: &str) -> String {
    let mut out = String::with_capacity(q.len() * 3);
    for &b in q.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The bang whose aliases contain `name` (case-insensitive), if any.
fn find(name: &str) -> Option<&'static Bang> {
    let name = name.to_ascii_lowercase();
    BANGS.iter().find(|b| b.aliases.contains(&name.as_str()))
}

/// Resolve `bang` + `query` to `(definition, url)`. `None` for an unknown bang.
///
/// No network, no process, no side effect: pure string work, which is why the
/// encoding property below can be tested exhaustively.
pub fn resolve(bang: &str, query: &str) -> Option<(&'static Bang, String)> {
    let def = find(bang)?;
    Some((def, def.url_template.replace("{}", &encode(query))))
}

/// The bang table, one aligned row per engine.
fn list() -> String {
    let width = BANGS
        .iter()
        .map(|b| b.aliases.join(", ").len())
        .max()
        .unwrap_or(0);
    let mut out = String::from(
        "Search shortcuts. voli builds the URL and your browser makes the request.\n\n",
    );
    for b in BANGS {
        out.push_str(&format!(
            "  {:<width$}  {}\n",
            b.aliases.join(", "),
            b.name,
            width = width
        ));
    }
    out.push_str(
        "\nUsage: voli web <bang> <query ...>   (--url prints the URL instead of opening it)\n",
    );
    out
}

/// `voli web` entry point. Returns the process exit code.
pub fn run(bang: Option<&str>, query: &[String], url_only: bool, json: bool) -> i32 {
    let Some(bang) = bang else {
        return print_list(json, 0);
    };
    let Some((def, url)) = resolve(bang, &query.join(" ")) else {
        crate::print_problem(
            &format!("unknown search shortcut '{bang}'"),
            "",
            "pick one of the shortcuts below, or run `voli web` to list them",
        );
        return print_list(json, crate::EXIT_ERROR);
    };
    if query.is_empty() {
        crate::print_problem(
            &format!("`voli web {bang}` needs something to search for"),
            "",
            &format!("try `voli web {bang} \"<what you're looking for>\"`"),
        );
        return crate::EXIT_ERROR;
    }

    if url_only {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "bang": bang, "provider": def.name,
                    "query": query.join(" "), "url": url, "opened": false,
                })
            );
        } else {
            println!("{url}");
        }
        return 0;
    }

    match open_url(&url) {
        Ok(()) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "bang": bang, "provider": def.name,
                        "query": query.join(" "), "url": url, "opened": true,
                    })
                );
            } else {
                // Same shape as an install line: mark, what happened, detail.
                println!("{} opened {} search", crate::success_mark(), def.name);
                println!("  {url}");
            }
            0
        }
        Err(e) => {
            crate::print_problem(
                "could not open the browser",
                &e.to_string(),
                &format!("open it yourself: {url}"),
            );
            crate::EXIT_ERROR
        }
    }
}

fn print_list(json: bool, code: i32) -> i32 {
    if json {
        let rows: Vec<_> = BANGS
            .iter()
            .map(|b| {
                serde_json::json!({
                    "aliases": b.aliases, "name": b.name, "url_template": b.url_template,
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "bangs": rows }));
    } else {
        print!("{}", list());
    }
    code
}

/// Hand `url` to the shell's default handler.
///
/// `ShellExecuteW` takes the URL as one `lpFile` string. There is no command
/// line, so there is nothing for a metacharacter to escape into -- the reason
/// this is not `cmd /c start <url>`, which would make a hostile query a
/// command-injection vector.
#[cfg(windows)]
fn open_url(url: &str) -> std::io::Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let open: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: both strings are NUL-terminated and outlive the call; the other
    // parameters are documented-null.
    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            open.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW returns a value > 32 on success; anything else is an error
    // code in disguise (SE_ERR_NOASSOC = 31, ERROR_FILE_NOT_FOUND = 2, ...).
    if rc as usize > 32 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "ShellExecuteW failed (code {})",
            rc as usize
        )))
    }
}

/// Non-Windows builds print the URL rather than guessing at a browser. voli is
/// a Windows tool; this exists so the crate still compiles elsewhere.
#[cfg(not(windows))]
fn open_url(url: &str) -> std::io::Result<()> {
    println!("{url}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The injection property. A query made of nothing but shell
    /// metacharacters must reach the URL only as `%XX` escapes, so the query's
    /// contribution stays inside a closed alphabet.
    #[test]
    fn shell_metacharacters_cannot_escape_into_the_url() {
        let hostile = "a & b | c \" d ^ e % f $ g ` h \n i ' j ; k < l > m ( n ) o { p } q\r\ttab";
        let (_, url) = resolve("g", hostile).unwrap();
        let query = url
            .strip_prefix("https://www.google.com/search?q=")
            .unwrap();
        assert!(
            query
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%')),
            "query portion leaked a raw character: {query}"
        );
        for c in ['&', '|', '"', '^', '$', '`', '\n', '\'', ';', ' ', '<', '>'] {
            assert!(
                !query.contains(c),
                "raw {c:?} survived encoding into {query}"
            );
        }
        // `%` only ever appears as the start of a well-formed escape triple.
        let bytes = query.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'%' {
                assert!(
                    i + 2 < bytes.len()
                        && bytes[i + 1].is_ascii_hexdigit()
                        && bytes[i + 2].is_ascii_hexdigit(),
                    "malformed escape at {i} in {query}"
                );
            }
        }
    }

    /// Guard against a future "simplification" to `cmd /c start <url>`, which
    /// would hand the query to a shell interpreter. This module must contain no
    /// process spawn at all: the URL reaches the OS as one `ShellExecuteW`
    /// argument or not at all.
    #[test]
    fn no_shell_interpreter_in_this_module() {
        let src = include_str!("cmd_web.rs");
        // Only real code counts -- the comments above necessarily name the very
        // things this test forbids, and the test module below does too.
        let code: String = src
            .split("mod tests {")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in ["Command", "process", "cmd.exe", "start ", "powershell"] {
            assert!(
                !code.contains(banned),
                "{banned:?} appeared in cmd_web.rs code -- the browser must be \
                 opened through ShellExecuteW, never a shell"
            );
        }
        assert!(code.contains("ShellExecuteW"), "the Win32 call vanished");
    }

    #[test]
    fn encodes_to_unreserved_set_only() {
        assert_eq!(encode("rust async"), "rust%20async");
        assert_eq!(encode("a+b=c&d"), "a%2Bb%3Dc%26d");
        assert_eq!(encode("safe-chars._~"), "safe-chars._~");
        // Non-ASCII goes out as UTF-8 percent bytes.
        assert_eq!(encode("caf\u{e9}"), "caf%C3%A9");
    }

    #[test]
    fn resolves_by_any_alias_case_insensitively() {
        let (a, _) = resolve("g", "x").unwrap();
        let (b, _) = resolve("GOOGLE", "x").unwrap();
        assert_eq!(a.name, b.name);
        assert_eq!(
            resolve("gh", "voli").unwrap().1,
            "https://github.com/search?type=repositories&q=voli"
        );
        assert!(resolve("definitely-not-a-bang", "x").is_none());
    }

    /// The table is the only thing a new engine touches, so its invariants are
    /// worth asserting: every row has a placeholder, is https, and no alias is
    /// claimed twice (a duplicate would silently shadow the later row).
    #[test]
    fn bang_table_is_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for b in BANGS {
            assert!(
                b.url_template.contains("{}"),
                "{} has no {{}} placeholder",
                b.name
            );
            assert!(
                b.url_template.starts_with("https://"),
                "{} is not https",
                b.name
            );
            assert!(!b.aliases.is_empty(), "{} has no aliases", b.name);
            for a in b.aliases {
                assert!(seen.insert(*a), "alias '{a}' is claimed twice");
                assert_eq!(*a, a.to_ascii_lowercase(), "alias '{a}' must be lowercase");
            }
        }
    }

    #[test]
    fn listing_mentions_every_engine() {
        let text = list();
        for b in BANGS {
            assert!(text.contains(b.name), "listing omits {}", b.name);
            assert!(
                text.contains(b.aliases[0]),
                "listing omits {}",
                b.aliases[0]
            );
        }
    }
}
