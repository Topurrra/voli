//! `voli install <pkg>[@version] …` (spec §9, §11 step 9).
//!
//! Two paths, auto-detected:
//! - **local**: a single `<name>.toml` file argument plus `--archive <path>` runs
//!   the local engine directly (the step-3 path, kept verbatim).
//! - **network**: everything else resolves names against the downloaded index,
//!   downloads (with a progress bar), and installs deps-first.
//!
//! `--json` swaps the human output (progress bars + confirmations) for a single
//! machine report.

use std::cell::RefCell;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};
use voli_core::remote::{PrefetchStep, prefetch_remote};
use voli_core::{
    Kind, Manifest, PackageRef, RemoteError, RemoteReport, SkillInstallReport, SkillRemoteReport,
    SkillStep, SkillTarget, Step, env, install_manifest, install_remote_env,
    install_skill_archive_many, install_skill_remote_many,
};

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;

pub struct Options<'a> {
    pub root: &'a Path,
    pub json: bool,
    pub yes: bool,
    pub no_env: bool,
    pub for_agents: &'a [String],
    pub project: bool,
    pub global: bool,
    pub parallel: bool,
}

/// Entry point for the `install` subcommand.
pub fn run(packages: &[String], archive: Option<&Path>, options: Options<'_>) -> i32 {
    let Options {
        root,
        json,
        yes,
        no_env,
        for_agents,
        project,
        global,
        parallel,
    } = options;
    // `--yes`, `--json`, or a non-TTY stdin all mean "don't wait for input":
    // apply env without prompting (spec §8, §9).
    let auto = yes || json || !std::io::stdin().is_terminal();
    if let Some(manifest) = local_manifest(packages) {
        if parallel {
            eprintln!("error: --parallel is only available for registry app packages");
            return EXIT_ERROR;
        }
        return install_local_path(
            manifest, archive, root, json, auto, no_env, for_agents, project, global,
        );
    }
    install_network(
        packages, root, json, auto, no_env, for_agents, project, global, parallel,
    )
}

/// Build the per-package env consent closure (spec §8). Prints the requested
/// vars, then applies without prompting when `auto`, skips entirely when
/// `no_env`, and otherwise asks `Apply? [Y/n]` (default yes).
fn env_consent(auto: bool, no_env: bool) -> impl FnMut(&str, &[(String, String)]) -> bool {
    move |name: &str, resolved: &[(String, String)]| {
        if no_env {
            println!("{name} requested environment variables — skipped (--no-env)");
            return false;
        }
        println!("{name} wants to set environment variables:");
        for (k, v) in resolved {
            println!("  {k} = {v}");
        }
        if auto {
            return true;
        }
        print!("Apply? [Y/n] ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        let a = line.trim().to_ascii_lowercase();
        a.is_empty() || a == "y" || a == "yes"
    }
}

/// If this is the local-manifest form (exactly one `<name>.toml` file arg),
/// return its path. Otherwise `None` means network install.
fn local_manifest(packages: &[String]) -> Option<&Path> {
    if packages.len() != 1 {
        return None;
    }
    let arg = &packages[0];
    let p = Path::new(arg);
    (arg.ends_with(".toml") && p.is_file()).then_some(p)
}

#[allow(clippy::too_many_arguments)]
fn install_local_path(
    manifest: &Path,
    archive: Option<&Path>,
    root: &Path,
    json: bool,
    auto: bool,
    no_env: bool,
    for_agents: &[String],
    project_scope: bool,
    global_scope: bool,
) -> i32 {
    let Some(archive) = archive else {
        eprintln!("error: --archive <path> is required to install from a local manifest");
        return EXIT_ERROR;
    };
    let text = match std::fs::read_to_string(manifest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", manifest.display());
            return EXIT_ERROR;
        }
    };
    let parsed = match Manifest::from_toml_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: invalid manifest: {e}");
            return EXIT_ERROR;
        }
    };
    if parsed.kind == Kind::Skill {
        let Some(home) = crate::user_home() else {
            return EXIT_ERROR;
        };
        let selection = match crate::skill_cli::resolve(
            for_agents,
            project_scope,
            global_scope,
            auto,
            &home,
            root,
        ) {
            Ok(selection) => selection,
            Err(error) => {
                eprintln!("error: {error}");
                return EXIT_ERROR;
            }
        };
        crate::skill_cli::print_plan(std::slice::from_ref(&parsed.name), &selection, &home, json);
        if !crate::skill_cli::confirm(auto, json) {
            println!("aborted.");
            return 0;
        }
        return match install_skill_archive_many(
            &parsed,
            archive,
            &selection.targets,
            selection.scope,
            &home,
            &selection.project,
            root,
        ) {
            Ok(reports) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": true,
                            "installed": reports.iter().map(|report| serde_json::json!({
                                "kind": "skill",
                                "name": report.name,
                                "version": report.version,
                                "target": report.target.as_str(),
                                "scope": report.scope.as_str(),
                                "install_dir": report.install_dir.display().to_string(),
                                "files": report.files,
                            })).collect::<Vec<_>>(),
                            "skipped": [],
                        })
                    );
                } else {
                    for report in &reports {
                        print_skill_installed(report);
                    }
                }
                crate::skill_cli::remember(&selection, root);
                EXIT_OK
            }
            Err(error) => {
                crate::print_remote_error("install", &parsed.name, &RemoteError::Skill(error));
                EXIT_ERROR
            }
        };
    }
    if parsed.kind == Kind::Mcp {
        eprintln!("error: MCP installation is not available yet");
        return EXIT_ERROR;
    }
    if !for_agents.is_empty() || project_scope || global_scope {
        eprintln!("error: --for, --project, and --global are only valid for skill packages");
        return EXIT_ERROR;
    }
    let mut consent = env_consent(auto, no_env);
    match install_manifest(
        &parsed,
        archive,
        &[],
        root,
        &env::env_subkey(),
        &mut consent,
    ) {
        Ok(r) => {
            println!(
                "{} installed {} {}",
                crate::success_mark(),
                r.name,
                r.version
            );
            println!("  files: {}", r.version_dir.display());
            for shim in &r.shims {
                println!("  shim:  {}", shim.display());
            }
            print_env_note(&r.env_applied);
            EXIT_OK
        }
        Err(e) => {
            crate::print_remote_error("install", &parsed.name, &RemoteError::Install(e));
            EXIT_ERROR
        }
    }
}

/// Split `name[@version]`; an empty version (`"foo@"`) is treated as unpinned.
fn parse_spec(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once('@') {
        Some((name, ver)) if !ver.is_empty() => (name, Some(ver)),
        Some((name, _)) => (name, None),
        None => (spec, None),
    }
}

struct PackageRows {
    _multi: MultiProgress,
    bars: Vec<ProgressBar>,
}

impl PackageRows {
    fn new(packages: &[(PackageRef, Option<&str>)]) -> PackageRows {
        let multi = MultiProgress::new();
        let bars = packages
            .iter()
            .enumerate()
            .map(|(index, (package, _))| {
                let bar = multi.add(ProgressBar::new_spinner());
                bar.set_style(row_style("dim"));
                bar.set_message(format!(
                    "[{}/{}] · waiting {}",
                    index + 1,
                    packages.len(),
                    package.name
                ));
                bar
            })
            .collect();
        PackageRows {
            _multi: multi,
            bars,
        }
    }

    fn step(&self, step: PrefetchStep) {
        match step {
            PrefetchStep::Queued { .. } => {}
            PrefetchStep::Downloading {
                position,
                total,
                name,
                version,
            } => {
                let bar = &self.bars[position - 1];
                bar.enable_steady_tick(Duration::from_millis(80));
                bar.set_style(crate::download_spinner_style());
                bar.set_message(format!("[{position}/{total}] downloading {name} {version}"));
            }
            PrefetchStep::Progress {
                position,
                done,
                length,
                ..
            } => {
                let bar = &self.bars[position - 1];
                match length {
                    Some(length) if done < length => {
                        bar.set_length(length);
                        bar.set_style(crate::download_bar_style());
                    }
                    None => bar.set_style(crate::download_spinner_style()),
                    Some(_) => {}
                }
                bar.set_position(done);
                crate::set_taskbar_progress(crate::TaskbarProgress::Indeterminate);
            }
            PrefetchStep::Prepared {
                position,
                total,
                name,
                bytes,
                cache_hit,
            } => {
                let bar = &self.bars[position - 1];
                bar.disable_steady_tick();
                bar.set_style(row_style("cyan"));
                let source = if cache_hit {
                    "cache ready"
                } else {
                    "downloads ready"
                };
                bar.set_message(format!(
                    "[{position}/{total}] {} {source} for {name} · {}",
                    crate::cache_mark_on(crate::MarkStream::Stderr),
                    HumanBytes(bytes)
                ));
            }
        }
    }

    fn bar(&self, position: usize) -> ProgressBar {
        self.bars[position - 1].clone()
    }

    fn cancel_after(&self, position: usize, packages: &[(PackageRef, Option<&str>)]) {
        for (index, bar) in self.bars.iter().enumerate().skip(position) {
            bar.disable_steady_tick();
            bar.set_style(row_style("dim"));
            bar.finish_with_message(format!(
                "[{}/{}] · not run {}",
                index + 1,
                packages.len(),
                packages[index].0.name
            ));
        }
    }

    fn fail_all(&self) {
        for bar in &self.bars {
            bar.disable_steady_tick();
            bar.set_style(row_style("red"));
            bar.finish_with_message("× parallel download failed");
        }
    }
}

fn row_style(color: &str) -> ProgressStyle {
    let template = if crate::progress_colors_enabled() {
        match color {
            "green" => "{msg:.green}",
            "red" => "{msg:.red}",
            "cyan" => "{msg:.cyan}",
            "plain" => "{msg}",
            _ => "{msg:.dim}",
        }
    } else {
        "{msg}"
    };
    ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_spinner())
}

#[allow(clippy::too_many_arguments)]
fn install_network(
    packages: &[String],
    root: &Path,
    json: bool,
    auto: bool,
    no_env: bool,
    for_agents: &[String],
    project_scope: bool,
    global_scope: bool,
    parallel: bool,
) -> i32 {
    let mut parsed = Vec::with_capacity(packages.len());
    for spec in packages {
        let (package, version) = parse_spec(spec);
        let package = match PackageRef::parse(package) {
            Ok(package) => package,
            Err(error) => {
                eprintln!("error: invalid package '{spec}': {error}");
                return EXIT_ERROR;
            }
        };
        parsed.push((package, version));
    }
    // Follow renames before anything draws a progress row, so the rows, the
    // ledger and the summary all say the same real name — and say out loud that
    // it is not the name that was typed.
    for (package, _) in &mut parsed {
        // A miss here (no index yet, or no alias) leaves the name alone and lets
        // the install path report it exactly as it always has.
        if let Ok(Some(real)) = voli_core::index::resolved_alias(root, package) {
            if !json {
                println!("note: {} is now {real}", package.name);
            }
            package.name = real;
        }
    }
    let kind = parsed[0].0.kind;
    if parsed.iter().any(|(package, _)| package.kind != kind) {
        eprintln!("error: install app and skill packages in separate commands");
        return EXIT_ERROR;
    }
    if kind == Kind::Mcp {
        eprintln!("error: MCP installation is not available yet");
        return EXIT_ERROR;
    }
    if kind == Kind::App && (!for_agents.is_empty() || project_scope || global_scope) {
        eprintln!("error: --for, --project, and --global are only valid for skill packages");
        return EXIT_ERROR;
    }
    if parallel && kind != Kind::App {
        eprintln!("error: --parallel is only available for app packages");
        return EXIT_ERROR;
    }
    let home = if kind == Kind::Skill {
        let Some(home) = crate::user_home() else {
            return EXIT_ERROR;
        };
        Some(home)
    } else {
        None
    };
    let selection = if kind == Kind::Skill {
        match crate::skill_cli::resolve(
            for_agents,
            project_scope,
            global_scope,
            auto,
            home.as_deref().expect("skill home resolved"),
            root,
        ) {
            Ok(selection) => {
                crate::skill_cli::print_plan(
                    &parsed
                        .iter()
                        .map(|(package, _)| package.name.clone())
                        .collect::<Vec<_>>(),
                    &selection,
                    home.as_deref().expect("skill home resolved"),
                    json,
                );
                if !crate::skill_cli::confirm(auto, json) {
                    println!("aborted.");
                    return 0;
                }
                Some(selection)
            }
            Err(error) => {
                eprintln!("error: {error}");
                return EXIT_ERROR;
            }
        }
    } else {
        None
    };

    let package_rows = (!json && (parallel || parsed.len() > 1)).then(|| PackageRows::new(&parsed));
    if parallel {
        let requests: Vec<_> = parsed
            .iter()
            .map(|(package, version)| {
                (
                    package.name.clone(),
                    version.map(std::string::ToString::to_string),
                )
            })
            .collect();
        crate::set_taskbar_progress(crate::TaskbarProgress::Indeterminate);
        if let Err(error) = prefetch_remote(&requests, root, &mut |step| {
            if let Some(rows) = &package_rows {
                rows.step(step);
            }
        }) {
            if let Some(rows) = &package_rows {
                rows.fail_all();
            }
            crate::set_taskbar_progress(crate::TaskbarProgress::Error);
            crate::print_remote_error("download", "requested packages", &error);
            return EXIT_ERROR;
        }
    }

    let mut agg = RemoteReport::default();
    let mut installed_skills = Vec::new();
    let mut skipped_skills = Vec::new();
    let mut failure: Option<(String, RemoteError)> = None;
    let started = Instant::now();
    let mut total_installed = 0usize;
    let mut total_bytes = 0u64;
    let subkey = env::env_subkey();

    for (i, (package, version)) in parsed.iter().enumerate() {
        let reporter = RefCell::new(match &package_rows {
            Some(rows) => Reporter::with_bar(json, i + 1, packages.len(), rows.bar(i + 1)),
            None => Reporter::new(json, i + 1, packages.len()),
        });
        if package.kind == Kind::App {
            let result = {
                let mut consent = env_consent(auto, no_env);
                let mut visible_consent = |name: &str, resolved: &[(String, String)]| {
                    reporter
                        .borrow_mut()
                        .during_prompt(|| consent(name, resolved))
                };
                install_remote_env(
                    &package.name,
                    *version,
                    root,
                    &subkey,
                    &mut visible_consent,
                    &mut |step| reporter.borrow_mut().step(step),
                )
            };
            let mut reporter = reporter.into_inner();
            let (installed_count, bytes) = reporter.stats();
            total_installed += installed_count;
            total_bytes = total_bytes.saturating_add(bytes);
            match result {
                Ok(mut report) => {
                    agg.installed.append(&mut report.installed);
                    agg.skipped.append(&mut report.skipped);
                    reporter.complete_row();
                }
                Err(error) => {
                    reporter.fail_row(&package.name);
                    if let Some(rows) = &package_rows {
                        rows.cancel_after(i + 1, &parsed);
                    }
                    crate::set_taskbar_progress(crate::TaskbarProgress::Error);
                    failure = Some((package.name.clone(), error));
                    break;
                }
            }
        } else {
            let selection = selection.as_ref().expect("skill selection resolved");
            let result = install_skill_remote_many(
                &package.name,
                *version,
                &selection.targets,
                selection.scope,
                home.as_deref().expect("skill home resolved"),
                &selection.project,
                root,
                &mut |step| reporter.borrow_mut().skill_step(step),
            );
            let mut reporter = reporter.into_inner();
            match result {
                Ok(reports) => {
                    for report in reports {
                        match report {
                            SkillRemoteReport::Installed(report) => {
                                reporter.finish_skill_installed(&report);
                                installed_skills.push(report);
                            }
                            SkillRemoteReport::Skipped {
                                name,
                                version,
                                target,
                            } => {
                                reporter.finish_skill_skipped(
                                    &name,
                                    &version,
                                    target,
                                    selection.scope.as_str(),
                                );
                                skipped_skills.push((
                                    name,
                                    version,
                                    target.as_str().to_string(),
                                    selection.scope.as_str().to_string(),
                                ));
                            }
                        }
                    }
                    let (installed_count, bytes) = reporter.stats();
                    total_installed += installed_count;
                    total_bytes = total_bytes.saturating_add(bytes);
                }
                Err(error) => {
                    reporter.fail_row(&format!("skill/{}", package.name));
                    if let Some(rows) = &package_rows {
                        rows.cancel_after(i + 1, &parsed);
                    }
                    crate::set_taskbar_progress(crate::TaskbarProgress::Error);
                    failure = Some((format!("skill/{}", package.name), error));
                    break;
                }
            }
        }
    }

    if json {
        print_json(&agg, &installed_skills, &skipped_skills, failure.as_ref());
    } else if let Some((name, error)) = &failure {
        crate::print_remote_error("install", name, error);
    } else if total_installed > 0 {
        crate::set_taskbar_progress(crate::TaskbarProgress::Clear);
        println!(
            "{} installed {} package(s) · {} · {:.1}s",
            crate::success_mark(),
            total_installed,
            HumanBytes(total_bytes),
            started.elapsed().as_secs_f32()
        );
    }
    if failure.is_some() {
        EXIT_ERROR
    } else {
        if let Some(selection) = &selection {
            crate::skill_cli::remember(selection, root);
        }
        EXIT_OK
    }
}

/// Drives the live per-package progress bar from [`Step`] events (human mode).
/// In `--json` mode it does nothing — the report is printed once at the end.
pub(crate) struct Reporter {
    json: bool,
    prefix: String,
    bar: Option<ProgressBar>,
    package: Option<String>,
    installing: bool,
    showing_unknown_progress: bool,
    bytes_processed: u64,
    installed_count: usize,
    retain_line: bool,
}

impl Reporter {
    pub(crate) fn new(json: bool, position: usize, total: usize) -> Reporter {
        Reporter {
            json,
            prefix: if total > 1 {
                format!("[{position}/{total}] ")
            } else {
                String::new()
            },
            bar: None,
            package: None,
            installing: false,
            showing_unknown_progress: false,
            bytes_processed: 0,
            installed_count: 0,
            retain_line: false,
        }
    }

    fn with_bar(json: bool, position: usize, total: usize, bar: ProgressBar) -> Reporter {
        let mut reporter = Reporter::new(json, position, total);
        reporter.bar = Some(bar);
        reporter.retain_line = true;
        reporter
    }

    /// Where this reporter's status lines end up.
    ///
    /// `retain_line` is exactly the "keep the progress row and rewrite it"
    /// mode, and a retained row is drawn by indicatif to stderr. Every other
    /// path clears the bar and falls back to `println!` on stdout. One
    /// predicate, so a mark can never be gated on the handle it is not
    /// actually headed for.
    fn mark_stream(&self) -> crate::MarkStream {
        if self.retain_line {
            crate::MarkStream::Stderr
        } else {
            crate::MarkStream::Stdout
        }
    }

    pub(crate) fn step(&mut self, step: Step) {
        if self.json {
            return;
        }
        match step {
            Step::Downloading { name, version } => self.start_download(name, version),
            Step::Progress { done, total } => self.download_progress(done, total),
            Step::Installing {
                name,
                version,
                bytes,
                cache_hit,
            } => self.start_install(name, version, bytes, cache_hit),
            Step::Installed(r) => {
                self.package = None;
                self.installing = false;
                self.showing_unknown_progress = false;
                self.installed_count += 1;
                crate::set_taskbar_progress(crate::TaskbarProgress::Clear);
                let status = format!(
                    "{}{} installed {} {}",
                    self.prefix,
                    crate::success_mark_on(self.mark_stream()),
                    r.name,
                    r.version
                );
                if self.retain_line {
                    if let Some(pb) = &self.bar {
                        pb.disable_steady_tick();
                        pb.set_style(row_style("plain"));
                        pb.set_message(status.clone());
                    }
                } else {
                    if let Some(pb) = self.bar.take() {
                        pb.finish_and_clear();
                    }
                    println!("{status}");
                }
                self.print_above(format!("  arch: {}", r.arch_note()));
                for shim in &r.shims {
                    self.print_above(format!("  shim: {}", shim.display()));
                }
                for (key, value) in &r.env_applied {
                    self.print_above(format!("  env:  {key} = {value}"));
                }
            }
            Step::Skipped { name, version } => {
                self.package = None;
                self.installing = false;
                crate::set_taskbar_progress(crate::TaskbarProgress::Clear);
                let status = format!(
                    "{}{} {name} {version} already installed - skipped",
                    self.prefix,
                    crate::success_mark_on(self.mark_stream())
                );
                if self.retain_line {
                    if let Some(pb) = &self.bar {
                        pb.disable_steady_tick();
                        pb.set_style(row_style("plain"));
                        pb.set_message(status.clone());
                    }
                } else {
                    if let Some(pb) = self.bar.take() {
                        pb.finish_and_clear();
                    }
                    println!("{status}");
                }
            }
        }
    }

    fn skill_step(&mut self, step: SkillStep) {
        if self.json {
            return;
        }
        match step {
            SkillStep::Downloading { name, version } => self.start_download(name, version),
            SkillStep::Progress { done, total } => self.download_progress(done, total),
            SkillStep::Installing {
                name,
                version,
                bytes,
                cache_hit,
            } => self.start_install(name, version, bytes, cache_hit),
        }
    }

    fn start_download(&mut self, name: &str, version: &str) {
        let package = format!("{name} {version}");
        let pb = self.bar.take().unwrap_or_else(ProgressBar::new_spinner);
        pb.enable_steady_tick(Duration::from_millis(80));
        pb.set_style(crate::download_spinner_style());
        pb.set_message(format!("{}downloading {package}", self.prefix));
        self.bar = Some(pb);
        self.package = Some(package);
        self.installing = false;
        self.showing_unknown_progress = false;
        crate::set_taskbar_progress(crate::TaskbarProgress::Indeterminate);
    }

    fn download_progress(&mut self, done: u64, total: Option<u64>) {
        let Some(pb) = &self.bar else {
            return;
        };
        match total {
            Some(total) => {
                if done < total && (self.installing || pb.length() != Some(total)) {
                    pb.set_length(total);
                    pb.set_style(crate::download_bar_style());
                    pb.set_message(format!(
                        "{}downloading {}",
                        self.prefix,
                        self.package.as_deref().unwrap_or("package")
                    ));
                    self.installing = false;
                    self.showing_unknown_progress = false;
                }
                let percent = done
                    .saturating_mul(100)
                    .checked_div(total)
                    .unwrap_or(100)
                    .min(100) as u8;
                crate::set_taskbar_progress(crate::TaskbarProgress::Value(percent));
            }
            None => {
                if self.installing || !self.showing_unknown_progress {
                    pb.set_style(crate::download_spinner_style());
                    pb.set_message(format!(
                        "{}downloading {}",
                        self.prefix,
                        self.package.as_deref().unwrap_or("package")
                    ));
                    self.installing = false;
                    self.showing_unknown_progress = true;
                }
                crate::set_taskbar_progress(crate::TaskbarProgress::Indeterminate);
            }
        }
        pb.set_position(done);
    }

    fn start_install(&mut self, name: &str, version: &str, bytes: u64, cache_hit: bool) {
        let package = format!("{name} {version}");
        let pb = if self.retain_line {
            let pb = self.bar.take().unwrap_or_else(ProgressBar::new_spinner);
            if cache_hit {
                // `ProgressBar::println` prints above the bar, on the bar's own
                // draw target, which is stderr -- not the stdout that the plain
                // `println!` in the other arm uses.
                pb.println(format!(
                    "{}{} found verified download in cache",
                    self.prefix,
                    crate::cache_mark_on(crate::MarkStream::Stderr)
                ));
            }
            pb.enable_steady_tick(Duration::from_millis(80));
            pb.set_style(crate::stage_spinner_style());
            pb.set_message(format!("{}installing {package}", self.prefix));
            pb
        } else {
            if let Some(pb) = self.bar.take() {
                pb.finish_and_clear();
            }
            if cache_hit {
                println!(
                    "{}{} found verified download in cache",
                    self.prefix,
                    crate::cache_mark()
                );
            }
            crate::stage_spinner(format!("{}installing {package}", self.prefix))
        };
        self.bar = Some(pb);
        self.package = Some(package);
        self.installing = true;
        self.showing_unknown_progress = false;
        self.bytes_processed = self.bytes_processed.saturating_add(bytes);
        crate::set_taskbar_progress(crate::TaskbarProgress::Indeterminate);
    }

    pub(crate) fn finish_bar(&mut self) {
        if let Some(pb) = self.bar.take() {
            pb.finish_and_clear();
        }
        self.package = None;
        self.installing = false;
        self.showing_unknown_progress = false;
    }

    pub(crate) fn stats(&self) -> (usize, u64) {
        (self.installed_count, self.bytes_processed)
    }

    fn print_above(&self, message: String) {
        if self.retain_line
            && let Some(pb) = &self.bar
        {
            pb.println(message);
        } else {
            println!("{message}");
        }
    }

    fn complete_row(&mut self) {
        if self.retain_line
            && let Some(pb) = self.bar.take()
        {
            pb.finish();
        }
    }

    fn fail_row(&mut self, name: &str) {
        if self.retain_line
            && let Some(pb) = self.bar.take()
        {
            pb.disable_steady_tick();
            pb.set_style(row_style("red"));
            pb.finish_with_message(format!("{}× failed {name}", self.prefix));
        } else {
            self.finish_bar();
        }
    }

    fn finish_skill_installed(&mut self, report: &SkillInstallReport) {
        self.installed_count += 1;
        self.installing = false;
        crate::set_taskbar_progress(crate::TaskbarProgress::Clear);
        if self.json {
            self.finish_bar();
            return;
        }
        let status = format!(
            "{}{} installed skill/{} {} for {} ({})",
            self.prefix,
            crate::success_mark_on(self.mark_stream()),
            report.name,
            report.version,
            report.target.as_str(),
            report.scope.as_str()
        );
        if self.retain_line {
            if let Some(pb) = self.bar.take() {
                pb.disable_steady_tick();
                pb.println(format!("  files: {}", report.install_dir.display()));
                pb.set_style(row_style("plain"));
                pb.finish_with_message(status);
            }
        } else {
            self.finish_bar();
            print_skill_installed(report);
        }
    }

    fn finish_skill_skipped(
        &mut self,
        name: &str,
        version: &str,
        target: SkillTarget,
        scope: &str,
    ) {
        self.installing = false;
        crate::set_taskbar_progress(crate::TaskbarProgress::Clear);
        if self.json {
            self.finish_bar();
            return;
        }
        let status = format!(
            "{}{} skill/{name} {version} already installed for {} ({scope}) - skipped",
            self.prefix,
            crate::success_mark_on(self.mark_stream()),
            target.as_str()
        );
        if self.retain_line {
            if let Some(pb) = self.bar.take() {
                pb.disable_steady_tick();
                pb.set_style(row_style("plain"));
                pb.finish_with_message(status);
            }
        } else {
            self.finish_bar();
            println!("{status}");
        }
    }

    fn during_prompt<T>(&mut self, prompt: impl FnOnce() -> T) -> T {
        if self.retain_line
            && let Some(pb) = &self.bar
        {
            pb.suspend(prompt)
        } else {
            self.finish_bar();
            prompt()
        }
    }
}

fn print_skill_installed(report: &SkillInstallReport) {
    println!(
        "{} installed skill/{} {} for {} ({})",
        crate::success_mark(),
        report.name,
        report.version,
        report.target.as_str(),
        report.scope.as_str()
    );
    println!("  files: {}", report.install_dir.display());
}

/// Confirm the env vars that were actually applied (spec §8). Empty when the
/// package set none or the user declined.
fn print_env_note(env_applied: &[(String, String)]) {
    for (k, v) in env_applied {
        println!("  env:  {k} = {v}");
    }
}

fn print_json(
    agg: &RemoteReport,
    installed_skills: &[SkillInstallReport],
    skipped_skills: &[(String, String, String, String)],
    failure: Option<&(String, RemoteError)>,
) {
    let mut installed: Vec<_> = agg
        .installed
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": "app",
                "name": r.name,
                "version": r.version,
                "version_dir": r.version_dir.display().to_string(),
                "shims": r.shims.iter().map(|s| s.display().to_string()).collect::<Vec<_>>(),
                "env_requested": r.env_requested.iter()
                    .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    installed.extend(installed_skills.iter().map(|report| {
        serde_json::json!({
            "kind": "skill",
            "name": report.name,
            "version": report.version,
            "target": report.target.as_str(),
            "scope": report.scope.as_str(),
            "install_dir": report.install_dir.display().to_string(),
            "files": report.files,
        })
    }));
    let mut skipped: Vec<_> = agg
        .skipped
        .iter()
        .map(|(n, v)| serde_json::json!({ "kind": "app", "name": n, "version": v }))
        .collect();
    skipped.extend(skipped_skills.iter().map(|(name, version, target, scope)| {
        serde_json::json!({
            "kind": "skill",
            "name": name,
            "version": version,
            "target": target,
            "scope": scope,
        })
    }));

    let mut obj = serde_json::json!({
        "ok": failure.is_none(),
        "installed": installed,
        "skipped": skipped,
    });
    if let Some((name, e)) = failure {
        let suggestions = match e {
            RemoteError::NotFound { suggestions, .. } => suggestions
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "kind": s.kind.as_str(),
                        "name": s.name,
                        "bin": s.bin,
                        "description": s.description,
                    })
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        obj["error"] = serde_json::json!({
            "package": name,
            "message": e.to_string(),
            "suggestions": suggestions,
        });
    }
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

#[cfg(test)]
mod reporter_tests {
    use super::Reporter;
    use crate::MarkStream;

    /// A retained progress row is drawn by indicatif to stderr; every other
    /// path clears the bar and falls back to `println!` on stdout. The mark has
    /// to follow that split, or a piped stdout silently decolours rows that are
    /// still on a terminal.
    #[test]
    fn a_retained_progress_row_gates_its_mark_on_stderr() {
        let mut reporter = Reporter::new(false, 1, 1);
        assert_eq!(
            reporter.mark_stream(),
            MarkStream::Stdout,
            "without a retained row the status is printed to stdout"
        );

        reporter.retain_line = true;
        assert_eq!(
            reporter.mark_stream(),
            MarkStream::Stderr,
            "a retained row is drawn to stderr, so the mark must ask stderr"
        );
    }
}
