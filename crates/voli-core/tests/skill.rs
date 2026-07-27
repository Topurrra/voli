#![cfg(windows)]

use std::fs;
use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use voli_core::{
    Manifest, SKILL_TARGET_IDS, SkillError, SkillTarget, State, install_skill_archive,
    uninstall_skill,
};
use zip::write::SimpleFileOptions;

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, contents) in entries {
            if name.ends_with('/') {
                writer.add_directory(*name, options).unwrap();
            } else {
                writer.start_file(*name, options).unwrap();
                writer.write_all(contents).unwrap();
            }
        }
        writer.finish().unwrap();
    }
    bytes
}

fn skill_md(name: &str) -> Vec<u8> {
    format!(
        "---\nname: {name}\ndescription: |\n  A useful skill\n  with two lines.\n---\n# {name}\n\nInstructions.\n"
    )
    .into_bytes()
}

fn write_archive(directory: &Path, bytes: &[u8], name: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn manifest(name: &str, archive: &[u8]) -> Manifest {
    Manifest::from_toml_str(&format!(
        r#"
name = "{name}"
version = "1.0.0"
kind = "skill"

[source.any]
url = "https://example.com/{name}.zip"
sha256 = "{}"
"#,
        hex::encode(Sha256::digest(archive))
    ))
    .unwrap()
}

#[test]
fn resolves_only_known_global_targets() {
    let home = Path::new("C:/Users/test");
    assert_eq!(
        "claude-code".parse::<SkillTarget>().unwrap(),
        SkillTarget::ClaudeCode
    );
    assert_eq!(
        SkillTarget::Windsurf.global_skills_dir(home),
        home.join(".codeium/windsurf/skills")
    );
    assert_eq!(
        "github-copilot"
            .parse::<SkillTarget>()
            .unwrap()
            .global_skills_dir(home),
        home.join(".copilot/skills")
    );
    assert_eq!(
        SkillTarget::Codex.global_skills_dir(home),
        home.join(".agents/skills")
    );
    assert_eq!(SKILL_TARGET_IDS.len(), 66);
    assert!(SKILL_TARGET_IDS.contains(&"claude-code"));
    assert!(!SKILL_TARGET_IDS.contains(&"opencode"));
    assert!("unknown".parse::<SkillTarget>().is_err());
}

#[test]
fn state_migration_preserves_existing_app_rows() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("db/state.sqlite");
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE installed (
                name TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                installed_at INTEGER NOT NULL
             );
             CREATE TABLE actions (
                package TEXT NOT NULL,
                seq INTEGER NOT NULL,
                action_kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (package, seq)
             );
             INSERT INTO installed VALUES ('ripgrep', '1.0.0', '{}', 1);",
        )
        .unwrap();
    drop(connection);

    let state = State::open(&database).unwrap();
    assert_eq!(state.list().unwrap()[0].name, "ripgrep");
    assert!(state.list_skills().unwrap().is_empty());
}

#[test]
fn installs_and_uninstalls_per_target() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let markdown = skill_md("test-skill");
    let archive_bytes = build_zip(&[
        ("test-skill/", b""),
        ("test-skill/SKILL.md", &markdown),
        ("test-skill/references/", b""),
        ("test-skill/references/example.md", b"example"),
    ]);
    let archive = write_archive(temp.path(), &archive_bytes, "skill.zip");
    let manifest = manifest("test-skill", &archive_bytes);

    let claude =
        install_skill_archive(&manifest, &archive, SkillTarget::ClaudeCode, &home, &root).unwrap();
    let codex =
        install_skill_archive(&manifest, &archive, SkillTarget::Codex, &home, &root).unwrap();

    assert_eq!(claude.install_dir, home.join(".claude/skills/test-skill"));
    assert_eq!(codex.install_dir, home.join(".agents/skills/test-skill"));
    assert_eq!(claude.files, 2);
    assert!(claude.install_dir.join("SKILL.md").is_file());
    let state = State::open(&root.join("db/state.sqlite")).unwrap();
    let skills = state.list_skills().unwrap();
    assert_eq!(skills.len(), 2);
    assert_eq!(skills[0].target, "claude-code");
    assert_eq!(skills[0].version, "1.0.0");
    assert!(skills[0].manifest_json.contains("\"kind\":\"skill\""));
    assert_eq!(skills[1].target, "codex");

    uninstall_skill("test-skill", SkillTarget::ClaudeCode, &home, &root).unwrap();
    assert!(!claude.install_dir.exists());
    assert!(codex.install_dir.exists());
}

#[test]
fn uninstall_prunes_voli_created_dirs_but_keeps_populated_ones() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    fs::create_dir_all(&home).unwrap();
    let markdown = skill_md("test-skill");
    let archive_bytes = build_zip(&[("test-skill/", b""), ("test-skill/SKILL.md", &markdown)]);
    let archive = write_archive(temp.path(), &archive_bytes, "skill.zip");
    let manifest = manifest("test-skill", &archive_bytes);

    // Windsurf has a deep global dir (.codeium/windsurf/skills) that voli must
    // fully create then fully remove — zero-trace (§2).
    install_skill_archive(&manifest, &archive, SkillTarget::Windsurf, &home, &root).unwrap();
    assert!(home.join(".codeium/windsurf/skills/test-skill").is_dir());
    uninstall_skill("test-skill", SkillTarget::Windsurf, &home, &root).unwrap();
    assert!(
        !home.join(".codeium").exists(),
        "voli-created scaffolding must be pruned"
    );
    assert!(home.exists(), "home itself is never removed");

    // But a sibling skill (or any content) in a shared dir must survive.
    let sibling = home.join(".codeium/windsurf/skills/other");
    fs::create_dir_all(&sibling).unwrap();
    fs::write(sibling.join("keep.txt"), b"keep").unwrap();
    install_skill_archive(&manifest, &archive, SkillTarget::Windsurf, &home, &root).unwrap();
    uninstall_skill("test-skill", SkillTarget::Windsurf, &home, &root).unwrap();
    assert!(
        sibling.join("keep.txt").is_file(),
        "populated sibling dir must never be pruned"
    );
}

#[test]
fn uninstall_refuses_modified_or_added_files() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let markdown = skill_md("protected");
    let archive_bytes = build_zip(&[("protected/SKILL.md", &markdown)]);
    let archive = write_archive(temp.path(), &archive_bytes, "skill.zip");
    let manifest = manifest("protected", &archive_bytes);
    let report =
        install_skill_archive(&manifest, &archive, SkillTarget::Cursor, &home, &root).unwrap();

    fs::write(report.install_dir.join("SKILL.md"), b"user edit").unwrap();
    assert!(matches!(
        uninstall_skill("protected", SkillTarget::Cursor, &home, &root),
        Err(SkillError::Changed(_))
    ));
    assert!(report.install_dir.exists());

    fs::write(report.install_dir.join("SKILL.md"), markdown).unwrap();
    fs::write(report.install_dir.join("notes.md"), b"user file").unwrap();
    assert!(matches!(
        uninstall_skill("protected", SkillTarget::Cursor, &home, &root),
        Err(SkillError::Changed(_))
    ));
    assert!(report.install_dir.join("notes.md").exists());
}

#[test]
fn uninstall_recovers_interrupted_skill_removal() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let markdown = skill_md("recoverable");
    let archive_bytes = build_zip(&[("recoverable/SKILL.md", &markdown)]);
    let archive = write_archive(temp.path(), &archive_bytes, "recoverable.zip");
    let report = install_skill_archive(
        &manifest("recoverable", &archive_bytes),
        &archive,
        SkillTarget::Cursor,
        &home,
        &root,
    )
    .unwrap();

    let quarantine = report
        .install_dir
        .parent()
        .unwrap()
        .join(".voli-removing-recoverable");
    fs::rename(&report.install_dir, &quarantine).unwrap();
    uninstall_skill("recoverable", SkillTarget::Cursor, &home, &root).unwrap();
    assert!(!quarantine.exists());
    assert!(
        State::open(&root.join("db/state.sqlite"))
            .unwrap()
            .list_skills()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn uninstall_clears_a_ledger_after_completed_directory_removal() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let markdown = skill_md("removed");
    let archive_bytes = build_zip(&[("removed/SKILL.md", &markdown)]);
    let archive = write_archive(temp.path(), &archive_bytes, "removed.zip");
    let report = install_skill_archive(
        &manifest("removed", &archive_bytes),
        &archive,
        SkillTarget::Cursor,
        &home,
        &root,
    )
    .unwrap();

    fs::remove_dir_all(&report.install_dir).unwrap();
    assert!(matches!(
        install_skill_archive(
            &manifest("removed", &archive_bytes),
            &archive,
            SkillTarget::Cursor,
            &home,
            &root
        ),
        Err(SkillError::IncompleteInstall { .. })
    ));
    uninstall_skill("removed", SkillTarget::Cursor, &home, &root).unwrap();
    assert!(
        State::open(&root.join("db/state.sqlite"))
            .unwrap()
            .list_skills()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn refuses_unowned_destination_and_name_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let destination = SkillTarget::Windsurf.global_skills_dir(&home).join("taken");
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("mine.txt"), b"user").unwrap();
    let markdown = skill_md("taken");
    let archive_bytes = build_zip(&[("taken/SKILL.md", &markdown)]);
    let archive = write_archive(temp.path(), &archive_bytes, "taken.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("taken", &archive_bytes),
            &archive,
            SkillTarget::Windsurf,
            &home,
            &root
        ),
        Err(SkillError::DestinationExists(_))
    ));
    assert_eq!(fs::read(destination.join("mine.txt")).unwrap(), b"user");

    let mismatch_bytes = build_zip(&[("wrong/SKILL.md", &skill_md("right"))]);
    let mismatch = write_archive(temp.path(), &mismatch_bytes, "mismatch.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("right", &mismatch_bytes),
            &mismatch,
            SkillTarget::Codex,
            &home,
            &root
        ),
        Err(SkillError::NameMismatch { .. })
    ));
}

#[test]
fn rejects_traversal_and_tar_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let traversal_bytes = build_zip(&[
        ("safe/SKILL.md", &skill_md("safe")),
        ("../outside.txt", b"escape"),
    ]);
    let traversal = write_archive(temp.path(), &traversal_bytes, "traversal.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("safe", &traversal_bytes),
            &traversal,
            SkillTarget::ClaudeCode,
            &home,
            &root
        ),
        Err(SkillError::UnsafeArchiveEntry(_))
    ));

    let mut zip_symlink_bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_symlink_bytes));
        let options = SimpleFileOptions::default();
        writer.start_file("linked/SKILL.md", options).unwrap();
        writer.write_all(&skill_md("linked")).unwrap();
        writer
            .add_symlink("linked/reference", "../outside", options)
            .unwrap();
        writer.finish().unwrap();
    }
    let zip_symlink = write_archive(temp.path(), &zip_symlink_bytes, "symlink.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("linked", &zip_symlink_bytes),
            &zip_symlink,
            SkillTarget::ClaudeCode,
            &home,
            &root
        ),
        Err(SkillError::UnsupportedEntry(_))
    ));

    let tar_path = temp.path().join("symlink.tar.gz");
    let encoder = GzEncoder::new(fs::File::create(&tar_path).unwrap(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let markdown = skill_md("linked");
    let mut file = tar::Header::new_gnu();
    file.set_path("linked/SKILL.md").unwrap();
    file.set_size(markdown.len() as u64);
    file.set_mode(0o644);
    file.set_cksum();
    builder.append(&file, markdown.as_slice()).unwrap();
    let mut link = tar::Header::new_gnu();
    link.set_path("linked/reference").unwrap();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_link_name("../outside").unwrap();
    link.set_size(0);
    link.set_mode(0o777);
    link.set_cksum();
    builder.append(&link, std::io::empty()).unwrap();
    builder.into_inner().unwrap().finish().unwrap();
    let tar_bytes = fs::read(&tar_path).unwrap();

    assert!(matches!(
        install_skill_archive(
            &manifest("linked", &tar_bytes),
            &tar_path,
            SkillTarget::ClaudeCode,
            &home,
            &root
        ),
        Err(SkillError::UnsupportedEntry(_))
    ));
}

#[test]
fn validates_official_name_and_description_limits() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    for (filename, body) in [
        (
            "uppercase.zip",
            "---\nname: Bad-Name\ndescription: valid\n---\n# Body\n",
        ),
        (
            "empty-description.zip",
            "---\nname: valid\ndescription: ''\n---\n# Body\n",
        ),
        (
            "consecutive.zip",
            "---\nname: bad--name\ndescription: valid\n---\n# Body\n",
        ),
    ] {
        let archive_bytes = build_zip(&[("SKILL.md", body.as_bytes())]);
        let archive = write_archive(temp.path(), &archive_bytes, filename);
        assert!(matches!(
            install_skill_archive(
                &manifest("valid", &archive_bytes),
                &archive,
                SkillTarget::Codex,
                &home,
                &root
            ),
            Err(SkillError::InvalidSkill(_))
        ));
    }
}

#[test]
fn rejects_ambiguous_windows_paths_and_duplicate_entries() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    for (filename, bad_path) in [
        ("ads.zip", "safe/data.txt:stream"),
        ("reserved.zip", "safe/CON.txt"),
        ("trailing.zip", "safe/name. "),
    ] {
        let bytes = build_zip(&[("safe/SKILL.md", &skill_md("safe")), (bad_path, b"bad")]);
        let archive = write_archive(temp.path(), &bytes, filename);
        assert!(matches!(
            install_skill_archive(
                &manifest("safe", &bytes),
                &archive,
                SkillTarget::Codex,
                &home,
                &root
            ),
            Err(SkillError::UnsafeArchiveEntry(_))
        ));
    }

    let deep_path = format!("safe/{}/file.txt", "nested/".repeat(64));
    let deep = build_zip(&[
        ("safe/SKILL.md", &skill_md("safe")),
        (&deep_path, b"too deep"),
    ]);
    let archive = write_archive(temp.path(), &deep, "deep.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("safe", &deep),
            &archive,
            SkillTarget::Codex,
            &home,
            &root
        ),
        Err(SkillError::UnsafeArchiveEntry(_))
    ));

    let duplicate = build_zip(&[
        ("safe/SKILL.md", &skill_md("safe")),
        ("safe/./SKILL.md", b"duplicate"),
    ]);
    let archive = write_archive(temp.path(), &duplicate, "duplicate.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("safe", &duplicate),
            &archive,
            SkillTarget::Codex,
            &home,
            &root
        ),
        Err(SkillError::DuplicateEntry(_))
    ));

    let case_duplicate = build_zip(&[
        ("safe/SKILL.md", &skill_md("safe")),
        ("safe/README.md", b"first"),
        ("safe/readme.md", b"second"),
    ]);
    let archive = write_archive(temp.path(), &case_duplicate, "case-duplicate.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("safe", &case_duplicate),
            &archive,
            SkillTarget::Codex,
            &home,
            &root
        ),
        Err(SkillError::DuplicateEntry(_))
    ));
}

#[test]
fn rejects_archives_over_the_entry_limit() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let root = temp.path().join("voli");
    let mut bytes = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut bytes));
        let options = SimpleFileOptions::default();
        writer.start_file("safe/SKILL.md", options).unwrap();
        writer.write_all(&skill_md("safe")).unwrap();
        for index in 0..10_000 {
            writer
                .add_directory(format!("safe/d{index}/"), options)
                .unwrap();
        }
        writer.finish().unwrap();
    }
    let archive = write_archive(temp.path(), &bytes, "too-many.zip");
    assert!(matches!(
        install_skill_archive(
            &manifest("safe", &bytes),
            &archive,
            SkillTarget::Codex,
            &home,
            &root
        ),
        Err(SkillError::TooManyEntries)
    ));
}
