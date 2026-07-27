//! Local state ledger in `db\state.sqlite` (spec §3).
//!
//! Two tables: `installed` (one row per package) and `actions` (the ordered,
//! per-package mutation log). Uninstall replays the action log backwards, so
//! cleanup is never guessed — it's read from here. All writes go through a
//! single transaction.

use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::install::Action;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS installed (
    name          TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    installed_at  INTEGER NOT NULL,
    pinned        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS actions (
    package     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    action_kind TEXT NOT NULL,
    payload     TEXT NOT NULL,
    PRIMARY KEY (package, seq)
);
CREATE TABLE IF NOT EXISTS installed_skills (
    target        TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    description   TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    install_dir   TEXT NOT NULL,
    installed_at  INTEGER NOT NULL,
    PRIMARY KEY (target, name)
);
CREATE TABLE IF NOT EXISTS skill_actions (
    target       TEXT NOT NULL,
    skill        TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    action_kind  TEXT NOT NULL,
    payload      TEXT NOT NULL,
    PRIMARY KEY (target, skill, seq)
);";

/// A row of the `installed` table.
#[derive(Debug, Clone)]
pub struct InstalledPkg {
    pub name: String,
    pub version: String,
    pub manifest_json: String,
    pub installed_at: i64,
    /// Excluded from `upgrade --all` when true (spec §9 pin).
    pub pinned: bool,
}

/// A target-scoped installed skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledSkill {
    pub target: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub manifest_json: String,
    pub install_dir: std::path::PathBuf,
    pub installed_at: i64,
}

/// One filesystem entry owned by an installed skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkillAction {
    DirectoryCreated {
        path: std::path::PathBuf,
    },
    FileWritten {
        path: std::path::PathBuf,
        sha256: String,
    },
}

impl SkillAction {
    fn kind_str(&self) -> &'static str {
        match self {
            SkillAction::DirectoryCreated { .. } => "directory_created",
            SkillAction::FileWritten { .. } => "file_written",
        }
    }
}

/// Handle to the local state database.
pub struct State {
    conn: Connection,
}

impl State {
    /// Open (creating if needed) the state db and ensure the schema exists.
    pub fn open(path: &Path) -> rusqlite::Result<State> {
        if let Some(parent) = path.parent() {
            // db\ is created by Paths::ensure(); this is a cheap safety net.
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        // Migrate DBs created before the `pinned` column existed. `CREATE TABLE
        // IF NOT EXISTS` won't add a column to a pre-existing table, so add it
        // here and ignore the "duplicate column" error on already-migrated DBs.
        if let Err(e) = conn.execute(
            "ALTER TABLE installed ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
            [],
        ) && !e.to_string().contains("duplicate column")
        {
            return Err(e);
        }
        Ok(State { conn })
    }

    /// Whether `name` is pinned (excluded from `upgrade --all`).
    pub fn is_pinned(&self, name: &str) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT pinned FROM installed WHERE name = ?1",
                [name],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v != 0)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(other),
            })
    }

    /// Set the pin flag on `name`. Returns whether the package existed.
    pub fn set_pinned(&mut self, name: &str, pinned: bool) -> rusqlite::Result<bool> {
        let n = self.conn.execute(
            "UPDATE installed SET pinned = ?2 WHERE name = ?1",
            rusqlite::params![name, pinned as i64],
        )?;
        Ok(n > 0)
    }

    pub fn is_installed(&self, name: &str) -> rusqlite::Result<bool> {
        Ok(self.installed_version(name)?.is_some())
    }

    /// The installed version of `name`, if present.
    pub fn installed_version(&self, name: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT version FROM installed WHERE name = ?1",
                [name],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
    }

    /// Insert the installed marker plus the whole action ledger in one txn.
    pub fn record_install(
        &mut self,
        name: &str,
        version: &str,
        manifest_json: &str,
        actions: &[Action],
    ) -> rusqlite::Result<()> {
        let now = now_unix_ms();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO installed (name, version, manifest_json, installed_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, version, manifest_json, now],
        )?;
        for (i, action) in actions.iter().enumerate() {
            // serde_json cannot fail on our own owned types; map defensively.
            let payload = serde_json::to_string(action)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            tx.execute(
                "INSERT INTO actions (package, seq, action_kind, payload)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![name, i as i64, action.kind_str(), payload],
            )?;
        }
        tx.commit()
    }

    /// Replace an installed package's version + entire ledger in one transaction
    /// (spec §3 upgrade). The pin flag is preserved across the swap.
    pub fn replace_install(
        &mut self,
        name: &str,
        version: &str,
        manifest_json: &str,
        actions: &[Action],
    ) -> rusqlite::Result<()> {
        let now = now_unix_ms();
        let tx = self.conn.transaction()?;
        let pinned: i64 = tx
            .query_row(
                "SELECT pinned FROM installed WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        tx.execute("DELETE FROM actions WHERE package = ?1", [name])?;
        tx.execute("DELETE FROM installed WHERE name = ?1", [name])?;
        tx.execute(
            "INSERT INTO installed (name, version, manifest_json, installed_at, pinned)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, version, manifest_json, now, pinned],
        )?;
        for (i, action) in actions.iter().enumerate() {
            let payload = serde_json::to_string(action)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            tx.execute(
                "INSERT INTO actions (package, seq, action_kind, payload)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![name, i as i64, action.kind_str(), payload],
            )?;
        }
        tx.commit()
    }

    /// The action ledger for `name`, in the order it was recorded (ascending seq).
    pub fn actions_for(&self, name: &str) -> rusqlite::Result<Vec<Action>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM actions WHERE package = ?1 ORDER BY seq ASC")?;
        let rows = stmt.query_map([name], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let payload = row?;
            let action: Action = serde_json::from_str(&payload).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            out.push(action);
        }
        Ok(out)
    }

    /// Remove a package's installed marker and action rows in one txn.
    pub fn remove_package(&mut self, name: &str) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM actions WHERE package = ?1", [name])?;
        tx.execute("DELETE FROM installed WHERE name = ?1", [name])?;
        tx.commit()
    }

    pub fn installed_skill(
        &self,
        target: &str,
        name: &str,
    ) -> rusqlite::Result<Option<InstalledSkill>> {
        self.conn
            .query_row(
                "SELECT target, name, version, description, manifest_json, install_dir, installed_at
                 FROM installed_skills WHERE target = ?1 AND name = ?2",
                rusqlite::params![target, name],
                |r| {
                    Ok(InstalledSkill {
                        target: r.get(0)?,
                        name: r.get(1)?,
                        version: r.get(2)?,
                        description: r.get(3)?,
                        manifest_json: r.get(4)?,
                        install_dir: std::path::PathBuf::from(r.get::<_, String>(5)?),
                        installed_at: r.get(6)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_skill_install(
        &mut self,
        target: &str,
        name: &str,
        version: &str,
        description: &str,
        manifest_json: &str,
        install_dir: &Path,
        actions: &[SkillAction],
    ) -> rusqlite::Result<()> {
        let now = now_unix_ms();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO installed_skills
             (target, name, version, description, manifest_json, install_dir, installed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                target,
                name,
                version,
                description,
                manifest_json,
                install_dir.to_string_lossy(),
                now
            ],
        )?;
        for (i, action) in actions.iter().enumerate() {
            let payload = serde_json::to_string(action)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            tx.execute(
                "INSERT INTO skill_actions (target, skill, seq, action_kind, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![target, name, i as i64, action.kind_str(), payload],
            )?;
        }
        tx.commit()
    }

    pub fn skill_actions_for(
        &self,
        target: &str,
        name: &str,
    ) -> rusqlite::Result<Vec<SkillAction>> {
        let mut stmt = self.conn.prepare(
            "SELECT payload FROM skill_actions
             WHERE target = ?1 AND skill = ?2 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![target, name], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let payload = row?;
            let action = serde_json::from_str(&payload).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            out.push(action);
        }
        Ok(out)
    }

    pub fn remove_skill(&mut self, target: &str, name: &str) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM skill_actions WHERE target = ?1 AND skill = ?2",
            rusqlite::params![target, name],
        )?;
        tx.execute(
            "DELETE FROM installed_skills WHERE target = ?1 AND name = ?2",
            rusqlite::params![target, name],
        )?;
        tx.commit()
    }

    /// All installed skills, ordered by target and name.
    pub fn list_skills(&self) -> rusqlite::Result<Vec<InstalledSkill>> {
        let mut stmt = self.conn.prepare(
            "SELECT target, name, version, description, manifest_json, install_dir, installed_at
             FROM installed_skills ORDER BY target ASC, name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(InstalledSkill {
                target: r.get(0)?,
                name: r.get(1)?,
                version: r.get(2)?,
                description: r.get(3)?,
                manifest_json: r.get(4)?,
                install_dir: std::path::PathBuf::from(r.get::<_, String>(5)?),
                installed_at: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// All installed packages, ordered by name.
    pub fn list(&self) -> rusqlite::Result<Vec<InstalledPkg>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, manifest_json, installed_at, pinned
             FROM installed ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(InstalledPkg {
                name: r.get(0)?,
                version: r.get(1)?,
                manifest_json: r.get(2)?,
                installed_at: r.get(3)?,
                pinned: r.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect()
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
