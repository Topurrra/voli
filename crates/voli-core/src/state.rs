//! Local state ledger in `db\state.sqlite` (spec §3).
//!
//! Two tables: `installed` (one row per package) and `actions` (the ordered,
//! per-package mutation log). Uninstall replays the action log backwards, so
//! cleanup is never guessed — it's read from here. All writes go through a
//! single transaction.

use std::path::Path;

use rusqlite::Connection;

use crate::install::Action;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS installed (
    name          TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    installed_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
    package     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    action_kind TEXT NOT NULL,
    payload     TEXT NOT NULL,
    PRIMARY KEY (package, seq)
);";

/// A row of the `installed` table.
#[derive(Debug, Clone)]
pub struct InstalledPkg {
    pub name: String,
    pub version: String,
    pub manifest_json: String,
    pub installed_at: i64,
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
        Ok(State { conn })
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

    /// All installed packages, ordered by name.
    pub fn list(&self) -> rusqlite::Result<Vec<InstalledPkg>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, version, manifest_json, installed_at FROM installed ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(InstalledPkg {
                name: r.get(0)?,
                version: r.get(1)?,
                manifest_json: r.get(2)?,
                installed_at: r.get(3)?,
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
