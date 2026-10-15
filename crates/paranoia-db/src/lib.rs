//! Local workspace store for the desktop app, backed by [redb] (a pure-Rust,
//! crash-safe embedded key/value store — no C toolchain needed).
//!
//! Everything is keyed by the SHA-256 of the analyzed file, so annotations
//! follow a binary regardless of where it lives on disk.

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::Value;

const ANNOTATIONS: TableDefinition<&str, &str> = TableDefinition::new("annotations");
const RECENT: TableDefinition<&str, &str> = TableDefinition::new("recent");

const MAX_RECENT: usize = 30;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("workspace database: {0}")]
    Db(String),
    #[error("workspace database: corrupt record: {0}")]
    Json(#[from] serde_json::Error),
}

macro_rules! db_err {
    ($($t:ty),*) => {$(
        impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Error::Db(e.to_string())
            }
        }
    )*};
}
db_err!(redb::DatabaseError, redb::TransactionError, redb::TableError, redb::StorageError, redb::CommitError);

pub type Result<T> = std::result::Result<T, Error>;

pub struct Store {
    db: Database,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(dir) = path.as_ref().parent() {
            std::fs::create_dir_all(dir).map_err(|e| Error::Db(e.to_string()))?;
        }
        let db = Database::create(path)?;
        // Create tables up front so read transactions never see them missing.
        let tx = db.begin_write()?;
        tx.open_table(ANNOTATIONS)?;
        tx.open_table(RECENT)?;
        tx.commit()?;
        Ok(Store { db })
    }

    fn get(&self, table: TableDefinition<&str, &str>, key: &str) -> Result<Option<Value>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(table)?;
        match t.get(key)? {
            Some(v) => Ok(Some(serde_json::from_str(v.value())?)),
            None => Ok(None),
        }
    }

    fn put(&self, table: TableDefinition<&str, &str>, key: &str, value: &Value) -> Result<()> {
        let text = serde_json::to_string(value)?;
        let tx = self.db.begin_write()?;
        tx.open_table(table)?.insert(key, text.as_str())?;
        tx.commit()?;
        Ok(())
    }

    pub fn annotations(&self, sha256: &str) -> Result<Option<Value>> {
        self.get(ANNOTATIONS, sha256)
    }

    pub fn set_annotations(&self, sha256: &str, value: &Value) -> Result<()> {
        self.put(ANNOTATIONS, sha256, value)
    }

    /// Recent files, most recently opened first. Entries must carry an `openedAt` number.
    pub fn recent(&self) -> Result<Vec<Value>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(RECENT)?;
        let mut out = Vec::new();
        for row in t.iter()? {
            let (_, v) = row?;
            if let Ok(v) = serde_json::from_str::<Value>(v.value()) {
                out.push(v);
            }
        }
        out.sort_by(|a, b| opened(b).total_cmp(&opened(a)));
        Ok(out)
    }

    pub fn add_recent(&self, sha256: &str, entry: &Value) -> Result<()> {
        self.put(RECENT, sha256, entry)?;
        // Trim the oldest entries.
        let all = self.recent()?;
        if all.len() > MAX_RECENT {
            let tx = self.db.begin_write()?;
            {
                let mut t = tx.open_table(RECENT)?;
                for v in &all[MAX_RECENT..] {
                    if let Some(k) = v.get("sha256").and_then(Value::as_str) {
                        t.remove(k)?;
                    }
                }
            }
            tx.commit()?;
        }
        Ok(())
    }

    pub fn remove_recent(&self, sha256: &str) -> Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(RECENT)?.remove(sha256)?;
        tx.commit()?;
        Ok(())
    }
}

fn opened(v: &Value) -> f64 {
    v.get("openedAt").and_then(Value::as_f64).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("paranoia-db-test-{}", std::process::id()));
        let path = dir.join("workspace.redb");
        let s = Store::open(&path).unwrap();
        assert!(s.annotations("abc").unwrap().is_none());
        s.set_annotations("abc", &json!({"names": {"4096": "main"}})).unwrap();
        assert_eq!(s.annotations("abc").unwrap().unwrap()["names"]["4096"], "main");

        for i in 0..(MAX_RECENT + 5) {
            s.add_recent(&format!("h{i}"), &json!({"sha256": format!("h{i}"), "openedAt": i})).unwrap();
        }
        let r = s.recent().unwrap();
        assert_eq!(r.len(), MAX_RECENT);
        assert_eq!(r[0]["sha256"], format!("h{}", MAX_RECENT + 4));
        s.remove_recent(&format!("h{}", MAX_RECENT + 4)).unwrap();
        assert_eq!(s.recent().unwrap().len(), MAX_RECENT - 1);
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }
}
