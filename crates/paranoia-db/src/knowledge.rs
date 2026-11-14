//! The function knowledge base: remembered functions, indexed so that similar
//! code in a new binary finds them without scanning everything.
//!
//! Tables:
//!
//! - `functions`: id → [`KnownFunction`] as JSON;
//! - `by_exact`: masked-bytes hash → ids, for identical code;
//! - `by_band`: LSH band key → ids, for similar code;
//! - `by_name`: hash of the name → ids, for recognising through the call graph;
//! - `by_identity`: hash of name and code → id, so learning the same function
//!   again updates it instead of adding a copy;
//! - `sources`: SHA-256 of a learned file → what was learned from it.
//!
//! The file holds names and comments, never code or strings from the binaries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use paranoia_core::memory::{band_keys, resolve, FunctionPrint, KnownFunction, Recall, MIN_INSTRUCTIONS};
use redb::{Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const FUNCTIONS: TableDefinition<'_, u64, &str> = TableDefinition::new("functions");
const BY_EXACT: MultimapTableDefinition<'_, u64, u64> = MultimapTableDefinition::new("by_exact");
const BY_BAND: MultimapTableDefinition<'_, u64, u64> = MultimapTableDefinition::new("by_band");
const BY_NAME: MultimapTableDefinition<'_, u64, u64> = MultimapTableDefinition::new("by_name");
const BY_IDENTITY: TableDefinition<'_, u64, u64> = TableDefinition::new("by_identity");
const SOURCES: TableDefinition<'_, &str, &str> = TableDefinition::new("sources");
const META: TableDefinition<'_, &str, u64> = TableDefinition::new("meta");

/// Bands shared by more functions than this are skipped when recalling: they hold
/// generic code (prologues, small wrappers) and would only add noise and time.
const MAX_BAND_IDS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub file: String,
    pub sha256: String,
    pub functions: usize,
    /// Seconds since the Unix epoch.
    pub time: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct LearnStats {
    pub added: usize,
    pub updated: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeStats {
    pub functions: u64,
    pub sources: Vec<SourceInfo>,
}

fn exact_key(k: &KnownFunction) -> u64 {
    k.print.exact ^ k.print.size as u64
}

/// FNV-1a over the name.
fn name_key(name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in name.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn identity(k: &KnownFunction) -> u64 {
    name_key(&k.name) ^ exact_key(k).rotate_left(17)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub struct Knowledge {
    db: Database,
}

impl Knowledge {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(dir) = path.as_ref().parent() {
            std::fs::create_dir_all(dir).map_err(|e| Error::Db(e.to_string()))?;
        }
        let db = Database::create(path)?;
        let tx = db.begin_write()?;
        tx.open_table(FUNCTIONS)?;
        tx.open_multimap_table(BY_EXACT)?;
        tx.open_multimap_table(BY_BAND)?;
        tx.open_multimap_table(BY_NAME)?;
        tx.open_table(BY_IDENTITY)?;
        tx.open_table(SOURCES)?;
        tx.open_table(META)?;
        tx.commit()?;
        Ok(Knowledge { db })
    }

    /// Stores functions. A function already known under the same name with the same
    /// code is replaced, so learning a file again after more work updates it.
    pub fn learn(&self, functions: &[KnownFunction]) -> Result<LearnStats> {
        let mut stats = LearnStats::default();
        let tx = self.db.begin_write()?;
        {
            let mut funcs = tx.open_table(FUNCTIONS)?;
            let mut by_exact = tx.open_multimap_table(BY_EXACT)?;
            let mut by_band = tx.open_multimap_table(BY_BAND)?;
            let mut by_name = tx.open_multimap_table(BY_NAME)?;
            let mut by_id = tx.open_table(BY_IDENTITY)?;
            let mut meta = tx.open_table(META)?;
            let mut sources = tx.open_table(SOURCES)?;
            let mut next = meta.get("next_id")?.map_or(1, |v| v.value());
            let mut per_source: BTreeMap<(String, String), usize> = BTreeMap::new();
            for k in functions {
                if k.print.instructions < MIN_INSTRUCTIONS || k.print.minhash.is_empty() {
                    continue;
                }
                *per_source.entry((k.source_sha256.clone(), k.source.clone())).or_default() += 1;
                let json = serde_json::to_string(k)?;
                let ident = identity(k);
                let existing = by_id.get(ident)?.map(|v| v.value());
                if let Some(id) = existing {
                    funcs.insert(id, json.as_str())?;
                    stats.updated += 1;
                    continue;
                }
                let id = next;
                next += 1;
                funcs.insert(id, json.as_str())?;
                by_id.insert(ident, id)?;
                by_exact.insert(exact_key(k), id)?;
                by_name.insert(name_key(&k.name), id)?;
                for b in band_keys(&k.print.minhash) {
                    by_band.insert(b, id)?;
                }
                stats.added += 1;
            }
            meta.insert("next_id", next)?;
            for ((sha, file), n) in per_source {
                let prev: Option<SourceInfo> = match sources.get(sha.as_str())? {
                    Some(v) => serde_json::from_str(v.value()).ok(),
                    None => None,
                };
                let info = SourceInfo { file, sha256: sha.clone(), functions: n.max(prev.map_or(0, |p| p.functions)), time: now() };
                sources.insert(sha.as_str(), serde_json::to_string(&info)?.as_str())?;
            }
        }
        tx.commit()?;
        Ok(stats)
    }

    /// Remembered functions for the functions in `prints`: same or similar code
    /// first, then neighbours in the call graph (see [`resolve`]). Functions learned
    /// from the same file (`own_sha256`) are never offered back to it, and functions
    /// that already carry the remembered name are left out.
    pub fn recall(&self, prints: &[FunctionPrint], own_sha256: &str, min_score: f32) -> Result<Vec<Recall>> {
        let tx = self.db.begin_read()?;
        let funcs = tx.open_table(FUNCTIONS)?;
        let by_exact = tx.open_multimap_table(BY_EXACT)?;
        let by_band = tx.open_multimap_table(BY_BAND)?;
        let by_name = tx.open_multimap_table(BY_NAME)?;
        let mut cache: HashMap<u64, Option<KnownFunction>> = HashMap::new();
        let mut load = |id: u64| -> Result<Option<KnownFunction>> {
            if let Some(k) = cache.get(&id) {
                return Ok(k.clone());
            }
            let k = match funcs.get(id)? {
                Some(v) => serde_json::from_str::<KnownFunction>(v.value()).ok().filter(|k| k.source_sha256 != own_sha256),
                None => None,
            };
            cache.insert(id, k.clone());
            Ok(k)
        };
        let mut candidates: Vec<Vec<KnownFunction>> = Vec::with_capacity(prints.len());
        for p in prints {
            let mut ids: HashSet<u64> = HashSet::new();
            if p.print.instructions >= MIN_INSTRUCTIONS {
                for v in by_exact.get(p.print.exact ^ p.print.size as u64)? {
                    ids.insert(v?.value());
                }
                for b in band_keys(&p.print.minhash) {
                    let vals = by_band.get(b)?;
                    if vals.len() as usize > MAX_BAND_IDS {
                        continue;
                    }
                    for v in vals {
                        ids.insert(v?.value());
                    }
                }
            }
            let mut ids: Vec<u64> = ids.into_iter().collect();
            ids.sort_unstable();
            let mut list = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(k) = load(id)? {
                    list.push(k);
                }
            }
            candidates.push(list);
        }
        let mut failed: Option<Error> = None;
        let mut find = |name: &str| -> Vec<KnownFunction> {
            let mut out = Vec::new();
            let ids: Vec<u64> = match by_name.get(name_key(name)) {
                Ok(vals) => vals.filter_map(|v| v.ok().map(|v| v.value())).take(MAX_BAND_IDS).collect(),
                Err(e) => {
                    failed.get_or_insert(e.into());
                    return out;
                }
            };
            for id in ids {
                match load(id) {
                    Ok(Some(k)) if k.name == name => out.push(k),
                    Ok(_) => {}
                    Err(e) => {
                        failed.get_or_insert(e);
                    }
                }
            }
            out
        };
        let out = resolve(prints, candidates, min_score, &mut find);
        match failed {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    pub fn stats(&self) -> Result<KnowledgeStats> {
        let tx = self.db.begin_read()?;
        let functions = tx.open_table(FUNCTIONS)?.len()?;
        let mut sources = Vec::new();
        for row in tx.open_table(SOURCES)?.iter()? {
            let (_, v) = row?;
            if let Ok(s) = serde_json::from_str::<SourceInfo>(v.value()) {
                sources.push(s);
            }
        }
        sources.sort_by_key(|s| std::cmp::Reverse(s.time));
        Ok(KnowledgeStats { functions, sources })
    }

    /// Every remembered function, for `paranoia memory export`.
    pub fn all(&self) -> Result<Vec<KnownFunction>> {
        let tx = self.db.begin_read()?;
        let mut v = Vec::new();
        for row in tx.open_table(FUNCTIONS)?.iter()? {
            let (_, json) = row?;
            v.push(serde_json::from_str(json.value())?);
        }
        Ok(v)
    }

    /// Removes everything learned from the file with this SHA-256. Returns how many functions went.
    pub fn forget_source(&self, sha256: &str) -> Result<usize> {
        let tx = self.db.begin_write()?;
        let mut removed = 0;
        {
            let mut funcs = tx.open_table(FUNCTIONS)?;
            let mut by_exact = tx.open_multimap_table(BY_EXACT)?;
            let mut by_band = tx.open_multimap_table(BY_BAND)?;
            let mut by_name = tx.open_multimap_table(BY_NAME)?;
            let mut by_id = tx.open_table(BY_IDENTITY)?;
            let mut doomed: Vec<(u64, KnownFunction)> = Vec::new();
            for row in funcs.iter()? {
                let (id, json) = row?;
                if let Ok(k) = serde_json::from_str::<KnownFunction>(json.value()) {
                    if k.source_sha256 == sha256 {
                        doomed.push((id.value(), k));
                    }
                }
            }
            for (id, k) in doomed {
                funcs.remove(id)?;
                by_id.remove(identity(&k))?;
                by_exact.remove(exact_key(&k), id)?;
                by_name.remove(name_key(&k.name), id)?;
                for b in band_keys(&k.print.minhash) {
                    by_band.remove(b, id)?;
                }
                removed += 1;
            }
            tx.open_table(SOURCES)?.remove(sha256)?;
        }
        tx.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paranoia_core::memory::Fingerprint;

    fn known(name: &str, exact: u64, minhash: Vec<u32>, sha: &str) -> KnownFunction {
        KnownFunction {
            name: name.into(),
            comment: Some(format!("about {name}")),
            var_names: BTreeMap::new(),
            var_types: BTreeMap::new(),
            types: String::new(),
            comments: Vec::new(),
            calls: Vec::new(),
            print: Fingerprint {
                size: 100,
                instructions: 30,
                blocks: 4,
                edges: 5,
                back_edges: 1,
                calls: 2,
                exact,
                shape: exact ^ 1,
                minhash,
                anchors: vec![1, 2, 3],
            },
            source: "a.exe".into(),
            source_sha256: sha.into(),
        }
    }

    fn print_of(k: &KnownFunction, address: u64) -> FunctionPrint {
        FunctionPrint { address, name: format!("sub_{address:X}"), named: false, print: k.print.clone(), callees: Vec::new() }
    }

    #[test]
    fn learn_recall_update_forget() {
        let dir = std::env::temp_dir().join(format!("paranoia-kb-test-{}", std::process::id()));
        let path = dir.join("memory.redb");
        let _ = std::fs::remove_file(&path);
        let kb = Knowledge::open(&path).unwrap();

        let mut decrypt = known("decrypt_config", 7, (0..64).collect(), "aaa");
        // The local types a remembered function's typed variables need travel with it.
        decrypt.types = "struct PACKET {\n  DWORD magic;\n};\n".into();
        let other = known("send_beacon", 9, (1000..1064).collect(), "aaa");
        let s = kb.learn(&[decrypt.clone(), other.clone()]).unwrap();
        assert_eq!((s.added, s.updated), (2, 0));
        // Learning the same functions again updates them in place.
        let s = kb.learn(std::slice::from_ref(&decrypt)).unwrap();
        assert_eq!((s.added, s.updated), (0, 1));
        assert_eq!(kb.stats().unwrap().functions, 2);

        // Identical code in another file: the types come back with the name.
        let r = kb.recall(&[print_of(&decrypt, 0x401000)], "bbb", 0.7).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].known.name, "decrypt_config");
        assert_eq!(r[0].known.types, decrypt.types, "recall keeps the type declarations");
        assert!(r[0].exact);

        // Similar code: most of the sketch and all anchors agree, the bytes don't.
        let mut changed = print_of(&decrypt, 0x402000);
        changed.print.exact = 99;
        changed.print.shape = 98;
        for v in changed.print.minhash.iter_mut().take(8) {
            *v += 5000;
        }
        let r = kb.recall(&[changed], "bbb", 0.7).unwrap();
        assert_eq!(r.len(), 1, "similar code is recalled");
        assert!(!r[0].exact);
        assert!(r[0].score < 1.0);

        // Never offered back to the file it came from.
        assert!(kb.recall(&[print_of(&decrypt, 0x401000)], "aaa", 0.7).unwrap().is_empty());

        assert_eq!(kb.forget_source("aaa").unwrap(), 2);
        assert_eq!(kb.stats().unwrap().functions, 0);
        assert!(kb.recall(&[print_of(&decrypt, 0x401000)], "bbb", 0.7).unwrap().is_empty());
        drop(kb);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
