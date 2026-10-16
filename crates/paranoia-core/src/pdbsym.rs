//! Microsoft PDB symbol loading: function names, sizes and globals from a
//! program database, matched to the binary by its CodeView GUID.

use std::io::Cursor;

use pdb::FallibleIterator;
use serde::{Deserialize, Serialize};

use crate::loader::Seed;
use crate::model::FunctionSource;
use crate::Binary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdbReport {
    pub functions: usize,
    pub names: usize,
    pub guid: String,
    /// False when the PDB belongs to a different build (loaded anyway on request).
    pub matched: bool,
}

fn guid_of_binary(bin: &Binary) -> Option<String> {
    bin.info.headers.iter().find(|h| h.key == "PDB GUID").map(|h| h.value.split_whitespace().next().unwrap_or("").to_uppercase())
}

impl Binary {
    /// Loads symbols from `bytes` (a .pdb). Refuses a mismatched PDB unless `force`.
    pub fn load_pdb(&mut self, bytes: Vec<u8>, force: bool) -> Result<PdbReport, String> {
        let mut pdb = pdb::PDB::open(Cursor::new(bytes)).map_err(|e| format!("not a valid PDB: {e}"))?;
        let info = pdb.pdb_information().map_err(|e| e.to_string())?;
        let guid = info.guid.to_string().to_uppercase();
        let matched = guid_of_binary(self).is_some_and(|g| g == guid);
        if !matched && !force {
            return Err(format!(
                "PDB GUID {guid} does not match this binary ({})",
                guid_of_binary(self).unwrap_or_else(|| "no CodeView record".into())
            ));
        }
        let map = pdb.address_map().map_err(|e| e.to_string())?;
        let base = self.info.image_base;

        let mut names: Vec<(u64, String)> = Vec::new();
        let mut seeds: Vec<Seed> = Vec::new();
        let add_proc = |rva: u32, len: u32, name: String, names: &mut Vec<(u64, String)>, seeds: &mut Vec<Seed>| {
            let va = base + rva as u64;
            names.push((va, name));
            seeds.push(Seed { address: va, source: FunctionSource::Symbol, end: (len > 0).then(|| va + len as u64) });
        };

        // Global symbol stream: publics and global data / procedures.
        let globals = pdb.global_symbols().map_err(|e| e.to_string())?;
        let mut it = globals.iter();
        while let Some(sym) = it.next().map_err(|e| e.to_string())? {
            match sym.parse() {
                Ok(pdb::SymbolData::Public(p)) => {
                    if let Some(rva) = p.offset.to_rva(&map) {
                        let name = p.name.to_string().into_owned();
                        if p.function || p.code {
                            add_proc(rva.0, 0, name, &mut names, &mut seeds);
                        } else {
                            names.push((base + rva.0 as u64, name));
                        }
                    }
                }
                Ok(pdb::SymbolData::Data(d)) => {
                    if let Some(rva) = d.offset.to_rva(&map) {
                        names.push((base + rva.0 as u64, d.name.to_string().into_owned()));
                    }
                }
                Ok(pdb::SymbolData::Procedure(p)) => {
                    if let Some(rva) = p.offset.to_rva(&map) {
                        add_proc(rva.0, p.len, p.name.to_string().into_owned(), &mut names, &mut seeds);
                    }
                }
                _ => {}
            }
        }
        // Per-module streams carry static functions with their sizes.
        let dbi = pdb.debug_information().map_err(|e| e.to_string())?;
        let mut modules = dbi.modules().map_err(|e| e.to_string())?;
        while let Some(m) = modules.next().map_err(|e| e.to_string())? {
            let Ok(Some(mi)) = pdb.module_info(&m) else { continue };
            let Ok(mut syms) = mi.symbols() else { continue };
            while let Ok(Some(sym)) = syms.next() {
                match sym.parse() {
                    Ok(pdb::SymbolData::Procedure(p)) => {
                        if let Some(rva) = p.offset.to_rva(&map) {
                            add_proc(rva.0, p.len, p.name.to_string().into_owned(), &mut names, &mut seeds);
                        }
                    }
                    Ok(pdb::SymbolData::Data(d)) => {
                        if let Some(rva) = d.offset.to_rva(&map) {
                            names.push((base + rva.0 as u64, d.name.to_string().into_owned()));
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut count = 0;
        for (va, n) in names {
            let pretty = crate::demangle(&n).unwrap_or(n);
            // PDB names win over export-derived ones; keep the first for duplicates.
            if self.pdb_names.insert(va) {
                self.static_names.insert(va, pretty);
                count += 1;
            }
        }
        let functions = seeds.len();
        let seeds: Vec<Seed> = seeds.into_iter().filter(|s| self.is_executable(s.address)).collect();
        self.seeds.extend(seeds);
        self.reanalyze();
        Ok(PdbReport { functions, names: count, guid, matched })
    }

    /// The PDB file name recorded in the binary (CodeView), if any.
    pub fn pdb_path(&self) -> Option<String> {
        self.info.headers.iter().find(|h| h.key == "PDB path").map(|h| h.value.clone())
    }
}
