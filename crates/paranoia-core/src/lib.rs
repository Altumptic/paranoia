//! # paranoia-core
//!
//! The analysis engine behind Paranoia: loads PE, ELF and Mach-O images,
//! disassembles x86, x86-64 and AArch64, discovers functions and basic
//! blocks, and builds cross references. It has no I/O, no threads and no
//! C dependencies, so the same code runs in the desktop app, the CLI and
//! WebAssembly.
//!
//! ```no_run
//! let bytes = std::fs::read("sample.exe").unwrap();
//! let mut bin = paranoia_core::Binary::load("sample.exe", bytes).unwrap();
//! bin.analyze();
//! for f in bin.functions().iter().take(10) {
//!     println!("{:#x} {}", f.address, f.name);
//! }
//! ```

mod analysis;
pub mod api;
mod demangle;
pub mod disasm;
mod loader;
mod metrics;
pub mod model;
mod pseudo;
mod strings;
mod tools;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

pub use loader::detect;
pub use model::*;
pub use demangle::demangle;
pub use pseudo::{PseudoLine, Pseudocode};
pub use tools::{parse_pattern, Callee, Hit, SearchKind};

use analysis::{Analysis, CodeSource};
use disasm::{Disassembler, NameLookup};
use loader::{MapRange, Seed};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unrecognized file format (expected PE, ELF or Mach-O)")]
    UnknownFormat,
    #[error("malformed {0} file: {1}")]
    Malformed(&'static str, String),
    #[error("address {0:#x} is not mapped")]
    Unmapped(u64),
}

/// User-authored annotations, persisted per file hash by the front-ends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Annotations {
    #[serde(default)]
    pub names: BTreeMap<u64, String>,
    #[serde(default)]
    pub comments: BTreeMap<u64, String>,
    /// Functions defined by hand (IDA's `P`).
    #[serde(default)]
    pub functions: BTreeSet<u64>,
    #[serde(default)]
    pub bookmarks: BTreeMap<u64, String>,
    /// Patched bytes by file offset.
    #[serde(default)]
    pub patches: BTreeMap<u64, u8>,
}

/// A loaded binary plus everything we learned about it.
pub struct Binary {
    file: Vec<u8>,
    slice: (usize, usize),
    info: BinaryInfo,
    ranges: Vec<MapRange>,
    symbols: Vec<Symbol>,
    seeds: Vec<Seed>,
    import_slots: HashMap<u64, usize>,
    /// Names from symbols and exports, by address.
    static_names: HashMap<u64, String>,
    analysis: Option<Analysis>,
    analysis_millis: u64,
    strings: Vec<StringEntry>,
    string_by_va: HashMap<u64, usize>,
    annotations: Annotations,
    /// Original values of patched bytes, by file offset.
    original_bytes: BTreeMap<u64, u8>,
}

impl Binary {
    /// Parses `bytes`. Cheap: no disassembly happens until [`Binary::analyze`].
    pub fn load(file_name: &str, bytes: Vec<u8>) -> Result<Self, Error> {
        let (format, loaded) = loader::load(&bytes)?;
        let slice = loaded.slice.unwrap_or((0, bytes.len()));
        let data = &bytes[slice.0..slice.0 + slice.1];

        let mut sections = loaded.sections;
        for s in &mut sections {
            let start = (s.offset as usize).min(data.len());
            let end = start.saturating_add(s.raw_size as usize).min(data.len());
            s.entropy = metrics::entropy(&data[start..end]);
        }
        let mut hashes = metrics::hashes(&bytes);
        hashes.imphash = loaded.imphash;
        let arch = loaded.arch.unwrap_or(Arch::Unknown);

        let mut ranges = loaded.ranges;
        ranges.sort_by_key(|r| r.vaddr);
        let mut warnings = loaded.warnings;
        if !arch.disassembly_supported() {
            warnings.push(format!("Disassembly for {} is not available yet; headers, imports and strings still work.", arch.label()));
        }

        let info = BinaryInfo {
            file_name: file_name.to_string(),
            file_size: bytes.len() as u64,
            format,
            arch,
            bits: loaded.bits,
            endian: if loaded.big_endian { Endian::Big } else { Endian::Little },
            kind: loaded.kind,
            entry: loaded.entry,
            image_base: loaded.image_base,
            entropy: metrics::entropy(&bytes),
            entropy_map: metrics::entropy_map(&bytes, 512),
            hashes,
            sections,
            imports: loaded.imports,
            exports: loaded.exports,
            libraries: loaded.libraries,
            symbol_count: loaded.symbols.len(),
            mitigations: loaded.mitigations,
            headers: loaded.headers,
            warnings,
            disassembly_supported: arch.disassembly_supported(),
        };

        let import_slots = info.imports.iter().enumerate().filter(|(_, i)| i.address != 0).map(|(n, i)| (i.address, n)).collect();
        let mut static_names = HashMap::new();
        let pretty = |n: &str| demangle::demangle(n).unwrap_or_else(|| n.to_string());
        for s in &loaded.symbols {
            if matches!(s.kind, SymbolKind::Function | SymbolKind::Object) {
                static_names.entry(s.address).or_insert_with(|| pretty(&s.name));
            }
        }
        for e in &info.exports {
            if e.address != 0 {
                static_names.entry(e.address).or_insert_with(|| pretty(&e.name));
            }
        }

        Ok(Binary {
            file: bytes,
            slice,
            info,
            ranges,
            symbols: loaded.symbols,
            seeds: loaded.seeds,
            import_slots,
            static_names,
            analysis: None,
            analysis_millis: 0,
            strings: Vec::new(),
            string_by_va: HashMap::new(),
            annotations: Annotations::default(),
            original_bytes: BTreeMap::new(),
        })
    }

    pub fn info(&self) -> &BinaryInfo {
        &self.info
    }

    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Bytes of the analyzed image (the selected slice for universal binaries).
    pub fn data(&self) -> &[u8] {
        &self.file[self.slice.0..self.slice.0 + self.slice.1]
    }

    pub fn is_analyzed(&self) -> bool {
        self.analysis.is_some()
    }

    // --------------------------------------------------------------------------------------------
    // Address translation
    // --------------------------------------------------------------------------------------------

    fn range_of(&self, va: u64) -> Option<&MapRange> {
        // Ranges are few (tens); prefer the most specific (smallest) mapping.
        self.ranges.iter().filter(|r| r.contains(va)).min_by_key(|r| r.vsize)
    }

    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        let r = self.range_of(va)?;
        let delta = va - r.vaddr;
        (delta < r.file_size).then(|| r.offset + delta)
    }

    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        self.ranges
            .iter()
            .filter(|r| offset >= r.offset && offset < r.offset + r.file_size)
            .min_by_key(|r| r.file_size)
            .map(|r| r.vaddr + (offset - r.offset))
    }

    /// File bytes backing `va` up to the end of its mapping.
    pub fn bytes_at(&self, va: u64) -> Option<&[u8]> {
        let r = self.range_of(va)?;
        let delta = va - r.vaddr;
        if delta >= r.file_size {
            return None;
        }
        let data = self.data();
        let start = (r.offset + delta) as usize;
        let end = ((r.offset + r.file_size) as usize).min(data.len());
        (start < end).then(|| &data[start..end])
    }

    pub fn is_executable(&self, va: u64) -> bool {
        self.range_of(va).is_some_and(|r| r.perms.x)
    }

    pub fn section_of(&self, va: u64) -> Option<&Section> {
        self.info.sections.iter().filter(|s| va >= s.vaddr && va < s.vaddr + s.vsize.max(1) && s.vaddr != 0).min_by_key(|s| s.vsize)
    }

    /// Raw file read (hex view). Clamped to the end of the image.
    pub fn read(&self, offset: u64, len: usize) -> &[u8] {
        let data = self.data();
        let start = (offset as usize).min(data.len());
        &data[start..start.saturating_add(len).min(data.len())]
    }

    // --------------------------------------------------------------------------------------------
    // Analysis
    // --------------------------------------------------------------------------------------------

    /// Runs auto-analysis (function discovery, CFG, xrefs, strings). Idempotent.
    pub fn analyze(&mut self) -> AnalysisStats {
        #[cfg(not(target_arch = "wasm32"))]
        let t0 = std::time::Instant::now();

        if self.analysis.is_none() {
            let mut seeds = self.seeds.clone();
            seeds.extend(self.annotations.functions.iter().filter(|a| self.is_executable(**a)).map(|&address| Seed {
                address,
                source: FunctionSource::User,
                end: None,
            }));
            let a = if self.info.disassembly_supported {
                let mut dis = Disassembler::new(self.info.arch);
                analysis::run(&Source(self), &mut dis, &seeds, self.info.arch == Arch::Arm64)
            } else {
                Analysis::default()
            };
            self.analysis = Some(a);
            self.build_strings(4);
            #[cfg(not(target_arch = "wasm32"))]
            {
                self.analysis_millis = t0.elapsed().as_millis() as u64;
            }
        }

        let a = self.analysis.as_ref().unwrap();
        AnalysisStats {
            functions: a.functions.len(),
            instructions: a.instruction_count,
            blocks: a.block_count,
            strings: self.strings.len(),
            xrefs: a.xrefs.values().map(Vec::len).sum(),
            millis: self.analysis_millis,
        }
    }

    fn build_strings(&mut self, min_len: usize) {
        let raw = strings::extract(self.data(), min_len);
        let mut out = Vec::with_capacity(raw.len());
        for s in raw {
            let address = self.offset_to_va(s.offset);
            // Byte runs inside code are mostly instruction noise; keep only convincing ones.
            if address.is_some_and(|a| self.is_executable(a)) && !looks_like_text(&s.value) {
                continue;
            }
            let section = address.and_then(|a| self.section_of(a)).map(|s| s.name.clone());
            let xrefs = address
                .and_then(|a| self.analysis.as_ref()?.xrefs.get(&a))
                .map_or(0, |x| x.iter().filter(|r| r.kind == XrefKind::Data).count());
            out.push(StringEntry { offset: s.offset, address, section, encoding: s.encoding, value: s.value, xrefs });
        }
        self.string_by_va = out.iter().enumerate().filter_map(|(i, s)| Some((s.address?, i))).collect();
        self.strings = out;
    }

    pub fn strings(&self) -> &[StringEntry] {
        &self.strings
    }

    fn function_name(&self, f: &analysis::Function) -> String {
        if let Some(n) = self.annotations.names.get(&f.address).or_else(|| self.static_names.get(&f.address)) {
            return n.clone();
        }
        if let Some(imp) = f.thunk_slot.and_then(|s| self.import_slots.get(&s)) {
            let n = &self.info.imports[*imp].name;
            return format!("j_{}", demangle::demangle(n).unwrap_or_else(|| n.clone()));
        }
        if f.address == self.info.entry {
            return "start".into();
        }
        format!("sub_{:X}", f.address)
    }

    pub fn functions(&self) -> Vec<FunctionSummary> {
        let Some(a) = &self.analysis else { return Vec::new() };
        let mut v: Vec<FunctionSummary> = a
            .functions
            .iter()
            .map(|f| FunctionSummary {
                address: f.address,
                name: self.function_name(f),
                size: f.end.saturating_sub(f.address),
                blocks: f.blocks.len(),
                instructions: f.instructions,
                calls: f.calls.len(),
                xrefs: a.xrefs.get(&f.address).map_or(0, |x| x.iter().filter(|r| r.kind != XrefKind::Data).count()),
                source: f.source,
                is_import_thunk: f.thunk_slot.is_some(),
            })
            .collect();
        v.sort_by_key(|f| f.address);
        v
    }

    /// The name shown for an address in operands and labels.
    pub fn name_at(&self, va: u64) -> Option<String> {
        if let Some(n) = self.annotations.names.get(&va) {
            return Some(n.clone());
        }
        if let Some(a) = &self.analysis {
            if let Some(&i) = a.by_start.get(&va) {
                return Some(self.function_name(&a.functions[i]));
            }
        }
        if let Some(n) = self.static_names.get(&va) {
            return Some(n.clone());
        }
        if let Some(&i) = self.import_slots.get(&va) {
            let n = &self.info.imports[i].name;
            return Some(demangle::demangle(n).unwrap_or_else(|| n.clone()));
        }
        let a = self.analysis.as_ref()?;
        let (start, _) = a.block_index.get_key_value(&va)?;
        Some(format!("loc_{start:X}"))
    }

    fn function_index_containing(&self, va: u64) -> Option<usize> {
        let a = self.analysis.as_ref()?;
        if let Some(&i) = a.by_start.get(&va) {
            return Some(i);
        }
        let f = a.function_containing(va)?;
        a.by_start.get(&f.address).copied()
    }

    pub fn function_at(&self, va: u64) -> Option<FunctionSummary> {
        let i = self.function_index_containing(va)?;
        let start = self.analysis.as_ref()?.functions[i].address;
        self.functions().into_iter().find(|f| f.address == start)
    }

    fn annotate(&self, insns: &mut [Instruction]) {
        let a = self.analysis.as_ref();
        for ins in insns {
            let va = ins.address;
            if a.is_some_and(|a| a.by_start.contains_key(&va) || a.block_index.contains_key(&va)) || self.static_names.contains_key(&va) {
                ins.label = self.name_at(va);
            }
            ins.user_comment = self.annotations.comments.get(&va).cloned();
            if let Some(t) = ins.target {
                if let Some(&si) = self.string_by_va.get(&t).filter(|_| !self.is_executable(t)) {
                    let s = &self.strings[si];
                    let prefix = if s.encoding == StringEncoding::Utf16 { "L" } else { "" };
                    let mut v: String = s.value.chars().take(120).collect();
                    if s.value.chars().count() > 120 {
                        v.push('…');
                    }
                    ins.comment = Some(format!("{prefix}\"{}\"", v.escape_debug()));
                } else if let Some(&ii) = self.import_slots.get(&t) {
                    let imp = &self.info.imports[ii];
                    if !imp.library.is_empty() {
                        ins.comment = Some(format!("{}!{}", imp.library, imp.name));
                    }
                } else if let Some(f) = a.and_then(|a| a.by_start.get(&t)).map(|&i| &a.unwrap().functions[i]) {
                    if let Some(&ii) = f.thunk_slot.and_then(|s| self.import_slots.get(&s)) {
                        let imp = &self.info.imports[ii];
                        ins.comment = Some(format!("{}!{}", imp.library, imp.name));
                    }
                }
            }
        }
    }

    /// Linear disassembly of up to `count` instructions starting at `va`.
    pub fn disassemble(&self, va: u64, count: usize) -> Result<Vec<Instruction>, Error> {
        let bytes = self.bytes_at(va).ok_or(Error::Unmapped(va))?;
        let mut out = disasm::render(self.info.arch, bytes, va, count, &Names(self));
        self.annotate(&mut out);
        Ok(collapse_padding(out))
    }

    /// The start of the function (or block) that precedes `va`, for scrolling a listing backwards.
    pub fn previous_anchor(&self, va: u64) -> Option<u64> {
        let a = self.analysis.as_ref()?;
        let r = self.range_of(va)?;
        a.block_index.range(r.vaddr..va).next_back().map(|(s, _)| *s).or_else(|| (va > r.vaddr).then_some(r.vaddr))
    }

    pub fn function_graph(&self, va: u64) -> Option<FunctionGraph> {
        let a = self.analysis.as_ref()?;
        let f = &a.functions[self.function_index_containing(va)?];
        let names = Names(self);
        let mut blocks = Vec::with_capacity(f.blocks.len());
        for b in &f.blocks {
            let bytes = self.bytes_at(b.start)?;
            let len = ((b.end - b.start) as usize).min(bytes.len());
            let mut insns = disasm::render(self.info.arch, &bytes[..len], b.start, usize::MAX, &names);
            self.annotate(&mut insns);
            blocks.push(GraphBlock { start: b.start, end: b.end, instructions: insns, succs: b.succs.clone() });
        }
        Some(FunctionGraph { address: f.address, name: self.function_name(f), blocks })
    }

    pub fn xrefs_to(&self, va: u64) -> Vec<Xref> {
        let Some(a) = &self.analysis else { return Vec::new() };
        let mut v: Vec<Xref> = a
            .xrefs
            .get(&va)
            .map(|refs| {
                refs.iter()
                    .map(|r| {
                        let f = a.function_containing(r.from);
                        Xref {
                            from: r.from,
                            to: va,
                            kind: r.kind,
                            function: f.map(|f| f.address),
                            function_name: f.map(|f| self.function_name(f)),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by_key(|x| x.from);
        v.dedup_by_key(|x| x.from);
        v
    }

    pub fn address_info(&self, va: u64) -> AddressInfo {
        let f = self.function_index_containing(va).map(|i| &self.analysis.as_ref().unwrap().functions[i]);
        AddressInfo {
            address: va,
            offset: self.va_to_offset(va),
            section: self.section_of(va).map(|s| s.name.clone()),
            name: self.name_at(va),
            function: f.map(|f| f.address),
            function_name: f.map(|f| self.function_name(f)),
            executable: self.is_executable(va),
        }
    }

    /// Searches names, imports, exports and strings. A hex number is treated as an address.
    pub fn search(&self, query: &str, limit: usize) -> Vec<SearchHit> {
        let q = query.trim();
        let mut hits = Vec::new();
        if q.is_empty() {
            return hits;
        }
        let hex = q.trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(addr) = u64::from_str_radix(hex, 16) {
            if self.range_of(addr).is_some() {
                hits.push(SearchHit { kind: "address".into(), label: format!("{addr:#x}"), detail: self.name_at(addr).unwrap_or_default(), address: addr });
            }
        }
        let ql = q.to_lowercase();
        let m = |s: &str| s.to_lowercase().contains(&ql);
        for f in self.functions() {
            if hits.len() >= limit {
                return hits;
            }
            if m(&f.name) {
                hits.push(SearchHit { kind: "function".into(), label: f.name, detail: format!("{} instructions", f.instructions), address: f.address });
            }
        }
        for i in &self.info.imports {
            if hits.len() >= limit {
                return hits;
            }
            if m(&i.name) {
                hits.push(SearchHit { kind: "import".into(), label: i.name.clone(), detail: i.library.clone(), address: i.address });
            }
        }
        for e in &self.info.exports {
            if hits.len() >= limit {
                return hits;
            }
            if e.address != 0 && m(&e.name) {
                hits.push(SearchHit { kind: "export".into(), label: e.name.clone(), detail: "export".into(), address: e.address });
            }
        }
        for s in &self.strings {
            if hits.len() >= limit {
                return hits;
            }
            if let Some(a) = s.address {
                if m(&s.value) {
                    hits.push(SearchHit { kind: "string".into(), label: s.value.chars().take(80).collect(), detail: s.section.clone().unwrap_or_default(), address: a });
                }
            }
        }
        hits
    }

    // --------------------------------------------------------------------------------------------
    // Annotations
    // --------------------------------------------------------------------------------------------

    pub fn annotations(&self) -> &Annotations {
        &self.annotations
    }

    /// Restores saved annotations: patches are re-applied and user functions re-analyzed.
    pub fn set_annotations(&mut self, a: Annotations) {
        let had_functions = !a.functions.is_empty();
        self.revert_patches();
        self.annotations = a;
        self.apply_saved_patches();
        if had_functions && self.analysis.is_some() {
            self.reanalyze();
        }
    }

    /// Renames an address. An empty name removes the user name.
    pub fn rename(&mut self, va: u64, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            self.annotations.names.remove(&va);
        } else {
            self.annotations.names.insert(va, name.to_string());
        }
    }

    pub fn set_comment(&mut self, va: u64, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            self.annotations.comments.remove(&va);
        } else {
            self.annotations.comments.insert(va, text.to_string());
        }
    }
}

struct Source<'a>(&'a Binary);

impl CodeSource for Source<'_> {
    fn code_at(&self, va: u64) -> Option<&[u8]> {
        if !self.0.is_executable(va) {
            return None;
        }
        self.0.bytes_at(va)
    }

    fn import_at(&self, va: u64) -> Option<&str> {
        self.0.import_slots.get(&va).map(|&i| self.0.info.imports[i].name.as_str())
    }
}

struct Names<'a>(&'a Binary);

impl NameLookup for Names<'_> {
    fn name_at(&self, va: u64) -> Option<String> {
        self.0.name_at(va)
    }
}

fn looks_like_text(s: &str) -> bool {
    let n = s.chars().count();
    if n < 8 {
        return false;
    }
    let good = s.chars().filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_' || *c == '.' || *c == '%').count();
    // Register-push prologues ("AWAVAUATA", "UVWATAUAVAWH") decode as upper-case noise;
    // real text in code sections is mostly lower-case.
    let letters = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let lower = s.chars().filter(|c| c.is_ascii_lowercase()).count();
    good * 10 >= n * 9 && lower * 2 >= letters && lower >= 4
}

/// Folds runs of `int3` / single-byte padding between functions into one `align` line.
fn collapse_padding(insns: Vec<Instruction>) -> Vec<Instruction> {
    let is_pad = |i: &Instruction| i.label.is_none() && i.user_comment.is_none() && i.mnemonic == "int3";
    let mut out: Vec<Instruction> = Vec::with_capacity(insns.len());
    for ins in insns {
        if is_pad(&ins) {
            if let Some(last) = out.last_mut() {
                if last.mnemonic == "align" || is_pad(last) {
                    if last.mnemonic != "align" {
                        last.mnemonic = "align".into();
                    }
                    last.size = last.size.saturating_add(ins.size);
                    last.operands = vec![Token { t: format!("{} bytes", last.size), k: TokenKind::Number }];
                    last.bytes = "cc…".into();
                    continue;
                }
            }
        }
        out.push(ins);
    }
    out
}
