//! Interactive tools on top of the analysis: searching, patching, user-defined
//! functions, bookmarks and export to other tools.

use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, OpKind};
use serde::{Deserialize, Serialize};

use crate::model::{Arch, XrefKind};
use crate::Binary;

const MAX_HITS: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub address: Option<u64>,
    pub offset: u64,
    pub function: Option<String>,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Callee {
    pub address: u64,
    pub name: String,
    pub count: usize,
    pub is_import: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchKind {
    /// Hex bytes with `??` wildcards: `48 8B ?? 24`.
    Bytes,
    /// ASCII and UTF-16LE text.
    Text,
    /// An immediate operand or displacement value in code.
    Immediate,
}

/// Parses `48 8b ?? 0x24` / `488B??24` into bytes with wildcards.
pub fn parse_pattern(p: &str) -> Result<Vec<Option<u8>>, String> {
    let cleaned: String = p.split_whitespace().map(|t| t.trim_start_matches("0x").trim_start_matches("0X")).collect::<Vec<_>>().join("");
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return Err("byte patterns need an even number of hex digits (use ?? for wildcards)".into());
    }
    cleaned
        .as_bytes()
        .chunks(2)
        .map(|c| {
            let s = std::str::from_utf8(c).unwrap_or("");
            if s == "??" || s == "**" {
                Ok(None)
            } else {
                u8::from_str_radix(s, 16).map(Some).map_err(|_| format!("`{s}` is not a hex byte"))
            }
        })
        .collect()
}

fn find_all(hay: &[u8], pat: &[Option<u8>], limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if pat.is_empty() || pat.len() > hay.len() {
        return out;
    }
    // Anchor on the first concrete byte for speed.
    let anchor = pat.iter().position(Option::is_some);
    let mut i = 0;
    while i + pat.len() <= hay.len() && out.len() < limit {
        if let Some(a) = anchor {
            let b = pat[a].unwrap();
            match hay[i + a..hay.len() - (pat.len() - a - 1)].iter().position(|&x| x == b) {
                Some(d) => i += d,
                None => break,
            }
        }
        if pat.iter().enumerate().all(|(k, p)| p.is_none_or(|p| hay[i + k] == p)) {
            out.push(i);
        }
        i += 1;
    }
    out
}

impl Binary {
    fn hit(&self, offset: u64, len: usize) -> Hit {
        let address = self.offset_to_va(offset);
        let function = address.and_then(|a| self.function_at(a)).map(|f| f.name);
        let data = self.read(offset, len.clamp(1, 24));
        Hit { address, offset, function, preview: hex::encode(data) }
    }

    pub fn search_advanced(&self, kind: SearchKind, query: &str) -> Result<Vec<Hit>, String> {
        let data = self.data();
        match kind {
            SearchKind::Bytes => {
                let pat = parse_pattern(query)?;
                Ok(find_all(data, &pat, MAX_HITS).into_iter().map(|o| self.hit(o as u64, pat.len())).collect())
            }
            SearchKind::Text => {
                if query.is_empty() {
                    return Err("enter some text".into());
                }
                let ascii: Vec<Option<u8>> = query.bytes().map(Some).collect();
                let wide: Vec<Option<u8>> = query.encode_utf16().flat_map(|u| u.to_le_bytes()).map(Some).collect();
                let mut hits: Vec<Hit> = find_all(data, &ascii, MAX_HITS).into_iter().map(|o| self.hit(o as u64, query.len())).collect();
                hits.extend(find_all(data, &wide, MAX_HITS).into_iter().map(|o| {
                    let mut h = self.hit(o as u64, wide.len());
                    h.preview = format!("L\"{query}\"");
                    h
                }));
                for h in hits.iter_mut().filter(|h| !h.preview.starts_with('L')) {
                    h.preview = format!("\"{query}\"");
                }
                hits.sort_by_key(|h| h.offset);
                hits.truncate(MAX_HITS);
                Ok(hits)
            }
            SearchKind::Immediate => {
                let q = query.trim();
                let v = if let Some(h) = q.strip_prefix("0x").or_else(|| q.strip_prefix("0X")) {
                    u64::from_str_radix(h, 16)
                } else if let Some(h) = q.strip_suffix('h') {
                    u64::from_str_radix(h, 16)
                } else {
                    q.parse::<i64>().map(|v| v as u64)
                }
                .map_err(|_| "enter a number (decimal, 0x… or …h)".to_string())?;
                self.search_immediate(v)
            }
        }
    }

    fn search_immediate(&self, value: u64) -> Result<Vec<Hit>, String> {
        if !matches!(self.info.arch, Arch::X86 | Arch::X86_64) {
            return Err("immediate search currently supports x86 and x86-64".into());
        }
        let bits = if self.info.arch == Arch::X86 { 32 } else { 64 };
        let a = self.analysis.as_ref().ok_or("analysis has not run")?;
        let mut hits = Vec::new();
        for f in &a.functions {
            for b in &f.blocks {
                let Some(bytes) = self.bytes_at(b.start) else { continue };
                let len = ((b.end - b.start) as usize).min(bytes.len());
                let mut d = Decoder::with_ip(bits, &bytes[..len], b.start, DecoderOptions::NONE);
                while d.can_decode() {
                    let i = d.decode();
                    let mut hit = (0..i.op_count()).any(|k| {
                        matches!(
                            i.op_kind(k),
                            OpKind::Immediate8
                                | OpKind::Immediate16
                                | OpKind::Immediate32
                                | OpKind::Immediate64
                                | OpKind::Immediate8to16
                                | OpKind::Immediate8to32
                                | OpKind::Immediate8to64
                                | OpKind::Immediate32to64
                        ) && (i.immediate(k) == value || i.immediate(k) as u32 as u64 == value)
                    });
                    hit |= (0..i.op_count()).any(|k| {
                        i.op_kind(k) == OpKind::Memory && !i.is_ip_rel_memory_operand() && i.memory_displacement64() == value && value != 0
                    });
                    if hit {
                        let ins = self.disassemble(i.ip(), 1).ok().and_then(|v| v.into_iter().next());
                        let text = ins
                            .map(|x| format!("{} {}", x.mnemonic, x.operands.iter().map(|t| t.t.as_str()).collect::<String>()))
                            .unwrap_or_default();
                        hits.push(Hit {
                            address: Some(i.ip()),
                            offset: self.va_to_offset(i.ip()).unwrap_or(0),
                            function: Some(self.function_name(f)),
                            preview: text,
                        });
                        if hits.len() >= MAX_HITS {
                            return Ok(hits);
                        }
                    }
                }
            }
        }
        hits.sort_by_key(|h| h.address);
        hits.dedup_by_key(|h| h.address);
        Ok(hits)
    }

    /// Functions called from the function containing `va`, most-called first.
    pub fn callees(&self, va: u64) -> Vec<Callee> {
        let Some(a) = &self.analysis else { return Vec::new() };
        let Some(f) = self.function_index_containing(va).map(|i| &a.functions[i]) else { return Vec::new() };
        let mut counts: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
        let blocks: Vec<(u64, u64)> = f.blocks.iter().map(|b| (b.start, b.end)).collect();
        for (target, refs) in &a.xrefs {
            for r in refs.iter().filter(|r| r.kind == XrefKind::Call) {
                if blocks.iter().any(|(s, e)| r.from >= *s && r.from < *e) {
                    *counts.entry(*target).or_default() += 1;
                }
            }
        }
        let mut v: Vec<Callee> = counts
            .into_iter()
            .map(|(t, count)| Callee {
                address: t,
                name: self.name_at(t).unwrap_or_else(|| format!("sub_{t:X}")),
                count,
                is_import: self.import_slots.contains_key(&t),
            })
            .collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(a.address.cmp(&b.address)));
        v
    }

    /// Defines a function at `va` (IDA's `P`) and re-runs auto-analysis.
    pub fn make_function(&mut self, va: u64) -> Result<(), String> {
        if !self.is_executable(va) {
            return Err(format!("{va:#x} is not in executable memory"));
        }
        self.annotations.functions.insert(va);
        self.reanalyze();
        if self.analysis.as_ref().is_some_and(|a| a.by_start.contains_key(&va)) {
            Ok(())
        } else {
            Err(format!("no valid code at {va:#x}"))
        }
    }

    pub fn reanalyze(&mut self) {
        self.analysis = None;
        self.analyze();
    }

    /// Writes `bytes` at file `offset`. Originals are remembered so patches can be reverted.
    pub fn patch(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let base = self.slice.0;
        let end = offset as usize + bytes.len();
        if end > self.slice.1 {
            return Err("patch runs past the end of the file".into());
        }
        for (k, &b) in bytes.iter().enumerate() {
            let off = offset + k as u64;
            let idx = base + off as usize;
            self.original_bytes.entry(off).or_insert(self.file[idx]);
            self.file[idx] = b;
            if self.original_bytes.get(&off) == Some(&b) {
                self.original_bytes.remove(&off);
                self.annotations.patches.remove(&off);
            } else {
                self.annotations.patches.insert(off, b);
            }
        }
        Ok(())
    }

    pub fn revert_patches(&mut self) {
        let base = self.slice.0;
        for (off, b) in std::mem::take(&mut self.original_bytes) {
            self.file[base + off as usize] = b;
        }
        self.annotations.patches.clear();
    }

    pub(crate) fn apply_saved_patches(&mut self) {
        let patches: Vec<(u64, u8)> = self.annotations.patches.iter().map(|(k, v)| (*k, *v)).collect();
        let base = self.slice.0;
        for (off, b) in patches {
            let idx = base + off as usize;
            if idx < self.file.len() {
                self.original_bytes.entry(off).or_insert(self.file[idx]);
                self.file[idx] = b;
            }
        }
    }

    /// The whole file including patches (for "Save patched file").
    pub fn file_bytes(&self) -> &[u8] {
        &self.file
    }

    pub fn patched_offsets(&self) -> BTreeSet<u64> {
        self.original_bytes.keys().copied().collect()
    }

    /// An IDC script that recreates names, comments and user functions in IDA.
    pub fn export_idc(&self) -> String {
        let mut s = String::new();
        s.push_str("// Generated by Paranoia — https://github.com/Altumptic/paranoia\n");
        s.push_str(&format!("// File: {}  sha256: {}\n", self.info.file_name, self.info.hashes.sha256));
        s.push_str("#include <idc.idc>\n\nstatic main() {\n");
        for va in &self.annotations.functions {
            s.push_str(&format!("    add_func({va:#x});\n"));
        }
        for (va, n) in &self.annotations.names {
            s.push_str(&format!("    set_name({va:#x}, \"{}\", SN_NOWARN);\n", n.escape_default()));
        }
        for (va, c) in &self.annotations.comments {
            s.push_str(&format!("    set_cmt({va:#x}, \"{}\", 0);\n", c.escape_default()));
        }
        for (va, c) in &self.annotations.bookmarks {
            s.push_str(&format!("    put_bookmark({va:#x}, 0, 0, 0, get_bookmark_count() , \"{}\");\n", c.escape_default()));
        }
        s.push_str("}\n");
        s
    }

    pub fn set_bookmark(&mut self, va: u64, text: Option<&str>) {
        match text {
            Some(t) => {
                self.annotations.bookmarks.insert(va, t.to_string());
            }
            None => {
                self.annotations.bookmarks.remove(&va);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(parse_pattern("48 8B ?? 24").unwrap(), vec![Some(0x48), Some(0x8b), None, Some(0x24)]);
        assert_eq!(parse_pattern("488b??24").unwrap().len(), 4);
        assert!(parse_pattern("4").is_err());
        let hay = [1u8, 0x48, 0x8b, 0x05, 0x24, 0x48, 0x8b, 0x00, 0x24];
        assert_eq!(find_all(&hay, &parse_pattern("48 8b ?? 24").unwrap(), 10), vec![1, 5]);
        assert_eq!(find_all(&hay, &parse_pattern("?? 8b").unwrap(), 10), vec![1, 5]);
    }
}
