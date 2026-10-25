//! FLIRT-style library recognition with IDA's text `.pat` format.
//!
//! A pattern line holds the first 32 bytes of a function (`..` for bytes that change
//! between builds: relocated addresses, calls and RIP-relative references), the CRC16
//! of the following fixed bytes, the function length and its name. Paranoia reads
//! `.pat` files made by IDA's FLAIR tools, writes its own from any binary with symbols
//! (`sigmake`) and ships a small built-in library for the MSVC x64 runtime.

use std::collections::{BTreeMap, HashMap};

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::model::{Arch, Flow};
use crate::Binary;

/// Built-in signatures (generated with `paranoia-cli sigmake --library` from binaries
/// with PDBs; only functions from the Microsoft C/C++ runtime libraries).
const BUILTIN_MSVC_X64: &str = include_str!("sigs/msvc_x64.pat");

#[derive(Debug, Clone)]
pub struct PatSig {
    pub pattern: Vec<Option<u8>>,
    pub crc_len: usize,
    pub crc: u16,
    pub len: u32,
    pub name: String,
}

impl PatSig {
    fn fixed(&self) -> usize {
        self.pattern.iter().filter(|b| b.is_some()).count() + self.crc_len
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigReport {
    pub signatures: usize,
    pub matched: usize,
    /// `(address, name)` of every recognised function.
    pub names: Vec<(u64, String)>,
}

/// FLIRT's CRC16 (polynomial 0x8408, inverted and byte-swapped).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u32 = 0xffff;
    for &b in data {
        let mut d = b as u32;
        for _ in 0..8 {
            if (crc ^ d) & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
            d >>= 1;
        }
    }
    let crc = !crc & 0xffff;
    (((crc << 8) | (crc >> 8)) & 0xffff) as u16
}

/// Parses a `.pat` file. Lines whose first public name is not at offset 0 are skipped.
pub fn parse_pat(text: &str) -> Result<Vec<PatSig>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line == "---" {
            break;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            return Err(format!("line {}: expected `pattern crclen crc len :offset name`", n + 1));
        }
        let p = f[0];
        if p.len() % 2 != 0 || p.len() > 64 {
            return Err(format!("line {}: bad pattern", n + 1));
        }
        let mut pattern = Vec::with_capacity(32);
        for k in (0..p.len()).step_by(2) {
            let h = &p[k..k + 2];
            pattern.push(if h == ".." {
                None
            } else {
                Some(u8::from_str_radix(h, 16).map_err(|_| format!("line {}: bad byte {h}", n + 1))?)
            });
        }
        let hex = |s: &str| u32::from_str_radix(s, 16).map_err(|_| format!("line {}: bad number {s}", n + 1));
        let crc_len = hex(f[1])? as usize;
        let crc = hex(f[2])? as u16;
        let len = hex(f[3])?;
        // Public names: `:0000 name`, `:0010@ local`, …; take the one at offset 0.
        let mut name = None;
        let mut k = 4;
        while k + 1 < f.len() {
            let off = f[k];
            if let Some(o) = off.strip_prefix(':') {
                let local = o.ends_with('@');
                if hex(o.trim_end_matches('@')).ok() == Some(0) && !local {
                    name = Some(f[k + 1].to_string());
                    break;
                }
                k += 2;
            } else {
                break;
            }
        }
        if let Some(name) = name {
            out.push(PatSig { pattern, crc_len, crc, len, name });
        }
    }
    Ok(out)
}

/// Names reserved for the C/C++ runtime (double-underscore and documented CRT entry points).
fn is_runtime_name(n: &str) -> bool {
    const PREFIXES: [&str; 22] = [
        "__scrt_",
        "__security_",
        "__GSHandler",
        "_RTC_",
        "__acrt_",
        "__vcrt_",
        "__std_",
        "__crt_",
        "_CRT_",
        "__isa_",
        "_initterm",
        "__C_specific_handler",
        "_guard_",
        "__report_",
        "__raise_securityfailure",
        "__chkstk",
        "_alloca_probe",
        "__CxxFrameHandler",
        "_CxxThrowException",
        "__DestructExceptionObject",
        "__FrameUnwindFilter",
        "__InternalCxxFrameHandler",
    ];
    const EXACT: [&str; 12] =
        ["memcpy", "memmove", "memset", "memcmp", "memchr", "strlen", "strcmp", "strchr", "wcslen", "_purecall", "atexit", "_onexit"];
    PREFIXES.iter().any(|p| n.starts_with(p)) || EXACT.contains(&n)
}

fn hex_byte(b: Option<u8>) -> String {
    b.map(|b| format!("{b:02X}")).unwrap_or_else(|| "..".into())
}

impl Binary {
    /// Bytes of the function at `start` that vary between builds (relocations, calls,
    /// references into the image), over the contiguous range `len`.
    fn variable_mask(&self, start: u64, len: usize) -> Option<Vec<bool>> {
        let bytes = self.bytes_at(start)?;
        let len = len.min(bytes.len());
        let mut mask = vec![false; len];
        let end = start + len as u64;
        let in_image = |v: u64| self.range_of(v).is_some();
        match self.info.arch {
            Arch::X86 | Arch::X86_64 => {
                let bits = if self.info.arch == Arch::X86 { 32 } else { 64 };
                let mut d = Decoder::with_ip(bits, &bytes[..len], start, DecoderOptions::NONE);
                while d.can_decode() {
                    let pos = d.position();
                    let ins = d.decode();
                    if ins.is_invalid() {
                        break;
                    }
                    let n = ins.len();
                    let co = d.get_constant_offsets(&ins);
                    let mut mark = |off: usize, size: usize| {
                        for m in mask.iter_mut().skip(pos + off).take(size) {
                            *m = true;
                        }
                    };
                    // Branches leaving the function: their relative displacement changes with layout.
                    let near = matches!(ins.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64);
                    if near {
                        let t = ins.near_branch_target();
                        let external = t < start || t >= end || matches!(ins.flow_control(), FlowControl::Call);
                        if external && n >= 5 {
                            mark(n - 4, 4);
                        }
                    }
                    if co.has_displacement() {
                        let rip = ins.is_ip_rel_memory_operand();
                        let abs = ins.memory_base() == Register::None
                            && ins.memory_index() == Register::None
                            && in_image(ins.memory_displacement64());
                        if rip || abs {
                            mark(co.displacement_offset(), co.displacement_size());
                        }
                    }
                    if co.has_immediate() && !near && co.immediate_size() >= 4 && in_image(ins.immediate(0).max(ins.immediate32() as u64)) {
                        mark(co.immediate_offset(), co.immediate_size());
                    }
                }
            }
            _ => {
                // Fixed-width ISAs: an instruction that references an address or leaves the function varies as a whole.
                let mut dis =
                    crate::disasm::Disassembler::with_mode(self.info.arch, self.info.bits, self.info.endian == crate::model::Endian::Big);
                let mut pos = 0usize;
                while pos < len {
                    let d = dis.decode(&bytes[pos..len], start + pos as u64);
                    let n = (d.len as usize).max(1);
                    let external = d.target.is_some_and(|t| t < start || t >= end) || matches!(d.flow, Flow::Call);
                    let word = bytes.get(pos..pos + 4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).unwrap_or(0);
                    let adrp = self.info.arch == Arch::Arm64 && word & 0x9f00_0000 == 0x9000_0000;
                    let auipc = self.info.arch == Arch::RiscV && word & 0x7f == 0x17;
                    if external || d.data_ref.is_some() || adrp || auipc {
                        for m in mask.iter_mut().skip(pos).take(n) {
                            *m = true;
                        }
                    }
                    pos += n;
                }
            }
        }
        Some(mask)
    }

    /// Contiguous length of the function at `va` (its first chunk).
    fn contiguous_len(&self, f: &crate::analysis::Function) -> usize {
        let mut blocks: Vec<(u64, u64)> = f.blocks.iter().map(|b| (b.start, b.end)).collect();
        blocks.sort();
        let mut end = f.address;
        for (s, e) in blocks {
            if s > end {
                break;
            }
            end = end.max(e);
        }
        (end - f.address) as usize
    }

    /// `.pat` line for one function, or `None` when it is too short or too variable to be useful.
    fn pat_line(&self, f: &crate::analysis::Function, name: &str) -> Option<String> {
        let len = self.contiguous_len(f).min(0x8000);
        if len < 16 {
            return None;
        }
        let bytes = self.original_bytes_at(f.address, len)?;
        let mask = self.variable_mask(f.address, len)?;
        let at = |i: usize| (i < len && !mask[i]).then(|| bytes[i]);
        let pattern: Vec<Option<u8>> = (0..32).map(|i| if i < len { at(i) } else { None }).collect();
        let crc_len = (32..len.min(32 + 255)).take_while(|&i| !mask[i]).count();
        let crc = crc16(&bytes[32.min(len)..32.min(len) + crc_len]);
        if pattern.iter().filter(|b| b.is_some()).count() + crc_len < 24 {
            return None;
        }
        let pat: String = pattern.iter().map(|b| hex_byte(*b)).collect();
        Some(format!("{pat} {crc_len:02X} {crc:04X} {len:04X} :0000 {name}"))
    }

    /// Original (unpatched) bytes, so signatures never capture local patches.
    fn original_bytes_at(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = self.bytes_at(va)?.get(..len)?.to_vec();
        for (i, b) in v.iter_mut().enumerate() {
            if let Some(off) = self.va_to_offset(va + i as u64) {
                if let Some(orig) = self.original_bytes.get(&off) {
                    *b = *orig;
                }
            }
        }
        Some(v)
    }

    /// Writes a `.pat` file for every named function (or only runtime-library ones).
    pub fn make_pat(&self, library_only: bool) -> String {
        let mut out = String::new();
        let Some(a) = &self.analysis else { return out };
        let mut seen = std::collections::HashSet::new();
        for f in &a.functions {
            if f.thunk_slot.is_some() {
                continue;
            }
            let Some(raw) = self.raw_names.get(&f.address).cloned().or_else(|| self.static_names.get(&f.address).cloned()) else {
                continue;
            };
            if library_only && !self.pdb_library.contains(&f.address) && !is_runtime_name(&raw) {
                continue;
            }
            let name = raw.replace(' ', "_");
            if let Some(line) = self.pat_line(f, &name) {
                if seen.insert(line.clone()) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
        }
        out.push_str("---\n");
        out
    }

    /// Matches signatures against unnamed functions. Ambiguous or over-general patterns are skipped.
    pub(crate) fn match_signatures(&self, sigs: &[PatSig]) -> BTreeMap<u64, String> {
        let mut found: BTreeMap<u64, String> = BTreeMap::new();
        let Some(a) = &self.analysis else { return found };
        let mut by_head: HashMap<[u8; 2], Vec<usize>> = HashMap::new();
        let mut wild: Vec<usize> = Vec::new();
        for (i, s) in sigs.iter().enumerate() {
            if s.fixed() < 24 {
                continue;
            }
            match (s.pattern.first().copied().flatten(), s.pattern.get(1).copied().flatten()) {
                (Some(x), Some(y)) => by_head.entry([x, y]).or_default().push(i),
                _ => wild.push(i),
            }
        }
        let mut hits: HashMap<usize, Vec<u64>> = HashMap::new();
        for f in &a.functions {
            if self.annotations.names.contains_key(&f.address) || self.static_names.contains_key(&f.address) || f.thunk_slot.is_some() {
                continue;
            }
            let Some(bytes) = self.bytes_at(f.address) else { continue };
            if bytes.len() < 2 {
                continue;
            }
            let cands = by_head.get(&[bytes[0], bytes[1]]).into_iter().flatten().chain(wild.iter());
            let mut names: Vec<usize> = Vec::new();
            for &i in cands {
                let s = &sigs[i];
                let need = s.pattern.len().max(32 + s.crc_len).min(s.len.max(s.pattern.len() as u32) as usize);
                if bytes.len() < need || bytes.len() < s.pattern.len() {
                    continue;
                }
                if !s.pattern.iter().zip(bytes).all(|(p, b)| p.is_none_or(|p| p == *b)) {
                    continue;
                }
                if s.crc_len > 0 && (bytes.len() < 32 + s.crc_len || crc16(&bytes[32..32 + s.crc_len]) != s.crc) {
                    continue;
                }
                names.push(i);
            }
            names.sort_by_key(|&i| sigs[i].name.clone());
            names.dedup_by_key(|i| sigs[*i].name.clone());
            if let [i] = names[..] {
                hits.entry(i).or_default().push(f.address);
            }
        }
        // A pattern that fits many functions is too generic to trust.
        for (i, vas) in hits {
            if vas.len() <= 2 {
                for va in vas {
                    found.insert(va, sigs[i].name.clone());
                }
            }
        }
        found
    }

    /// Applies the built-in libraries that fit this binary (run after analysis).
    pub(crate) fn apply_builtin_signatures(&mut self) {
        self.lib_names.clear();
        if self.info.arch != Arch::X86_64 || self.info.format != crate::model::Format::Pe {
            return;
        }
        let Ok(sigs) = parse_pat(BUILTIN_MSVC_X64) else { return };
        let found = self.match_signatures(&sigs);
        for (va, raw) in found {
            self.lib_names.insert(va, crate::demangle(&raw).unwrap_or(raw));
        }
    }

    /// Applies a user `.pat` file; the names are kept with the annotations.
    pub fn apply_pat(&mut self, text: &str) -> Result<SigReport, String> {
        let sigs = parse_pat(text)?;
        let found = self.match_signatures(&sigs);
        let mut report = SigReport { signatures: sigs.len(), matched: found.len(), names: Vec::new() };
        for (va, raw) in found {
            let name = crate::demangle(&raw).unwrap_or(raw);
            self.annotations.library.insert(va, name.clone());
            report.names.push((va, name));
        }
        Ok(report)
    }

    /// Library name for a function, if a signature recognised it.
    pub(crate) fn library_name(&self, va: u64) -> Option<&String> {
        self.annotations.library.get(&va).or_else(|| self.lib_names.get(&va))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_flirt() {
        // Reference value from the FLAIR documentation's algorithm.
        assert_eq!(crc16(&[]), 0x0000);
        assert_eq!(crc16(b"123456789"), 0x6e90);
    }

    #[test]
    fn parses_pat_lines() {
        let text = "4883EC28E8........4883C428C3.................................... 00 0000 000E :0000 _initterm_e ^0005 _foo\n---\n";
        let s = parse_pat(text).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "_initterm_e");
        assert_eq!(s[0].pattern[0], Some(0x48));
        assert_eq!(s[0].pattern[5], None);
        assert_eq!(s[0].len, 0x0e);
    }

    #[test]
    fn builtin_library_parses() {
        let s = parse_pat(BUILTIN_MSVC_X64).unwrap();
        assert!(s.len() > 20, "built-in library has {} signatures", s.len());
    }
}
