//! Per-function fingerprints.
//!
//! A fingerprint describes a function without its addresses, so the same code
//! compiled into another build, another version or another sample produces the
//! same (or a close) fingerprint. It has four parts, from strict to loose:
//!
//! - `exact`: the function's bytes with everything that depends on layout masked
//!   out (call and jump displacements, references into the image). Equal when the
//!   machine code is the same.
//! - `shape`: the sequence of instructions reduced to mnemonic and operand kinds
//!   (`mov r,m`, `call i`). Survives register renaming and moved data.
//! - `minhash`: a MinHash sketch of instruction 3-grams. Two sketches agree in
//!   about as many slots as the 3-gram sets overlap, which gives a similarity for
//!   functions that were edited.
//! - `anchors`: hashes of the imports a function calls, the strings it uses and
//!   its unusual constants. These rarely change between versions and identify a
//!   function even when the compiler rearranged it.
//!
//! The hashes are FNV-1a with a fixed finaliser, so they are stable across
//! platforms and Rust versions and can be stored in a knowledge base.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::analysis::Function;
use crate::disasm::NameLookup;
use crate::model::{Arch, Flow, Instruction, TokenKind};
use crate::Binary;

/// Number of MinHash slots. 64 gives a similarity error of about ±0.12.
pub const SKETCH: usize = 64;
/// LSH bands over the sketch: 16 bands of 4 slots. Two functions with a 3-gram
/// similarity of 0.5 share at least one band with a probability of about 0.65,
/// at 0.7 about 0.98.
pub const BANDS: usize = 16;
const ROWS: usize = SKETCH / BANDS;

/// Functions shorter than this are too generic to be matched on their own
/// (`ret`, `xor eax,eax; ret`, thunks). They can still be matched through the call graph.
pub const MIN_INSTRUCTIONS: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Bytes covered by the blocks.
    pub size: u32,
    pub instructions: u32,
    pub blocks: u32,
    pub edges: u32,
    /// Edges that go back to an earlier block (loops).
    pub back_edges: u32,
    /// Call instructions.
    pub calls: u32,
    pub exact: u64,
    pub shape: u64,
    pub minhash: Vec<u32>,
    /// Sorted, deduplicated hashes of imports, strings and constants.
    pub anchors: Vec<u64>,
}

/// A fingerprint together with where it was found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPrint {
    pub address: u64,
    /// The name shown for the function (may be an auto name).
    pub name: String,
    /// The name came from the user, symbols, exports or debug info, not `sub_…`.
    pub named: bool,
    pub print: Fingerprint,
    /// Functions in the same binary this one calls directly.
    pub callees: Vec<u64>,
}

/// Stable 64-bit hash.
pub(crate) fn hash_bytes(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    mix(h)
}

/// splitmix64 finaliser.
pub(crate) fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn sketch(features: &BTreeSet<u64>) -> Vec<u32> {
    let mut out = vec![u32::MAX; SKETCH];
    for &f in features {
        for (i, slot) in out.iter_mut().enumerate() {
            let v = mix(f ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)) as u32;
            if v < *slot {
                *slot = v;
            }
        }
    }
    out
}

/// LSH keys of a sketch: one per band, with the band number mixed in.
pub fn band_keys(minhash: &[u32]) -> Vec<u64> {
    minhash
        .chunks(ROWS)
        .enumerate()
        .map(|(band, rows)| {
            let mut bytes = Vec::with_capacity(ROWS * 4);
            for r in rows {
                bytes.extend_from_slice(&r.to_le_bytes());
            }
            hash_bytes(band as u64 + 1, &bytes)
        })
        .collect()
}

/// Fraction of equal sketch slots: an estimate of the Jaccard similarity of the 3-gram sets.
pub fn sketch_similarity(a: &[u32], b: &[u32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b).filter(|(x, y)| x == y).count() as f32 / a.len() as f32
}

fn jaccard(a: &[u64], b: &[u64]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let (mut i, mut j, mut common) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                common += 1;
                i += 1;
                j += 1;
            }
        }
    }
    common as f32 / (a.len() + b.len() - common) as f32
}

fn ratio(a: u32, b: u32) -> f32 {
    if a == 0 && b == 0 {
        1.0
    } else {
        a.min(b) as f32 / a.max(b) as f32
    }
}

/// Similarity of two fingerprints between 0 and 1. 1 means the masked machine
/// code is identical.
pub fn similarity(a: &Fingerprint, b: &Fingerprint) -> f32 {
    if a.exact == b.exact && a.size == b.size {
        return 1.0;
    }
    let code = if a.shape == b.shape { 1.0 } else { sketch_similarity(&a.minhash, &b.minhash) };
    let cfg = (ratio(a.blocks, b.blocks) + ratio(a.edges, b.edges) + ratio(a.back_edges, b.back_edges) + ratio(a.calls, b.calls)) / 4.0;
    let size = ratio(a.instructions, b.instructions);
    let score = if a.anchors.is_empty() && b.anchors.is_empty() {
        0.65 * code + 0.2 * cfg + 0.15 * size
    } else {
        0.5 * code + 0.25 * jaccard(&a.anchors, &b.anchors) + 0.15 * cfg + 0.1 * size
    };
    // Never report a non-identical function as a perfect match.
    score.min(0.999)
}

struct NoNames;

impl NameLookup for NoNames {
    fn name_at(&self, _va: u64) -> Option<String> {
        None
    }
}

/// Mnemonic with the condition removed, so `jz`/`jnz` or `b.eq`/`b.ne` count as the same
/// instruction: compilers flip conditions freely between builds.
fn normal_mnemonic(arch: Arch, m: &str) -> String {
    let m = m.to_ascii_lowercase();
    match arch {
        Arch::X86 | Arch::X86_64 => {
            if m.starts_with('j') && m != "jmp" {
                return "jcc".into();
            }
            for p in ["cmov", "set"] {
                if m.starts_with(p) {
                    return format!("{p}cc");
                }
            }
            m
        }
        Arch::Arm64 | Arch::Arm | Arch::Thumb => match m.split_once('.') {
            Some(("b", _)) => "b.cc".into(),
            _ => m,
        },
        _ => m,
    }
}

/// `mov r,m`: the mnemonic and one letter per operand (register, immediate, memory).
fn token(arch: Arch, ins: &Instruction) -> String {
    let mut t = normal_mnemonic(arch, &ins.mnemonic);
    let mut kinds = String::new();
    let mut depth = 0i32;
    let mut cur: Option<char> = None;
    let flush = |cur: &mut Option<char>, kinds: &mut String| {
        if let Some(c) = cur.take() {
            kinds.push(c);
        }
    };
    for tok in &ins.operands {
        let opens = tok.t.matches('[').count() as i32;
        let closes = tok.t.matches(']').count() as i32;
        if tok.k == TokenKind::Punct && tok.t.trim() == "," && depth == 0 {
            flush(&mut cur, &mut kinds);
            continue;
        }
        if opens > 0 || depth > 0 {
            cur = Some('m');
        } else {
            let k = match tok.k {
                TokenKind::Register => Some('r'),
                TokenKind::Number | TokenKind::Address | TokenKind::Symbol => Some('i'),
                _ => None,
            };
            if let Some(k) = k {
                if cur != Some('m') {
                    cur = Some(if cur == Some('r') && k == 'i' { 'r' } else { k });
                }
            }
        }
        depth += opens - closes;
    }
    flush(&mut cur, &mut kinds);
    if !kinds.is_empty() {
        t.push(' ');
        t.push_str(&kinds);
    }
    t
}

/// Parses an immediate as printed by the disassemblers (`0x1f`, `1Fh`, `#0x20`, `-8`, `42`).
fn parse_number(text: &str) -> Option<u64> {
    let t = text.trim().trim_start_matches('#');
    let (neg, t) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()?
    } else if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        u64::from_str_radix(h, 16).ok()?
    } else {
        t.parse::<u64>().ok()?
    };
    Some(if neg { v.wrapping_neg() } else { v })
}

/// A constant worth remembering: large enough to be specific, not an address, not a mask.
fn is_distinctive_constant(v: u64, bits: u32) -> bool {
    let v = if bits <= 32 { v & 0xffff_ffff } else { v };
    let ones = v.count_ones();
    let width = if v >> 32 == 0 { 32 } else { 64 };
    v >= 0x1000 && ones >= 3 && ones <= width - 3
}

fn anchor(kind: u8, bytes: &[u8]) -> u64 {
    hash_bytes(0xa0 + kind as u64, bytes)
}

impl Binary {
    /// The function's name when it isn't an auto name: the user's, or one from symbols,
    /// exports or a PDB.
    pub(crate) fn real_name(&self, va: u64) -> Option<&String> {
        self.annotations.names.get(&va).or_else(|| self.static_names.get(&va))
    }

    pub(super) fn fingerprint_of(&self, f: &Function, starts: &HashMap<u64, usize>) -> FunctionPrint {
        let arch = self.info.arch;
        let bits = self.info.bits as u32;
        let image = |v: u64| self.range_of(v).is_some();
        let mut blocks: Vec<_> = f.blocks.iter().collect();
        blocks.sort_by_key(|b| b.start);

        let mut exact_bytes: Vec<u8> = Vec::new();
        let mut tokens: Vec<u64> = Vec::new();
        let mut shape_bytes: Vec<u8> = Vec::new();
        let mut anchors: BTreeSet<u64> = BTreeSet::new();
        let mut callees: BTreeSet<u64> = BTreeSet::new();
        let (mut size, mut insns, mut calls, mut edges, mut back) = (0u32, 0u32, 0u32, 0u32, 0u32);

        for b in &blocks {
            edges += b.succs.len() as u32;
            back += b.succs.iter().filter(|e| e.to <= b.start).count() as u32;
            let len = b.end.saturating_sub(b.start) as usize;
            if len == 0 {
                continue;
            }
            size = size.saturating_add(len as u32);
            if let (Some(bytes), Some(mask)) = (self.original_bytes_at(b.start, len), self.variable_mask(b.start, len)) {
                exact_bytes.extend(bytes.iter().zip(&mask).map(|(byte, m)| if *m { 0 } else { *byte }));
                exact_bytes.push(0xa5);
            }
            let Some(code) = self.bytes_at(b.start) else { continue };
            let code = &code[..len.min(code.len())];
            for ins in self.render_code(code, b.start, usize::MAX, &NoNames) {
                insns += 1;
                let t = token(arch, &ins);
                shape_bytes.extend_from_slice(t.as_bytes());
                shape_bytes.push(b';');
                tokens.push(hash_bytes(0, t.as_bytes()));
                if ins.flow == Flow::Call {
                    calls += 1;
                }
                if let Some(target) = ins.target {
                    if let Some(&i) = self.import_slots.get(&target) {
                        let n = crate::analysis::strip_decoration(&self.info.imports[i].name);
                        anchors.insert(anchor(1, n.as_bytes()));
                    } else if let Some(&fi) = starts.get(&target) {
                        let callee = &self.analysis.as_ref().map(|a| &a.functions[fi]);
                        match callee.and_then(|c| c.thunk_slot).and_then(|s| self.import_slots.get(&s)) {
                            Some(&i) => {
                                let n = crate::analysis::strip_decoration(&self.info.imports[i].name);
                                anchors.insert(anchor(1, n.as_bytes()));
                            }
                            None if ins.flow == Flow::Call || ins.flow == Flow::Jump && (target < f.address || target >= f.end) => {
                                if target != f.address {
                                    callees.insert(target);
                                }
                            }
                            None => {}
                        }
                    } else if let Some(&si) = self.string_by_va.get(&target) {
                        anchors.insert(anchor(2, self.strings[si].value.as_bytes()));
                    }
                }
                for tok in ins.operands.iter().filter(|t| t.k == TokenKind::Number) {
                    if let Some(v) = parse_number(&tok.t) {
                        if is_distinctive_constant(v, bits) && !image(v) {
                            anchors.insert(anchor(3, &v.to_le_bytes()));
                        }
                    }
                }
            }
        }

        let mut grams: BTreeSet<u64> = BTreeSet::new();
        if tokens.len() < 3 {
            grams.extend(tokens.iter().copied());
        } else {
            for w in tokens.windows(3) {
                grams.insert(mix(w[0] ^ mix(w[1] ^ mix(w[2]))));
            }
        }
        let print = Fingerprint {
            size,
            instructions: insns,
            blocks: blocks.len() as u32,
            edges,
            back_edges: back,
            calls,
            exact: hash_bytes(1, &exact_bytes),
            shape: hash_bytes(2, &shape_bytes),
            minhash: sketch(&grams),
            anchors: anchors.into_iter().collect(),
        };
        let named = self.real_name(f.address).is_some();
        FunctionPrint { address: f.address, name: self.function_name(f), named, print, callees: callees.into_iter().collect() }
    }

    /// Fingerprints of every function except import thunks. Empty before [`Binary::analyze`].
    pub fn fingerprints(&self) -> Vec<FunctionPrint> {
        let Some(a) = &self.analysis else { return Vec::new() };
        let mut v: Vec<FunctionPrint> =
            a.functions.iter().filter(|f| f.thunk_slot.is_none()).map(|f| self.fingerprint_of(f, &a.by_start)).collect();
        v.sort_by_key(|p| p.address);
        v
    }

    /// Fingerprint of the function containing `va`.
    pub fn fingerprint_at(&self, va: u64) -> Option<FunctionPrint> {
        let a = self.analysis.as_ref()?;
        let i = self.function_index_containing(va)?;
        Some(self.fingerprint_of(&a.functions[i], &a.by_start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_parse_in_every_style() {
        assert_eq!(parse_number("0x1f"), Some(0x1f));
        assert_eq!(parse_number("1Fh"), Some(0x1f));
        assert_eq!(parse_number("#0x20"), Some(0x20));
        assert_eq!(parse_number("42"), Some(42));
        assert_eq!(parse_number("-8"), Some(8u64.wrapping_neg()));
        assert_eq!(parse_number("rax"), None);
    }

    #[test]
    fn masks_and_small_numbers_are_not_anchors() {
        assert!(!is_distinctive_constant(0xffff_ffff, 32));
        assert!(!is_distinctive_constant(0x10, 64));
        assert!(!is_distinctive_constant(0x8000_0000, 32));
        assert!(is_distinctive_constant(0x5f37_59df, 32));
        assert!(is_distinctive_constant(0x9e37_79b9_7f4a_7c15, 64));
    }

    #[test]
    fn sketch_tracks_set_overlap() {
        let a: BTreeSet<u64> = (0..400).collect();
        let b: BTreeSet<u64> = (100..500).collect(); // Jaccard 300/500 = 0.6
        let s = sketch_similarity(&sketch(&a), &sketch(&b));
        assert!((s - 0.6).abs() < 0.2, "estimate {s}");
        assert_eq!(sketch_similarity(&sketch(&a), &sketch(&a)), 1.0);
    }

    #[test]
    fn conditions_are_folded() {
        assert_eq!(normal_mnemonic(Arch::X86_64, "jnz"), "jcc");
        assert_eq!(normal_mnemonic(Arch::X86_64, "jmp"), "jmp");
        assert_eq!(normal_mnemonic(Arch::X86_64, "cmovge"), "cmovcc");
        assert_eq!(normal_mnemonic(Arch::Arm64, "b.ne"), "b.cc");
        assert_eq!(normal_mnemonic(Arch::Arm64, "bl"), "bl");
    }

    #[test]
    fn hashes_are_stable() {
        // Stored in knowledge bases: changing these breaks every saved database.
        assert_eq!(hash_bytes(0, b""), mix(0xcbf2_9ce4_8422_2325));
        assert_eq!(hash_bytes(0, b"paranoia"), 0x48a4_f27c_d86b_b3f6);
    }
}
