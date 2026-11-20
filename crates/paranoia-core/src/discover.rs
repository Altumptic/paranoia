//! Function starts that nothing points at.
//!
//! A 32-bit x86 image has no `.pdata`, and compilers leave plenty of functions that no direct
//! call reaches: callbacks, virtual methods, exports used only internally. Recursive descent
//! from entry points and exports finds a fraction of them, so after it has run this pass looks
//! at the code it did not cover and adds a function wherever one plainly starts:
//!
//! - a standard prologue (`push ebp; mov ebp, esp`, with or without the hot-patch `mov edi, edi`)
//!   at a place where the previous function ended: after padding (`int3`, `nop`), or after a
//!   `ret`; or
//! - an address the image's base relocations point at (a function pointer in a table or a
//!   `push offset callback`) that is in uncovered code and also starts after padding or a `ret`,
//!   or with a prologue.
//!
//! Every candidate must also decode: the first instructions are valid and reach a `ret` or a
//! `jmp` (or run a good way without a break), so data that happens to look like a prologue is
//! rejected. The result is a list of seeds; the analysis runs again with them, which follows
//! their calls, and this pass runs again on what is still uncovered.
//!
//! Raw firmware images (x86-64, AArch64, ARM, Thumb) have no unwind table or symbols either, so
//! they get the same treatment with that CPU's function-start patterns ([`raw_prologue`]): a frame
//! set-up right after a `ret`, a branch or padding, checked by decoding.

use std::collections::BTreeSet;

use crate::analysis::Analysis;
use crate::disasm::Disassembler;
use crate::model::{Arch, Flow, Format, SymbolKind};
use crate::Binary;

/// Rounds of "scan, then analyse again". A round's new functions call others that the next
/// round's recursive descent finds on its own; a third round rarely adds anything.
pub(crate) const MAX_ROUNDS: usize = 3;
/// Instructions a candidate must decode before it counts as code, if it hasn't ended sooner.
const TRIAL_INSTRUCTIONS: usize = 16;

/// `(start, end)` of everything the analysis covered, sorted and merged.
fn covered(a: &Analysis) -> Vec<(u64, u64)> {
    merge(a.block_index.iter().map(|(&s, &(e, _))| (s, e)).collect())
}

/// Sorted, non-overlapping ranges covering the same bytes.
fn merge(mut v: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// The parts of `[lo, hi)` that `covered` leaves out.
fn gaps(covered: &[(u64, u64)], lo: u64, hi: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = lo;
    let first = covered.partition_point(|&(_, e)| e <= lo);
    for &(s, e) in &covered[first..] {
        if s >= hi {
            break;
        }
        if s > at {
            out.push((at, s.min(hi)));
        }
        at = at.max(e);
    }
    if at < hi {
        out.push((at, hi));
    }
    out
}

/// A standard 32-bit frame setup at the start of `code`.
fn has_prologue(code: &[u8]) -> bool {
    code.starts_with(&[0x55, 0x8b, 0xec]) || code.starts_with(&[0x55, 0x89, 0xe5]) || code.starts_with(&[0x8b, 0xff, 0x55, 0x8b, 0xec])
}

/// Whether the previous function plausibly ended just before offset `off` of `section`:
/// padding, a `ret`, or a `ret imm16`.
fn follows_end(section: &[u8], off: usize) -> bool {
    match off.checked_sub(1).map(|i| section[i]) {
        None => true,
        Some(0xcc | 0x90 | 0xc3) => true,
        Some(0x00) => off >= 3 && section[off - 3] == 0xc2,
        Some(_) => false,
    }
}

/// A function-start pattern at offset `off` of a raw image, for the CPU the image is for.
/// `section` is the whole range; the previous function's end is checked by [`raw_follows_end`].
fn raw_prologue(arch: Arch, s: &[u8], off: usize) -> bool {
    let w = |o: usize| s.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let h = |o: usize| s.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    match arch {
        Arch::X86_64 => {
            let c = &s[off..];
            c.starts_with(&[0x55, 0x48, 0x89, 0xe5])
                || c.starts_with(&[0x48, 0x83, 0xec])
                || c.starts_with(&[0x48, 0x89, 0x5c, 0x24])
                || c.starts_with(&[0x48, 0x89, 0x4c, 0x24])
                || c.starts_with(&[0x48, 0x8b, 0xc4])
                // Go: `cmp rsp, [r14+16]` (stack check) and `lea r12, [rsp-N]` (big frames)
                || c.starts_with(&[0x49, 0x3b, 0x66, 0x10])
                || c.starts_with(&[0x4c, 0x8d, 0x64, 0x24])
                || c.starts_with(&[0x4c, 0x8d, 0xa4, 0x24])
                || c.starts_with(&[0x40, 0x53])
                || c.starts_with(&[0x40, 0x55])
                || c.starts_with(&[0x40, 0x56])
                || c.starts_with(&[0x40, 0x57])
                || (matches!(c.first(), Some(0x55 | 0x53 | 0x56 | 0x57)) && matches!(c.get(1), Some(0x41 | 0x53 | 0x56 | 0x57 | 0x48)))
                || (c.first() == Some(&0x41) && matches!(c.get(1), Some(0x54..=0x57)))
        }
        // stp x29, x30, [sp, #-N]! ; sub sp, sp, #N ; str x30, [sp, #-N]! (Go) ; ldr x16, [x28, #16] (Go's stack check) ; paciasp ; bti c
        Arch::Arm64 => {
            off & 3 == 0
                && w(off).is_some_and(|x| {
                    x & 0xffc0_7fff == 0xa980_7bfd
                        || x & 0xff00_03ff == 0xd100_03ff
                        || x & 0xffe0_0fff == 0xf800_0ffe
                        || x == 0xf940_0b90
                        || x == 0xd503_233f
                        || x == 0xd503_245f
                })
        }
        // push {..., lr} (16-bit and 32-bit forms)
        Arch::Thumb => {
            off & 1 == 0
                && (h(off).is_some_and(|x| x & 0xff00 == 0xb500) || w(off).is_some_and(|x| x & 0xffff == 0xe92d && (x >> 16) & 0x4000 != 0))
        }
        // push {..., lr}
        Arch::Arm => off & 3 == 0 && w(off).is_some_and(|x| x & 0xffff_4000 == 0xe92d_4000),
        _ => false,
    }
}

/// Whether the bytes before `off` end in an x86 multi-byte `nop`, the padding GCC, LLVM and MinGW leave
/// between functions (`66 90`, `0f 1f 40 00`, `66 0f 1f 44 00 00`, `0f 1f 84 00 00 00 00 00`, …).
fn nop_padding_before(s: &[u8], off: usize) -> bool {
    NOPS.iter().any(|n| s[..off].ends_with(n))
}

const NOPS: &[&[u8]] = &[
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// The offset where the run of padding bytes (`int3`, `nop`, multi-byte `nop`) that ends at `off` begins.
fn padding_start(s: &[u8], mut off: usize) -> usize {
    'again: loop {
        if off >= 1 && matches!(s[off - 1], 0xcc | 0x90) {
            off -= 1;
            continue;
        }
        for n in NOPS {
            if s[..off].ends_with(n) {
                off -= n.len();
                continue 'again;
            }
        }
        return off;
    }
}

/// A hard function end right before `off`: a return, or padding. Unlike [`raw_follows_end`] a branch
/// does not count, because code after a `jmp` is usually the next block of the same function.
fn raw_hard_end(arch: Arch, s: &[u8], off: usize) -> bool {
    let w = |o: usize| s.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let h = |o: usize| s.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    match arch {
        // `int3` padding is never code. A `nop` run also pads loop headers inside a function, so it counts
        // only right after a `ret`.
        Arch::X86_64 => {
            off >= 2 && s[off] != 0xcc && {
                let p = padding_start(s, off);
                (s[off - 1] == 0xcc && s[off - 2] == 0xcc)
                    || (p < off && p >= 1 && (s[p - 1] == 0xc3 || (p >= 3 && s[p - 3] == 0xc2 && s[p - 1] == 0x00)))
            }
        }
        Arch::Arm64 => {
            off >= 4 && w(off - 4).is_some_and(|x| x == 0xd65f_03c0 || x == 0 || x == 0xd503_201f || x & 0xffe0_001f == 0xd420_0000)
        }
        Arch::Thumb => off >= 2 && h(off - 2).is_some_and(|x| x == 0x4770 || x == 0x0000 || x == 0xbf00 || x & 0xff00 == 0xbd00),
        Arch::Arm => {
            off >= 4 && w(off - 4).is_some_and(|x| x == 0xe12f_ff1e || x == 0 || x == 0xe320_f000 || x & 0xffff_8000 == 0xe8bd_8000)
        }
        _ => false,
    }
}

/// Whether the previous function plausibly ended just before offset `off`: a return, an
/// unconditional branch, padding.
fn raw_follows_end(arch: Arch, s: &[u8], off: usize) -> bool {
    if off == 0 {
        return true;
    }
    let w = |o: usize| s.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let h = |o: usize| s.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    match arch {
        Arch::X86_64 => follows_end(s, off) || nop_padding_before(s, off),
        Arch::Arm64 => {
            off >= 4
                && w(off - 4).is_some_and(|x| {
                    x == 0xd65f_03c0
                        || x == 0
                        || x == 0xd503_201f
                        || x & 0xfc00_0000 == 0x1400_0000
                        || x & 0xffff_fc1f == 0xd61f_0000
                        || x == 0xd420_0000
                        || x & 0xffe0_001f == 0xd420_0000
                })
        }
        Arch::Thumb => {
            off >= 2
                && h(off - 2).is_some_and(|x| x == 0x4770 || x == 0x0000 || x == 0xbf00 || x & 0xff00 == 0xbd00 || x & 0xf800 == 0xe000)
        }
        Arch::Arm => {
            off >= 4
                && w(off - 4).is_some_and(|x| {
                    x == 0xe12f_ff1e
                        || x == 0
                        || x == 0xe320_f000
                        || x == 0xe1a0_0000
                        || x & 0xffff_8000 == 0xe8bd_8000
                        || x & 0xff00_0000 == 0xea00_0000
                })
        }
        _ => false,
    }
}

impl Binary {
    /// Whether the bytes at `code` (loaded at `va`) decode as the start of a function.
    fn decodes_as_function(&self, code: &[u8], va: u64) -> bool {
        let mut dis = Disassembler::with_mode(self.info.arch, self.info.bits, false);
        let (mut off, mut count) = (0usize, 0usize);
        while count < TRIAL_INSTRUCTIONS {
            let Some(rest) = code.get(off..).filter(|r| !r.is_empty()) else { return false };
            let d = dis.decode(rest, va + off as u64);
            if !d.valid || d.flow == Flow::Interrupt {
                return false;
            }
            off += d.len as usize;
            count += 1;
            // A `ret` or an unconditional `jmp` ends the function (a lone `jmp` is a thunk); a
            // conditional jump falls through and decoding goes on.
            if matches!(d.flow, Flow::Ret | Flow::Jump) {
                return true;
            }
        }
        true
    }

    /// Starts of functions in code the analysis did not cover (see the module docs). Only 32-bit
    /// x86, where no unwind table seeds the analysis.
    pub(crate) fn scan_function_starts(&self, a: &Analysis, loose: bool) -> Vec<u64> {
        if self.is_scannable_raw() {
            return self.scan_raw(a, loose);
        }
        if self.info.arch != Arch::X86 {
            return Vec::new();
        }
        let covered = covered(a);
        let mut pointers: Vec<u64> = self.code_pointers.clone();
        pointers.sort_unstable();
        pointers.dedup();
        let mut found: BTreeSet<u64> = BTreeSet::new();
        for range in self.ranges.iter().filter(|r| r.perms.x) {
            let Some(bytes) = self.bytes_at(range.vaddr) else { continue };
            let size = (range.vsize.max(range.file_size) as usize).min(bytes.len());
            let section = &bytes[..size];
            for (lo, hi) in gaps(&covered, range.vaddr, range.vaddr + size as u64) {
                let (start, end) = ((lo - range.vaddr) as usize, (hi - range.vaddr) as usize);
                let mut check = |off: usize, need_prologue: bool| {
                    let va = range.vaddr + off as u64;
                    let code = &section[off..];
                    let prologue = has_prologue(code);
                    // Right after covered code the previous function's end isn't visible in the
                    // bytes, so only a prologue counts there; elsewhere padding or a `ret` must
                    // precede it. (This also keeps `push ebp; mov ebp, esp` two bytes after a
                    // hot-patch `mov edi, edi` from becoming a second function.)
                    let boundary = if off == start { prologue } else { follows_end(section, off) };
                    if (prologue || !need_prologue) && boundary && self.decodes_as_function(code, va) {
                        found.insert(va);
                    }
                };
                let from = pointers.partition_point(|&p| p < lo);
                for &p in pointers[from..].iter().take_while(|&&p| p < hi) {
                    check((p - range.vaddr) as usize, false);
                }
                for (off, &byte) in section.iter().enumerate().take(end).skip(start) {
                    if matches!(byte, 0x55 | 0x8b) {
                        check(off, true);
                    }
                }
            }
        }
        found.into_iter().collect()
    }
}

impl Binary {
    /// A raw image of a CPU the raw scan knows. These get a second, looser scan once the strict one
    /// has nothing left to add (see `analyze`).
    pub(crate) fn is_scannable_raw(&self) -> bool {
        self.info.format == Format::Raw && matches!(self.info.arch, Arch::X86_64 | Arch::Arm64 | Arch::Thumb | Arch::Arm)
    }

    /// The scan for raw images of CPUs whose images carry no unwind table: function-start patterns
    /// after a function end, in the code the descent did not cover. `loose` also accepts a start with
    /// no recognisable prologue right after a return or padding: by then the descent has followed every
    /// call, so what is left uncovered is mostly leaf functions nothing calls directly.
    fn scan_raw(&self, a: &Analysis, loose: bool) -> Vec<u64> {
        let arch = self.info.arch;
        let step = match arch {
            Arch::X86_64 => 1,
            Arch::Thumb => 2,
            _ => 4,
        };
        // Data the image names (a Cortex-M vector table) is not code, whatever it decodes as.
        let mut covered = covered(a);
        covered.extend(
            self.symbols
                .iter()
                .filter(|s| s.kind == SymbolKind::Object && s.size > 0)
                .map(|s| (s.address, s.address.saturating_add(s.size))),
        );
        let covered = merge(covered);
        let mut found: BTreeSet<u64> = BTreeSet::new();
        for range in self.ranges.iter().filter(|r| r.perms.x) {
            let Some(bytes) = self.bytes_at(range.vaddr) else { continue };
            let size = (range.vsize.max(range.file_size) as usize).min(bytes.len());
            let section = &bytes[..size];
            for (lo, hi) in gaps(&covered, range.vaddr, range.vaddr + size as u64) {
                let (start, end) = ((lo - range.vaddr) as usize, (hi - range.vaddr) as usize);
                let first = start.div_ceil(step) * step;
                for off in (first..end).step_by(step) {
                    // Right after covered code the previous function's end may be anywhere, as for 32-bit x86.
                    let ends = off == start || raw_follows_end(arch, section, off);
                    let starts = raw_prologue(arch, section, off) || (loose && off != start && raw_hard_end(arch, section, off));
                    if !starts || !ends {
                        continue;
                    }
                    // Padding is not a function, however it decodes (zero words are `movs r0, r0` on Thumb and
                    // `andeq` on ARM): the first bytes must not be one repeated value.
                    if !varied(&section[off..]) {
                        continue;
                    }
                    // And a function does not start with an erased word, a zero word or a padding byte.
                    let first = &section[off..];
                    let head = match arch {
                        Arch::Thumb => 2,
                        Arch::X86_64 => 1,
                        _ => 4,
                    };
                    if first.len() >= head
                        && (first[..head].iter().all(|b| *b == 0 || *b == 0xff) || (arch == Arch::X86_64 && first[0] == 0xcc))
                    {
                        continue;
                    }
                    let va = range.vaddr + off as u64;
                    if self.decodes_as_function(&section[off..], va) {
                        found.insert(va);
                    }
                }
            }
        }
        found.into_iter().collect()
    }
}

/// Whether the first 16 bytes of `code` hold at least four different values: not zeros, `0xff` fill, or a
/// repeated filler pattern.
fn varied(code: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut n = 0;
    for &b in code.iter().take(16) {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n >= 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_are_what_coverage_leaves() {
        let cov = [(0x10, 0x20), (0x30, 0x40)];
        assert_eq!(gaps(&cov, 0x0, 0x50), vec![(0x0, 0x10), (0x20, 0x30), (0x40, 0x50)]);
        assert_eq!(gaps(&cov, 0x12, 0x38), vec![(0x20, 0x30)]);
        assert_eq!(gaps(&cov, 0x10, 0x20), vec![]);
        assert_eq!(gaps(&[], 0x5, 0x9), vec![(0x5, 0x9)]);
    }

    #[test]
    fn prologues_and_boundaries() {
        assert!(has_prologue(&[0x55, 0x8b, 0xec, 0x83]));
        assert!(has_prologue(&[0x8b, 0xff, 0x55, 0x8b, 0xec]));
        assert!(has_prologue(&[0x55, 0x89, 0xe5]));
        assert!(!has_prologue(&[0x55, 0x8b, 0xc0]));
        let sec = [0xc3, 0xcc, 0xcc, 0x55, 0x8b, 0xec, 0xc2, 0x08, 0x00, 0x90, 0x41];
        assert!(follows_end(&sec, 0));
        assert!(follows_end(&sec, 2));
        assert!(!follows_end(&sec, 4));
        assert!(follows_end(&sec, 9), "after ret imm16");
        assert!(follows_end(&sec, 10), "after a nop");
    }
}
