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

use std::collections::BTreeSet;

use crate::analysis::Analysis;
use crate::disasm::Disassembler;
use crate::model::{Arch, Flow};
use crate::Binary;

/// Rounds of "scan, then analyse again". A round's new functions call others that the next
/// round's recursive descent finds on its own; a third round rarely adds anything.
pub(crate) const MAX_ROUNDS: usize = 3;
/// Instructions a candidate must decode before it counts as code, if it hasn't ended sooner.
const TRIAL_INSTRUCTIONS: usize = 16;

/// `(start, end)` of everything the analysis covered, sorted and merged.
fn covered(a: &Analysis) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = a.block_index.iter().map(|(&s, &(e, _))| (s, e)).collect();
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
    pub(crate) fn scan_function_starts(&self, a: &Analysis) -> Vec<u64> {
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
