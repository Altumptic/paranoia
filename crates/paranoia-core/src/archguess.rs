//! Which CPU is this raw image for? A statistical guess from machine-code patterns.
//!
//! Every compiler leaves the same marks at function boundaries: `ret`, a frame set-up, a stack
//! adjustment. Each CPU's marks are specific 16-, 24- or 32-bit patterns that random bytes almost
//! never contain. The scan counts them for every candidate CPU (aligned, in both byte orders where
//! it matters) and compares each count with what random data would give by chance: the CPU whose
//! count stands furthest above chance, by a clear margin over the runner-up, is the guess.
//!
//! This is the same idea as published "CPU recognisers", reduced to the patterns that matter most.
//! It needs code (a few KiB at least), says nothing when the evidence is thin, and is weakest where
//! architectures share encodings (x86 / x86-64 by byte patterns, ARM / Thumb when the code is
//! mostly leaf functions). Cortex-M images are recognised earlier, by their vector table.

use crate::model::Arch;

/// How much of the image is scanned.
const SCAN_LIMIT: usize = 1 << 20;

/// A CPU guess with the evidence behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchGuess {
    pub arch: Arch,
    pub bits: u8,
    pub big_endian: bool,
    /// The `--arch` name that selects it.
    pub name: &'static str,
    /// Pattern hits for this CPU, and for the runner-up.
    pub hits: usize,
    pub runner_up: usize,
}

/// One candidate: its marks counted, and how many a random image would have shown.
#[derive(Default, Clone, Copy)]
struct Tally {
    hits: usize,
    chance: f64,
}

impl Tally {
    /// How many standard deviations above chance (Poisson), 0 when at or below it.
    fn z(&self) -> f64 {
        self.excess() / (self.chance + 1.0).sqrt()
    }

    /// Hits beyond what chance gives, never negative.
    fn excess(&self) -> f64 {
        (self.hits as f64 - self.chance).max(0.0)
    }
}

fn le32(d: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
}
fn be32(d: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
}
fn le16(d: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([d[i], d[i + 1]])
}

/// Expected random hits of a pattern that fixes `bits` bits, over `n` aligned positions.
fn chance(n: usize, bits: u32) -> f64 {
    n as f64 / 2f64.powi(bits as i32)
}

/// Guesses the CPU of `data`, or `None` when the evidence is thin or ambiguous.
pub fn guess_arch(data: &[u8]) -> Option<ArchGuess> {
    let d = &data[..data.len().min(SCAN_LIMIT)];
    if d.len() < 256 {
        return None;
    }
    let (n8, n16, n32) = (d.len(), d.len() / 2, d.len() / 4);

    // (name, arch, bits, big_endian, tally)
    let mut arm64 = Tally::default();
    let mut arm32 = Tally::default();
    let mut thumb = Tally::default();
    let mut x64 = Tally::default();
    let mut x86 = Tally::default();
    let mut mips_le = Tally::default();
    let mut mips_be = Tally::default();
    let mut ppc = Tally::default();
    let mut ppc64_marks = 0usize;
    let mut rv = Tally::default();
    let (mut rv_sd, mut rv_sw) = (0usize, 0usize);

    // Words, aligned to 4.
    for i in (0..n32 * 4).step_by(4) {
        let l = le32(d, i);
        let b = be32(d, i);
        // AArch64: ret; stp x29, x30, [sp, #-N]!; ldp x29, x30, [sp], #N
        if l == 0xd65f_03c0 {
            arm64.hits += 1;
        }
        if l & 0xffc0_7fff == 0xa980_7bfd {
            arm64.hits += 1;
        }
        if l & 0xffc0_7fff == 0xa8c0_7bfd {
            arm64.hits += 1;
        }
        // ARM: bx lr; push {..., lr}; pop {..., pc}
        if l == 0xe12f_ff1e {
            arm32.hits += 1;
        }
        if l & 0xffff_4000 == 0xe92d_4000 {
            arm32.hits += 1;
        }
        if l & 0xffff_8000 == 0xe8bd_8000 {
            arm32.hits += 1;
        }
        // MIPS: jr ra; addiu sp, sp, -N; sw ra, N(sp)
        for (t, w) in [(&mut mips_le, l), (&mut mips_be, b)] {
            if w == 0x03e0_0008 {
                t.hits += 1;
            }
            if w & 0xffff_8000 == 0x27bd_8000 {
                t.hits += 1;
            }
            if w & 0xffff_0000 == 0xafbf_0000 {
                t.hits += 1;
            }
        }
        // PowerPC (big-endian): blr; mflr r0; stwu r1, -N(r1); std r0, 16(r1) / ld r0, 16(r1)
        if b == 0x4e80_0020 {
            ppc.hits += 1;
        }
        if b == 0x7c08_02a6 {
            ppc.hits += 1;
        }
        if b & 0xffff_8000 == 0x9421_8000 {
            ppc.hits += 1;
        }
        if b == 0xf801_0010 || b == 0xe801_0010 {
            ppc64_marks += 1;
        }
        // RISC-V: ret; addi sp, sp, -N; sd/sw ra, N(sp)
        if l == 0x0000_8067 {
            rv.hits += 1;
        }
        if l & 0x800f_ffff == 0x8001_0113 {
            rv.hits += 1;
        }
        if l & 0x01ff_f07f == 0x0011_3023 {
            rv.hits += 1;
            rv_sd += 1;
        }
        if l & 0x01ff_f07f == 0x0011_2023 {
            rv.hits += 1;
            rv_sw += 1;
        }
    }
    arm64.chance = chance(n32, 32) + 2.0 * chance(n32, 25);
    arm32.chance = chance(n32, 32) + 2.0 * chance(n32, 17);
    mips_le.chance = chance(n32, 32) + chance(n32, 17) + chance(n32, 16);
    mips_be.chance = mips_le.chance;
    ppc.chance = 2.0 * chance(n32, 32) + chance(n32, 17);
    rv.chance = chance(n32, 32) + chance(n32, 21) + 2.0 * chance(n32, 18);

    // Halfwords, aligned to 2: Thumb `bx lr`, `push {..., lr}`, `pop {..., pc}`; RISC-V compressed `ret`.
    let mut c_ret = 0usize;
    for i in (0..n16 * 2).step_by(2) {
        let h = le16(d, i);
        if h == 0x4770 {
            thumb.hits += 1;
        }
        if h & 0xff00 == 0xb500 {
            thumb.hits += 1;
        }
        if h & 0xff00 == 0xbd00 {
            thumb.hits += 1;
        }
        if h == 0x8082 {
            c_ret += 1;
        }
    }
    rv.hits += c_ret;
    rv.chance += chance(n16, 16);
    thumb.chance = chance(n16, 16) + 2.0 * chance(n16, 8);

    // Bytes: x86 and x86-64.
    for w in d.windows(5) {
        match w {
            [0x55, 0x48, 0x89, 0xe5, ..] => x64.hits += 1,
            [0x48, 0x83, 0xec, ..] | [0x48, 0x8b, 0x05, ..] | [0x48, 0x8d, 0x05, ..] | [0x48, 0x8d, 0x0d, ..] => x64.hits += 1,
            [0x48, 0x89, 0x5c, 0x24, ..] => x64.hits += 1,
            [0xc3, 0xcc, 0xcc, ..] => x64.hits += 1,
            [0x55, 0x8b, 0xec, ..] | [0x55, 0x89, 0xe5, ..] => x86.hits += 1,
            [0xc2, 0x04 | 0x08 | 0x0c | 0x10, 0x00, ..] => x86.hits += 1,
            [0x8b, 0x45, 0x08, ..] | [0x8b, 0x4d, 0x08, ..] => x86.hits += 1,
            _ => {}
        }
    }
    // x86-64 fixes 24 bits in five of its marks and 32 in two; x86 fixes 24 bits in eight.
    x64.chance = 5.0 * chance(n8, 24) + 2.0 * chance(n8, 32);
    x86.chance = 8.0 * chance(n8, 24);

    // The candidates and their z scores. MIPS and PowerPC pick their byte order / width by the stronger tally.
    let mips = if mips_le.z() >= mips_be.z() { (mips_le, false) } else { (mips_be, true) };
    let (rv_bits, rv_name) = if rv_sd >= rv_sw && rv_sd > 0 { (64, "riscv64") } else { (32, "riscv32") };
    let (ppc_bits, ppc_name) = if ppc64_marks > 0 { (64, "ppc64") } else { (32, "ppc") };
    let mut cands: Vec<(Tally, Arch, u8, bool, &'static str)> = vec![
        (arm64, Arch::Arm64, 64, false, "arm64"),
        (arm32, Arch::Arm, 32, false, "arm"),
        (thumb, Arch::Thumb, 32, false, "thumb"),
        (x64, Arch::X86_64, 64, false, "x86-64"),
        (x86, Arch::X86, 32, false, "x86"),
        (mips.0, Arch::Mips, 32, mips.1, "mips"),
        (ppc, Arch::PowerPc, ppc_bits, true, ppc_name),
        (rv, Arch::RiscV, rv_bits, false, rv_name),
    ];
    cands.sort_by(|a, b| b.0.z().total_cmp(&a.0.z()));
    let (best, second) = (&cands[0], &cands[1]);
    // Evidence: well above chance, enough hits to mean something, and clearly ahead of the runner-up
    // (compared by what each stands above chance, so a weak pattern's chance hits do not count).
    if best.0.z() < 6.0 || best.0.hits < 4 || best.0.excess() < 2.0 * second.0.excess() + 3.0 {
        return None;
    }
    Some(ArchGuess { arch: best.1, bits: best.2, big_endian: best.3, name: best.4, hits: best.0.hits, runner_up: second.0.hits })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pseudo-random filler (xorshift), the same on every run.
    fn noise(n: usize, mut s: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    /// Filler with `marks` (each a byte string) planted every `gap` bytes, aligned to `align`.
    fn image(marks: &[&[u8]], total: usize, gap: usize, align: usize) -> Vec<u8> {
        let mut d = noise(total, 0x9e37_79b9_7f4a_7c15);
        let mut at = 64;
        let mut k = 0;
        while at + 8 < total {
            let m = marks[k % marks.len()];
            d[at..at + m.len()].copy_from_slice(m);
            at += gap;
            at = at.div_ceil(align) * align;
            k += 1;
        }
        d
    }

    #[test]
    fn each_cpu_is_recognised_from_its_function_boundaries() {
        let w = |v: u32| v.to_le_bytes().to_vec();
        let wb = |v: u32| v.to_be_bytes().to_vec();
        let cases: Vec<(&str, Vec<u8>, usize, usize)> = vec![
            ("arm64", [w(0xd65f_03c0), w(0xa9bf_7bfd), w(0xa8c1_7bfd)].concat(), 4, 4),
            ("arm", [w(0xe12f_ff1e), w(0xe92d_4800), w(0xe8bd_8800)].concat(), 4, 4),
            (
                "thumb",
                [0x4770u16.to_le_bytes().to_vec(), 0xb580u16.to_le_bytes().to_vec(), 0xbd80u16.to_le_bytes().to_vec()].concat(),
                2,
                2,
            ),
            ("x86-64", vec![0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc3, 0xcc, 0xcc], 1, 16),
            ("x86", vec![0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0xc2, 0x04, 0x00], 1, 16),
            ("mips", [w(0x03e0_0008), w(0x27bd_ffe0), w(0xafbf_001c)].concat(), 4, 4),
            ("ppc", [wb(0x4e80_0020), wb(0x7c08_02a6), wb(0x9421_ffe0)].concat(), 4, 4),
            ("riscv32", [w(0x0000_8067), w(0xff01_0113), w(0x0011_2623)].concat(), 4, 4),
        ];
        for (name, marks, _unit, align) in cases {
            let parts: Vec<&[u8]> = marks.chunks(if align == 1 { marks.len() } else { align }).collect();
            let d = image(&parts, 16 * 1024, 40, align.max(1));
            let g = guess_arch(&d).unwrap_or_else(|| panic!("{name}: no guess"));
            assert_eq!(g.name, name, "{name}: {g:?}");
            assert!(g.hits >= 4, "{name}: {g:?}");
        }
    }

    #[test]
    fn big_endian_mips_and_ppc64_and_riscv64_are_told_apart() {
        let wb = |v: u32| v.to_be_bytes().to_vec();
        let w = |v: u32| v.to_le_bytes().to_vec();
        let be = [wb(0x03e0_0008), wb(0x27bd_ffe0), wb(0xafbf_001c)].concat();
        let g = guess_arch(&image(&be.chunks(4).collect::<Vec<_>>(), 16 * 1024, 40, 4)).unwrap();
        assert_eq!((g.name, g.big_endian), ("mips", true), "{g:?}");
        let p64 = [wb(0x4e80_0020), wb(0x7c08_02a6), wb(0xf801_0010), wb(0xe801_0010)].concat();
        assert_eq!(guess_arch(&image(&p64.chunks(4).collect::<Vec<_>>(), 16 * 1024, 40, 4)).unwrap().name, "ppc64");
        // ret; addi sp, sp, -16; `sd ra, 8(sp)` (funct3 011, rs1 = sp, rs2 = ra).
        let rv64 = [w(0x0000_8067), w(0xff01_0113), w(0x0011_3423)].concat();
        assert_eq!(guess_arch(&image(&rv64.chunks(4).collect::<Vec<_>>(), 16 * 1024, 40, 4)).unwrap().name, "riscv64");
    }

    #[test]
    fn noise_zeros_and_text_give_no_guess() {
        for seed in 1..=5u64 {
            assert!(guess_arch(&noise(512 * 1024, seed)).is_none(), "seed {seed}");
        }
        assert!(guess_arch(&[0u8; 64 * 1024]).is_none());
        assert!(guess_arch(&[0xffu8; 64 * 1024]).is_none());
        assert!(guess_arch(&b"The quick brown fox jumps over the lazy dog. ".repeat(2000)).is_none());
        assert!(guess_arch(&[0x55, 0x8b, 0xec]).is_none(), "too short to judge");
    }

    #[test]
    fn a_few_stray_patterns_are_not_enough() {
        let mut d = noise(32 * 1024, 7);
        d[100..104].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
        d[200..204].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
        assert!(guess_arch(&d).is_none());
    }
}
