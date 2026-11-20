//! Differential execution of Thumb-2 pseudocode against real hardware semantics (QEMU).
//!
//! Random Thumb functions are assembled, run under QEMU's Cortex-M model with random inputs, and the same
//! machine code is opened as a raw image, decompiled, and the *generated C text* is executed by a small
//! interpreter of the C subset the generator writes. Every result must agree. This measures whether the
//! pseudocode computes what the code computes, not just whether it looks plausible.
//!
//! The test runs only when `PARANOIA_QEMU` names a QEMU (for example `qemu-system-arm`, or on Windows with
//! WSL `wsl -d kali -- qemu-system-arm` plus `PARANOIA_QEMU_WSL=1` to turn paths into `/mnt/d/...`).
//! `PARANOIA_QEMU_FUNCS` sets how many functions (default 120), `PARANOIA_QEMU_SEED` the seed.

use std::collections::HashMap;

// ------------------------------------------------------------------------------------------------
// A small deterministic generator
// ------------------------------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

// ------------------------------------------------------------------------------------------------
// Thumb encoders (16-bit forms, low registers) and the generator
// ------------------------------------------------------------------------------------------------

fn movs_imm(rd: u16, imm: u16) -> u16 {
    0x2000 | rd << 8 | imm
}
fn add_sub_reg(sub: bool, rd: u16, rn: u16, rm: u16) -> u16 {
    0x1800 | (sub as u16) << 9 | rm << 6 | rn << 3 | rd
}
fn add_sub_imm3(sub: bool, rd: u16, rn: u16, imm: u16) -> u16 {
    0x1C00 | (sub as u16) << 9 | imm << 6 | rn << 3 | rd
}
fn add_sub_imm8(sub: bool, rd: u16, imm: u16) -> u16 {
    0x3000 | (sub as u16) << 11 | rd << 8 | imm
}
/// `lsls` (0), `lsrs` (1), `asrs` (2) by an immediate.
fn shift_imm(op: u16, rd: u16, rm: u16, imm: u16) -> u16 {
    op << 11 | imm << 6 | rm << 3 | rd
}
fn alu(op: u16, rd: u16, rm: u16) -> u16 {
    0x4000 | op << 6 | rm << 3 | rd
}
fn cmp_imm(rn: u16, imm: u16) -> u16 {
    0x2800 | rn << 8 | imm
}
fn mem(op: u16, rt: u16, rn: u16, imm5: u16) -> u16 {
    op | imm5 << 6 | rn << 3 | rt
}
const STR: u16 = 0x6000;
const LDR: u16 = 0x6800;
const STRB: u16 = 0x7000;
const LDRB: u16 = 0x7800;
const STRH: u16 = 0x8000;
const LDRH: u16 = 0x8800;
const BX_LR: u16 = 0x4770;
/// `b<cond>` over `skip` halfwords that follow it (`skip >= 1`).
fn bcc(cond: u16, skip: usize) -> u16 {
    0xD000 | cond << 8 | ((skip as i16 - 1) as u16 & 0xff)
}
/// `b` over `skip` halfwords that follow it.
fn b(skip: usize) -> u16 {
    0xE000 | ((skip as i16 - 1) as u16 & 0x7ff)
}
/// `bl` from `at` to `to`.
fn bl(at: u32, to: u32) -> [u16; 2] {
    let off = to.wrapping_sub(at + 4) as i32;
    let v = off >> 1;
    let s = ((v >> 23) & 1) as u16;
    let (i1, i2) = (((v >> 22) & 1) as u16, ((v >> 21) & 1) as u16);
    let (imm10, imm11) = (((v >> 11) & 0x3ff) as u16, (v & 0x7ff) as u16);
    let (j1, j2) = (!(i1 ^ s) & 1, !(i2 ^ s) & 1);
    [0xF000 | s << 10 | imm10, 0xD000 | j1 << 13 | j2 << 11 | imm11]
}

/// 32-bit encodings: `movw`/`movt`, data processing with a shifted register, `addw`/`subw`, the `ldr`/`str` family
/// with a 12-bit offset or an index with write-back, `mul`/`mla`/`udiv`/`sdiv`.
fn wide(hw1: u16, hw2: u16) -> Vec<u16> {
    vec![hw1, hw2]
}
fn movw_movt(top: bool, rd: u16, imm16: u16) -> Vec<u16> {
    let (imm4, i, imm3, imm8) = (imm16 >> 12, (imm16 >> 11) & 1, (imm16 >> 8) & 7, imm16 & 0xff);
    wide(if top { 0xF2C0 } else { 0xF240 } | i << 10 | imm4, imm3 << 12 | rd << 8 | imm8)
}
/// `op.w rd, rn, rm, <shift> #n`: op AND 0, BIC 1, ORR 2, EOR 4, ADD 8, SUB 13, RSB 14; shift LSL 0, LSR 1, ASR 2.
fn shifted(op: u16, s: bool, rd: u16, rn: u16, rm: u16, shift: u16, n: u16) -> Vec<u16> {
    wide(0xEA00 | op << 5 | (s as u16) << 4 | rn, (n >> 2) << 12 | rd << 8 | (n & 3) << 6 | shift << 4 | rm)
}
fn addw_subw(sub: bool, rd: u16, rn: u16, imm12: u16) -> Vec<u16> {
    wide(if sub { 0xF2A0 } else { 0xF200 } | (imm12 >> 11) << 10 | rn, ((imm12 >> 8) & 7) << 12 | rd << 8 | imm12 & 0xff)
}
/// `ldr.w`/`str.w` family with a 12-bit offset: hw1 base 0xF8C0 (str.w) / 0xF8D0 (ldr.w), byte 0xF880/0xF890,
/// half 0xF8A0/0xF8B0, signed byte 0xF990, signed half 0xF9B0.
fn mem_w(hw1: u16, rt: u16, rn: u16, imm12: u16) -> Vec<u16> {
    wide(hw1 | rn, rt << 12 | imm12)
}
/// The indexed form: `[rn, #±imm8]!` (pre) or `[rn], #±imm8` (post), hw1 0xF840 | size bits | load bit.
fn mem_idx(hw1: u16, rt: u16, rn: u16, imm8: u16, pre: bool, add: bool) -> Vec<u16> {
    wide(hw1 | rn, rt << 12 | 1 << 11 | (pre as u16) << 10 | (add as u16) << 9 | 1 << 8 | imm8)
}
fn mul_w(rd: u16, rn: u16, rm: u16) -> Vec<u16> {
    wide(0xFB00 | rn, 0xF000 | rd << 8 | rm)
}
fn mla_w(rd: u16, rn: u16, rm: u16, ra: u16) -> Vec<u16> {
    wide(0xFB00 | rn, ra << 12 | rd << 8 | rm)
}
fn div_w(signed: bool, rd: u16, rn: u16, rm: u16) -> Vec<u16> {
    wide(if signed { 0xFB90 } else { 0xFBB0 } | rn, 0xF0F0 | rd << 8 | rm)
}
/// `cbz`/`cbnz rn` over `skip` halfwords (1..=64).
fn cbz(nonzero: bool, rn: u16, skip: usize) -> u16 {
    0xB100 | (nonzero as u16) << 11 | (skip as u16 - 1) << 3 | rn
}

/// Conditions after which the lifter's reading of the flags is exact. After `cmp` every condition; after other
/// flag-setting instructions only the ones the result alone decides.
const COND_EQ: u16 = 0;
const COND_NE: u16 = 1;
const COND_MI: u16 = 4;
const COND_PL: u16 = 5;
/// Every condition after a compare except overflow set / clear (vs, vc), which the pseudocode writes as `__flags_o`.
const ALL_CONDS: [u16; 12] = [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13];

struct Gen<'a> {
    rng: &'a mut Rng,
    /// `r4` is a variable of this function (it has a frame that saves it and has been set).
    r4: bool,
}

impl Gen<'_> {
    fn dst(&mut self) -> u16 {
        if self.r4 && self.rng.chance(20) {
            4
        } else {
            self.rng.below(3) as u16
        }
    }
    fn src(&mut self) -> u16 {
        if self.r4 && self.rng.chance(15) {
            4
        } else {
            self.rng.below(4) as u16
        }
    }
    /// One plain instruction; the flag says it sets the flags (so a branch may use eq/ne/mi/pl right after it).
    fn plain(&mut self) -> Vec<u16> {
        if self.rng.chance(30) {
            return self.wide_plain();
        }
        vec![self.plain16().0]
    }

    fn plain16(&mut self) -> (u16, bool) {
        let (rd, rn, rm) = (self.dst(), self.src(), self.src());
        match self.rng.below(100) {
            0..=9 => (movs_imm(rd, self.rng.below(256) as u16), true),
            10..=21 => (add_sub_reg(false, rd, rn, rm), true),
            22..=31 => (add_sub_reg(true, rd, rn, rm), true),
            32..=36 => (add_sub_imm3(self.rng.chance(50), rd, rn, self.rng.below(8) as u16), true),
            37..=43 => (add_sub_imm8(self.rng.chance(50), rd, self.rng.below(256) as u16), true),
            44..=51 => {
                let op = self.rng.below(3) as u16;
                let imm = if op == 0 { self.rng.below(32) } else { 1 + self.rng.below(31) } as u16;
                (shift_imm(op, rd, rn, imm), true)
            }
            // ands, eors, orrs, bics, muls, mvns, negs: two registers, N and Z from the result.
            52..=71 => {
                let op = [0, 1, 12, 14, 13, 15, 9][self.rng.below(7)];
                (alu(op, rd, rn), true)
            }
            // mov rd, rm (no flags)
            72..=74 => (0x4600 | rn << 3 | rd, false),
            // loads and stores through the buffer pointer r3
            75..=79 => (mem(LDR, rd, 3, self.rng.below(16) as u16), false),
            80..=83 => (mem(STR, rn, 3, self.rng.below(16) as u16), false),
            84..=86 => (mem(LDRB, rd, 3, self.rng.below(32) as u16), false),
            87..=89 => (mem(STRB, rn, 3, self.rng.below(32) as u16), false),
            90..=93 => (mem(LDRH, rd, 3, self.rng.below(32) as u16), false),
            94..=96 => (mem(STRH, rn, 3, self.rng.below(32) as u16), false),
            _ => (alu(8, rn, rm), true), // tst
        }
    }

    /// One 32-bit instruction (or a short sequence) from the forms the lifter models.
    fn wide_plain(&mut self) -> Vec<u16> {
        let (rd, rn, rm, ra) = (self.dst(), self.src(), self.src(), self.src());
        match self.rng.below(16) {
            0 => movw_movt(false, rd, self.rng.next() as u16),
            1 => movw_movt(true, rd, self.rng.next() as u16),
            2..=4 => {
                let op = [0, 1, 2, 4, 8, 13, 14][self.rng.below(7)];
                let shift = self.rng.below(3) as u16;
                let n = if shift == 0 { self.rng.below(32) } else { 1 + self.rng.below(31) } as u16;
                shifted(op, self.rng.chance(30), rd, rn, rm, shift, n)
            }
            5 => addw_subw(self.rng.chance(50), rd, rn, self.rng.below(4096) as u16),
            6 => {
                // loads and stores with a 12-bit offset through r3
                let (hw1, scale) = [(0xF8D0, 4), (0xF8C0, 4), (0xF890, 1), (0xF880, 1), (0xF8B0, 2), (0xF8A0, 2), (0xF990, 1), (0xF9B0, 2)]
                    [self.rng.below(8)];
                let slot = self.rng.below((64 / scale) as usize) as u16;
                mem_w(hw1, if hw1 & 0x10 != 0 { rd } else { rn }, 3, slot * scale)
            }
            7 | 8 => mul_w(rd, rn, rm),
            9 => mla_w(rd, rn, rm, ra),
            10 => div_w(self.rng.chance(50), rd, rn, rm),
            11 => vec![[0xB2C0, 0xB280, 0xB240, 0xB200][self.rng.below(4)] | rn << 3 | rd], // uxtb uxth sxtb sxth
            12 => {
                // indexed access keeps r3 inside the buffer: a pre-index store/load of a small step, undone afterwards
                let step = 4 * (1 + self.rng.below(4)) as u16;
                let load = self.rng.chance(50);
                // (the register is never r3: a transfer register equal to the written-back base is unpredictable)
                let mut v = mem_idx(if load { 0xF850 } else { 0xF840 }, rd, 3, step, true, true);
                // the second moves back down: net r3 unchanged after a post-index of -step
                v.extend(mem_idx(if load { 0xF850 } else { 0xF840 }, rd, 3, step, false, false));
                v
            }
            13 => {
                // r3 is the buffer pointer: a post-indexed load then a subtraction back
                let step = 4 * (1 + self.rng.below(3)) as u16;
                let mut v = mem_idx(0xF850, rd, 3, step, false, true);
                v.extend(addw_subw(true, 3, 3, step));
                v
            }
            _ => shifted(self.rng.below(2) as u16 * 8, false, rd, rn, rm, 0, 0),
        }
    }

    /// A compare (or a flag-setting instruction) and the conditions that may follow it.
    fn test(&mut self) -> (Vec<u16>, Vec<u16>) {
        let rn = self.src();
        match self.rng.below(5) {
            0 => (vec![cmp_imm(rn, self.rng.below(256) as u16)], ALL_CONDS.to_vec()),
            1 | 2 => (vec![alu(10, rn, self.src())], ALL_CONDS.to_vec()),
            3 => (vec![alu(8, rn, self.src())], vec![COND_EQ, COND_NE, COND_MI, COND_PL]),
            _ => {
                let rd = self.dst();
                let m = self.src();
                (vec![add_sub_reg(self.rng.chance(50), rd, rn, m)], vec![COND_EQ, COND_NE, COND_MI, COND_PL])
            }
        }
    }

    /// A sequence of statements: plain instructions, `if`, `if`/`else`, and counting loops (when `r4` is free to
    /// count). `depth` limits nesting.
    fn block(&mut self, len: usize, depth: usize) -> Vec<u16> {
        let mut code = Vec::new();
        for _ in 0..len {
            match if depth == 0 { 0 } else { self.rng.below(12) } {
                0..=6 => code.extend(self.plain()),
                7 | 8 => {
                    let (t, conds) = self.test();
                    let cond = conds[self.rng.below(conds.len())];
                    let n = 1 + self.rng.below(3);
                    let body = self.block(n, depth - 1);
                    code.extend(t);
                    code.push(bcc(cond, body.len()));
                    code.extend(body);
                }
                11 if depth > 0 && self.rng.chance(40) => {
                    let n = 1 + self.rng.below(3);
                    let body = self.block(n, depth - 1);
                    let rn = self.rng.below(3) as u16;
                    code.push(cbz(self.rng.chance(50), rn, body.len()));
                    code.extend(body);
                }
                9 | 10 => {
                    let (t, conds) = self.test();
                    let cond = conds[self.rng.below(conds.len())];
                    let (na, ne) = (1 + self.rng.below(3), 1 + self.rng.below(3));
                    let (a, e) = (self.block(na, depth - 1), self.block(ne, depth - 1));
                    code.extend(t);
                    code.push(bcc(cond, a.len() + 1));
                    code.extend(a);
                    code.push(b(e.len()));
                    code.extend(e);
                }
                _ if self.r4 => {
                    // r4 counts down from 1..4 and the body leaves it alone.
                    let n = 1 + self.rng.below(4) as u16;
                    self.r4 = false;
                    let k = 1 + self.rng.below(3);
                    let body = self.block(k, depth - 1);
                    self.r4 = true;
                    code.push(movs_imm(4, n));
                    let len = body.len() as i16;
                    if self.rng.chance(50) {
                        // do { body; r4--; } while (r4 != 0)
                        code.extend(body);
                        code.push(add_sub_imm8(true, 4, 1));
                        code.push(0xD000 | COND_NE << 8 | ((-(len + 3)) as u16 & 0xff));
                    } else {
                        // while (r4 != 0) { body; r4--; }  tested at the top, jumping back with `b`
                        code.push(cmp_imm(4, 0));
                        code.push(bcc(COND_EQ, body.len() + 2));
                        code.extend(body);
                        code.push(add_sub_imm8(true, 4, 1));
                        code.push(0xE000 | ((-(len + 5)) as u16 & 0x7ff));
                    }
                }
                _ => code.extend(self.plain()),
            }
        }
        code
    }

    fn function(&mut self) -> Vec<u16> {
        let framed = self.rng.chance(40);
        let mut code: Vec<u16> = Vec::new();
        if framed {
            // push {r4, r5, lr}: r5 is the driver's, so it is saved; r4 becomes a variable, set first.
            code.push(0xB530);
            let from = self.rng.below(4) as u16;
            code.push(if self.rng.chance(50) { 0x4600 | from << 3 | 4 } else { movs_imm(4, self.rng.below(256) as u16) });
            self.r4 = true;
        }
        let len = 3 + self.rng.below(7);
        code.extend(self.block(len, 2));
        // Make the buffer's contents count: fold the first words into r0.
        if self.rng.chance(60) {
            code.extend([mem(LDR, 1, 3, 0), mem(LDR, 2, 3, 1), add_sub_reg(false, 0, 0, 1), alu(1, 0, 2)]);
        }
        // Compilers compute the result last: most functions end with an instruction that writes r0.
        if self.rng.chance(85) {
            let (rn, rm) = (self.src(), self.src());
            code.push(match self.rng.below(3) {
                0 => add_sub_reg(self.rng.chance(50), 0, rn, rm),
                1 => movs_imm(0, self.rng.below(256) as u16),
                _ => alu([0, 1, 12][self.rng.below(3)], 0, rn),
            });
        }
        code.push(if framed { 0xBD30 } else { BX_LR }); // pop {r4, r5, pc}
        code
    }
}

// ------------------------------------------------------------------------------------------------
// The test image: vector table, a driver that calls every function with every input set, a print routine
// ------------------------------------------------------------------------------------------------

const RAM: u32 = 0x2000_0000;
const BUF: u32 = RAM + 0x1000;
const DRIVER: u32 = 0x100;
const PRINT: u32 = 0x8000;
const TABLE: u32 = 0x8100;
const FUNCS: u32 = 0x9000;
// The driver builds the table and buffer addresses by hand (`movs` and shifts).
const _: () = assert!(TABLE & 0xff == 0 && TABLE >> 8 < 256 && BUF == 0x2000_1000);
const STRIDE: u32 = 0x400;

struct Image {
    bytes: Vec<u8>,
    funcs: Vec<u32>,
    cases: Vec<[u32; 4]>,
}

fn put16(img: &mut [u8], at: u32, h: u16) {
    img[at as usize..at as usize + 2].copy_from_slice(&h.to_le_bytes());
}
fn put32(img: &mut [u8], at: u32, w: u32) {
    img[at as usize..at as usize + 4].copy_from_slice(&w.to_le_bytes());
}

fn build_image(funcs: &[Vec<u16>], cases: &[[u32; 4]]) -> Image {
    let size = (FUNCS + STRIDE * funcs.len() as u32 + 0x100) as usize;
    let mut img = vec![0u8; size.max(0x8000)];
    put32(&mut img, 0, RAM + 0x10000);
    put32(&mut img, 4, DRIVER | 1);
    for i in 2..16 {
        put32(&mut img, i * 4, (PRINT - 4) | 1); // a `b .` for every other vector
    }
    put16(&mut img, PRINT - 4, 0xE7FE);
    // print: r0 as eight letters A-P (a nibble each) and a newline on the UART.
    let p = PRINT;
    let code = [
        0x4800 | 7 << 8 | 5, // ldr r7, [pc, #20]  (the literal after the code)
        movs_imm(3, 8),
        shift_imm(1, 2, 0, 28),       // lsrs r2, r0, #28
        add_sub_imm8(false, 2, 0x41), // adds r2, #'A'
        0x7000 | 7 << 3 | 2,          // strb r2, [r7]
        shift_imm(0, 0, 0, 4),        // lsls r0, r0, #4
        add_sub_imm8(true, 3, 1),     // subs r3, #1
        0xD100 | 0xF9,                // bne <loop>
        movs_imm(2, 10),
        0x7000 | 7 << 3 | 2,
        BX_LR,
    ];
    for (i, h) in code.iter().enumerate() {
        put16(&mut img, p + 2 * i as u32, *h);
    }
    put32(&mut img, p + 24, 0x4000_C000);
    // the input table
    for (i, c) in cases.iter().enumerate() {
        for (k, w) in c.iter().enumerate() {
            put32(&mut img, TABLE + 16 * i as u32 + 4 * k as u32, *w);
        }
    }
    // the functions
    let mut addrs = Vec::new();
    for (i, f) in funcs.iter().enumerate() {
        let at = FUNCS + STRIDE * i as u32;
        assert!(f.len() * 2 < STRIDE as usize);
        for (k, h) in f.iter().enumerate() {
            put16(&mut img, at + 2 * k as u32, *h);
        }
        addrs.push(at);
    }
    // the driver: for every function the scratch buffer is cleared, then r5 walks the input table; every input
    // set runs the function and prints its r0. Constants are built with `movs` and shifts (a literal pool would
    // be out of reach of the later functions).
    let mut at = DRIVER;
    let emit = |img: &mut Vec<u8>, h: u16, at: &mut u32| {
        put16(img, *at, h);
        *at += 2;
    };
    for &f in &addrs {
        for h in [movs_imm(5, (TABLE >> 8) as u16), shift_imm(0, 5, 5, 8)] {
            emit(&mut img, h, &mut at); // r5 = the table
        }
        for h in [movs_imm(4, 0x20), shift_imm(0, 4, 4, 16), add_sub_imm8(false, 4, 0x10), shift_imm(0, 4, 4, 8)] {
            emit(&mut img, h, &mut at); // r4 = the buffer
        }
        for r in 0..4 {
            emit(&mut img, movs_imm(r, 0), &mut at);
        }
        for _ in 0..4 {
            emit(&mut img, 0xC000 | 4 << 8 | 0x0F, &mut at); // stmia r4!, {r0-r3}: 16 bytes of zeros
        }
        for _ in cases {
            emit(&mut img, 0xC800 | 5 << 8 | 0x0F, &mut at); // ldmia r5!, {r0-r3}
            for h in bl(at, f) {
                emit(&mut img, h, &mut at);
            }
            for h in bl(at, PRINT) {
                emit(&mut img, h, &mut at);
            }
        }
    }
    emit(&mut img, 0xE7FE, &mut at);
    assert!(at <= PRINT - 4, "the driver ({at:#x}) runs into the print routine");
    Image { bytes: img, funcs: addrs, cases: cases.to_vec() }
}

// ------------------------------------------------------------------------------------------------
// QEMU
// ------------------------------------------------------------------------------------------------

fn run_qemu(image: &[u8], outputs: usize) -> Result<Vec<u32>, String> {
    use std::io::Read;
    let cmd = std::env::var("PARANOIA_QEMU").map_err(|_| "PARANOIA_QEMU is not set".to_string())?;
    let mut parts = cmd.split_whitespace();
    let program = parts.next().ok_or("empty PARANOIA_QEMU")?;
    let dir = std::env::var("PARANOIA_QEMU_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let file = dir.join(format!("paranoia-qemu-{}.bin", std::process::id()));
    std::fs::write(&file, image).map_err(|e| e.to_string())?;
    let mut path = file.to_string_lossy().replace('\\', "/");
    if std::env::var_os("PARANOIA_QEMU_WSL").is_some() {
        // D:/x/y -> /mnt/d/x/y
        let (drive, rest) = path.split_at(1);
        path = format!("/mnt/{}{}", drive.to_lowercase(), &rest[1..]);
    }
    let mut child = std::process::Command::new(program)
        .args(parts)
        .args(["-M", "lm3s6965evb", "-kernel", &path, "-display", "none", "-monitor", "none", "-serial", "stdio"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {program}: {e}"))?;
    let mut out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut text = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while text.iter().filter(|b| **b == b'\n').count() < outputs && std::time::Instant::now() < deadline {
        if let Ok(chunk) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
            text.extend(chunk);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&file);
    let mut words = Vec::new();
    for line in text.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let line: Vec<u8> = line.iter().copied().filter(|b| b.is_ascii_uppercase()).collect();
        if line.len() != 8 {
            return Err(format!("bad output line {:?}", String::from_utf8_lossy(&line)));
        }
        words.push(line.iter().fold(0u32, |a, b| a << 4 | u32::from(b - b'A')));
    }
    if words.len() < outputs {
        return Err(format!("QEMU printed {} of {outputs} results", words.len()));
    }
    Ok(words)
}

// ------------------------------------------------------------------------------------------------
// An interpreter for the C the generator writes
// ------------------------------------------------------------------------------------------------

/// A 32-bit value with C's signedness: comparisons, `>>` and `/` depend on it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct V {
    v: u32,
    unsigned: bool,
}

#[derive(Debug, Clone)]
enum E {
    Num(V),
    Var(String),
    Un(char, Box<E>),
    Bin(String, Box<E>, Box<E>),
    Cast(bool, Box<E>),
    Load(u8, Box<E>),
}

fn tokenize(s: &str) -> Result<Vec<String>, String> {
    let c: Vec<char> = s.chars().collect();
    let (mut i, mut out) = (0, Vec::new());
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            let st = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(c[st..i].iter().collect());
        } else {
            let two: String = c[i..(i + 2).min(c.len())].iter().collect();
            if ["<<", ">>", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "|=", "&=", "^="].contains(&two.as_str()) {
                out.push(two);
                i += 2;
            } else if "+-*/%&|^~!<>=()[];,:?{}".contains(ch) {
                out.push(ch.to_string());
                i += 1;
            } else {
                return Err(format!("unexpected character {ch:?}"));
            }
        }
    }
    Ok(out)
}

struct P {
    t: Vec<String>,
    i: usize,
}

const TYPES: [&str; 9] = ["int", "unsigned", "uint8_t", "uint16_t", "uint32_t", "int8_t", "int16_t", "int32_t", "size_t"];

impl P {
    fn peek(&self) -> Option<&str> {
        self.t.get(self.i).map(String::as_str)
    }
    fn eat(&mut self, s: &str) -> bool {
        if self.peek() == Some(s) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn expr(&mut self, min: u8) -> Result<E, String> {
        let mut l = self.unary()?;
        while let Some(op) = self.peek().map(str::to_string) {
            let p = match op.as_str() {
                "||" => 1,
                "&&" => 2,
                "|" => 3,
                "^" => 4,
                "&" => 5,
                "==" | "!=" => 6,
                "<" | "<=" | ">" | ">=" => 7,
                "<<" | ">>" => 8,
                "+" | "-" => 9,
                "*" | "/" | "%" => 10,
                _ => break,
            };
            if p < min {
                break;
            }
            self.i += 1;
            let r = self.expr(p + 1)?;
            l = E::Bin(op, Box::new(l), Box::new(r));
        }
        Ok(l)
    }
    fn is_type_at(&self, i: usize) -> bool {
        self.t.get(i).is_some_and(|t| TYPES.contains(&t.as_str()) || t == "const" || t == "char")
    }
    fn unary(&mut self) -> Result<E, String> {
        let Some(t) = self.peek().map(str::to_string) else { return Err("expression ends early".into()) };
        match t.as_str() {
            "-" | "!" | "~" => {
                self.i += 1;
                Ok(E::Un(t.chars().next().unwrap(), Box::new(self.unary()?)))
            }
            "*" => {
                // *(uintN_t *)(addr) or *(uintN_t *)x
                self.i += 1;
                if !self.eat("(") {
                    return Err("a dereference needs a cast".into());
                }
                let ty = self.peek().ok_or("cast ends early")?.to_string();
                self.i += 1;
                if !self.eat("*") || !self.eat(")") {
                    return Err("bad pointer cast".into());
                }
                let size = match ty.as_str() {
                    "uint8_t" | "int8_t" => 1,
                    "uint16_t" | "int16_t" => 2,
                    "uint32_t" | "int32_t" | "unsigned" | "int" => 4,
                    other => return Err(format!("unsupported pointer type {other}")),
                };
                Ok(E::Load(size, Box::new(self.unary()?)))
            }
            "(" => {
                if self.is_type_at(self.i + 1) && self.t.get(self.i + 2).map(String::as_str) == Some(")") {
                    let unsigned = self.t[self.i + 1] != "int" && self.t[self.i + 1] != "int32_t";
                    self.i += 3;
                    return Ok(E::Cast(unsigned, Box::new(self.unary()?)));
                }
                self.i += 1;
                let e = self.expr(1)?;
                if !self.eat(")") {
                    return Err("missing )".into());
                }
                Ok(e)
            }
            _ => {
                self.i += 1;
                if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    let v = u64::from_str_radix(h, 16).map_err(|_| format!("bad number {t}"))?;
                    return Ok(E::Num(V { v: v as u32, unsigned: v > 0x7fff_ffff }));
                }
                if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    let v: u64 = t.parse().map_err(|_| format!("bad number {t}"))?;
                    return Ok(E::Num(V { v: v as u32, unsigned: v > 0x7fff_ffff }));
                }
                if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Ok(E::Var(t));
                }
                Err(format!("unexpected token {t}"))
            }
        }
    }
}

fn parse_expr(s: &str) -> Result<E, String> {
    let mut p = P { t: tokenize(s)?, i: 0 };
    let e = p.expr(1)?;
    if p.i != p.t.len() {
        return Err(format!("trailing tokens in `{s}`"));
    }
    Ok(e)
}

#[derive(Debug, Clone)]
enum Op {
    Assign(String, E),
    Store(u8, E, E),
    Jz(E, usize),
    Jmp(usize),
    Ret(Option<E>),
    Switch(E, Vec<(Vec<u32>, String)>),
}

struct Program {
    params: Vec<String>,
    code: Vec<Op>,
    labels: HashMap<String, usize>,
    var_unsigned: HashMap<String, bool>,
    returns_value: bool,
}

enum Frame {
    If(usize),
    Else(usize),
    While(usize, usize),
    Do(usize),
    For(usize, usize, Option<(String, E)>),
    Switch,
    Body,
}

fn compile(lines: &[String]) -> Result<Program, String> {
    let mut prog =
        Program { params: Vec::new(), code: Vec::new(), labels: HashMap::new(), var_unsigned: HashMap::new(), returns_value: false };
    let mut stack: Vec<Frame> = Vec::new();
    let mut cases: Vec<(Vec<u32>, String)> = Vec::new();
    let mut switch_op: Vec<usize> = Vec::new();
    let mut gotos: Vec<(usize, String)> = Vec::new();
    let mut started = false;
    let mut closed = false;
    for raw in lines {
        let l = raw.trim();
        if l.is_empty() || l.starts_with("//") {
            continue;
        }
        if !started {
            // `int f(int a1, int a2)` / `void f()`
            if l.contains('(') && !l.ends_with(';') && l != "{" {
                prog.returns_value = !l.starts_with("void");
                let args = l.split_once('(').unwrap().1.trim_end_matches(')');
                for a in args.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                    let name = a.rsplit([' ', '*']).next().unwrap().to_string();
                    prog.var_unsigned.insert(name.clone(), !a.starts_with("int "));
                    prog.params.push(name);
                }
                continue;
            }
            if l == "{" {
                started = true;
                stack.push(Frame::Body);
                continue;
            }
        }
        let here = prog.code.len();
        if let Some(rest) = l.strip_suffix(';') {
            // declarations
            let first = rest.split_whitespace().next().unwrap_or("");
            if TYPES.contains(&first) && !rest.contains('=') && !rest.contains('(') {
                for v in rest[first.len()..].split(',').map(|v| v.trim().trim_start_matches('*')) {
                    prog.var_unsigned.insert(v.to_string(), first != "int" && first != "int32_t");
                }
                continue;
            }
            if let Some(cond) = rest.strip_prefix("} while (").and_then(|r| r.strip_suffix(')')) {
                let Some(Frame::Do(start)) = stack.pop() else { return Err("} while without do".into()) };
                prog.code.push(Op::Jz(parse_expr(cond)?, prog.code.len() + 2));
                prog.code.push(Op::Jmp(start));
                continue;
            }
            if let Some(label) = rest.strip_prefix("goto ") {
                gotos.push((here, label.trim().to_string()));
                prog.code.push(Op::Jmp(0));
                continue;
            }
            if rest == "return" {
                prog.code.push(Op::Ret(None));
                continue;
            }
            if let Some(v) = rest.strip_prefix("return ") {
                prog.code.push(Op::Ret(Some(parse_expr(v)?)));
                continue;
            }
            if let Some(g) = rest.strip_prefix("if (").and_then(|r| r.split_once(") goto ")) {
                // `if (c) goto L;` jumps when c holds: Jz over a Jmp.
                prog.code.push(Op::Jz(parse_expr(g.0)?, here + 2));
                gotos.push((here + 1, g.1.trim().to_string()));
                prog.code.push(Op::Jmp(0));
                continue;
            }
            if rest.starts_with("case ") {
                // `case 0: case 2: goto L`
                let mut nums = Vec::new();
                let mut r = rest;
                while let Some(x) = r.strip_prefix("case ") {
                    let (n, tail) = x.split_once(':').ok_or("bad case")?;
                    nums.push(n.trim().parse::<u32>().map_err(|_| "bad case number")?);
                    r = tail.trim();
                }
                let label = r.strip_prefix("goto ").ok_or("a case that is not a goto")?.trim().to_string();
                cases.push((nums, label));
                continue;
            }
            if rest.contains("__asm") {
                return Err(format!("unsupported: {l}"));
            }
            // assignment or store
            let (lhs, rhs) = rest.split_once(" = ").ok_or_else(|| format!("unsupported statement: {l}"))?;
            if lhs.starts_with('*') {
                let p = parse_expr(lhs)?;
                let E::Load(size, addr) = p else { return Err(format!("bad store target {lhs}")) };
                prog.code.push(Op::Store(size, *addr, parse_expr(rhs)?));
            } else {
                if !lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!("unsupported assignment target: {l}"));
                }
                prog.code.push(Op::Assign(lhs.to_string(), parse_expr(rhs)?));
            }
            continue;
        }
        if let Some(label) = l.strip_suffix(':') {
            prog.labels.insert(label.to_string(), here);
            continue;
        }
        if l == "}" {
            match stack.pop() {
                Some(Frame::If(j)) => {
                    let end = prog.code.len();
                    if let Op::Jz(_, t) = &mut prog.code[j] {
                        *t = end;
                    }
                }
                Some(Frame::Else(j)) => {
                    let end = prog.code.len();
                    prog.code[j] = Op::Jmp(end);
                }
                Some(Frame::While(start, j)) => {
                    prog.code.push(Op::Jmp(start));
                    let end = prog.code.len();
                    if let Op::Jz(_, t) = &mut prog.code[j] {
                        *t = end;
                    }
                }
                Some(Frame::For(start, j, step)) => {
                    if let Some((v, e)) = step {
                        prog.code.push(Op::Assign(v, e));
                    }
                    prog.code.push(Op::Jmp(start));
                    let end = prog.code.len();
                    if let Op::Jz(_, t) = &mut prog.code[j] {
                        *t = end;
                    }
                }
                Some(Frame::Switch) => {
                    let at = switch_op.pop().ok_or("switch bookkeeping")?;
                    if let Op::Switch(_, c) = &mut prog.code[at] {
                        *c = std::mem::take(&mut cases);
                    }
                }
                Some(Frame::Body) => closed = true,
                Some(Frame::Do(_)) => {}
                None => return Err("unbalanced braces".into()),
            }
            continue;
        }
        if l == "} else {" {
            let Some(Frame::If(j)) = stack.pop() else { return Err("else without if".into()) };
            let jmp = prog.code.len();
            prog.code.push(Op::Jmp(0));
            let end = prog.code.len();
            if let Op::Jz(_, t) = &mut prog.code[j] {
                *t = end;
            }
            stack.push(Frame::Else(jmp));
            continue;
        }
        if let Some(c) = l.strip_prefix("if (").and_then(|r| r.strip_suffix(") {")) {
            prog.code.push(Op::Jz(parse_expr(c)?, 0));
            stack.push(Frame::If(here));
            continue;
        }
        if let Some(c) = l.strip_prefix("while (").and_then(|r| r.strip_suffix(") {")) {
            prog.code.push(Op::Jz(parse_expr(c)?, 0));
            stack.push(Frame::While(here, here));
            continue;
        }
        if l == "do {" {
            stack.push(Frame::Do(here));
            continue;
        }
        if let Some(h) = l.strip_prefix("for (").and_then(|r| r.strip_suffix(") {")) {
            let parts: Vec<&str> = h.split(';').map(str::trim).collect();
            if parts.len() != 3 {
                return Err(format!("unsupported for: {l}"));
            }
            if let Some((v, e)) = parts[0].split_once(" = ") {
                prog.code.push(Op::Assign(v.trim().to_string(), parse_expr(e)?));
            }
            let start = prog.code.len();
            let j = prog.code.len();
            prog.code.push(Op::Jz(parse_expr(parts[1])?, 0));
            let step = if let Some((v, e)) = parts[2].split_once(" = ") {
                Some((v.trim().to_string(), parse_expr(e)?))
            } else if let Some(v) = parts[2].strip_suffix("++") {
                Some((v.to_string(), parse_expr(&format!("{v} + 1"))?))
            } else if let Some(v) = parts[2].strip_suffix("--") {
                Some((v.to_string(), parse_expr(&format!("{v} - 1"))?))
            } else if parts[2].is_empty() {
                None
            } else {
                return Err(format!("unsupported for step: {l}"));
            };
            stack.push(Frame::For(start, j, step));
            continue;
        }
        if let Some(e) = l.strip_prefix("switch (").and_then(|r| r.strip_suffix(") {")) {
            switch_op.push(here);
            prog.code.push(Op::Switch(parse_expr(e)?, Vec::new()));
            stack.push(Frame::Switch);
            continue;
        }
        return Err(format!("unsupported line: {l}"));
    }
    if !closed || !stack.is_empty() {
        return Err("unbalanced braces at the end".into());
    }
    for (at, label) in gotos {
        let t = *prog.labels.get(&label).ok_or_else(|| format!("goto {label} without a label"))?;
        prog.code[at] = Op::Jmp(t);
    }
    for op in &mut prog.code {
        if let Op::Switch(_, cs) = op {
            for c in cs.iter() {
                if !prog.labels.contains_key(&c.1) {
                    return Err(format!("case goto {} without a label", c.1));
                }
            }
        }
    }
    Ok(prog)
}

#[derive(Default)]
struct Memory(HashMap<u32, u8>);

impl Memory {
    fn read(&self, addr: u32, size: u8) -> Result<u32, String> {
        if !(RAM..RAM + 0x10000).contains(&addr) || !(RAM..RAM + 0x10000).contains(&addr.wrapping_add(size as u32 - 1)) {
            return Err(format!("read outside RAM at {addr:#x}"));
        }
        Ok((0..size as u32).fold(0u32, |a, i| a | u32::from(*self.0.get(&(addr + i)).unwrap_or(&0)) << (8 * i)))
    }
    fn write(&mut self, addr: u32, size: u8, v: u32) -> Result<(), String> {
        if !(RAM..RAM + 0x10000).contains(&addr) || !(RAM..RAM + 0x10000).contains(&addr.wrapping_add(size as u32 - 1)) {
            return Err(format!("write outside RAM at {addr:#x}"));
        }
        for i in 0..size as u32 {
            self.0.insert(addr + i, (v >> (8 * i)) as u8);
        }
        Ok(())
    }
}

fn eval(e: &E, vars: &HashMap<String, V>, mem: &Memory) -> Result<V, String> {
    Ok(match e {
        E::Num(v) => *v,
        E::Var(n) => *vars.get(n).ok_or_else(|| format!("read of {n} before it is set"))?,
        E::Un(op, a) => {
            let a = eval(a, vars, mem)?;
            match op {
                '-' => V { v: a.v.wrapping_neg(), unsigned: a.unsigned },
                '~' => V { v: !a.v, unsigned: a.unsigned },
                _ => V { v: u32::from(a.v == 0), unsigned: false },
            }
        }
        E::Cast(unsigned, a) => V { v: eval(a, vars, mem)?.v, unsigned: *unsigned },
        E::Load(size, a) => {
            let addr = eval(a, vars, mem)?.v;
            // uint32_t loads are unsigned; narrower ones promote to a signed int
            V { v: mem.read(addr, *size)?, unsigned: *size == 4 }
        }
        E::Bin(op, a, b) => {
            // && and || short-circuit
            if op == "&&" || op == "||" {
                let x = eval(a, vars, mem)?.v != 0;
                if (op == "&&" && !x) || (op == "||" && x) {
                    return Ok(V { v: u32::from(x), unsigned: false });
                }
                return Ok(V { v: u32::from(eval(b, vars, mem)?.v != 0), unsigned: false });
            }
            let (x, y) = (eval(a, vars, mem)?, eval(b, vars, mem)?);
            let unsigned = x.unsigned || y.unsigned;
            let (sx, sy) = (x.v as i32, y.v as i32);
            let bool_v = |c: bool| V { v: u32::from(c), unsigned: false };
            match op.as_str() {
                "+" => V { v: x.v.wrapping_add(y.v), unsigned },
                "-" => V { v: x.v.wrapping_sub(y.v), unsigned },
                "*" => V { v: x.v.wrapping_mul(y.v), unsigned },
                "/" | "%" => {
                    if y.v == 0 {
                        // Undefined in C; a Cortex-M gives 0 (it does not trap unless told to).
                        return Ok(V { v: 0, unsigned });
                    }
                    let r = match (unsigned, op.as_str()) {
                        (true, "/") => x.v / y.v,
                        (true, _) => x.v % y.v,
                        (false, "/") => sx.wrapping_div(sy) as u32,
                        (false, _) => sx.wrapping_rem(sy) as u32,
                    };
                    V { v: r, unsigned }
                }
                "&" => V { v: x.v & y.v, unsigned },
                "|" => V { v: x.v | y.v, unsigned },
                "^" => V { v: x.v ^ y.v, unsigned },
                "<<" | ">>" => {
                    if y.v >= 32 {
                        return Err(format!("shift by {} is undefined in C", y.v));
                    }
                    let r = match (op.as_str(), x.unsigned) {
                        ("<<", _) => x.v << y.v,
                        (_, true) => x.v >> y.v,
                        (_, false) => (sx >> y.v) as u32,
                    };
                    V { v: r, unsigned: x.unsigned }
                }
                "==" => bool_v(x.v == y.v),
                "!=" => bool_v(x.v != y.v),
                "<" => bool_v(if unsigned { x.v < y.v } else { sx < sy }),
                "<=" => bool_v(if unsigned { x.v <= y.v } else { sx <= sy }),
                ">" => bool_v(if unsigned { x.v > y.v } else { sx > sy }),
                ">=" => bool_v(if unsigned { x.v >= y.v } else { sx >= sy }),
                other => return Err(format!("operator {other}")),
            }
        }
    })
}

/// Runs the program; returns its result (`None` for `return;`).
fn run(p: &Program, args: &[u32], mem: &mut Memory) -> Result<Option<u32>, String> {
    let mut vars: HashMap<String, V> = HashMap::new();
    for (k, name) in p.params.iter().enumerate() {
        let unsigned = p.var_unsigned.get(name).copied().unwrap_or(false);
        vars.insert(name.clone(), V { v: *args.get(k).ok_or("more parameters than inputs")?, unsigned });
    }
    let (mut pc, mut steps) = (0usize, 0u32);
    while pc < p.code.len() {
        steps += 1;
        if steps > 200_000 {
            return Err("did not finish".into());
        }
        match &p.code[pc] {
            Op::Assign(n, e) => {
                let v = eval(e, &vars, mem)?;
                let unsigned = p.var_unsigned.get(n).copied().unwrap_or(v.unsigned);
                vars.insert(n.clone(), V { v: v.v, unsigned });
                pc += 1;
            }
            Op::Store(size, a, e) => {
                let (addr, v) = (eval(a, &vars, mem)?.v, eval(e, &vars, mem)?.v);
                mem.write(addr, *size, v)?;
                pc += 1;
            }
            Op::Jz(c, t) => pc = if eval(c, &vars, mem)?.v == 0 { *t } else { pc + 1 },
            Op::Jmp(t) => pc = *t,
            Op::Ret(e) => return e.as_ref().map(|e| eval(e, &vars, mem).map(|v| v.v)).transpose(),
            Op::Switch(e, cases) => {
                let x = eval(e, &vars, mem)?.v;
                match cases.iter().find(|(n, _)| n.contains(&x)) {
                    Some((_, l)) => pc = p.labels[l],
                    None => pc += 1,
                }
            }
        }
    }
    Ok(None)
}

// ------------------------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::RawOptions;

    fn c_text(lines: &[crate::PseudoLine]) -> Vec<String> {
        lines.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()).collect()
    }

    fn run_text(text: &str, args: &[u32]) -> Result<Option<u32>, String> {
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        run(&compile(&lines)?, args, &mut Memory::default())
    }

    #[test]
    fn the_interpreter_follows_c_semantics() {
        let t =
            "int f(int a1, int a2)\n{\n  int v1;\n  if (a1 > a2) {\n    v1 = a1 - a2;\n  } else {\n    v1 = a2 >> 1;\n  }\n  return v1;\n}";
        assert_eq!(run_text(t, &[9, 4]), Ok(Some(5)));
        assert_eq!(run_text(t, &[0xffff_fff0, 0xffff_fff0]), Ok(Some(0xffff_fff8)), "`>>` on an int is arithmetic");
        let u = "int f(int a1)\n{\n  return (unsigned)a1 >> 4;\n}";
        assert_eq!(run_text(u, &[0xf000_0000]), Ok(Some(0x0f00_0000)));
        let l =
            "int f(int a1)\n{\n  int v1;\n  v1 = 0;\n  do {\n    v1 = v1 + a1;\n    a1 = a1 - 1;\n  } while (a1 != 0);\n  return v1;\n}";
        assert_eq!(run_text(l, &[4]), Ok(Some(10)));
        let g = "int f(int a1)\n{\n  if (a1 == 0) goto loc_1;\n  return 7;\nloc_1:\n  return 9;\n}";
        assert_eq!((run_text(g, &[0]), run_text(g, &[1])), (Ok(Some(9)), Ok(Some(7))));
        let m = "int f(int a1)\n{\n  *(uint32_t *)(a1) = 0x12345678;\n  return *(uint8_t *)(a1 + 1);\n}";
        assert_eq!(run_text(m, &[RAM + 8]), Ok(Some(0x56)));
        assert!(run_text("int f()\n{\n  return 1 << 40;\n}", &[]).is_err());
        assert!(compile(&["int f()".into(), "{".into(), "  x = __asm(\"nop\");".into(), "}".into()]).is_err());
    }

    #[test]
    fn the_assembler_matches_the_disassembler() {
        // A few encodings checked against what the decoder reads back.
        use yaxpeax_arch::{Decoder as _, U8Reader};
        let d = yaxpeax_arm::armv7::InstDecoder::default_thumb();
        let text = |h: u16| d.decode(&mut U8Reader::new(&h.to_le_bytes())).unwrap().to_string();
        assert_eq!(text(movs_imm(1, 7)), "movs r1, 0x7");
        assert_eq!(text(add_sub_reg(false, 0, 1, 2)), "adds r0, r1, r2");
        assert_eq!(text(add_sub_reg(true, 2, 0, 1)), "subs r2, r0, r1");
        assert_eq!(text(shift_imm(1, 0, 1, 3)), "lsrs r0, r1, 0x3");
        assert_eq!(text(mem(LDR, 0, 3, 2)), "ldr r0, [r3, 0x8]");
        assert_eq!(text(mem(STRB, 1, 3, 5)), "strb r1, [r3, 0x5]");
        assert_eq!(text(alu(12, 0, 1)), "orrs r0, r1");
        assert_eq!(text(cmp_imm(2, 9)), "cmp r2, 0x9");
        assert_eq!(text(BX_LR), "bx lr");
    }

    #[test]
    fn thumb_pseudocode_matches_qemu() {
        if std::env::var_os("PARANOIA_QEMU").is_none() {
            eprintln!("skipped: PARANOIA_QEMU is not set");
            return;
        }
        let n: usize = std::env::var("PARANOIA_QEMU_FUNCS").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
        let seed: u64 = std::env::var("PARANOIA_QEMU_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x7a3c_91d5_2b4e_6f08);
        let mut rng = Rng(seed);
        let funcs: Vec<Vec<u16>> = (0..n).map(|_| Gen { rng: &mut rng, r4: false }.function()).collect();
        // Inputs: edge values and random ones; r3 is the address of the scratch buffer.
        let edge = [0u32, 1, 2, 3, 7, 0x7f, 0x80, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0xffff_fffe, 0x1234_5678];
        let cases: Vec<[u32; 4]> = (0..10)
            .map(|k| {
                let pick = |rng: &mut Rng| if rng.chance(60) { edge[rng.below(edge.len())] } else { rng.next() as u32 };
                [if k == 0 { 0 } else { pick(&mut rng) }, if k == 1 { 1 } else { pick(&mut rng) }, pick(&mut rng), BUF]
            })
            .collect();
        let opts = RawOptions::for_arch("thumb", 0).unwrap();
        let (mut ok, mut wrong, mut skipped, mut void) = (0usize, 0usize, 0usize, 0usize);
        let mut reasons: HashMap<String, usize> = HashMap::new();
        let mut shown = 0;
        // One image holds at most ~200 functions (the driver calls each with every input set).
        for chunk in funcs.chunks(120) {
            let image = build_image(chunk, &cases);
            if let Ok(keep) = std::env::var("PARANOIA_QEMU_KEEP") {
                std::fs::write(keep, &image.bytes).unwrap();
            }
            let expect = run_qemu(&image.bytes, chunk.len() * cases.len()).expect("QEMU");
            let mut bin = crate::Binary::load_raw("qemu.bin", image.bytes.clone(), &opts).unwrap();
            bin.analyze();
            for (fi, &addr) in image.funcs.iter().enumerate() {
                let listing = chunk[fi].iter().map(|h| format!("{h:04x}")).collect::<Vec<_>>().join(" ");
                let Some(pc) = bin.pseudocode(addr as u64) else {
                    skipped += 1;
                    *reasons.entry("no pseudocode".into()).or_default() += 1;
                    continue;
                };
                let lines = c_text(&pc.lines);
                let prog = match compile(&lines) {
                    Ok(p) => p,
                    Err(e) => {
                        skipped += 1;
                        *reasons.entry(format!("cannot read the C: {}", e.split(':').next().unwrap_or(""))).or_default() += 1;
                        if shown < 3 {
                            shown += 1;
                            eprintln!(
                                "--- skipped ({e}): {listing}
{}",
                                lines.join(
                                    "
"
                                )
                            );
                        }
                        continue;
                    }
                };
                // The driver clears the buffer before every function and the cases run in order, so each function
                // gets fresh memory that persists across its cases, on both sides.
                let mut function_ok = true;
                let mut mem = Memory::default();
                let mut detail = String::new();
                for (ci, case) in image.cases.iter().enumerate() {
                    let want = expect[fi * image.cases.len() + ci];
                    let got = match run(&prog, &case[..], &mut mem) {
                        Ok(Some(v)) => Some(v),
                        Ok(None) if !prog.returns_value => {
                            // The pseudocode says the function returns nothing: r0 was not written last, so the return
                            // value is a guess and not comparable; its memory effects still replay.
                            void += 1;
                            continue;
                        }
                        Ok(None) => None,
                        Err(e) => {
                            detail = format!("case {ci} {case:x?}: {e}");
                            function_ok = false;
                            *reasons.entry(format!("C failed: {}", e.split(' ').take(3).collect::<Vec<_>>().join(" "))).or_default() += 1;
                            break;
                        }
                    };
                    if got != Some(want) {
                        detail = format!("case {ci} {case:x?}: machine {want:#x}, C {got:x?}");
                        function_ok = false;
                        *reasons.entry("different result".into()).or_default() += 1;
                        break;
                    }
                }
                if function_ok {
                    ok += 1;
                } else {
                    wrong += 1;
                    if shown < 6 {
                        shown += 1;
                        eprintln!(
                            "--- MISMATCH {detail}
    code: {listing}
{}",
                            lines.join(
                                "
"
                            )
                        );
                    }
                }
            }
        }
        eprintln!("Thumb vs QEMU: {n} functions, {} cases each: {ok} agree, {wrong} differ, {skipped} not comparable ({void} void case runs skipped); {reasons:?}", cases.len());
        assert_eq!(wrong, 0, "pseudocode and machine code disagree");
    }
}
