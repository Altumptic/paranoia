//! MIPS decoder: MIPS32 / MIPS64 (release 2) integer, FPU basics and common COP0,
//! big- or little-endian. Branches have a delay slot; the decoder reports the branch
//! itself and the caller decides where the block ends.

use crate::model::Flow;

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Reg(u8),
    FReg(u8),
    Imm(i64),
    /// `offset(base)`
    Mem(i64, u8),
    Addr(u64),
    Cop0(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Effect {
    None,
    /// `lui rt, hi`: rt holds `hi << 16`.
    SetAddr(u8, u64),
    /// `addiu rt, rs, imm` (and `daddiu`, `ori` for the low half).
    AddImm(u8, u8, i64),
    /// Load / store through `imm(rs)`; `rt` for loads (0 for stores).
    Mem(u8, u8, i64, u8),
    Write(u8),
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub mnemonic: String,
    pub ops: Vec<Op>,
    pub flow: Flow,
    pub target: Option<u64>,
    /// Branches and jumps execute the next instruction (delay slot) first.
    pub delay_slot: bool,
    pub effect: Effect,
}

pub const REGS: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5",
    "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
];

fn i(m: &str, ops: Vec<Op>) -> Insn {
    Insn { mnemonic: m.to_string(), ops, flow: Flow::None, target: None, delay_slot: false, effect: Effect::None }
}

/// Decodes the instruction word at `bytes`.
pub fn decode(bytes: &[u8], va: u64, big_endian: bool, bits64: bool) -> Option<Insn> {
    let b: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let w = if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) };
    decode_word(w, va, bits64)
}

pub fn decode_word(w: u32, va: u64, bits64: bool) -> Option<Insn> {
    use Op::*;
    let op = w >> 26;
    let rs = ((w >> 21) & 31) as u8;
    let rt = ((w >> 16) & 31) as u8;
    let rd = ((w >> 11) & 31) as u8;
    let sa = ((w >> 6) & 31) as i64;
    let funct = w & 63;
    let imm = (w & 0xffff) as u16 as i16 as i64;
    let uimm = (w & 0xffff) as i64;
    let branch_t = va.wrapping_add(4).wrapping_add((imm << 2) as u64);
    let branch = |m: &str, ops: Vec<Op>, flow: Flow| Insn {
        mnemonic: m.to_string(),
        ops,
        flow,
        target: Some(branch_t),
        delay_slot: true,
        effect: Effect::None,
    };
    let r3 = |m: &str| {
        let mut x = i(m, vec![Reg(rd), Reg(rs), Reg(rt)]);
        x.effect = Effect::Write(rd);
        x
    };
    let load = |m: &str, size: u8| {
        let mut x = i(m, vec![Reg(rt), Mem(imm, rs)]);
        x.effect = Effect::Mem(rt, rs, imm, size);
        x
    };
    let store = |m: &str, size: u8| {
        let mut x = i(m, vec![Reg(rt), Mem(imm, rs)]);
        x.effect = Effect::Mem(0, rs, imm, size);
        x
    };
    let insn = match op {
        0 => match funct {
            0 if w == 0 => i("nop", vec![]),
            0 if w == 0x40 => i("ssnop", vec![]),
            0 | 2 | 3 | 56 | 58 | 59 | 60 | 62 | 63 => {
                let m = match funct {
                    0 => "sll",
                    2 if rs == 1 => "rotr",
                    2 => "srl",
                    3 => "sra",
                    56 => "dsll",
                    58 => "dsrl",
                    59 => "dsra",
                    60 => "dsll32",
                    62 => "dsrl32",
                    _ => "dsra32",
                };
                let mut x = i(m, vec![Reg(rd), Reg(rt), Imm(sa)]);
                x.effect = Effect::Write(rd);
                x
            }
            4 | 6 | 7 | 20 | 22 | 23 => {
                let m = match funct {
                    4 => "sllv",
                    6 => "srlv",
                    7 => "srav",
                    20 => "dsllv",
                    22 => "dsrlv",
                    _ => "dsrav",
                };
                let mut x = i(m, vec![Reg(rd), Reg(rt), Reg(rs)]);
                x.effect = Effect::Write(rd);
                x
            }
            8 => {
                let mut x = i("jr", vec![Reg(rs)]);
                x.flow = if rs == 31 { Flow::Ret } else { Flow::Jump };
                x.delay_slot = true;
                x
            }
            9 => {
                let mut x = if rd == 31 { i("jalr", vec![Reg(rs)]) } else { i("jalr", vec![Reg(rd), Reg(rs)]) };
                x.flow = Flow::Call;
                x.delay_slot = true;
                x
            }
            10 => r3("movz"),
            11 => r3("movn"),
            12 => i("syscall", vec![]),
            13 => {
                let mut x = i("break", vec![]);
                x.flow = Flow::Interrupt;
                x
            }
            15 => i("sync", vec![]),
            16 | 18 => {
                let mut x = i(if funct == 16 { "mfhi" } else { "mflo" }, vec![Reg(rd)]);
                x.effect = Effect::Write(rd);
                x
            }
            17 => i("mthi", vec![Reg(rs)]),
            19 => i("mtlo", vec![Reg(rs)]),
            24..=31 => {
                let m = ["mult", "multu", "div", "divu", "dmult", "dmultu", "ddiv", "ddivu"][(funct - 24) as usize];
                i(m, vec![Reg(rs), Reg(rt)])
            }
            33 | 37 if rt == 0 => {
                let mut x = i("move", vec![Reg(rd), Reg(rs)]);
                x.effect = Effect::Write(rd);
                x
            }
            45 if rt == 0 && bits64 => {
                let mut x = i("move", vec![Reg(rd), Reg(rs)]);
                x.effect = Effect::Write(rd);
                x
            }
            35 if rs == 0 => {
                let mut x = i("negu", vec![Reg(rd), Reg(rt)]);
                x.effect = Effect::Write(rd);
                x
            }
            39 if rt == 0 => {
                let mut x = i("not", vec![Reg(rd), Reg(rs)]);
                x.effect = Effect::Write(rd);
                x
            }
            32..=47 => {
                let m = match funct {
                    32 => "add",
                    33 => "addu",
                    34 => "sub",
                    35 => "subu",
                    36 => "and",
                    37 => "or",
                    38 => "xor",
                    39 => "nor",
                    42 => "slt",
                    43 => "sltu",
                    44 => "dadd",
                    45 => "daddu",
                    46 => "dsub",
                    47 => "dsubu",
                    _ => return None,
                };
                r3(m)
            }
            48..=54 => {
                let m = ["tge", "tgeu", "tlt", "tltu", "teq", "", "tne"][(funct - 48) as usize];
                if m.is_empty() {
                    return None;
                }
                i(m, vec![Reg(rs), Reg(rt)])
            }
            _ => return None,
        },
        1 => match rt {
            0 => branch("bltz", vec![Reg(rs), Addr(branch_t)], Flow::CondJump),
            1 if rs == 0 => branch("b", vec![Addr(branch_t)], Flow::Jump),
            1 => branch("bgez", vec![Reg(rs), Addr(branch_t)], Flow::CondJump),
            2 => branch("bltzl", vec![Reg(rs), Addr(branch_t)], Flow::CondJump),
            3 => branch("bgezl", vec![Reg(rs), Addr(branch_t)], Flow::CondJump),
            16 => branch("bltzal", vec![Reg(rs), Addr(branch_t)], Flow::Call),
            17 if rs == 0 => branch("bal", vec![Addr(branch_t)], Flow::Call),
            17 => branch("bgezal", vec![Reg(rs), Addr(branch_t)], Flow::Call),
            _ => return None,
        },
        2 | 3 => {
            let t = (va.wrapping_add(4) & !0x0fff_ffff) | (((w & 0x03ff_ffff) as u64) << 2);
            Insn {
                mnemonic: if op == 2 { "j" } else { "jal" }.into(),
                ops: vec![Addr(t)],
                flow: if op == 2 { Flow::Jump } else { Flow::Call },
                target: Some(t),
                delay_slot: true,
                effect: Effect::None,
            }
        }
        4 if rs == 0 && rt == 0 => branch("b", vec![Addr(branch_t)], Flow::Jump),
        4 | 5 | 20 | 21 if rt == 0 => {
            let m = match op {
                4 => "beqz",
                5 => "bnez",
                20 => "beqzl",
                _ => "bnezl",
            };
            branch(m, vec![Reg(rs), Addr(branch_t)], Flow::CondJump)
        }
        4 | 5 | 20 | 21 => {
            let m = match op {
                4 => "beq",
                5 => "bne",
                20 => "beql",
                _ => "bnel",
            };
            branch(m, vec![Reg(rs), Reg(rt), Addr(branch_t)], Flow::CondJump)
        }
        6 | 7 | 22 | 23 => {
            let m = match op {
                6 => "blez",
                7 => "bgtz",
                22 => "blezl",
                _ => "bgtzl",
            };
            branch(m, vec![Reg(rs), Addr(branch_t)], Flow::CondJump)
        }
        8 | 9 | 24 | 25 => {
            let m = match op {
                8 => "addi",
                9 => "addiu",
                24 => "daddi",
                _ => "daddiu",
            };
            let mut x =
                if rs == 0 && (op == 9 || op == 25) { i("li", vec![Reg(rt), Imm(imm)]) } else { i(m, vec![Reg(rt), Reg(rs), Imm(imm)]) };
            x.effect = Effect::AddImm(rt, rs, imm);
            x
        }
        10 | 11 => {
            let mut x = i(if op == 10 { "slti" } else { "sltiu" }, vec![Reg(rt), Reg(rs), Imm(imm)]);
            x.effect = Effect::Write(rt);
            x
        }
        12..=14 => {
            let mut x = if op == 13 && rs == 0 {
                i("li", vec![Reg(rt), Imm(uimm)])
            } else {
                i(["andi", "ori", "xori"][(op - 12) as usize], vec![Reg(rt), Reg(rs), Imm(uimm)])
            };
            x.effect = if op == 13 { Effect::AddImm(rt, rs, uimm) } else { Effect::Write(rt) };
            x
        }
        15 => {
            let mut x = i("lui", vec![Reg(rt), Imm(uimm)]);
            x.effect = Effect::SetAddr(rt, ((uimm << 16) as i32 as i64) as u64);
            x
        }
        16 => match rs {
            0 => {
                let mut x = i("mfc0", vec![Reg(rt), Cop0(rd)]);
                x.effect = Effect::Write(rt);
                x
            }
            4 => i("mtc0", vec![Reg(rt), Cop0(rd)]),
            16 if funct == 24 => {
                let mut x = i("eret", vec![]);
                x.flow = Flow::Ret;
                x
            }
            16 if funct == 32 => i("wait", vec![]),
            _ => return None,
        },
        17 => decode_cop1(w, va)?,
        28 => match funct {
            0 => i("madd", vec![Reg(rs), Reg(rt)]),
            1 => i("maddu", vec![Reg(rs), Reg(rt)]),
            2 => r3("mul"),
            4 => i("msub", vec![Reg(rs), Reg(rt)]),
            32 | 33 => {
                let mut x = i(if funct == 32 { "clz" } else { "clo" }, vec![Reg(rd), Reg(rs)]);
                x.effect = Effect::Write(rd);
                x
            }
            _ => return None,
        },
        31 => match funct {
            0 => {
                let mut x = i("ext", vec![Reg(rt), Reg(rs), Imm(sa), Imm(rd as i64 + 1)]);
                x.effect = Effect::Write(rt);
                x
            }
            4 => {
                let mut x = i("ins", vec![Reg(rt), Reg(rs), Imm(sa), Imm(rd as i64 - sa + 1)]);
                x.effect = Effect::Write(rt);
                x
            }
            32 => {
                let m = match sa {
                    2 => "wsbh",
                    16 => "seb",
                    24 => "seh",
                    _ => return None,
                };
                let mut x = i(m, vec![Reg(rd), Reg(rt)]);
                x.effect = Effect::Write(rd);
                x
            }
            59 => {
                let mut x = i("rdhwr", vec![Reg(rt), Imm(rd as i64)]);
                x.effect = Effect::Write(rt);
                x
            }
            _ => return None,
        },
        32 => load("lb", 1),
        33 => load("lh", 2),
        34 => load("lwl", 4),
        35 => load("lw", 4),
        36 => load("lbu", 1),
        37 => load("lhu", 2),
        38 => load("lwr", 4),
        39 => load("lwu", 4),
        26 => load("ldl", 8),
        27 => load("ldr", 8),
        40 => store("sb", 1),
        41 => store("sh", 2),
        42 => store("swl", 4),
        43 => store("sw", 4),
        44 => store("sdl", 8),
        45 => store("sdr", 8),
        46 => store("swr", 4),
        47 => i("cache", vec![Imm(rt as i64), Mem(imm, rs)]),
        48 => load("ll", 4),
        51 => i("pref", vec![Imm(rt as i64), Mem(imm, rs)]),
        52 => load("lld", 8),
        55 => load("ld", 8),
        56 => {
            let mut x = store("sc", 4);
            x.effect = Effect::Write(rt);
            x
        }
        60 => {
            let mut x = store("scd", 8);
            x.effect = Effect::Write(rt);
            x
        }
        63 => store("sd", 8),
        49 | 53 | 57 | 61 => {
            let m = match op {
                49 => "lwc1",
                53 => "ldc1",
                57 => "swc1",
                _ => "sdc1",
            };
            let mut x = i(m, vec![FReg(rt), Mem(imm, rs)]);
            x.effect = Effect::Mem(0, rs, imm, if op == 49 || op == 57 { 4 } else { 8 });
            x
        }
        _ => return None,
    };
    Some(insn)
}

fn decode_cop1(w: u32, va: u64) -> Option<Insn> {
    use Op::*;
    let fmt = (w >> 21) & 31;
    let ft = ((w >> 16) & 31) as u8;
    let fs = ((w >> 11) & 31) as u8;
    let fd = ((w >> 6) & 31) as u8;
    let funct = w & 63;
    match fmt {
        0 | 1 | 2 | 4 | 5 | 6 => {
            let m = ["mfc1", "dmfc1", "cfc1", "", "mtc1", "dmtc1", "ctc1"][fmt as usize];
            let mut x = i(m, vec![Reg(ft), FReg(fs)]);
            if fmt < 4 {
                x.effect = Effect::Write(ft);
            }
            Some(x)
        }
        8 => {
            let imm = (w & 0xffff) as u16 as i16 as i64;
            let t = va.wrapping_add(4).wrapping_add((imm << 2) as u64);
            let m = ["bc1f", "bc1t", "bc1fl", "bc1tl"][((w >> 16) & 3) as usize];
            Some(Insn {
                mnemonic: m.into(),
                ops: vec![Addr(t)],
                flow: Flow::CondJump,
                target: Some(t),
                delay_slot: true,
                effect: Effect::None,
            })
        }
        16 | 17 | 20 | 21 => {
            let f = match fmt {
                16 => "s",
                17 => "d",
                20 => "w",
                _ => "l",
            };
            let (base, ops) = match funct {
                0 => ("add", vec![FReg(fd), FReg(fs), FReg(ft)]),
                1 => ("sub", vec![FReg(fd), FReg(fs), FReg(ft)]),
                2 => ("mul", vec![FReg(fd), FReg(fs), FReg(ft)]),
                3 => ("div", vec![FReg(fd), FReg(fs), FReg(ft)]),
                4 => ("sqrt", vec![FReg(fd), FReg(fs)]),
                5 => ("abs", vec![FReg(fd), FReg(fs)]),
                6 => ("mov", vec![FReg(fd), FReg(fs)]),
                7 => ("neg", vec![FReg(fd), FReg(fs)]),
                13 => ("trunc.w", vec![FReg(fd), FReg(fs)]),
                32 => ("cvt.s", vec![FReg(fd), FReg(fs)]),
                33 => ("cvt.d", vec![FReg(fd), FReg(fs)]),
                36 => ("cvt.w", vec![FReg(fd), FReg(fs)]),
                37 => ("cvt.l", vec![FReg(fd), FReg(fs)]),
                50 => ("c.eq", vec![FReg(fs), FReg(ft)]),
                60 => ("c.lt", vec![FReg(fs), FReg(ft)]),
                62 => ("c.le", vec![FReg(fs), FReg(ft)]),
                _ => return None,
            };
            Some(i(&format!("{base}.{f}"), ops))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        let d = |w: u32| decode_word(w, 0x400000, false).unwrap();
        assert_eq!(d(0x03e0_0008).mnemonic, "jr"); // jr ra
        assert_eq!(d(0x03e0_0008).flow, Flow::Ret);
        let jal = d(0x0c10_0010); // jal 0x400040
        assert_eq!((jal.flow, jal.target, jal.delay_slot), (Flow::Call, Some(0x400040), true));
        assert_eq!(d(0x27bd_ffe0).ops, vec![Op::Reg(29), Op::Reg(29), Op::Imm(-32)]); // addiu sp, sp, -32
        assert_eq!(d(0x3c1c_0042).effect, Effect::SetAddr(28, 0x0042_0000)); // lui gp, 0x42
        assert_eq!(d(0x8fbf_001c).mnemonic, "lw"); // lw ra, 28(sp)
        assert_eq!(d(0x1040_0003).mnemonic, "beqz"); // beqz v0, +16
        assert_eq!(d(0x1040_0003).target, Some(0x400010));
        assert_eq!(d(0x0000_0000).mnemonic, "nop");
        assert_eq!(d(0x0080_1025).mnemonic, "move"); // move v0, a0 (or)
        let be = decode(&0x03e0_0008u32.to_be_bytes(), 0, true, false).unwrap();
        assert_eq!(be.mnemonic, "jr");
    }

    fn noise(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn never_panics_on_noise() {
        for seed in 1..64u64 {
            let b = noise(seed, 4096);
            for off in (0..b.len() - 3).step_by(4) {
                let _ = decode(&b[off..], off as u64, seed % 2 == 0, seed % 3 == 0);
            }
        }
    }
}
