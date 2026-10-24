//! RISC-V decoder: RV32 / RV64 with the I, M, A, F, D, C and Zicsr extensions.
//! Output uses the usual assembler aliases (`li`, `mv`, `ret`, `j`, `beqz`, `sext.w`, …)
//! and compressed instructions are shown in their expanded form, as objdump and IDA do.

use crate::model::Flow;

/// One decoded operand.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Reg(u8),
    FReg(u8),
    Imm(i64),
    /// `offset(base)`
    Mem(i64, u8),
    /// Absolute target address (branches and jumps).
    Addr(u64),
    Csr(u16),
}

/// Register effects the data-reference tracker needs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Effect {
    None,
    /// `auipc rd, imm` / `lui rd, imm`: rd holds a known address.
    SetAddr(u8, u64),
    /// `addi rd, rs1, imm`.
    AddImm(u8, u8, i64),
    /// Load / store through `imm(rs1)`; `rd` for loads (0 for stores).
    Mem(u8, u8, i64, u8),
    /// `jalr rd, imm(rs1)`.
    Jalr(u8, u8, i64),
    /// Any other write to `rd`.
    Write(u8),
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub len: u8,
    pub mnemonic: String,
    pub ops: Vec<Op>,
    pub flow: Flow,
    pub target: Option<u64>,
    pub effect: Effect,
}

pub const REGS: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5",
    "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
];
pub const FREGS: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2",
    "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

fn sext(v: u32, bits: u32) -> i64 {
    ((v << (32 - bits)) as i32 >> (32 - bits)) as i64
}

fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

fn insn(len: u8, m: &str, ops: Vec<Op>) -> Insn {
    Insn { len, mnemonic: m.to_string(), ops, flow: Flow::None, target: None, effect: Effect::None }
}

/// Decodes one instruction; `xlen` is 32 or 64.
pub fn decode(bytes: &[u8], va: u64, xlen: u32) -> Option<Insn> {
    if bytes.len() < 2 {
        return None;
    }
    let half = u16::from_le_bytes([bytes[0], bytes[1]]);
    if half & 3 != 3 {
        return decode_c(half, va, xlen);
    }
    if bytes.len() < 4 || half & 0x1c == 0x1c {
        return None; // 48-bit and longer encodings are not supported
    }
    decode32(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), va, xlen)
}

fn load_name(f3: u32) -> Option<&'static str> {
    Some(match f3 {
        0 => "lb",
        1 => "lh",
        2 => "lw",
        3 => "ld",
        4 => "lbu",
        5 => "lhu",
        6 => "lwu",
        _ => return None,
    })
}

fn decode32(w: u32, va: u64, xlen: u32) -> Option<Insn> {
    let opcode = w & 0x7f;
    let rd = bits(w, 11, 7) as u8;
    let rs1 = bits(w, 19, 15) as u8;
    let rs2 = bits(w, 24, 20) as u8;
    let f3 = bits(w, 14, 12);
    let f7 = bits(w, 31, 25);
    let imm_i = sext(w >> 20, 12);
    let imm_s = sext((bits(w, 31, 25) << 5) | bits(w, 11, 7), 12);
    let imm_b = sext((bits(w, 31, 31) << 12) | (bits(w, 7, 7) << 11) | (bits(w, 30, 25) << 5) | (bits(w, 11, 8) << 1), 13);
    let imm_u = (w & 0xffff_f000) as i32 as i64;
    let imm_j = sext((bits(w, 31, 31) << 20) | (bits(w, 19, 12) << 12) | (bits(w, 20, 20) << 11) | (bits(w, 30, 21) << 1), 21);
    use Op::*;
    let r = |m: &str| insn(4, m, vec![Reg(rd), Reg(rs1), Reg(rs2)]);
    let mut i = match opcode {
        0x37 => {
            let mut i = insn(4, "lui", vec![Reg(rd), Imm((imm_u >> 12) & 0xfffff)]);
            i.effect = Effect::SetAddr(rd, imm_u as u64);
            return Some(i);
        }
        0x17 => {
            let mut i = insn(4, "auipc", vec![Reg(rd), Imm((imm_u >> 12) & 0xfffff)]);
            i.effect = Effect::SetAddr(rd, va.wrapping_add(imm_u as u64));
            return Some(i);
        }
        0x6f => {
            let t = va.wrapping_add(imm_j as u64);
            let mut i = match rd {
                0 => insn(4, "j", vec![Addr(t)]),
                1 => insn(4, "jal", vec![Addr(t)]),
                _ => insn(4, "jal", vec![Reg(rd), Addr(t)]),
            };
            i.flow = if rd == 0 { Flow::Jump } else { Flow::Call };
            i.target = Some(t);
            return Some(i);
        }
        0x67 if f3 == 0 => {
            let mut i = if rd == 0 && rs1 == 1 && imm_i == 0 {
                let mut i = insn(4, "ret", vec![]);
                i.flow = Flow::Ret;
                i
            } else if rd == 0 {
                let mut i = if imm_i == 0 { insn(4, "jr", vec![Reg(rs1)]) } else { insn(4, "jr", vec![Mem(imm_i, rs1)]) };
                i.flow = Flow::Jump;
                i
            } else {
                let mut i =
                    if rd == 1 && imm_i == 0 { insn(4, "jalr", vec![Reg(rs1)]) } else { insn(4, "jalr", vec![Reg(rd), Mem(imm_i, rs1)]) };
                i.flow = Flow::Call;
                i
            };
            i.effect = Effect::Jalr(rd, rs1, imm_i);
            return Some(i);
        }
        0x63 => {
            let t = va.wrapping_add(imm_b as u64);
            let names = ["beq", "bne", "", "", "blt", "bge", "bltu", "bgeu"];
            let m = names[f3 as usize];
            if m.is_empty() {
                return None;
            }
            let mut i = if rs2 == 0 && f3 <= 1 {
                insn(4, if f3 == 0 { "beqz" } else { "bnez" }, vec![Reg(rs1), Addr(t)])
            } else {
                insn(4, m, vec![Reg(rs1), Reg(rs2), Addr(t)])
            };
            i.flow = Flow::CondJump;
            i.target = Some(t);
            return Some(i);
        }
        0x03 => {
            let m = load_name(f3)?;
            let mut i = insn(4, m, vec![Reg(rd), Mem(imm_i, rs1)]);
            i.effect = Effect::Mem(rd, rs1, imm_i, 1 << (f3 & 3));
            return Some(i);
        }
        0x23 => {
            let m = ["sb", "sh", "sw", "sd"].get(f3 as usize)?;
            let mut i = insn(4, m, vec![Reg(rs2), Mem(imm_s, rs1)]);
            i.effect = Effect::Mem(0, rs1, imm_s, 1 << f3);
            return Some(i);
        }
        0x07 | 0x27 => {
            let m = match (opcode, f3) {
                (0x07, 2) => "flw",
                (0x07, 3) => "fld",
                (0x27, 2) => "fsw",
                (0x27, 3) => "fsd",
                _ => return None,
            };
            let (reg, off) = if opcode == 0x07 { (rd, imm_i) } else { (rs2, imm_s) };
            let mut i = insn(4, m, vec![FReg(reg), Mem(off, rs1)]);
            i.effect = Effect::Mem(0, rs1, off, if f3 == 2 { 4 } else { 8 });
            return Some(i);
        }
        0x13 => {
            let sh = if xlen == 64 { bits(w, 25, 20) as i64 } else { rs2 as i64 };
            let mut i = match f3 {
                0 if rs1 == 0 && rd == 0 && imm_i == 0 => insn(4, "nop", vec![]),
                0 if rs1 == 0 => insn(4, "li", vec![Reg(rd), Imm(imm_i)]),
                0 if imm_i == 0 => insn(4, "mv", vec![Reg(rd), Reg(rs1)]),
                0 => insn(4, "addi", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
                2 => insn(4, "slti", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
                3 if imm_i == 1 => insn(4, "seqz", vec![Reg(rd), Reg(rs1)]),
                3 => insn(4, "sltiu", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
                4 if imm_i == -1 => insn(4, "not", vec![Reg(rd), Reg(rs1)]),
                4 => insn(4, "xori", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
                6 => insn(4, "ori", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
                7 => insn(4, "andi", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
                1 => insn(4, "slli", vec![Reg(rd), Reg(rs1), Imm(sh)]),
                5 => insn(4, if w & 0x4000_0000 != 0 { "srai" } else { "srli" }, vec![Reg(rd), Reg(rs1), Imm(sh)]),
                _ => return None,
            };
            i.effect = if f3 == 0 { Effect::AddImm(rd, rs1, imm_i) } else { Effect::Write(rd) };
            return Some(i);
        }
        0x1b if xlen == 64 => match f3 {
            0 if imm_i == 0 => insn(4, "sext.w", vec![Reg(rd), Reg(rs1)]),
            0 => insn(4, "addiw", vec![Reg(rd), Reg(rs1), Imm(imm_i)]),
            1 => insn(4, "slliw", vec![Reg(rd), Reg(rs1), Imm(rs2 as i64)]),
            5 => insn(4, if w & 0x4000_0000 != 0 { "sraiw" } else { "srliw" }, vec![Reg(rd), Reg(rs1), Imm(rs2 as i64)]),
            _ => return None,
        },
        0x33 => match (f7, f3) {
            (0, 0) => r("add"),
            (0x20, 0) if rs1 == 0 => insn(4, "neg", vec![Reg(rd), Reg(rs2)]),
            (0x20, 0) => r("sub"),
            (0, 1) => r("sll"),
            (0, 2) => r("slt"),
            (0, 3) if rs1 == 0 => insn(4, "snez", vec![Reg(rd), Reg(rs2)]),
            (0, 3) => r("sltu"),
            (0, 4) => r("xor"),
            (0, 5) => r("srl"),
            (0x20, 5) => r("sra"),
            (0, 6) => r("or"),
            (0, 7) => r("and"),
            (1, f) => r(["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"][f as usize]),
            _ => return None,
        },
        0x3b if xlen == 64 => match (f7, f3) {
            (0, 0) => r("addw"),
            (0x20, 0) if rs1 == 0 => insn(4, "negw", vec![Reg(rd), Reg(rs2)]),
            (0x20, 0) => r("subw"),
            (0, 1) => r("sllw"),
            (0, 5) => r("srlw"),
            (0x20, 5) => r("sraw"),
            (1, 0) => r("mulw"),
            (1, 4) => r("divw"),
            (1, 5) => r("divuw"),
            (1, 6) => r("remw"),
            (1, 7) => r("remuw"),
            _ => return None,
        },
        0x0f => match f3 {
            0 => insn(4, "fence", vec![]),
            1 => insn(4, "fence.i", vec![]),
            _ => return None,
        },
        0x73 => {
            let csr = (w >> 20) as u16;
            let mut i = match (f3, w >> 7) {
                (0, 0xe0) if w == 0x0000_0073 => insn(4, "ecall", vec![]),
                (0, _) if w == 0x0010_0073 => {
                    let mut i = insn(4, "ebreak", vec![]);
                    i.flow = Flow::Interrupt;
                    i
                }
                (0, _) if w == 0x3020_0073 || w == 0x1020_0073 => {
                    let mut i = insn(4, if w == 0x3020_0073 { "mret" } else { "sret" }, vec![]);
                    i.flow = Flow::Ret;
                    i
                }
                (0, _) if w == 0x1050_0073 => insn(4, "wfi", vec![]),
                (0, _) => insn(4, "ecall", vec![]),
                (1, _) => insn(4, "csrrw", vec![Reg(rd), Csr(csr), Reg(rs1)]),
                (2, _) if rs1 == 0 => insn(4, "csrr", vec![Reg(rd), Csr(csr)]),
                (2, _) => insn(4, "csrrs", vec![Reg(rd), Csr(csr), Reg(rs1)]),
                (3, _) => insn(4, "csrrc", vec![Reg(rd), Csr(csr), Reg(rs1)]),
                (5, _) => insn(4, "csrrwi", vec![Reg(rd), Csr(csr), Imm(rs1 as i64)]),
                (6, _) => insn(4, "csrrsi", vec![Reg(rd), Csr(csr), Imm(rs1 as i64)]),
                (7, _) => insn(4, "csrrci", vec![Reg(rd), Csr(csr), Imm(rs1 as i64)]),
                _ => return None,
            };
            if f3 != 0 {
                i.effect = Effect::Write(rd);
            }
            return Some(i);
        }
        0x2f => {
            let sz = match f3 {
                2 => "w",
                3 => "d",
                _ => return None,
            };
            let base = match bits(w, 31, 27) {
                0x02 => "lr",
                0x03 => "sc",
                0x01 => "amoswap",
                0x00 => "amoadd",
                0x04 => "amoxor",
                0x0c => "amoand",
                0x08 => "amoor",
                0x10 => "amomin",
                0x14 => "amomax",
                0x18 => "amominu",
                0x1c => "amomaxu",
                _ => return None,
            };
            let m = format!("{base}.{sz}");
            let ops = if base == "lr" { vec![Reg(rd), Mem(0, rs1)] } else { vec![Reg(rd), Reg(rs2), Mem(0, rs1)] };
            Insn { len: 4, mnemonic: m, ops, flow: Flow::None, target: None, effect: Effect::Write(rd) }
        }
        0x53 => return decode_fp(w, rd, rs1, rs2),
        0x43 | 0x47 | 0x4b | 0x4f => {
            let base = ["fmadd", "fmsub", "fnmsub", "fnmadd"][((opcode >> 2) & 3) as usize];
            let fmt = if bits(w, 26, 25) == 1 { "d" } else { "s" };
            let rs3 = bits(w, 31, 27) as u8;
            Insn {
                len: 4,
                mnemonic: format!("{base}.{fmt}"),
                ops: vec![FReg(rd), FReg(rs1), FReg(rs2), FReg(rs3)],
                flow: Flow::None,
                target: None,
                effect: Effect::None,
            }
        }
        _ => return None,
    };
    if i.effect == Effect::None && matches!(opcode, 0x33 | 0x3b | 0x1b) {
        i.effect = Effect::Write(rd);
    }
    Some(i)
}

fn decode_fp(w: u32, rd: u8, rs1: u8, rs2: u8) -> Option<Insn> {
    use Op::*;
    let f7 = w >> 25;
    let fmt = if f7 & 1 == 1 { "d" } else { "s" };
    let f3 = bits(w, 14, 12);
    let ff = |m: String, ops: Vec<Op>| Some(Insn { len: 4, mnemonic: m, ops, flow: Flow::None, target: None, effect: Effect::None });
    let toint =
        |m: String, ops: Vec<Op>| Some(Insn { len: 4, mnemonic: m, ops, flow: Flow::None, target: None, effect: Effect::Write(rd) });
    match f7 >> 2 {
        0x00 => ff(format!("fadd.{fmt}"), vec![FReg(rd), FReg(rs1), FReg(rs2)]),
        0x01 => ff(format!("fsub.{fmt}"), vec![FReg(rd), FReg(rs1), FReg(rs2)]),
        0x02 => ff(format!("fmul.{fmt}"), vec![FReg(rd), FReg(rs1), FReg(rs2)]),
        0x03 => ff(format!("fdiv.{fmt}"), vec![FReg(rd), FReg(rs1), FReg(rs2)]),
        0x0b => ff(format!("fsqrt.{fmt}"), vec![FReg(rd), FReg(rs1)]),
        0x04 => {
            let base = match (f3, rs1 == rs2) {
                (0, true) => return ff(format!("fmv.{fmt}"), vec![FReg(rd), FReg(rs1)]),
                (1, true) => return ff(format!("fneg.{fmt}"), vec![FReg(rd), FReg(rs1)]),
                (2, true) => return ff(format!("fabs.{fmt}"), vec![FReg(rd), FReg(rs1)]),
                (0, _) => "fsgnj",
                (1, _) => "fsgnjn",
                _ => "fsgnjx",
            };
            ff(format!("{base}.{fmt}"), vec![FReg(rd), FReg(rs1), FReg(rs2)])
        }
        0x05 => ff(format!("{}.{fmt}", if f3 == 0 { "fmin" } else { "fmax" }), vec![FReg(rd), FReg(rs1), FReg(rs2)]),
        0x08 => ff(if f7 & 1 == 1 { "fcvt.d.s".into() } else { "fcvt.s.d".into() }, vec![FReg(rd), FReg(rs1)]),
        0x14 => {
            let m = ["fle", "flt", "feq"].get(f3 as usize)?;
            toint(format!("{m}.{fmt}"), vec![Reg(rd), FReg(rs1), FReg(rs2)])
        }
        0x18 => {
            let to = ["w", "wu", "l", "lu"].get(rs2 as usize)?;
            toint(format!("fcvt.{to}.{fmt}"), vec![Reg(rd), FReg(rs1)])
        }
        0x1a => {
            let from = ["w", "wu", "l", "lu"].get(rs2 as usize)?;
            ff(format!("fcvt.{fmt}.{from}"), vec![FReg(rd), Reg(rs1)])
        }
        0x1c if f3 == 0 => toint(if fmt == "d" { "fmv.x.d".into() } else { "fmv.x.w".into() }, vec![Reg(rd), FReg(rs1)]),
        0x1c if f3 == 1 => toint(format!("fclass.{fmt}"), vec![Reg(rd), FReg(rs1)]),
        0x1e => ff(if fmt == "d" { "fmv.d.x".into() } else { "fmv.w.x".into() }, vec![FReg(rd), Reg(rs1)]),
        _ => None,
    }
}

/// Compressed (16-bit) instructions, shown expanded.
fn decode_c(h: u16, va: u64, xlen: u32) -> Option<Insn> {
    use Op::*;
    let w = h as u32;
    let op = w & 3;
    let f3 = bits(w, 15, 13);
    let rd = bits(w, 11, 7) as u8;
    let rs2 = bits(w, 6, 2) as u8;
    let rdp = (bits(w, 4, 2) + 8) as u8; // rd' / rs2'
    let rs1p = (bits(w, 9, 7) + 8) as u8; // rs1' / rd'
    let ci_imm = sext((bits(w, 12, 12) << 5) | bits(w, 6, 2), 6);
    let c = |m: &str, ops: Vec<Op>| insn(2, m, ops);
    let mut i = match (op, f3) {
        (0, 0) => {
            let nz = (bits(w, 10, 7) << 6) | (bits(w, 12, 11) << 4) | (bits(w, 5, 5) << 3) | (bits(w, 6, 6) << 2);
            if nz == 0 {
                return None;
            }
            let mut i = c("addi", vec![Reg(rdp), Reg(2), Imm(nz as i64)]);
            i.effect = Effect::Write(rdp);
            i
        }
        (0, 1) | (0, 3) | (0, 5) | (0, 7) if f3 & 1 == 1 && (f3 != 3 && f3 != 7 || xlen == 64) => {
            // c.fld / c.ld / c.fsd / c.sd (8-byte, offset uimm[7:6|5:3])
            let off = ((bits(w, 6, 5) << 6) | (bits(w, 12, 10) << 3)) as i64;
            let (m, fp, load) = match f3 {
                1 => ("fld", true, true),
                3 => ("ld", false, true),
                5 => ("fsd", true, false),
                _ => ("sd", false, false),
            };
            let r = if fp { FReg(rdp) } else { Reg(rdp) };
            let mut i = c(m, vec![r, Mem(off, rs1p)]);
            i.effect = Effect::Mem(if load && !fp { rdp } else { 0 }, rs1p, off, 8);
            i
        }
        (0, 2) | (0, 6) | (0, 3) | (0, 7) => {
            // c.lw / c.sw (and c.flw / c.fsw on RV32)
            let off = ((bits(w, 5, 5) << 6) | (bits(w, 12, 10) << 3) | (bits(w, 6, 6) << 2)) as i64;
            let (m, fp, load) = match f3 {
                2 => ("lw", false, true),
                6 => ("sw", false, false),
                3 => ("flw", true, true),
                _ => ("fsw", true, false),
            };
            let r = if fp { FReg(rdp) } else { Reg(rdp) };
            let mut i = c(m, vec![r, Mem(off, rs1p)]);
            i.effect = Effect::Mem(if load && !fp { rdp } else { 0 }, rs1p, off, 4);
            i
        }
        (1, 0) => {
            let mut i = if rd == 0 { c("nop", vec![]) } else { c("addi", vec![Reg(rd), Reg(rd), Imm(ci_imm)]) };
            i.effect = Effect::AddImm(rd, rd, ci_imm);
            i
        }
        (1, 1) if xlen == 64 => {
            let mut i = if ci_imm == 0 { c("sext.w", vec![Reg(rd), Reg(rd)]) } else { c("addiw", vec![Reg(rd), Reg(rd), Imm(ci_imm)]) };
            i.effect = Effect::Write(rd);
            i
        }
        (1, 1) | (1, 5) => {
            let off = sext(
                (bits(w, 12, 12) << 11)
                    | (bits(w, 8, 8) << 10)
                    | (bits(w, 10, 9) << 8)
                    | (bits(w, 6, 6) << 7)
                    | (bits(w, 7, 7) << 6)
                    | (bits(w, 2, 2) << 5)
                    | (bits(w, 11, 11) << 4)
                    | (bits(w, 5, 3) << 1),
                12,
            );
            let t = va.wrapping_add(off as u64);
            let mut i = if f3 == 5 { c("j", vec![Addr(t)]) } else { c("jal", vec![Addr(t)]) };
            i.flow = if f3 == 5 { Flow::Jump } else { Flow::Call };
            i.target = Some(t);
            i
        }
        (1, 2) => {
            let mut i = c("li", vec![Reg(rd), Imm(ci_imm)]);
            i.effect = Effect::AddImm(rd, 0, ci_imm);
            i
        }
        (1, 3) if rd == 2 => {
            let imm = sext(
                (bits(w, 12, 12) << 9) | (bits(w, 4, 3) << 7) | (bits(w, 5, 5) << 6) | (bits(w, 2, 2) << 5) | (bits(w, 6, 6) << 4),
                10,
            );
            c("addi", vec![Reg(2), Reg(2), Imm(imm)])
        }
        (1, 3) => {
            let v = ci_imm << 12;
            let mut i = c("lui", vec![Reg(rd), Imm((v >> 12) & 0xfffff)]);
            i.effect = Effect::SetAddr(rd, v as u64);
            i
        }
        (1, 4) => {
            let sh = ((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as i64;
            let mut i = match bits(w, 11, 10) {
                0 => c("srli", vec![Reg(rs1p), Reg(rs1p), Imm(sh)]),
                1 => c("srai", vec![Reg(rs1p), Reg(rs1p), Imm(sh)]),
                2 => c("andi", vec![Reg(rs1p), Reg(rs1p), Imm(ci_imm)]),
                _ => {
                    let m = match (bits(w, 12, 12), bits(w, 6, 5)) {
                        (0, 0) => "sub",
                        (0, 1) => "xor",
                        (0, 2) => "or",
                        (0, 3) => "and",
                        (1, 0) => "subw",
                        (1, 1) => "addw",
                        _ => return None,
                    };
                    c(m, vec![Reg(rs1p), Reg(rs1p), Reg(rdp)])
                }
            };
            i.effect = Effect::Write(rs1p);
            i
        }
        (1, 6) | (1, 7) => {
            let off = sext(
                (bits(w, 12, 12) << 8) | (bits(w, 6, 5) << 6) | (bits(w, 2, 2) << 5) | (bits(w, 11, 10) << 3) | (bits(w, 4, 3) << 1),
                9,
            );
            let t = va.wrapping_add(off as u64);
            let mut i = c(if f3 == 6 { "beqz" } else { "bnez" }, vec![Reg(rs1p), Addr(t)]);
            i.flow = Flow::CondJump;
            i.target = Some(t);
            i
        }
        (2, 0) => {
            let sh = ((bits(w, 12, 12) << 5) | bits(w, 6, 2)) as i64;
            let mut i = c("slli", vec![Reg(rd), Reg(rd), Imm(sh)]);
            i.effect = Effect::Write(rd);
            i
        }
        (2, 1) | (2, 3) if f3 == 1 || xlen == 64 => {
            let off = ((bits(w, 4, 2) << 6) | (bits(w, 12, 12) << 5) | (bits(w, 6, 5) << 3)) as i64;
            let mut i = if f3 == 1 { c("fld", vec![FReg(rd), Mem(off, 2)]) } else { c("ld", vec![Reg(rd), Mem(off, 2)]) };
            if f3 == 3 {
                i.effect = Effect::Write(rd);
            }
            i
        }
        (2, 2) | (2, 3) => {
            let off = ((bits(w, 3, 2) << 6) | (bits(w, 12, 12) << 5) | (bits(w, 6, 4) << 2)) as i64;
            let mut i = if f3 == 2 { c("lw", vec![Reg(rd), Mem(off, 2)]) } else { c("flw", vec![FReg(rd), Mem(off, 2)]) };
            if f3 == 2 {
                i.effect = Effect::Write(rd);
            }
            i
        }
        (2, 4) => {
            let bit12 = bits(w, 12, 12);
            match (bit12, rd, rs2) {
                (0, 1, 0) => {
                    let mut i = c("ret", vec![]);
                    i.flow = Flow::Ret;
                    i
                }
                (0, _, 0) if rd != 0 => {
                    let mut i = c("jr", vec![Reg(rd)]);
                    i.flow = Flow::Jump;
                    i.effect = Effect::Jalr(0, rd, 0);
                    i
                }
                (0, _, _) => {
                    let mut i = c("mv", vec![Reg(rd), Reg(rs2)]);
                    i.effect = Effect::Write(rd);
                    i
                }
                (1, 0, 0) => {
                    let mut i = c("ebreak", vec![]);
                    i.flow = Flow::Interrupt;
                    i
                }
                (1, _, 0) => {
                    let mut i = c("jalr", vec![Reg(rd)]);
                    i.flow = Flow::Call;
                    i.effect = Effect::Jalr(1, rd, 0);
                    i
                }
                _ => {
                    let mut i = c("add", vec![Reg(rd), Reg(rd), Reg(rs2)]);
                    i.effect = Effect::Write(rd);
                    i
                }
            }
        }
        (2, 5) | (2, 7) if f3 == 5 || xlen == 64 => {
            let off = ((bits(w, 9, 7) << 6) | (bits(w, 12, 10) << 3)) as i64;
            if f3 == 5 {
                c("fsd", vec![FReg(rs2), Mem(off, 2)])
            } else {
                c("sd", vec![Reg(rs2), Mem(off, 2)])
            }
        }
        (2, 6) | (2, 7) => {
            let off = ((bits(w, 8, 7) << 6) | (bits(w, 12, 9) << 2)) as i64;
            if f3 == 6 {
                c("sw", vec![Reg(rs2), Mem(off, 2)])
            } else {
                c("fsw", vec![FReg(rs2), Mem(off, 2)])
            }
        }
        _ => return None,
    };
    if i.mnemonic == "addi" && matches!(i.ops.as_slice(), [Reg(2), Reg(2), _]) {
        i.effect = Effect::Write(2);
    }
    Some(i)
}

/// CSR names for the common machine / user registers.
pub fn csr_name(c: u16) -> Option<&'static str> {
    Some(match c {
        0x001 => "fflags",
        0x002 => "frm",
        0x003 => "fcsr",
        0xc00 => "cycle",
        0xc01 => "time",
        0xc02 => "instret",
        0x100 => "sstatus",
        0x104 => "sie",
        0x105 => "stvec",
        0x140 => "sscratch",
        0x141 => "sepc",
        0x142 => "scause",
        0x143 => "stval",
        0x144 => "sip",
        0x180 => "satp",
        0x300 => "mstatus",
        0x301 => "misa",
        0x304 => "mie",
        0x305 => "mtvec",
        0x340 => "mscratch",
        0x341 => "mepc",
        0x342 => "mcause",
        0x343 => "mtval",
        0x344 => "mip",
        0xf14 => "mhartid",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(w: u32) -> Insn {
        decode(&w.to_le_bytes(), 0x1000, 64).unwrap()
    }

    #[test]
    fn base_instructions() {
        assert_eq!(d(0x0000_8067).mnemonic, "ret"); // jalr x0, 0(ra)
        assert_eq!(d(0x0000_8067).flow, Flow::Ret);
        let jal = d(0x0100_00ef); // jal ra, +16
        assert_eq!((jal.mnemonic.as_str(), jal.flow, jal.target), ("jal", Flow::Call, Some(0x1010)));
        assert_eq!(d(0x0050_0513).ops, vec![Op::Reg(10), Op::Imm(5)]); // li a0, 5
        assert_eq!(d(0x0050_0513).mnemonic, "li");
        assert_eq!(d(0x00b5_0533).mnemonic, "add"); // add a0, a0, a1
        assert_eq!(d(0x02b5_0533).mnemonic, "mul");
        assert_eq!(d(0xfe05_1ee3).flow, Flow::CondJump); // bnez a0, -4
        assert_eq!(d(0xfe05_1ee3).target, Some(0x1000 - 4));
        assert_eq!(d(0x0081_3503).mnemonic, "ld"); // ld a0, 8(sp)
        assert_eq!(d(0x0000_0517).effect, Effect::SetAddr(10, 0x1000)); // auipc a0, 0
    }

    #[test]
    fn compressed() {
        let c = |h: u16| decode(&h.to_le_bytes(), 0x2000, 64).unwrap();
        assert_eq!(c(0x8082).mnemonic, "ret");
        assert_eq!(c(0x4515).mnemonic, "li"); // c.li a0, 5
        assert_eq!(c(0x4515).ops, vec![Op::Reg(10), Op::Imm(5)]);
        assert_eq!(c(0x1141).ops, vec![Op::Reg(2), Op::Reg(2), Op::Imm(-16)]); // c.addi sp, -16
        assert_eq!(c(0xe406).mnemonic, "sd"); // c.sdsp ra, 8(sp)
        assert_eq!(c(0xe406).ops, vec![Op::Reg(1), Op::Mem(8, 2)]);
        assert_eq!(c(0x60a2).mnemonic, "ld"); // c.ldsp ra, 8(sp)
        assert_eq!(c(0x852e).mnemonic, "mv"); // c.mv a0, a1
        assert_eq!(c(0xa001).flow, Flow::Jump); // c.j 0
    }
}
