//! PowerPC decoder: 32- and 64-bit (Power ISA integer core, branches, loads / stores, common
//! floating point, SPR moves, rotates), big- or little-endian, with the simplified mnemonics
//! assemblers print (`li`, `lis`, `mr`, `nop`, `blr`, `beq`, `mflr`, `slwi`, …).
//!
//! Instructions are 4 bytes. `bl` is a call, `b` a jump, `bc` conditional, `blr` a return,
//! `bctr` / `bctrl` indirect jump / call; `bcl 20,31,$+4` (the PIC "get PC" idiom) is not a call.
//! Vector code is covered for what compilers emit in ordinary code (AltiVec compares and logic,
//! VSX loads / stores / moves, `xxlxor`); the rest of the vector ISA shows as `.word`.

use crate::model::Flow;

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Reg(u8),
    FReg(u8),
    Cr(u8),
    Imm(i64),
    /// `offset(base)`
    Mem(i64, u8),
    Addr(u64),
    Spr(u16),
    /// AltiVec vector register `vN`.
    Vr(u8),
    /// VSX register `vsN` (0–63).
    Vs(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Effect {
    None,
    /// `lis rD, hi`: rD holds `hi << 16`.
    SetAddr(u8, u64),
    /// `addi rD, rA, imm` / `ori rA, rS, imm` building an address.
    AddImm(u8, u8, i64),
    /// Load / store through `imm(rA)`: (destination for loads or 32 for none, base, offset, size).
    Mem(u8, u8, i64, u8),
    Write(u8),
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub mnemonic: String,
    pub ops: Vec<Op>,
    pub flow: Flow,
    pub target: Option<u64>,
    pub effect: Effect,
}

fn ins(m: impl Into<String>, ops: Vec<Op>) -> Insn {
    Insn { mnemonic: m.into(), ops, flow: Flow::None, target: None, effect: Effect::None }
}

/// The same instruction, marked as writing `rd`.
fn w(mut i: Insn, rd: u8) -> Insn {
    i.effect = Effect::Write(rd);
    i
}

pub fn spr_name(n: u16) -> Option<&'static str> {
    Some(match n {
        1 => "xer",
        8 => "lr",
        9 => "ctr",
        268 => "tbl",
        269 => "tbu",
        26 => "srr0",
        27 => "srr1",
        272 => "sprg0",
        273 => "sprg1",
        274 => "sprg2",
        275 => "sprg3",
        287 => "pvr",
        _ => return None,
    })
}

pub fn decode(bytes: &[u8], va: u64, big_endian: bool, bits64: bool) -> Option<Insn> {
    let b: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let word = if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) };
    decode_word(word, va, bits64)
}

fn sext(v: u32, bits: u32) -> i64 {
    let s = 32 - bits;
    (((v << s) as i32) >> s) as i64
}

fn cond_name(bo: u32, bi: u32) -> Option<&'static str> {
    let c = bi & 3;
    match bo & 0x1e {
        12 => Some(["lt", "gt", "eq", "so"][c as usize]),
        4 => Some(["ge", "le", "ne", "ns"][c as usize]),
        _ => None,
    }
}

pub fn decode_word(x: u32, va: u64, bits64: bool) -> Option<Insn> {
    let op = x >> 26;
    let rd = ((x >> 21) & 31) as u8;
    let ra = ((x >> 16) & 31) as u8;
    let rb = ((x >> 11) & 31) as u8;
    let simm = sext(x & 0xffff, 16);
    let uimm = (x & 0xffff) as i64;
    let rc = if x & 1 != 0 { "." } else { "" };
    let mask = |v: u64| if bits64 { v } else { v & 0xffff_ffff };
    use Op::{Cr, FReg, Imm, Mem, Reg};
    let mem = |m: &str, size: u8, load: bool, fp: bool| -> Insn {
        let mut i = ins(m, vec![if fp { FReg(rd) } else { Reg(rd) }, Mem(simm, ra)]);
        i.effect = Effect::Mem(if load && !fp { rd } else { 32 }, ra, simm, size);
        i
    };
    let i = match op {
        2 => ins("tdi", vec![Imm(rd as i64), Reg(ra), Imm(simm)]),
        3 => {
            if rd == 31 {
                let mut i = ins("twi", vec![Imm(31), Reg(ra), Imm(simm)]);
                i.flow = Flow::Interrupt;
                i
            } else {
                ins("twi", vec![Imm(rd as i64), Reg(ra), Imm(simm)])
            }
        }
        7 => w(ins("mulli", vec![Reg(rd), Reg(ra), Imm(simm)]), rd),
        8 => w(ins("subfic", vec![Reg(rd), Reg(ra), Imm(simm)]), rd),
        10 | 11 => {
            let crf = rd >> 2;
            let l = rd & 1 == 1;
            let m = match (op, l) {
                (10, false) => "cmplwi",
                (10, true) => "cmpldi",
                (11, false) => "cmpwi",
                _ => "cmpdi",
            };
            let mut ops = Vec::new();
            if crf != 0 {
                ops.push(Cr(crf));
            }
            ops.push(Reg(ra));
            ops.push(Imm(if op == 10 { uimm } else { simm }));
            ins(m, ops)
        }
        12 => w(ins("addic", vec![Reg(rd), Reg(ra), Imm(simm)]), rd),
        13 => w(ins("addic.", vec![Reg(rd), Reg(ra), Imm(simm)]), rd),
        14 => {
            if ra == 0 {
                let mut i = ins("li", vec![Reg(rd), Imm(simm)]);
                i.effect = Effect::SetAddr(rd, mask(simm as u64));
                i
            } else {
                let mut i = ins("addi", vec![Reg(rd), Reg(ra), Imm(simm)]);
                i.effect = Effect::AddImm(rd, ra, simm);
                i
            }
        }
        15 => {
            if ra == 0 {
                let mut i = ins("lis", vec![Reg(rd), Imm(simm)]);
                i.effect = Effect::SetAddr(rd, mask((simm << 16) as u64));
                i
            } else {
                w(ins("addis", vec![Reg(rd), Reg(ra), Imm(simm)]), rd)
            }
        }
        16 => {
            let bo = (x >> 21) & 31;
            let bi = (x >> 16) & 31;
            let disp = sext(x & 0xfffc, 16);
            let abs = x & 2 != 0;
            let lk = x & 1 != 0;
            let target = mask(if abs { disp as u64 } else { va.wrapping_add(disp as u64) });
            if lk && bo == 20 && target == va.wrapping_add(4) {
                // `bcl 20,31,$+4`: reads the PC into LR; execution simply continues.
                let mut i = ins("bcl", vec![Imm(20), Imm(bi as i64), Op::Addr(target)]);
                i.effect = Effect::Write(32);
                return Some(i);
            }
            let (m, ops) = if bo & 0x14 == 0x14 {
                ("b".to_string(), vec![Op::Addr(target)])
            } else if let Some(c) = cond_name(bo, bi) {
                let mut o = Vec::new();
                if bi >> 2 != 0 {
                    o.push(Cr((bi >> 2) as u8));
                }
                o.push(Op::Addr(target));
                (format!("b{c}"), o)
            } else if bo & 0x1e == 16 {
                ("bdnz".to_string(), vec![Op::Addr(target)])
            } else if bo & 0x1e == 18 {
                ("bdz".to_string(), vec![Op::Addr(target)])
            } else {
                ("bc".to_string(), vec![Imm(bo as i64), Imm(bi as i64), Op::Addr(target)])
            };
            let always = bo & 0x14 == 0x14;
            let mut i = ins(format!("{m}{}{}", if lk { "l" } else { "" }, if abs { "a" } else { "" }), ops);
            i.flow = match (lk, always) {
                (true, _) => Flow::Call,
                (false, true) => Flow::Jump,
                (false, false) => Flow::CondJump,
            };
            i.target = Some(target);
            i
        }
        17 => ins("sc", vec![]),
        18 => {
            let disp = sext(x & 0x03ff_fffc, 26);
            let abs = x & 2 != 0;
            let lk = x & 1 != 0;
            let target = mask(if abs { disp as u64 } else { va.wrapping_add(disp as u64) });
            let mut i = ins(format!("b{}{}", if lk { "l" } else { "" }, if abs { "a" } else { "" }), vec![Op::Addr(target)]);
            i.flow = if lk { Flow::Call } else { Flow::Jump };
            i.target = Some(target);
            i
        }
        19 => return decode_19(x),
        20 => w(
            ins(format!("rlwimi{rc}"), vec![Reg(ra), Reg(rd), Imm(rb as i64), Imm(((x >> 6) & 31) as i64), Imm(((x >> 1) & 31) as i64)]),
            ra,
        ),
        21 => {
            let (sh, mb, me) = (rb as u32, (x >> 6) & 31, (x >> 1) & 31);
            let i = if mb == 0 && me == 31 - sh {
                ins(format!("slwi{rc}"), vec![Reg(ra), Reg(rd), Imm(sh as i64)])
            } else if me == 31 && sh != 0 && sh + mb == 32 {
                ins(format!("srwi{rc}"), vec![Reg(ra), Reg(rd), Imm(mb as i64)])
            } else if sh == 0 && me == 31 {
                ins(format!("clrlwi{rc}"), vec![Reg(ra), Reg(rd), Imm(mb as i64)])
            } else if mb == 0 && me == 31 {
                ins(format!("rotlwi{rc}"), vec![Reg(ra), Reg(rd), Imm(sh as i64)])
            } else {
                ins(format!("rlwinm{rc}"), vec![Reg(ra), Reg(rd), Imm(sh as i64), Imm(mb as i64), Imm(me as i64)])
            };
            w(i, ra)
        }
        23 => w(ins(format!("rlwnm{rc}"), vec![Reg(ra), Reg(rd), Reg(rb), Imm(((x >> 6) & 31) as i64), Imm(((x >> 1) & 31) as i64)]), ra),
        24 => {
            if rd == 0 && ra == 0 && uimm == 0 {
                ins("nop", vec![])
            } else {
                let mut i = ins("ori", vec![Reg(ra), Reg(rd), Imm(uimm)]);
                i.effect = Effect::AddImm(ra, rd, uimm);
                i
            }
        }
        25 => w(ins("oris", vec![Reg(ra), Reg(rd), Imm(uimm)]), ra),
        26 => w(ins("xori", vec![Reg(ra), Reg(rd), Imm(uimm)]), ra),
        27 => w(ins("xoris", vec![Reg(ra), Reg(rd), Imm(uimm)]), ra),
        28 => w(ins("andi.", vec![Reg(ra), Reg(rd), Imm(uimm)]), ra),
        29 => w(ins("andis.", vec![Reg(ra), Reg(rd), Imm(uimm)]), ra),
        30 if (x >> 1) & 0xf == 8 || (x >> 1) & 0xf == 9 => {
            // MDS form: rotate by register.
            let mbe = (((x >> 6) & 31) | (((x >> 5) & 1) << 5)) as i64;
            let m = if (x >> 1) & 0xf == 8 { "rldcl" } else { "rldcr" };
            w(ins(format!("{m}{rc}"), vec![Reg(ra), Reg(rd), Reg(rb), Imm(mbe)]), ra)
        }
        30 => {
            // MD / MDS forms (64-bit rotates).
            let sh = (((x >> 11) & 31) | (((x >> 1) & 1) << 5)) as i64;
            let mbe = (((x >> 6) & 31) | (((x >> 5) & 1) << 5)) as i64;
            let m = match (x >> 2) & 7 {
                0 => "rldicl",
                1 => "rldicr",
                2 => "rldic",
                3 => "rldimi",
                _ => return None,
            };
            w(ins(format!("{m}{rc}"), vec![Reg(ra), Reg(rd), Imm(sh), Imm(mbe)]), ra)
        }
        31 => return decode_31(x),
        32 => mem("lwz", 4, true, false),
        33 => mem("lwzu", 4, true, false),
        34 => mem("lbz", 1, true, false),
        35 => mem("lbzu", 1, true, false),
        36 => mem("stw", 4, false, false),
        37 => mem("stwu", 4, false, false),
        38 => mem("stb", 1, false, false),
        39 => mem("stbu", 1, false, false),
        40 => mem("lhz", 2, true, false),
        41 => mem("lhzu", 2, true, false),
        42 => mem("lha", 2, true, false),
        43 => mem("lhau", 2, true, false),
        44 => mem("sth", 2, false, false),
        45 => mem("sthu", 2, false, false),
        46 => mem("lmw", 4, true, false),
        47 => mem("stmw", 4, false, false),
        48 => mem("lfs", 4, true, true),
        49 => mem("lfsu", 4, true, true),
        50 => mem("lfd", 8, true, true),
        51 => mem("lfdu", 8, true, true),
        52 => mem("stfs", 4, false, true),
        53 => mem("stfsu", 4, false, true),
        54 => mem("stfd", 8, false, true),
        55 => mem("stfdu", 8, false, true),
        58 | 62 => {
            let ds = sext(x & 0xfffc, 16);
            let (m, load) = match (op, x & 3) {
                (58, 0) => ("ld", true),
                (58, 1) => ("ldu", true),
                (58, 2) => ("lwa", true),
                (62, 0) => ("std", false),
                (62, 1) => ("stdu", false),
                _ => return None,
            };
            let mut i = ins(m, vec![Reg(rd), Mem(ds, ra)]);
            i.effect = Effect::Mem(if load { rd } else { 32 }, ra, ds, if m == "lwa" { 4 } else { 8 });
            i
        }
        59 | 63 => return decode_fp(x, op == 59),
        4 => return decode_altivec(x),
        60 => {
            // XX3 logical ops: VSX register = TX/AX/BX bit * 32 + field.
            let t = rd | (((x & 1) as u8) << 5);
            let a = ra | ((((x >> 2) & 1) as u8) << 5);
            let b = rb | ((((x >> 1) & 1) as u8) << 5);
            let m = match (x >> 3) & 0xff {
                130 => "xxland",
                146 if a == b => return Some(ins("xxlmr", vec![Op::Vs(t), Op::Vs(a)])),
                146 => "xxlor",
                154 => "xxlxor",
                162 => "xxlnor",
                _ => return None,
            };
            ins(m, vec![Op::Vs(t), Op::Vs(a), Op::Vs(b)])
        }
        _ => return None,
    };
    Some(i)
}

fn decode_19(x: u32) -> Option<Insn> {
    let xo = (x >> 1) & 0x3ff;
    let bo = (x >> 21) & 31;
    let bi = (x >> 16) & 31;
    let lk = x & 1 != 0;
    let (a, b, c) = (((x >> 21) & 31) as i64, ((x >> 16) & 31) as i64, ((x >> 11) & 31) as i64);
    let mut i = match xo {
        16 | 528 => {
            let reg = if xo == 16 { "lr" } else { "ctr" };
            let always = bo & 0x14 == 0x14;
            let name = if always {
                format!("b{reg}{}", if lk { "l" } else { "" })
            } else if let Some(cn) = cond_name(bo, bi) {
                format!("b{cn}{reg}{}", if lk { "l" } else { "" })
            } else {
                format!("bc{reg}{}", if lk { "l" } else { "" })
            };
            let mut ops = Vec::new();
            if !always && bi >> 2 != 0 {
                ops.push(Op::Cr((bi >> 2) as u8));
            }
            let mut i = ins(name, ops);
            i.flow = match (xo, lk, always) {
                (_, true, _) => Flow::Call,
                (16, false, true) => Flow::Ret,
                (528, false, true) => Flow::Jump,
                // A conditional return / indirect jump: the fall-through path continues.
                _ => Flow::None,
            };
            if lk {
                i.effect = Effect::Write(32);
            }
            i
        }
        0 => ins("mcrf", vec![Op::Cr((a >> 2) as u8), Op::Cr((b >> 2) as u8)]),
        18 => {
            let mut i = ins("rfid", vec![]);
            i.flow = Flow::Ret;
            i
        }
        50 => {
            let mut i = ins("rfi", vec![]);
            i.flow = Flow::Ret;
            i
        }
        150 => ins("isync", vec![]),
        193 if a == b && b == c => ins("crclr", vec![Op::Imm(a)]),
        289 if a == b && b == c => ins("crset", vec![Op::Imm(a)]),
        33 => ins("crnor", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        129 => ins("crandc", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        193 => ins("crxor", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        225 => ins("crnand", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        257 => ins("crand", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        289 => ins("creqv", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        417 => ins("crorc", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        449 => ins("cror", vec![Op::Imm(a), Op::Imm(b), Op::Imm(c)]),
        _ => return None,
    };
    if i.mnemonic.is_empty() {
        i.mnemonic = "?".into();
    }
    Some(i)
}

fn decode_31(x: u32) -> Option<Insn> {
    use Op::{Imm, Reg};
    let rd = ((x >> 21) & 31) as u8;
    let ra = ((x >> 16) & 31) as u8;
    let rb = ((x >> 11) & 31) as u8;
    let rc = if x & 1 != 0 { "." } else { "" };
    let xo10 = (x >> 1) & 0x3ff;
    let xo9 = (x >> 1) & 0x1ff;
    let oe = if x & 0x400 != 0 { "o" } else { "" };
    // XO-form arithmetic (rD, rA, rB), matched on the 9-bit opcode.
    let arith = match xo9 {
        266 => Some("add"),
        40 => Some("subf"),
        8 => Some("subfc"),
        10 => Some("addc"),
        136 => Some("subfe"),
        138 => Some("adde"),
        235 => Some("mullw"),
        233 => Some("mulld"),
        75 => Some("mulhw"),
        11 => Some("mulhwu"),
        73 => Some("mulhd"),
        9 => Some("mulhdu"),
        491 => Some("divw"),
        459 => Some("divwu"),
        489 => Some("divd"),
        457 => Some("divdu"),
        _ => None,
    };
    if let Some(m) = arith {
        return Some(w(ins(format!("{m}{oe}{rc}"), vec![Reg(rd), Reg(ra), Reg(rb)]), rd));
    }
    let unary = match xo9 {
        104 => Some("neg"),
        200 => Some("subfze"),
        202 => Some("addze"),
        232 => Some("subfme"),
        234 => Some("addme"),
        _ => None,
    };
    if let Some(m) = unary {
        return Some(w(ins(format!("{m}{oe}{rc}"), vec![Reg(rd), Reg(ra)]), rd));
    }
    // isel rD, rA, rB, BC (A-form, 5-bit opcode 15).
    if (x >> 1) & 31 == 15 {
        let bc = ((x >> 6) & 31) as i64;
        return Some(w(ins("isel", vec![Reg(rd), Reg(ra), Reg(rb), Imm(bc)]), rd));
    }
    // sradi (XS form, 9-bit opcode 413).
    if (x >> 2) & 0x1ff == 413 {
        let sh = (rb as i64) | ((((x >> 1) & 1) as i64) << 5);
        return Some(w(ins(format!("sradi{rc}"), vec![Reg(ra), Reg(rd), Imm(sh)]), ra));
    }
    let logical = |m: &str| w(ins(format!("{m}{rc}"), vec![Reg(ra), Reg(rd), Reg(rb)]), ra);
    let indexed = |m: &str, size: u8, load: bool| {
        let mut i = ins(m, vec![Reg(rd), Reg(ra), Reg(rb)]);
        i.effect = if load { Effect::Write(rd) } else { Effect::None };
        let _ = size;
        i
    };
    let i = match xo10 {
        0 | 32 => {
            let crf = rd >> 2;
            let l = rd & 1 == 1;
            let m = match (xo10, l) {
                (0, false) => "cmpw",
                (0, true) => "cmpd",
                (_, false) => "cmplw",
                _ => "cmpld",
            };
            let mut ops = Vec::new();
            if crf != 0 {
                ops.push(Op::Cr(crf));
            }
            ops.push(Reg(ra));
            ops.push(Reg(rb));
            ins(m, ops)
        }
        4 => {
            let mut i =
                if rd == 31 && ra == 0 && rb == 0 { ins("trap", vec![]) } else { ins("tw", vec![Imm(rd as i64), Reg(ra), Reg(rb)]) };
            if rd == 31 {
                i.flow = Flow::Interrupt;
            }
            i
        }
        68 => ins("td", vec![Imm(rd as i64), Reg(ra), Reg(rb)]),
        28 => logical("and"),
        60 => logical("andc"),
        444 if rd == rb => w(ins(format!("mr{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        444 => logical("or"),
        124 if rd == rb => w(ins(format!("not{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        124 => logical("nor"),
        316 => logical("xor"),
        284 => logical("eqv"),
        476 => logical("nand"),
        412 => logical("orc"),
        24 => logical("slw"),
        536 => logical("srw"),
        792 => logical("sraw"),
        27 => logical("sld"),
        539 => logical("srd"),
        794 => logical("srad"),
        824 => w(ins(format!("srawi{rc}"), vec![Reg(ra), Reg(rd), Imm(rb as i64)]), ra),
        26 => w(ins(format!("cntlzw{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        58 => w(ins(format!("cntlzd{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        954 => w(ins(format!("extsb{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        922 => w(ins(format!("extsh{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        986 => w(ins(format!("extsw{rc}"), vec![Reg(ra), Reg(rd)]), ra),
        339 | 467 => {
            let spr = (((x >> 16) & 31) | (((x >> 11) & 31) << 5)) as u16;
            let from = xo10 == 339;
            match (from, spr_name(spr)) {
                (true, Some(n @ ("lr" | "ctr" | "xer"))) => w(ins(format!("mf{n}"), vec![Reg(rd)]), rd),
                (false, Some(n @ ("lr" | "ctr" | "xer"))) => ins(format!("mt{n}"), vec![Reg(rd)]),
                (true, _) => w(ins("mfspr", vec![Reg(rd), Op::Spr(spr)]), rd),
                (false, _) => ins("mtspr", vec![Op::Spr(spr), Reg(rd)]),
            }
        }
        371 => w(ins("mftb", vec![Reg(rd)]), rd),
        19 => w(ins("mfcr", vec![Reg(rd)]), rd),
        144 => ins("mtcrf", vec![Imm(((x >> 12) & 0xff) as i64), Reg(rd)]),
        83 => w(ins("mfmsr", vec![Reg(rd)]), rd),
        146 => ins("mtmsr", vec![Reg(rd)]),
        178 => ins("mtmsrd", vec![Reg(rd)]),
        598 => ins(if rd & 3 == 1 { "lwsync" } else { "sync" }, vec![]),
        854 => ins("eieio", vec![]),
        86 => ins("dcbf", vec![Reg(ra), Reg(rb)]),
        54 => ins("dcbst", vec![Reg(ra), Reg(rb)]),
        278 => ins("dcbt", vec![Reg(ra), Reg(rb)]),
        1014 => ins("dcbz", vec![Reg(ra), Reg(rb)]),
        982 => ins("icbi", vec![Reg(ra), Reg(rb)]),
        23 => indexed("lwzx", 4, true),
        55 => indexed("lwzux", 4, true),
        87 => indexed("lbzx", 1, true),
        279 => indexed("lhzx", 2, true),
        343 => indexed("lhax", 2, true),
        21 => indexed("ldx", 8, true),
        53 => indexed("ldux", 8, true),
        341 => indexed("lwax", 4, true),
        20 => indexed("lwarx", 4, true),
        84 => indexed("ldarx", 8, true),
        534 => indexed("lwbrx", 4, true),
        151 => indexed("stwx", 4, false),
        183 => indexed("stwux", 4, false),
        215 => indexed("stbx", 1, false),
        407 => indexed("sthx", 2, false),
        149 => indexed("stdx", 8, false),
        181 => indexed("stdux", 8, false),
        150 => indexed("stwcx.", 4, false),
        214 => indexed("stdcx.", 8, false),
        662 => indexed("stwbrx", 4, false),
        52 => indexed("lbarx", 1, true),
        116 => indexed("lharx", 2, true),
        694 => indexed("stbcx.", 1, false),
        726 => indexed("sthcx.", 2, false),
        532 => indexed("ldbrx", 8, true),
        660 => indexed("stdbrx", 8, false),
        246 => ins("dcbtst", vec![Reg(ra), Reg(rb)]),
        122 => w(ins("popcntb", vec![Reg(ra), Reg(rd)]), ra),
        378 => w(ins("popcntw", vec![Reg(ra), Reg(rd)]), ra),
        506 => w(ins("popcntd", vec![Reg(ra), Reg(rd)]), ra),
        508 => logical("cmpb"),
        103 => ins("lvx", vec![Op::Vr(rd), Reg(ra), Reg(rb)]),
        231 => ins("stvx", vec![Op::Vr(rd), Reg(ra), Reg(rb)]),
        // VSX loads / stores / moves; the register number's top bit is the instruction's last bit.
        844 => ins("lxvd2x", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra), Reg(rb)]),
        972 => ins("stxvd2x", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra), Reg(rb)]),
        780 => ins("lxvw4x", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra), Reg(rb)]),
        908 => ins("stxvw4x", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra), Reg(rb)]),
        588 => ins("lxsdx", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra), Reg(rb)]),
        716 => ins("stxsdx", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra), Reg(rb)]),
        51 => w(ins("mfvsrd", vec![Reg(ra), Op::Vs(rd | (((x & 1) as u8) << 5))]), ra),
        115 => w(ins("mfvsrwz", vec![Reg(ra), Op::Vs(rd | (((x & 1) as u8) << 5))]), ra),
        179 => ins("mtvsrd", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra)]),
        243 => ins("mtvsrwz", vec![Op::Vs(rd | (((x & 1) as u8) << 5)), Reg(ra)]),
        535 => ins("lfsx", vec![Op::FReg(rd), Reg(ra), Reg(rb)]),
        599 => ins("lfdx", vec![Op::FReg(rd), Reg(ra), Reg(rb)]),
        663 => ins("stfsx", vec![Op::FReg(rd), Reg(ra), Reg(rb)]),
        727 => ins("stfdx", vec![Op::FReg(rd), Reg(ra), Reg(rb)]),
        _ => return None,
    };
    Some(i)
}

/// AltiVec: the compares, logic and permutes ordinary compiled code uses.
fn decode_altivec(x: u32) -> Option<Insn> {
    let (d, a, b, c) = (((x >> 21) & 31) as u8, ((x >> 16) & 31) as u8, ((x >> 11) & 31) as u8, ((x >> 6) & 31) as u8);
    use Op::Vr;
    // VA form (6-bit opcode).
    match x & 0x3f {
        43 => return Some(ins("vperm", vec![Vr(d), Vr(a), Vr(b), Vr(c)])),
        44 => return Some(ins("vsldoi", vec![Vr(d), Vr(a), Vr(b), Op::Imm(((x >> 6) & 15) as i64)])),
        42 => return Some(ins("vsel", vec![Vr(d), Vr(a), Vr(b), Vr(c)])),
        _ => {}
    }
    // VC form compares (10-bit opcode, record bit 0x400).
    let rc = if x & 0x400 != 0 { "." } else { "" };
    let cmp = match x & 0x3ff {
        6 => Some("vcmpequb"),
        70 => Some("vcmpequh"),
        134 => Some("vcmpequw"),
        199 => Some("vcmpequd"),
        7 => Some("vcmpneb"),
        _ => None,
    };
    if let Some(m) = cmp {
        return Some(ins(format!("{m}{rc}"), vec![Vr(d), Vr(a), Vr(b)]));
    }
    // VX form (11-bit opcode).
    let m = match x & 0x7ff {
        1028 => "vand",
        1092 => "vandc",
        1156 if a == b => return Some(ins("vmr", vec![Vr(d), Vr(a)])),
        1156 => "vor",
        1220 => "vxor",
        1284 => "vnor",
        0 => "vaddubm",
        64 => "vadduhm",
        128 => "vaddudm",
        1024 => "vsububm",
        1088 => "vsubuhm",
        1152 => "vsubuwm",
        524 => return Some(ins("vspltb", vec![Vr(d), Vr(b), Op::Imm(a as i64 & 15)])),
        588 => return Some(ins("vsplth", vec![Vr(d), Vr(b), Op::Imm(a as i64 & 7)])),
        652 => return Some(ins("vspltw", vec![Vr(d), Vr(b), Op::Imm(a as i64 & 3)])),
        780 => return Some(ins("vspltisb", vec![Vr(d), Op::Imm(((a as i64) << 59) >> 59)])),
        _ => return None,
    };
    Some(ins(m, vec![Vr(d), Vr(a), Vr(b)]))
}

fn decode_fp(x: u32, single: bool) -> Option<Insn> {
    use Op::FReg;
    let d = ((x >> 21) & 31) as u8;
    let a = ((x >> 16) & 31) as u8;
    let b = ((x >> 11) & 31) as u8;
    let c = ((x >> 6) & 31) as u8;
    let rc = if x & 1 != 0 { "." } else { "" };
    let s = if single { "s" } else { "" };
    // A-form (5-bit opcode).
    let a_form = match (x >> 1) & 31 {
        18 => Some(("fdiv", vec![FReg(d), FReg(a), FReg(b)])),
        20 => Some(("fsub", vec![FReg(d), FReg(a), FReg(b)])),
        21 => Some(("fadd", vec![FReg(d), FReg(a), FReg(b)])),
        22 => Some(("fsqrt", vec![FReg(d), FReg(b)])),
        25 => Some(("fmul", vec![FReg(d), FReg(a), FReg(c)])),
        28 => Some(("fmsub", vec![FReg(d), FReg(a), FReg(c), FReg(b)])),
        29 => Some(("fmadd", vec![FReg(d), FReg(a), FReg(c), FReg(b)])),
        30 => Some(("fnmsub", vec![FReg(d), FReg(a), FReg(c), FReg(b)])),
        31 => Some(("fnmadd", vec![FReg(d), FReg(a), FReg(c), FReg(b)])),
        23 if !single => Some(("fsel", vec![FReg(d), FReg(a), FReg(c), FReg(b)])),
        _ => None,
    };
    if let Some((m, ops)) = a_form {
        return Some(ins(format!("{m}{s}{rc}"), ops));
    }
    if single {
        return None;
    }
    let crf = d >> 2;
    let i = match (x >> 1) & 0x3ff {
        0 => ins("fcmpu", vec![Op::Cr(crf), FReg(a), FReg(b)]),
        32 => ins("fcmpo", vec![Op::Cr(crf), FReg(a), FReg(b)]),
        72 => ins(format!("fmr{rc}"), vec![FReg(d), FReg(b)]),
        40 => ins(format!("fneg{rc}"), vec![FReg(d), FReg(b)]),
        264 => ins(format!("fabs{rc}"), vec![FReg(d), FReg(b)]),
        12 => ins(format!("frsp{rc}"), vec![FReg(d), FReg(b)]),
        14 => ins(format!("fctiw{rc}"), vec![FReg(d), FReg(b)]),
        15 => ins(format!("fctiwz{rc}"), vec![FReg(d), FReg(b)]),
        814 => ins(format!("fctid{rc}"), vec![FReg(d), FReg(b)]),
        815 => ins(format!("fctidz{rc}"), vec![FReg(d), FReg(b)]),
        846 => ins(format!("fcfid{rc}"), vec![FReg(d), FReg(b)]),
        583 => ins("mffs", vec![FReg(d)]),
        711 => ins("mtfsf", vec![Op::Imm(((x >> 17) & 0xff) as i64), FReg(b)]),
        _ => return None,
    };
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(word: u32, va: u64) -> String {
        let i = decode_word(word, va, false).unwrap_or_else(|| panic!("{word:#010x} did not decode"));
        let ops: Vec<String> = i
            .ops
            .iter()
            .map(|o| match o {
                Op::Reg(r) => format!("r{r}"),
                Op::FReg(r) => format!("f{r}"),
                Op::Cr(c) => format!("cr{c}"),
                Op::Imm(v) => v.to_string(),
                Op::Mem(off, b) => format!("{off}(r{b})"),
                Op::Addr(a) => format!("{a:#x}"),
                Op::Spr(s) => format!("spr{s}"),
                Op::Vr(v) => format!("v{v}"),
                Op::Vs(v) => format!("vs{v}"),
            })
            .collect();
        format!("{} {}", i.mnemonic, ops.join(",")).trim_end().to_string()
    }

    #[test]
    fn common_function_prologue_and_epilogue() {
        // Standard 32-bit SysV prologue / epilogue as emitted by GCC.
        assert_eq!(text(0x9421_fff0, 0), "stwu r1,-16(r1)");
        assert_eq!(text(0x7c08_02a6, 0), "mflr r0");
        assert_eq!(text(0x9001_0014, 0), "stw r0,20(r1)");
        assert_eq!(text(0x3860_0000, 0), "li r3,0");
        assert_eq!(text(0x3d20_1002, 0), "lis r9,4098");
        assert_eq!(text(0x3929_0010, 0), "addi r9,r9,16");
        assert_eq!(text(0x7c7f_1b78, 0), "mr r31,r3");
        assert_eq!(text(0x8001_0014, 0), "lwz r0,20(r1)");
        assert_eq!(text(0x7c08_03a6, 0), "mtlr r0");
        assert_eq!(text(0x3821_0010, 0), "addi r1,r1,16");
        assert_eq!(text(0x4e80_0020, 0), "blr");
        assert_eq!(text(0x6000_0000, 0), "nop");
        assert_eq!(text(0x7fe0_0008, 0), "trap"); // tw 31,0,0
        assert_eq!(decode_word(0x7fe0_0008, 0, false).unwrap().flow, Flow::Interrupt);
        assert_eq!(text(0x4400_0002, 0), "sc");
    }

    #[test]
    fn branches_and_flow() {
        let at = 0x1000_0000u64;
        let bl = decode_word(0x4800_0101, at, false).unwrap(); // bl +0x100
        assert_eq!((bl.mnemonic.as_str(), bl.flow, bl.target), ("bl", Flow::Call, Some(at + 0x100)));
        let b = decode_word(0x4bff_fff0, at, false).unwrap(); // b -0x10
        assert_eq!((b.mnemonic.as_str(), b.flow, b.target), ("b", Flow::Jump, Some(at - 0x10)));
        let beq = decode_word(0x4182_000c, at, false).unwrap(); // beq +0xc
        assert_eq!((beq.mnemonic.as_str(), beq.flow, beq.target), ("beq", Flow::CondJump, Some(at + 0xc)));
        assert_eq!(text(0x4082_fff8, 0x100), "bne 0xf8");
        assert_eq!(text(0x419e_0010, 0x100), "beq cr7,0x110");
        assert_eq!(text(0x4200_fff0, 0x100), "bdnz 0xf0");
        let blr = decode_word(0x4e80_0020, 0, false).unwrap();
        assert_eq!(blr.flow, Flow::Ret);
        let bctr = decode_word(0x4e80_0420, 0, false).unwrap();
        assert_eq!((bctr.mnemonic.as_str(), bctr.flow), ("bctr", Flow::Jump));
        let bctrl = decode_word(0x4e80_0421, 0, false).unwrap();
        assert_eq!((bctrl.mnemonic.as_str(), bctrl.flow), ("bctrl", Flow::Call));
        // A conditional return does not end the block.
        assert_eq!(decode_word(0x4d82_0020, 0, false).unwrap().mnemonic, "beqlr");
        assert_eq!(decode_word(0x4d82_0020, 0, false).unwrap().flow, Flow::None);
        // bcl 20,31,$+4: the PIC idiom is not a call.
        let pic = decode_word(0x429f_0005, 0x2000, false).unwrap();
        assert_eq!((pic.mnemonic.as_str(), pic.flow), ("bcl", Flow::None));
    }

    #[test]
    fn compares_logic_and_64_bit() {
        assert_eq!(text(0x2c03_0000, 0), "cmpwi r3,0");
        assert_eq!(text(0x2f89_0005, 0), "cmpwi cr7,r9,5");
        assert_eq!(text(0x2803_000a, 0), "cmplwi r3,10");
        assert_eq!(text(0x7c03_2000, 0), "cmpw r3,r4");
        assert_eq!(text(0x7c63_2214, 0), "add r3,r3,r4");
        assert_eq!(text(0x7c64_1850, 0), "subf r3,r4,r3");
        assert_eq!(text(0x7c63_21d6, 0), "mullw r3,r3,r4");
        assert_eq!(text(0x5463_103a, 0), "slwi r3,r3,2");
        assert_eq!(text(0x5463_f87e, 0), "srwi r3,r3,1");
        assert_eq!(text(0x5463_063e, 0), "clrlwi r3,r3,24");
        assert_eq!(text(0x7c63_0774, 0), "extsb r3,r3");
        assert_eq!(text(0xe8610010, 0), "ld r3,16(r1)");
        assert_eq!(text(0xf8210000 | 0xfff1, 0), "stdu r1,-16(r1)");
        assert_eq!(text(0x7c69_02a6, 0), "mfctr r3");
        assert_eq!(text(0x7c69_03a6, 0), "mtctr r3");
        assert_eq!(text(0xfc20_1090, 0), "fmr f1,f2");
        assert_eq!(text(0xec21_102a, 0), "fadds f1,f1,f2");
        // Words seen in Go's ppc64 runtime.
        assert_eq!(text(0x7c64_2a1e, 0), "isel r3,r4,r5,8");
        assert_eq!(text(0xf000_0cd6, 0).split(' ').next(), Some("xxlxor"));
        assert_eq!(text(0x7c00_1e99, 0), "lxvd2x vs32,r0,r3");
        assert_eq!(text(0x1000_0406 | (1 << 10), 0).split(' ').next(), Some("vcmpequb."));
    }

    #[test]
    fn byte_order_and_address_tracking_effects() {
        let be = decode(&[0x4e, 0x80, 0x00, 0x20], 0, true, false).unwrap();
        let le = decode(&[0x20, 0x00, 0x80, 0x4e], 0, false, true).unwrap();
        assert_eq!((be.mnemonic.as_str(), le.mnemonic.as_str()), ("blr", "blr"));
        assert!(decode(&[0x4e, 0x80], 0, true, false).is_none());
        assert_eq!(decode_word(0x3d20_1002, 0, false).unwrap().effect, Effect::SetAddr(9, 0x1002_0000));
        assert_eq!(decode_word(0x3929_0010, 0, false).unwrap().effect, Effect::AddImm(9, 9, 0x10));
        assert_eq!(decode_word(0x8069_0008, 0, false).unwrap().effect, Effect::Mem(3, 9, 8, 4));
        // lis of a negative half on a 32-bit target stays a 32-bit address.
        assert_eq!(decode_word(0x3d20_8000, 0, false).unwrap().effect, Effect::SetAddr(9, 0x8000_0000));
    }

    #[test]
    fn every_word_decodes_or_is_refused_without_panicking() {
        let mut seed = 0x1234_5678u32;
        for _ in 0..200_000 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            for bits64 in [false, true] {
                let _ = decode_word(seed, 0x1000, bits64);
            }
        }
    }
}
