//! AArch64 → SSA statements. The same IR as x86 (see the parent module), so the SSA passes and
//! the C generator work unchanged; only lifting and the AAPCS64 calling convention live here.
//!
//! Numbering (see `A64_NAMES`): `xN` is variable N except `x4` (31), and `sp` is variable 4, so
//! the return register is 0 and the stack pointer is `RSP` on every ISA. `xzr` / `wzr` read as 0.
//!
//! Conditions use the x86 condition names the C generator already understands (`eq` → `e`,
//! `hs` → `ae`, `lt` → `l`, …); `cbz`, `cbnz`, `tbz` and `tbnz` become a comparison plus a branch.
//! Instructions without a model (SIMD, exclusive access, conditional selects, …) keep their text
//! with the registers they read and write.

use std::collections::BTreeMap;

use yaxpeax_arm::armv8::a64::{Instruction, Opcode, Operand, ShiftStyle, SizeCode};

use super::{build_lifted, Expr, Isa, Kind, SsaFunction, Stmt, Var, RSP};
use crate::model::Edge;

/// Argument registers `x0`–`x7` in AAPCS64 order, as variables.
pub(crate) const ARGS: [Var; 8] = [0, 1, 2, 3, 31, 5, 6, 7];

/// Registers a call may change: `x0`–`x18` and the link register `x30` (not `x0`: the result).
const CLOBBERED: [u16; 19] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30];

/// The variable of general-purpose register `n` (0–30); 31 is the stack pointer here.
fn var(n: u16) -> Var {
    match n {
        4 => 31,
        31 => RSP,
        n => n as Var,
    }
}

fn width(s: SizeCode) -> u8 {
    match s {
        SizeCode::X => 64,
        SizeCode::W => 32,
    }
}

fn bin(op: &'static str, a: Expr, b: Expr) -> Expr {
    Expr::Bin(op, Box::new(a), Box::new(b))
}

/// `addr + delta`, folded into an existing `base ± k` so stack slots stay `sp_n ± d`
/// (the second register of `ldp` / `stp`).
fn offset(addr: &Expr, delta: i64) -> Expr {
    match addr {
        Expr::Bin(op @ ("+" | "-"), base, k) => match &**k {
            Expr::Const(k) => {
                let v = if *op == "+" { k + delta } else { delta - k };
                match v {
                    0 => (**base).clone(),
                    v if v < 0 => bin("-", (**base).clone(), Expr::Const(-v)),
                    v => bin("+", (**base).clone(), Expr::Const(v)),
                }
            }
            _ => bin("+", addr.clone(), Expr::Const(delta)),
        },
        Expr::Const(c) => Expr::Const(c.wrapping_add(delta)),
        _ => bin("+", addr.clone(), Expr::Const(delta)),
    }
}

/// A register operand as a value: `xzr` is 0, `Register` 31 is `xzr`, `RegisterOrSP` 31 is `sp`.
fn reg(op: &Operand) -> Option<Expr> {
    Some(match *op {
        Operand::Register(_, 31) => Expr::Const(0),
        Operand::Register(_, n) | Operand::RegisterOrSP(_, n) => Expr::Use(var(n), 0),
        _ => return None,
    })
}

/// A source operand: register, immediate or shifted / extended register.
fn src(op: &Operand) -> Option<Expr> {
    Some(match *op {
        Operand::Register(..) | Operand::RegisterOrSP(..) => reg(op)?,
        Operand::Immediate(i) => Expr::Const(i64::from(i)),
        // Logical immediates (`orr x3, xzr, #1`, `and w0, w0, #0xff`).
        Operand::Imm64(i) => Expr::Const(i as i64),
        Operand::Imm16(i) => Expr::Const(i64::from(i)),
        Operand::ImmShift(i, s) => Expr::Const(i64::from(i) << s),
        Operand::RegShift(style, amount, size, n) => {
            let base = reg(&Operand::Register(size, n))?;
            let by = Expr::Const(i64::from(amount));
            match style {
                ShiftStyle::LSL if amount == 0 => base,
                ShiftStyle::LSL => bin("<<", base, by),
                ShiftStyle::LSR => bin(">>", base, by),
                ShiftStyle::ASR => bin(">>s", base, by),
                // Extends: the value itself (scaled), which is what address arithmetic needs.
                ShiftStyle::ROR => return None,
                _ if amount == 0 => base,
                _ => bin("<<", base, by),
            }
        }
        _ => return None,
    })
}

/// The register an instruction writes in full: `(variable, width)`; `None` for `xzr`.
fn dst(op: &Operand) -> Option<(Var, u8)> {
    match *op {
        Operand::Register(_, 31) => None,
        Operand::Register(s, n) | Operand::RegisterOrSP(s, n) => Some((var(n), width(s))),
        _ => None,
    }
}

/// Bytes a load or store moves, from its opcode and register size.
fn access_size(op: Opcode, rt: &Operand) -> Option<u8> {
    let reg_bytes = match rt {
        Operand::Register(SizeCode::X, _) => 8,
        Operand::Register(SizeCode::W, _) => 4,
        _ => return None,
    };
    Some(match op {
        Opcode::LDRB | Opcode::STRB | Opcode::LDURB | Opcode::STURB | Opcode::LDRSB | Opcode::LDURSB => 1,
        Opcode::LDRH | Opcode::STRH | Opcode::LDURH | Opcode::STURH | Opcode::LDRSH | Opcode::LDURSH => 2,
        Opcode::LDRSW | Opcode::LDURSW | Opcode::LDPSW => 4,
        _ => reg_bytes,
    })
}

/// A memory operand: the address used, plus a base-register update before (`[x0, #8]!`) or after
/// (`[x0], #8`) the access.
struct Mem {
    addr: Expr,
    pre: Option<(Var, Expr)>,
    post: Option<(Var, Expr)>,
}

fn mem(op: &Operand, ip: u64) -> Option<Mem> {
    let base = |n: u16| Expr::Use(var(n), 0);
    let plus = |e: Expr, off: i64| match off {
        0 => e,
        o if o < 0 => bin("-", e, Expr::Const(-o)),
        o => bin("+", e, Expr::Const(o)),
    };
    Some(match *op {
        Operand::RegPreIndex(n, off, false) => Mem { addr: plus(base(n), off.into()), pre: None, post: None },
        Operand::RegPreIndex(n, off, true) => Mem { addr: base(n), pre: Some((var(n), plus(base(n), off.into()))), post: None },
        Operand::RegPostIndex(n, off) => Mem { addr: base(n), pre: None, post: Some((var(n), plus(base(n), off.into()))) },
        Operand::RegRegOffset(n, m, size, style, amount) => {
            let index = src(&Operand::RegShift(style, amount, size, m))?;
            Mem { addr: bin("+", base(n), index), pre: None, post: None }
        }
        Operand::PCOffset(o) => Mem { addr: Expr::Const(ip.wrapping_add(o as u64) as i64), pre: None, post: None },
        _ => return None,
    })
}

/// The x86 name of an AArch64 condition (after `cmp a, b`), or `None` for "always".
fn cond(c: u8) -> Option<&'static str> {
    Some(match c {
        0 => "e",
        1 => "ne",
        2 => "ae",
        3 => "b",
        4 => "s",
        5 => "ns",
        6 => "o",
        7 => "no",
        8 => "a",
        9 => "be",
        10 => "ge",
        11 => "l",
        12 => "g",
        13 => "le",
        _ => return None,
    })
}

/// The bit `tbz` / `tbnz` tests (yaxpeax gives it as `Imm16`).
fn bit_number(op: &Operand) -> Option<u32> {
    match *op {
        Operand::Imm16(b) => Some(u32::from(b)),
        Operand::Immediate(b) => Some(b),
        _ => None,
    }
}

fn target(i: &Instruction, ip: u64) -> Option<u64> {
    i.operands.iter().find_map(|o| match *o {
        Operand::PCOffset(off) => Some(ip.wrapping_add(off as u64)),
        _ => None,
    })
}

/// Decoded blocks of a function: start → (instructions with their addresses, edges).
pub(crate) type Blocks = BTreeMap<u64, (Vec<(u64, Instruction)>, Vec<Edge>)>;

/// One lifted statement: the kind and whether it sets the condition flags.
type Lifted = Vec<(Kind, bool)>;

fn assign(def: Var, width: u8, expr: Expr) -> Kind {
    Kind::Assign { def, ver: 0, expr, width }
}

fn call(target: String, extra: Option<Expr>) -> Kind {
    let mut args: Vec<Expr> = extra.into_iter().collect();
    args.extend(ARGS.iter().map(|v| Expr::Use(*v, 0)));
    Kind::Call { target, args, ret: Some((0, 0)), clobbers: CLOBBERED.iter().map(|n| (var(*n), 0)).collect() }
}

/// Lifts one instruction at `ip`.
fn lift(i: &Instruction, ip: u64) -> Lifted {
    use Opcode as O;
    let ops = &i.operands;
    let generic = || generic(i);
    match i.opcode {
        // Control flow.
        O::B => vec![(Kind::Branch { cond: None, uses: Vec::new(), target: target(i, ip) }, false)],
        O::Bcc(c) => vec![(Kind::Branch { cond: cond(c).map(str::to_string), uses: Vec::new(), target: target(i, ip) }, false)],
        O::CBZ | O::CBNZ => match reg(&ops[0]) {
            Some(r) => vec![
                (Kind::Flags { test: false, a: r, b: Expr::Const(0) }, true),
                (
                    Kind::Branch {
                        cond: Some(if i.opcode == O::CBZ { "e" } else { "ne" }.into()),
                        uses: Vec::new(),
                        target: target(i, ip),
                    },
                    false,
                ),
            ],
            None => generic(),
        },
        O::TBZ | O::TBNZ => match (reg(&ops[0]), bit_number(&ops[1])) {
            (Some(r), Some(bit)) if bit < 64 => vec![
                (Kind::Flags { test: true, a: r, b: Expr::Const(1i64.wrapping_shl(bit)) }, true),
                (
                    Kind::Branch {
                        cond: Some(if i.opcode == O::TBZ { "e" } else { "ne" }.into()),
                        uses: Vec::new(),
                        target: target(i, ip),
                    },
                    false,
                ),
            ],
            _ => generic(),
        },
        O::BL => vec![(call(target(i, ip).map_or_else(|| "?".into(), |t| format!("sub_{t:X}")), None), false)],
        O::BLR | O::BLRAA | O::BLRAAZ | O::BLRAB | O::BLRABZ => match reg(&ops[0]) {
            Some(r) => vec![(call(format!("[{}]", super::Expr::text_plain(&r, super::Names { isa: Isa::A64, bits: 64 })), Some(r)), false)],
            None => generic(),
        },
        O::BR | O::BRAA | O::BRAAZ | O::BRAB | O::BRABZ => {
            let mut uses: Vec<Expr> = reg(&ops[0]).into_iter().collect();
            // A jump through a register may be a tail call: it passes the arguments on.
            uses.extend(ARGS.iter().chain(std::iter::once(&0)).map(|v| Expr::Use(*v, 0)));
            vec![(Kind::Branch { cond: None, uses, target: None }, false)]
        }
        O::RET | O::RETAA | O::RETAB => vec![(Kind::Return { val: Some(Expr::Use(0, 0)) }, false)],
        // Hints that do nothing for data flow (pointer authentication, branch targets, nop).
        O::HINT | O::PACIASP | O::AUTIASP | O::PACIBSP | O::AUTIBSP => Vec::new(),

        // Addresses and moves.
        O::ADR | O::ADRP => match (dst(&ops[0]), &ops[1]) {
            (Some((d, w)), Operand::PCOffset(off)) => {
                let base = if i.opcode == O::ADRP { ip & !0xfff } else { ip };
                vec![(assign(d, w, Expr::Const(base.wrapping_add(*off as u64) as i64)), false)]
            }
            _ => generic(),
        },
        O::MOVZ | O::MOVN => match (dst(&ops[0]), src(&ops[1])) {
            (Some((d, w)), Some(Expr::Const(v))) => {
                let v = if i.opcode == O::MOVN { !v } else { v };
                vec![(assign(d, w, Expr::Const(if w == 32 { i64::from(v as u32) } else { v })), false)]
            }
            (None, _) => Vec::new(),
            _ => generic(),
        },
        O::MOVK => match (dst(&ops[0]), &ops[1]) {
            (Some((d, w)), Operand::ImmShift(v, s)) => {
                let mask = !(0xffffi64 << s);
                let keep = bin("&", Expr::Use(d, 0), Expr::Const(mask));
                vec![(assign(d, w, bin("|", keep, Expr::Const(i64::from(*v) << s))), false)]
            }
            _ => generic(),
        },

        // Arithmetic and logic: `op rd, rn, op2`.
        O::ADD | O::SUB | O::AND | O::ORR | O::EOR | O::BIC | O::ORN | O::EON | O::ADDS | O::SUBS | O::ANDS | O::BICS => {
            let (Some(a), Some(b)) = (src(&ops[1]), src(&ops[2])) else { return generic() };
            let (op, b) = match i.opcode {
                O::ADD | O::ADDS => ("+", b),
                O::SUB | O::SUBS => ("-", b),
                O::AND | O::ANDS => ("&", b),
                O::ORR => ("|", b),
                O::EOR => ("^", b),
                O::BIC | O::BICS => ("&", Expr::Un("~", Box::new(b))),
                O::ORN => ("|", Expr::Un("~", Box::new(b))),
                _ => ("^", Expr::Un("~", Box::new(b))),
            };
            let sets = matches!(i.opcode, O::ADDS | O::SUBS | O::ANDS | O::BICS);
            match (dst(&ops[0]), i.opcode) {
                // cmp / tst: only the flags.
                (None, O::SUBS) => vec![(Kind::Flags { test: false, a, b }, true)],
                (None, O::ANDS) => vec![(Kind::Flags { test: true, a, b }, true)],
                (None, _) if sets => generic(),
                (None, _) => Vec::new(),
                // subs rd, rn, op2: the comparison for the branch, then the result.
                (Some((d, w)), O::SUBS) => {
                    vec![(Kind::Flags { test: false, a: a.clone(), b: b.clone() }, true), (assign(d, w, bin(op, a, b)), false)]
                }
                // mov rd, rm (orr rd, xzr, rm) and mov rd, sp (add rd, sp, #0).
                (Some((d, w)), O::ORR) if a == Expr::Const(0) => vec![(assign(d, w, b), false)],
                (Some((d, w)), O::ADD) if b == Expr::Const(0) => vec![(assign(d, w, a), false)],
                (Some((d, w)), _) => vec![(assign(d, w, bin(op, a, b)), sets)],
            }
        }
        O::LSLV | O::LSRV | O::ASRV => match (dst(&ops[0]), src(&ops[1]), src(&ops[2])) {
            (Some((d, w)), Some(a), Some(b)) => {
                let op = match i.opcode {
                    O::LSLV => "<<",
                    O::LSRV => ">>",
                    _ => ">>s",
                };
                vec![(assign(d, w, bin(op, a, b)), false)]
            }
            _ => generic(),
        },
        // Shifts by a constant are bitfield moves: `lsl` / `lsr` are UBFM, `asr` is SBFM.
        O::UBFM | O::SBFM => match (dst(&ops[0]), src(&ops[1]), &ops[2], &ops[3]) {
            (Some((d, w)), Some(a), Operand::Immediate(immr), Operand::Immediate(imms)) => {
                let top = u32::from(w) - 1;
                let (immr, imms) = (*immr, *imms);
                let e = if imms == top {
                    let op = if i.opcode == O::UBFM { ">>" } else { ">>s" };
                    if immr == 0 {
                        a
                    } else {
                        bin(op, a, Expr::Const(immr.into()))
                    }
                } else if i.opcode == O::UBFM && imms + 1 == immr {
                    bin("<<", a, Expr::Const((top - imms).into()))
                } else {
                    return generic();
                };
                vec![(assign(d, w, e), false)]
            }
            _ => generic(),
        },
        O::MADD | O::MSUB => match (dst(&ops[0]), src(&ops[1]), src(&ops[2]), src(&ops[3])) {
            (Some((d, w)), Some(a), Some(b), Some(c)) => {
                let product = bin("*", a, b);
                let e = match (i.opcode, c) {
                    (O::MADD, Expr::Const(0)) => product,
                    (O::MADD, c) => bin("+", c, product),
                    (_, c) => bin("-", c, product),
                };
                vec![(assign(d, w, e), false)]
            }
            _ => generic(),
        },
        O::SDIV | O::UDIV => match (dst(&ops[0]), src(&ops[1]), src(&ops[2])) {
            (Some((d, w)), Some(a), Some(b)) => vec![(assign(d, w, bin("/", a, b)), false)],
            _ => generic(),
        },
        O::NEG => match (dst(&ops[0]), src(&ops[1])) {
            (Some((d, w)), Some(a)) => vec![(assign(d, w, Expr::Un("-", Box::new(a))), false)],
            _ => generic(),
        },

        // Loads and stores.
        O::LDR | O::LDRB | O::LDRH | O::LDRSB | O::LDRSH | O::LDRSW | O::LDUR | O::LDURB | O::LDURH | O::LDURSB | O::LDURSH | O::LDURSW => {
            match (dst(&ops[0]), access_size(i.opcode, &ops[0]), mem(&ops[1], ip)) {
                (Some((d, w)), Some(size), Some(m)) => {
                    with_writeback(m, |addr| vec![(assign(d, w, Expr::Load(size, Box::new(addr))), false)])
                }
                _ => generic(),
            }
        }
        O::STR | O::STRB | O::STRH | O::STUR | O::STURB | O::STURH => {
            match (reg(&ops[0]), access_size(i.opcode, &ops[0]), mem(&ops[1], ip)) {
                (Some(val), Some(size), Some(m)) => with_writeback(m, |addr| vec![(Kind::Store { size, addr, val }, false)]),
                _ => generic(),
            }
        }
        O::LDP | O::LDPSW | O::LDNP => match (dst(&ops[0]), dst(&ops[1]), access_size(i.opcode, &ops[0]), mem(&ops[2], ip)) {
            (Some((d1, w1)), Some((d2, w2)), Some(size), Some(m)) => with_writeback(m, |addr| {
                let second = offset(&addr, i64::from(size));
                vec![(assign(d1, w1, Expr::Load(size, Box::new(addr))), false), (assign(d2, w2, Expr::Load(size, Box::new(second))), false)]
            }),
            _ => generic(),
        },
        O::STP | O::STNP => match (reg(&ops[0]), reg(&ops[1]), access_size(i.opcode, &ops[0]), mem(&ops[2], ip)) {
            (Some(v1), Some(v2), Some(size), Some(m)) => with_writeback(m, |addr| {
                let second = offset(&addr, i64::from(size));
                vec![(Kind::Store { size, addr, val: v1 }, false), (Kind::Store { size, addr: second, val: v2 }, false)]
            }),
            _ => generic(),
        },
        _ => generic(),
    }
}

/// Wraps an access in its base-register updates; `access` gets the address to use.
fn with_writeback(m: Mem, access: impl FnOnce(Expr) -> Lifted) -> Lifted {
    let mut out = Vec::new();
    if let Some((v, e)) = m.pre {
        out.push((assign(v, 64, e), false));
    }
    out.extend(access(m.addr));
    if let Some((v, e)) = m.post {
        out.push((assign(v, 64, e), false));
    }
    out
}

/// An instruction without a model: its text, the registers it reads and the one it writes.
fn generic(i: &Instruction) -> Lifted {
    let name = format!("{:?}", i.opcode);
    // Stores, compares and prefetches read their first operand; everything else writes it.
    let writes_first = !(name.starts_with("ST") || name.starts_with("PRF") || name.starts_with("CC") || name.starts_with("CM"));
    let mut uses = Vec::new();
    let mut defs = Vec::new();
    for (k, op) in i.operands.iter().enumerate() {
        let regs: Vec<(Var, bool)> = match *op {
            Operand::Register(_, 31) => Vec::new(),
            Operand::Register(_, n) | Operand::RegisterOrSP(_, n) | Operand::RegShift(_, _, _, n) => vec![(var(n), k == 0 && writes_first)],
            Operand::RegPreIndex(n, _, _) | Operand::RegPostIndex(n, _) => vec![(var(n), false)],
            Operand::RegRegOffset(n, m, ..) => vec![(var(n), false), (var(m), false)],
            _ => Vec::new(),
        };
        for (v, def) in regs {
            if def {
                defs.push((v, 0));
            } else {
                uses.push(Expr::Use(v, 0));
            }
        }
    }
    let sets_flags = name.ends_with('S') && !name.starts_with("LD") && !name.starts_with("ST") || name.starts_with("CC");
    vec![(Kind::Other { text: i.to_string(), uses, defs }, sets_flags)]
}

/// Builds the SSA form of an AArch64 function from its decoded blocks.
pub(crate) fn build(entry: u64, blocks: &Blocks) -> SsaFunction {
    let mut lifted: BTreeMap<u64, (Vec<Stmt>, Vec<Edge>)> = BTreeMap::new();
    for (start, (insns, succs)) in blocks {
        let mut stmts = Vec::new();
        for (ip, i) in insns {
            for (kind, flags) in lift(i, *ip) {
                stmts.push(Stmt { address: *ip, kind, dead: false, flags, push: false });
            }
        }
        lifted.insert(*start, (stmts, succs.clone()));
    }
    build_lifted(entry, lifted, 64, Isa::A64, &ARGS)
}

/// Whether the function leaves a value in `x0`: a `ret` shortly after something writes `x0`.
pub(crate) fn returns_value(blocks: &Blocks) -> bool {
    blocks.values().any(|(v, _)| {
        v.last().is_some_and(|(_, l)| matches!(l.opcode, Opcode::RET | Opcode::RETAA | Opcode::RETAB))
            && v.iter().rev().skip(1).take(6).any(|(_, i)| {
                matches!(i.opcode, Opcode::BL | Opcode::BLR)
                    || matches!(i.operands[0], Operand::Register(_, 0)) && !i.opcode.to_string().starts_with("ST")
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EdgeKind;
    use yaxpeax_arch::{Decoder as _, U8Reader};
    use yaxpeax_arm::armv8::a64::InstDecoder;

    fn decode(words: &[u32], start: u64) -> Vec<(u64, Instruction)> {
        words
            .iter()
            .enumerate()
            .map(|(k, w)| {
                let bytes = w.to_le_bytes();
                let i = InstDecoder::default().decode(&mut U8Reader::new(&bytes)).unwrap();
                (start + 4 * k as u64, i)
            })
            .collect()
    }

    type Spec<'a> = (u64, &'a [u32], &'a [(u64, EdgeKind)]);

    fn blocks(list: &[Spec]) -> Blocks {
        list.iter().map(|(s, w, e)| (*s, (decode(w, *s), e.iter().map(|(to, kind)| Edge { to: *to, kind: *kind }).collect()))).collect()
    }

    fn c_text(f: &SsaFunction, returns: bool) -> String {
        let names = |_: u64| None;
        let o = super::super::COptions { name: "f", entry: 0x1000, returns, args: ARGS.to_vec(), names: &names };
        f.to_c(&o)
            .iter()
            .map(|l| "  ".repeat(l.indent as usize) + &l.tokens.iter().map(|t| t.t.as_str()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn arithmetic_and_compare() {
        // add x0, x0, x1 ; cmp x0, #0x10 ; b.lt +8 ; mov x0, #0x10 ; ret
        let b = blocks(&[
            (0x1000, &[0x8b01_0000, 0xf100_401f, 0x5400_004b], &[(0x100c, EdgeKind::False), (0x1010, EdgeKind::True)]),
            (0x100c, &[0xd280_0200], &[(0x1010, EdgeKind::Fall)]),
            (0x1010, &[0xd65f_03c0], &[]),
        ]);
        let f = build(0x1000, &b);
        let ssa: String = f.lines().iter().map(|l| l.1.clone()).collect::<Vec<_>>().join("\n");
        assert!(ssa.contains("x0_1 = x0 + x1") || ssa.contains("x0_1 = x0_0 + x1_0"), "{ssa}");
        assert!(ssa.contains("phi"), "the join at 0x1010 merges two values of x0:\n{ssa}");
        let c = c_text(&f, true);
        // `b.lt` skips the `mov`, so the `mov` runs when the sum is not below 0x10.
        assert!(c.contains("a1 + a2") && c.contains(">= 0x10) {"), "{c}");
        assert!(c.contains("return"), "{c}");
    }

    #[test]
    fn frame_calls_and_stack_slots() {
        // stp x29, x30, [sp, #-16]! ; mov x29, sp ; str x0, [sp, #8]... (as sub sp form) ;
        // bl +0x100 ; ldp x29, x30, [sp], #16 ; ret
        let b = blocks(&[(0x1000, &[0xa9bf_7bfd, 0x9100_03fd, 0x9400_0040, 0xa8c1_7bfd, 0xd65f_03c0], &[])]);
        let f = build(0x1000, &b);
        let ssa: String = f.lines().iter().map(|l| l.1.clone()).collect::<Vec<_>>().join("\n");
        assert!(ssa.contains("sp_1 = sp - 0x10") || ssa.contains("sp_1 = sp_0 - 0x10"), "{ssa}");
        assert!(ssa.contains("call sub_1108("), "{ssa}");
        let c = c_text(&f, true);
        assert!(c.contains("sub_1108("), "{c}");
        assert!(!c.contains("sp"), "stack bookkeeping disappears in C:\n{c}");
    }

    #[test]
    fn cbz_tbz_and_odd_instructions_do_not_panic() {
        // cbz x1, +8 ; tbnz w2, #3, +8 ; csel x0, x1, x2, eq (generic) ; ret
        let b = blocks(&[
            (0x2000, &[0xb400_0041], &[(0x2004, EdgeKind::False), (0x2008, EdgeKind::True)]),
            (0x2004, &[0x3718_0042], &[(0x2008, EdgeKind::False), (0x200c, EdgeKind::True)]),
            (0x2008, &[0x9a82_0020], &[(0x200c, EdgeKind::Fall)]),
            (0x200c, &[0xd65f_03c0], &[]),
        ]);
        let f = build(0x2000, &b);
        let c = c_text(&f, true);
        assert!(c.contains("== 0") || c.contains("!= 0"), "{c}");
        assert!(c.contains("& 8"), "tbnz tests bit 3:\n{c}");
        // Every 32-bit word decodes to something; none of it may panic the lifter.
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..20_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if let Ok(i) = InstDecoder::default().decode(&mut U8Reader::new(&seed.to_le_bytes())) {
                let _ = lift(&i, 0x4000);
            }
        }
    }
}
