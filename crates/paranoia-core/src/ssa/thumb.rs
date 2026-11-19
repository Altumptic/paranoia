//! Thumb-2 lifting into the SSA IR (Cortex-M and other Thumb-only cores). The passes and the C generator
//! are shared with x86 and AArch64.
//!
//! `r0` is variable 0 (the result register, like `rax`), `sp` is variable 4 and `r4` takes 31, so nothing
//! downstream needs to know the ISA. Conditions use the x86 names the C generator knows. Instructions the
//! lifter does not model are kept as text with the registers they read and write; instructions inside an
//! `it` block are always kept that way (with their condition), except a conditional branch.

use std::collections::BTreeMap;

use yaxpeax_arm::armv7::{ConditionCode, Instruction, Opcode, Operand, RegShiftStyle, ShiftStyle};

use super::{build_lifted, Expr, Isa, Kind, SsaFunction, Stmt, Var, RSP};
use crate::model::Edge;

/// Argument registers `r0`–`r3` (AAPCS), as variables.
pub(crate) const ARGS: [Var; 4] = [0, 1, 2, 3];

/// Registers a call may change besides the result `r0`: `r1`–`r3`, `r12` and the link register.
const CLOBBERED: [u8; 5] = [1, 2, 3, 12, 14];

const LR: u8 = 14;
const PC: u8 = 15;

/// The variable of register `n`: `sp` (13) is the stack pointer slot, `r4` takes 31.
fn var(n: u8) -> Var {
    match n {
        4 => 31,
        13 => RSP,
        n => Var::from(n),
    }
}

fn bin(op: &'static str, a: Expr, b: Expr) -> Expr {
    Expr::Bin(op, Box::new(a), Box::new(b))
}

fn assign(def: Var, expr: Expr) -> Kind {
    Kind::Assign { def, ver: 0, expr, width: 32 }
}

fn plus(e: Expr, off: i64) -> Expr {
    if let Expr::Const(c) = e {
        return Expr::Const(c.wrapping_add(off));
    }
    match off {
        0 => e,
        o if o < 0 => bin("-", e, Expr::Const(-o)),
        o => bin("+", e, Expr::Const(o)),
    }
}

/// A register operand as a value (`pc` reads as the address of the instruction plus 4).
fn reg(op: &Operand, ip: u64) -> Option<Expr> {
    match op {
        Operand::Reg(r) if r.number() == PC => Some(Expr::Const((ip + 4) as i64)),
        Operand::Reg(r) => Some(Expr::Use(var(r.number()), 0)),
        _ => None,
    }
}

/// A flexible second operand: an immediate, a register, or a register shifted by an immediate.
fn src(op: &Operand, ip: u64) -> Option<Expr> {
    match op {
        Operand::Imm32(v) => Some(Expr::Const(i64::from(*v))),
        Operand::Imm12(v) => Some(Expr::Const(i64::from(*v))),
        Operand::Reg(_) => reg(op, ip),
        Operand::RegShift(s) => match s.into_shift() {
            RegShiftStyle::RegImm(sh) => {
                let base = Expr::Use(var(sh.shiftee().number()), 0);
                let by = Expr::Const(i64::from(sh.imm()));
                Some(match sh.stype() {
                    ShiftStyle::LSL if sh.imm() == 0 => base,
                    ShiftStyle::LSL => bin("<<", base, by),
                    ShiftStyle::LSR => bin(">>", base, by),
                    ShiftStyle::ASR => bin(">>s", base, by),
                    _ => return None,
                })
            }
            RegShiftStyle::RegReg(_) => None,
        },
        _ => None,
    }
}

/// The destination register of an instruction: its variable (`None` for `pc`, which is a jump).
fn dst(op: &Operand) -> Option<Var> {
    match op {
        Operand::Reg(r) if r.number() != PC => Some(var(r.number())),
        _ => None,
    }
}

/// The address a load or store uses, and a base-register update before or after it.
struct Mem {
    addr: Expr,
    pre: Option<(Var, Expr)>,
    post: Option<(Var, Expr)>,
}

fn mem(op: &Operand, ip: u64) -> Option<Mem> {
    let base =
        |r: &yaxpeax_arm::armv7::Reg| if r.number() == PC { Expr::Const(((ip + 4) & !3) as i64) } else { Expr::Use(var(r.number()), 0) };
    let signed = |add: bool, off: i64| if add { off } else { -off };
    Some(match *op {
        Operand::RegDeref(r) => Mem { addr: base(&r), pre: None, post: None },
        Operand::RegDerefPreindexOffset(r, off, add, wback) => {
            let addr = plus(base(&r), signed(add, i64::from(off)));
            if wback {
                Mem { addr: addr.clone(), pre: Some((var(r.number()), addr)), post: None }
            } else {
                Mem { addr, pre: None, post: None }
            }
        }
        Operand::RegDerefPostindexOffset(r, off, add, _) => {
            Mem { addr: base(&r), pre: None, post: Some((var(r.number()), plus(base(&r), signed(add, i64::from(off))))) }
        }
        Operand::RegDerefPreindexReg(r, m, add, false) => {
            let idx = Expr::Use(var(m.number()), 0);
            Mem { addr: bin(if add { "+" } else { "-" }, base(&r), idx), pre: None, post: None }
        }
        Operand::RegDerefPreindexRegShift(r, s, add, false) => {
            let idx = src(&Operand::RegShift(s), ip)?;
            Mem { addr: bin(if add { "+" } else { "-" }, base(&r), idx), pre: None, post: None }
        }
        _ => return None,
    })
}

/// The x86 name of an ARM condition, or `None` for "always".
fn cond_name(c: ConditionCode) -> Option<&'static str> {
    Some(match c {
        ConditionCode::EQ => "e",
        ConditionCode::NE => "ne",
        ConditionCode::HS => "ae",
        ConditionCode::LO => "b",
        ConditionCode::MI => "s",
        ConditionCode::PL => "ns",
        ConditionCode::VS => "o",
        ConditionCode::VC => "no",
        ConditionCode::HI => "a",
        ConditionCode::LS => "be",
        ConditionCode::GE => "ge",
        ConditionCode::LT => "l",
        ConditionCode::GT => "g",
        ConditionCode::LE => "le",
        ConditionCode::AL => return None,
    })
}

fn cond_from_number(n: u8) -> ConditionCode {
    use ConditionCode as C;
    [C::EQ, C::NE, C::HS, C::LO, C::MI, C::PL, C::VS, C::VC, C::HI, C::LS, C::GE, C::LT, C::GT, C::LE, C::AL][usize::from(n.min(14))]
}

/// The branch target: Thumb offsets are in halfwords, from the end of the instruction.
fn target(i: &Instruction, ip: u64) -> Option<u64> {
    let len = if i.wide { 4 } else { 2 };
    i.operands.iter().find_map(|o| match *o {
        Operand::BranchThumbOffset(off) => Some((ip + len).wrapping_add((i64::from(off) * 2) as u64)),
        _ => None,
    })
}

/// Decoded blocks of a function: start → (instructions with their addresses, edges).
pub(crate) type Blocks = BTreeMap<u64, (Vec<(u64, Instruction)>, Vec<Edge>)>;

type Lifted = Vec<(Kind, bool)>;

fn call(target: String, extra: Option<Expr>) -> Kind {
    let mut args: Vec<Expr> = extra.into_iter().collect();
    args.extend(ARGS.iter().map(|v| Expr::Use(*v, 0)));
    Kind::Call { target, args, ret: Some((0, 0)), clobbers: CLOBBERED.iter().map(|n| (var(*n), 0)).collect() }
}

/// The registers in a `push` / `pop` list, lowest first.
fn list(op: &Operand) -> Vec<u8> {
    match op {
        Operand::RegList(mask) => (0..16u8).filter(|r| mask & (1 << r) != 0).collect(),
        _ => Vec::new(),
    }
}

/// Lifts one instruction. `it` is the condition this instruction runs under inside an `it` block.
fn lift(i: &Instruction, ip: u64, it: Option<ConditionCode>) -> Lifted {
    use Opcode as O;
    let ops = &i.operands;
    let generic = |why: Option<ConditionCode>| generic(i, why);
    // Inside an `it` block everything but a branch is kept as text, with its condition.
    if let Some(c) = it {
        if i.opcode != O::B {
            return generic(Some(c));
        }
        return vec![(Kind::Branch { cond: cond_name(c).map(str::to_string), uses: Vec::new(), target: target(i, ip) }, false)];
    }
    match i.opcode {
        O::B => vec![(Kind::Branch { cond: cond_name(i.condition).map(str::to_string), uses: Vec::new(), target: target(i, ip) }, false)],
        O::CBZ | O::CBNZ => match reg(&ops[0], ip) {
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
            None => generic(None),
        },
        O::BL => vec![(call(target(i, ip).map_or_else(|| "?".into(), |t| format!("sub_{t:X}")), None), false)],
        O::BLX => match reg(&ops[0], ip) {
            Some(r) => {
                vec![(call(format!("[{}]", super::Expr::text_plain(&r, super::Names { isa: Isa::Thumb, bits: 32 })), Some(r)), false)]
            }
            None => match target(i, ip) {
                Some(t) => vec![(call(format!("sub_{t:X}"), None), false)],
                None => generic(None),
            },
        },
        O::BX => match &ops[0] {
            Operand::Reg(r) if r.number() == LR => vec![(Kind::Return { val: Some(Expr::Use(0, 0)) }, false)],
            op => {
                // A jump through a register may be a tail call: it passes the arguments on.
                let mut uses: Vec<Expr> = reg(op, ip).into_iter().collect();
                uses.extend(ARGS.iter().chain(std::iter::once(&0)).map(|v| Expr::Use(*v, 0)));
                vec![(Kind::Branch { cond: None, uses, target: None }, false)]
            }
        },
        O::PUSH => {
            let regs = list(&ops[0]);
            let n = regs.len() as i64;
            let mut out: Lifted = vec![(assign(RSP, bin("-", Expr::Use(RSP, 0), Expr::Const(4 * n))), false)];
            for (k, r) in regs.iter().enumerate() {
                let val = if *r == PC { Expr::Const(ip as i64) } else { Expr::Use(var(*r), 0) };
                out.push((Kind::Store { size: 4, addr: plus(Expr::Use(RSP, 0), 4 * k as i64), val }, false));
            }
            out
        }
        O::POP => {
            let regs = list(&ops[0]);
            let n = regs.len() as i64;
            let mut out: Lifted = Vec::new();
            let mut returns = false;
            for (k, r) in regs.iter().enumerate() {
                if *r == PC {
                    returns = true;
                } else {
                    out.push((assign(var(*r), Expr::Load(4, Box::new(plus(Expr::Use(RSP, 0), 4 * k as i64)))), false));
                }
            }
            out.push((assign(RSP, bin("+", Expr::Use(RSP, 0), Expr::Const(4 * n))), false));
            if returns {
                out.push((Kind::Return { val: Some(Expr::Use(0, 0)) }, false));
            }
            out
        }
        O::MOV | O::MVN => match (dst(&ops[0]), src(&ops[1], ip)) {
            (Some(d), Some(v)) => {
                let v = if i.opcode == O::MVN { Expr::Un("~", Box::new(v)) } else { v };
                vec![(assign(d, v), i.s)]
            }
            _ => generic(None),
        },
        O::MOVT => match (dst(&ops[0]), &ops[1]) {
            (Some(d), Operand::Imm32(v)) => {
                let keep = bin("&", Expr::Use(d, 0), Expr::Const(0xffff));
                vec![(assign(d, bin("|", keep, Expr::Const(i64::from(*v) << 16))), false)]
            }
            _ => generic(None),
        },
        O::ADD | O::SUB | O::AND | O::ORR | O::EOR | O::BIC | O::RSB => {
            // `op rd, rn, op2`, or `op rd, op2` meaning `op rd, rd, op2`.
            let three = !matches!(ops[2], Operand::Nothing);
            let (rn, op2) = if three { (reg(&ops[1], ip), src(&ops[2], ip)) } else { (reg(&ops[0], ip), src(&ops[1], ip)) };
            let (Some(d), Some(a), Some(b)) = (dst(&ops[0]), rn, op2) else { return generic(None) };
            let (op, a, b) = match i.opcode {
                O::ADD => ("+", a, b),
                O::SUB => ("-", a, b),
                O::AND => ("&", a, b),
                O::ORR => ("|", a, b),
                O::EOR => ("^", a, b),
                O::BIC => ("&", a, Expr::Un("~", Box::new(b))),
                _ => ("-", b, a), // rsb: op2 - rn
            };
            if i.opcode == O::SUB && i.s {
                return vec![(Kind::Flags { test: false, a: a.clone(), b: b.clone() }, true), (assign(d, bin(op, a, b)), false)];
            }
            // `add rd, sp, #0` and `adds rd, rn, #0` are moves.
            if matches!(i.opcode, O::ADD | O::SUB | O::ORR) && b == Expr::Const(0) {
                return vec![(assign(d, a), i.s)];
            }
            vec![(assign(d, bin(op, a, b)), i.s)]
        }
        O::LSL | O::LSR | O::ASR => {
            let three = !matches!(ops[2], Operand::Nothing);
            let (rm, by) = if three { (reg(&ops[1], ip), src(&ops[2], ip)) } else { (reg(&ops[0], ip), src(&ops[1], ip)) };
            match (dst(&ops[0]), rm, by) {
                (Some(d), Some(a), Some(b)) => {
                    let op = match i.opcode {
                        O::LSL => "<<",
                        O::LSR => ">>",
                        _ => ">>s",
                    };
                    vec![(assign(d, bin(op, a, b)), i.s)]
                }
                _ => generic(None),
            }
        }
        O::MUL => {
            let three = !matches!(ops[2], Operand::Nothing);
            let (a, b) = if three { (reg(&ops[1], ip), reg(&ops[2], ip)) } else { (reg(&ops[0], ip), reg(&ops[1], ip)) };
            match (dst(&ops[0]), a, b) {
                (Some(d), Some(a), Some(b)) => vec![(assign(d, bin("*", a, b)), i.s)],
                _ => generic(None),
            }
        }
        O::CMP | O::CMN | O::TST | O::TEQ => match (reg(&ops[0], ip), src(&ops[1], ip)) {
            (Some(a), Some(b)) if i.opcode == O::CMP => vec![(Kind::Flags { test: false, a, b }, true)],
            (Some(a), Some(b)) if i.opcode == O::TST => vec![(Kind::Flags { test: true, a, b }, true)],
            _ => generic(None),
        },
        O::ADR => match (dst(&ops[0]), &ops[1]) {
            (Some(d), Operand::Imm32(off)) => vec![(assign(d, Expr::Const((((ip + 4) & !3) as i64).wrapping_add(i64::from(*off)))), false)],
            _ => generic(None),
        },
        O::LDR | O::LDRB | O::LDRH | O::LDRSB | O::LDRSH => {
            let size = match i.opcode {
                O::LDRB | O::LDRSB => 1,
                O::LDRH | O::LDRSH => 2,
                _ => 4,
            };
            match (dst(&ops[0]), mem(&ops[1], ip)) {
                (Some(d), Some(m)) => with_writeback(m, |addr| vec![(assign(d, Expr::Load(size, Box::new(addr))), false)]),
                _ => generic(None),
            }
        }
        O::STR | O::STRB | O::STRH => {
            let size = match i.opcode {
                O::STRB => 1,
                O::STRH => 2,
                _ => 4,
            };
            match (reg(&ops[0], ip), mem(&ops[1], ip)) {
                (Some(val), Some(m)) => with_writeback(m, |addr| vec![(Kind::Store { size, addr, val }, false)]),
                _ => generic(None),
            }
        }
        O::LDRD => match (dst(&ops[0]), dst(&ops[1]), mem(&ops[2], ip)) {
            (Some(d1), Some(d2), Some(m)) => with_writeback(m, |addr| {
                let second = plus(addr.clone(), 4);
                vec![(assign(d1, Expr::Load(4, Box::new(addr))), false), (assign(d2, Expr::Load(4, Box::new(second))), false)]
            }),
            _ => generic(None),
        },
        O::STRD => match (reg(&ops[0], ip), reg(&ops[1], ip), mem(&ops[2], ip)) {
            (Some(v1), Some(v2), Some(m)) => with_writeback(m, |addr| {
                let second = plus(addr.clone(), 4);
                vec![(Kind::Store { size: 4, addr, val: v1 }, false), (Kind::Store { size: 4, addr: second, val: v2 }, false)]
            }),
            _ => generic(None),
        },
        // Nothing for the data flow.
        O::NOP | O::HINT | O::DMB | O::DSB | O::ISB | O::IT | O::BKPT | O::YIELD | O::SEV | O::WFE | O::WFI => Vec::new(),
        _ => generic(None),
    }
}

fn with_writeback(m: Mem, access: impl FnOnce(Expr) -> Lifted) -> Lifted {
    let mut out = Vec::new();
    if let Some((v, e)) = m.pre {
        out.push((assign(v, e), false));
    }
    out.extend(access(m.addr));
    if let Some((v, e)) = m.post {
        out.push((assign(v, e), false));
    }
    out
}

/// An instruction without a model: its text, the registers it reads and the one it writes. Under an `it`
/// condition the destination keeps its old value when the condition fails, so it is read as well.
fn generic(i: &Instruction, under: Option<ConditionCode>) -> Lifted {
    let name = format!("{:?}", i.opcode);
    let writes_first =
        !(name.starts_with("ST") || name.starts_with("CM") || name.starts_with("TST") || name.starts_with("TEQ") || name == "PUSH");
    let (mut uses, mut defs) = (Vec::new(), Vec::new());
    for (k, op) in i.operands.iter().enumerate() {
        let regs: Vec<(Var, bool)> = match op {
            Operand::Reg(r) if r.number() == PC => Vec::new(),
            Operand::Reg(r) => vec![(var(r.number()), k == 0 && writes_first)],
            Operand::RegWBack(r, _) => vec![(var(r.number()), false)],
            Operand::RegList(m) => (0..16u8).filter(|r| m & (1 << r) != 0 && *r != PC).map(|r| (var(r), name == "POP")).collect(),
            Operand::RegDeref(r) | Operand::RegDerefPreindexOffset(r, ..) | Operand::RegDerefPostindexOffset(r, ..) => {
                vec![(var(r.number()), false)]
            }
            Operand::RegDerefPreindexReg(r, m, ..) | Operand::RegDerefPostindexReg(r, m, ..) => {
                vec![(var(r.number()), false), (var(m.number()), false)]
            }
            Operand::RegShift(s) => match s.into_shift() {
                RegShiftStyle::RegImm(sh) => vec![(var(sh.shiftee().number()), false)],
                RegShiftStyle::RegReg(_) => Vec::new(),
            },
            _ => Vec::new(),
        };
        for (v, def) in regs {
            if def {
                defs.push((v, 0));
                if under.is_some() {
                    uses.push(Expr::Use(v, 0));
                }
            } else {
                uses.push(Expr::Use(v, 0));
            }
        }
    }
    if name == "POP" || name == "PUSH" {
        uses.push(Expr::Use(RSP, 0));
        defs.push((RSP, 0));
    }
    let text = match under.and_then(cond_name) {
        Some(c) => format!("{i} /* if {c} */"),
        None => i.to_string(),
    };
    let sets_flags = i.s || name.starts_with("CM") || name.starts_with("TST") || name.starts_with("TEQ");
    vec![(Kind::Other { text, uses, defs }, sets_flags)]
}

/// Builds the SSA form of a Thumb function from its decoded blocks.
pub(crate) fn build(entry: u64, blocks: &Blocks) -> SsaFunction {
    let mut lifted: BTreeMap<u64, (Vec<Stmt>, Vec<Edge>)> = BTreeMap::new();
    for (start, (insns, succs)) in blocks {
        let mut stmts = Vec::new();
        // The `it` block in progress: the condition of each of its remaining instructions.
        let mut under: Vec<ConditionCode> = Vec::new();
        for (ip, i) in insns {
            let it = if under.is_empty() { None } else { Some(under.remove(0)) };
            if i.opcode == Opcode::IT {
                if let (Operand::Imm32(first), Operand::Imm32(mask)) = (&i.operands[0], &i.operands[1]) {
                    let (first, mask) = (*first as u8, *mask as u8 & 0xf);
                    let count = 4u32.saturating_sub(mask.trailing_zeros()) as usize;
                    under = (0..count)
                        .map(|k| {
                            // The first instruction runs on the condition; later ones on it or its inverse.
                            let then = k == 0 || ((mask >> (4 - k)) & 1) == (first & 1);
                            cond_from_number(if then { first } else { first ^ 1 })
                        })
                        .collect();
                }
            }
            for (kind, flags) in lift(i, *ip, it) {
                stmts.push(Stmt { address: *ip, kind, dead: false, flags, push: false });
            }
        }
        lifted.insert(*start, (stmts, succs.clone()));
    }
    build_lifted(entry, lifted, 32, Isa::Thumb, &ARGS)
}

/// Whether the function leaves a value in `r0`: a `bx lr` / `pop {…, pc}` shortly after something writes `r0`.
pub(crate) fn returns_value(blocks: &Blocks) -> bool {
    blocks.values().any(|(v, _)| {
        let ends = v.last().is_some_and(|(_, l)| {
            matches!(l.opcode, Opcode::BX) && matches!(l.operands[0], Operand::Reg(r) if r.number() == LR)
                || matches!(l.opcode, Opcode::POP) && matches!(l.operands[0], Operand::RegList(m) if m & (1 << PC) != 0)
        });
        ends && v.iter().rev().skip(1).take(6).any(|(_, i)| {
            matches!(i.opcode, Opcode::BL | Opcode::BLX)
                || matches!(i.operands[0], Operand::Reg(r) if r.number() == 0)
                    && !format!("{:?}", i.opcode).starts_with("ST")
                    && !matches!(i.opcode, Opcode::CMP | Opcode::TST)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EdgeKind;
    use yaxpeax_arch::{Decoder as _, U8Reader};
    use yaxpeax_arm::armv7::InstDecoder;

    fn decode(halfwords: &[u16], start: u64) -> Vec<(u64, Instruction)> {
        let bytes: Vec<u8> = halfwords.iter().flat_map(|h| h.to_le_bytes()).collect();
        let d = InstDecoder::default_thumb();
        let mut r = U8Reader::new(&bytes);
        let (mut at, mut out) = (start, Vec::new());
        while ((at - start) as usize) < bytes.len() {
            let Ok(i) = d.decode(&mut r) else { break };
            let len = if i.wide { 4 } else { 2 };
            out.push((at, i));
            at += len;
        }
        out
    }

    type Spec<'a> = (u64, &'a [u16], &'a [(u64, EdgeKind)]);

    fn blocks(list: &[Spec<'_>]) -> Blocks {
        list.iter().map(|(s, w, e)| (*s, (decode(w, *s), e.iter().map(|(to, kind)| Edge { to: *to, kind: *kind }).collect()))).collect()
    }

    fn c_text(f: &SsaFunction, returns: bool) -> String {
        let names = |_: u64| None;
        let o =
            super::super::COptions { name: "f", entry: 0x1000, returns, args: ARGS.to_vec(), names: &names, switches: Default::default() };
        f.to_c(&o)
            .iter()
            .map(|l| "  ".repeat(l.indent as usize) + &l.tokens.iter().map(|t| t.t.as_str()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_function_with_a_frame_a_call_and_a_branch() {
        // push {r7, lr}; add r7, sp, #0; sub sp, #8; adds r0, r0, r1; cmp r0, #10; ble +; movs r0, #10;
        // bl +0x100; add sp, #8; pop {r7, pc}
        let b = blocks(&[
            (0x1000, &[0xb580, 0xaf00, 0xb082, 0x1840, 0x280a, 0xdd01], &[(0x100c, EdgeKind::False), (0x1010, EdgeKind::True)]),
            (0x100c, &[0x200a, 0xf000, 0xf880], &[(0x1012, EdgeKind::Fall)]),
            (0x1012, &[0xb002, 0xbd80], &[]),
        ]);
        let f = build(0x1000, &b);
        let c = c_text(&f, true);
        assert!(c.contains("a1 + a2"), "adds r0, r0, r1: {c}");
        assert!(c.contains("sub_") && c.contains('('), "the bl is a call: {c}");
        assert!(c.contains("return"), "pop {{pc}} returns: {c}");
        assert!(!c.contains("sp"), "stack bookkeeping disappears: {c}");
    }

    #[test]
    fn loads_stores_literals_and_flags() {
        // ldr r1, [r0, #4]; str r1, [sp, #4] (after sub sp); ldr r2, [pc, #8]; movw/movt; subs r0, r0, r1; bx lr
        let b = blocks(&[(0x1000, &[0xb082, 0x6841, 0x9101, 0x4a02, 0x1a40, 0x4770], &[])]);
        let f = build(0x1000, &b);
        let ssa: String = f.lines().iter().map(|l| l.1.clone()).collect::<Vec<_>>().join("\n");
        assert!(ssa.contains("*(u32 *)(r0_0 + 4)"), "the load from r0 + 4 is modelled: {ssa}");
        assert!(ssa.contains("*(u32 *)0x1010"), "the literal-pool address is folded: {ssa}");
        let c = c_text(&f, true);
        assert!(c.contains("return"), "{c}");
    }

    #[test]
    fn an_it_block_keeps_its_instructions_as_text_with_the_condition() {
        // cmp r0, #0; it eq; moveq r0, #1; bx lr
        let b = blocks(&[(0x1000, &[0x2800, 0xbf08, 0x2001, 0x4770], &[])]);
        let c = c_text(&build(0x1000, &b), true);
        assert!(c.contains("if e"), "the conditional move says under which condition it runs: {c}");
        assert!(!c.contains("= 1;") || c.contains("__asm"), "it is not turned into an unconditional assignment: {c}");
    }

    #[test]
    fn cbz_movt_and_odd_instructions_do_not_panic() {
        // cbz r0, +; movw r2, #0x1234; movt r2, #1; ldrd r0, r1, [r0, #8]; bx lr
        let b = blocks(&[
            (0x2000, &[0xb100], &[(0x2002, EdgeKind::False), (0x2004, EdgeKind::True)]),
            (0x2002, &[0xf240, 0x1234, 0xf2c0, 0x0201], &[(0x2004, EdgeKind::Fall)]),
            (0x2004, &[0xe9d0, 0x0102, 0x4770], &[]),
        ]);
        let c = c_text(&build(0x2000, &b), true);
        assert!(c.contains("== 0") || c.contains("!= 0"), "{c}");
        // Every 16-bit and 32-bit word the decoder accepts lifts without panicking.
        let mut seed = 0x9e37_79b9u32;
        let d = InstDecoder::default_thumb();
        for _ in 0..30_000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if let Ok(i) = d.decode(&mut U8Reader::new(&seed.to_le_bytes())) {
                let _ = lift(&i, 0x4000, None);
                let _ = lift(&i, 0x4000, Some(ConditionCode::NE));
            }
        }
    }
}
