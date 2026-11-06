//! SSA intermediate representation for x86 / x86-64 functions.
//!
//! Each machine instruction is lifted to IR statements over the general-purpose registers
//! (`rax = rcx + 0x10`, `*(u32 *)(rsp + 8) = rdx`, `rax = call f(...)`). The function is then put
//! into SSA form the classic way (Cytron et al.): dominators (Cooper–Harvey–Kennedy), dominance
//! frontiers, phi nodes at the iterated frontier of every register's definitions, and renaming
//! along the dominator tree, so every value has exactly one definition: `rax_3 = phi(rax_1, rax_2)`.
//!
//! On the SSA form three classic passes run:
//! * **constant propagation** — through expressions and phi nodes whose inputs agree;
//! * **copy propagation** — `rax_2 = rcx_1` makes `rax_2` an alias of `rcx_1`;
//! * **dead code** — pure definitions nobody uses are marked dead (iterated).
//!
//! Calls clobber the ABI's volatile registers (each clobber is a new, unknown version), so values
//! are never carried across a call wrongly. Memory is not modelled: loads are opaque values.

use std::collections::{BTreeMap, HashMap, HashSet};

use iced_x86::{FlowControl, Formatter, Instruction as Ins, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::model::Edge;

mod c;
pub(crate) use c::COptions;

/// A register family (`rax` … `r15`), numbered 0..16.
type Var = u8;

/// The SSA variable index of a register family (`rax` = 0 … `r15` = 15).
pub(crate) fn var_index(r: Register) -> Option<Var> {
    var_of(r)
}

fn var_of(r: Register) -> Option<Var> {
    let f = r.full_register();
    if f.is_gpr64() {
        Some((f as u32 - Register::RAX as u32) as u8)
    } else {
        None
    }
}

const NAMES64: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const NAMES32: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const RSP: Var = 4;

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Const(i64),
    /// A register value: (family, SSA version).
    Use(Var, u32),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    Un(&'static str, Box<Expr>),
    Load(u8, Box<Expr>),
    /// A value the IR does not model (`mul` high half, `cpuid`, a clobber, …).
    Opaque(String),
}

#[derive(Debug, Clone)]
enum Kind {
    /// `def = expr` (`width` bits are kept: 32-bit writes zero-extend on x86-64).
    Assign {
        def: Var,
        ver: u32,
        expr: Expr,
        width: u8,
    },
    Store {
        size: u8,
        addr: Expr,
        val: Expr,
    },
    Call {
        target: String,
        args: Vec<Expr>,
        ret: Option<(Var, u32)>,
        clobbers: Vec<(Var, u32)>,
    },
    /// `target`: a direct jump's destination (a jump out of the function is a tail call).
    Branch {
        cond: Option<String>,
        uses: Vec<Expr>,
        target: Option<u64>,
    },
    Return {
        val: Option<Expr>,
    },
    /// `cmp a, b` / `test a, b`: sets the flags a conditional branch reads.
    Flags {
        test: bool,
        a: Expr,
        b: Expr,
    },
    /// Anything else: its text, the registers it reads and the ones it writes (as opaque values).
    Other {
        text: String,
        uses: Vec<Expr>,
        defs: Vec<(Var, u32)>,
    },
}

#[derive(Debug, Clone)]
struct Stmt {
    address: u64,
    kind: Kind,
    dead: bool,
    /// The instruction sets the condition flags (the last flag setter feeds a conditional branch).
    flags: bool,
    /// The store half of a `push` (32-bit call arguments).
    push: bool,
}

#[derive(Debug, Clone)]
struct Phi {
    var: Var,
    ver: u32,
    /// (predecessor block, version flowing in)
    args: Vec<(u64, u32)>,
    dead: bool,
}

#[derive(Debug, Clone, Default)]
struct Block {
    start: u64,
    preds: Vec<u64>,
    succs: Vec<u64>,
    phis: Vec<Phi>,
    stmts: Vec<Stmt>,
    /// Branch target (taken / unconditional edge) and fall-through successor.
    taken: Option<u64>,
    fall: Option<u64>,
}

/// Summary numbers of one function's SSA form.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SsaStats {
    pub blocks: usize,
    pub phis: usize,
    pub values: usize,
    pub constants: usize,
    pub copies: usize,
    pub dead: usize,
}

/// What the SSA form proves about single instructions, for the C view.
#[derive(Debug, Default)]
pub struct SsaFacts {
    /// (address, register family) of plain register assignments whose value is never read.
    pub dead: HashSet<(u64, &'static str)>,
    /// (address, register family) → the value the assignment there always produces.
    pub consts: HashMap<(u64, &'static str), i64>,
}

/// A function in SSA form.
pub struct SsaFunction {
    blocks: Vec<Block>,
    bits: u32,
    /// Known constant value of each SSA value (family, version).
    consts: HashMap<(Var, u32), i64>,
    /// Addresses of definitions that are dead in the IR as lifted (before folding), for the C view.
    unused: HashSet<u64>,
    unused_defs: HashSet<(u64, Var)>,
    /// Copy aliases: value → the value it copies.
    copies: HashMap<(Var, u32), (Var, u32)>,
    pub stats: SsaStats,
}

// ------------------------------------------------------------------------------------------------
// Lifting (versions are filled in by renaming; 0 = not yet renamed)

struct Lifter {
    bits: u32,
    volatile: Vec<Var>,
    /// Registers that carry arguments (read by calls and tail jumps).
    args: Vec<Var>,
}

impl Lifter {
    fn reg(&self, r: Register) -> Expr {
        match var_of(r) {
            Some(v) => Expr::Use(v, 0),
            None => Expr::Opaque(format!("{r:?}").to_ascii_lowercase()),
        }
    }

    fn mem(&self, i: &Ins) -> Expr {
        if i.is_ip_rel_memory_operand() {
            return Expr::Const(i.ip_rel_memory_address() as i64);
        }
        let mut e: Option<Expr> = None;
        let base = i.memory_base();
        if base != Register::None {
            e = Some(self.reg(base));
        }
        let idx = i.memory_index();
        if idx != Register::None {
            let s = i.memory_index_scale() as i64;
            let t = if s == 1 { self.reg(idx) } else { Expr::Bin("*", Box::new(self.reg(idx)), Box::new(Expr::Const(s))) };
            e = Some(match e {
                Some(b) => Expr::Bin("+", Box::new(b), Box::new(t)),
                None => t,
            });
        }
        let d = if self.bits == 32 { i.memory_displacement32() as i32 as i64 } else { i.memory_displacement64() as i64 };
        match e {
            Some(b) if d == 0 => b,
            Some(b) => Expr::Bin(if d < 0 { "-" } else { "+" }, Box::new(b), Box::new(Expr::Const(d.unsigned_abs() as i64))),
            None => Expr::Const(d),
        }
    }

    fn operand(&self, i: &Ins, n: u32) -> Expr {
        match i.op_kind(n) {
            OpKind::Register => self.reg(i.op_register(n)),
            OpKind::Memory => Expr::Load(i.memory_size().size() as u8, Box::new(self.mem(i))),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Expr::Const(i.immediate(n) as i64),
            _ => Expr::Opaque("?".into()),
        }
    }

    /// The register a write to operand 0 defines in full, with its width (`None` for partial writes).
    fn full_def(&self, i: &Ins) -> Option<(Var, u8)> {
        if i.op_kind(0) != OpKind::Register {
            return None;
        }
        let r = i.op_register(0);
        let v = var_of(r)?;
        let w = r.size() as u8 * 8;
        // 32-bit writes zero-extend on x86-64; 8/16-bit writes merge with the old value.
        (w >= 32).then_some((v, w))
    }

    fn lift(&self, i: &Ins, info: &mut InstructionInfoFactory) -> Vec<Kind> {
        use Expr::{Bin, Const, Use};
        let a = i.ip();
        let _ = a;
        let m = i.mnemonic();
        let assign = |def: Var, width: u8, expr: Expr| Kind::Assign { def, ver: 0, expr, width };
        // Stack push / pop.
        if m == Mnemonic::Push && i.op_count() == 1 {
            let size = if self.bits == 64 { 8 } else { 4 };
            let val = self.operand(i, 0);
            return vec![
                assign(RSP, self.bits as u8, Bin("-", Box::new(Use(RSP, 0)), Box::new(Const(size)))),
                Kind::Store { size: size as u8, addr: Use(RSP, 0), val },
            ];
        }
        if m == Mnemonic::Pop && i.op_count() == 1 && i.op_kind(0) == OpKind::Register {
            if let Some(v) = var_of(i.op_register(0)) {
                let size = if self.bits == 64 { 8 } else { 4 };
                return vec![
                    assign(v, self.bits as u8, Expr::Load(size as u8, Box::new(Use(RSP, 0)))),
                    assign(RSP, self.bits as u8, Bin("+", Box::new(Use(RSP, 0)), Box::new(Const(size)))),
                ];
            }
        }
        match i.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => {
                let target = match i.op_kind(0) {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => format!("sub_{:X}", i.near_branch_target()),
                    _ => format!("[{}]", Expr::text_plain(&self.operand(i, 0), self.bits)),
                };
                let mut args = Vec::new();
                if matches!(i.op_kind(0), OpKind::Register | OpKind::Memory) {
                    args.push(self.operand(i, 0));
                }
                args.extend(self.args.iter().map(|v| Expr::Use(*v, 0)));
                return vec![Kind::Call {
                    target,
                    args,
                    ret: Some((0, 0)),
                    clobbers: self.volatile.iter().filter(|v| **v != 0).map(|v| (*v, 0)).collect(),
                }];
            }
            FlowControl::Return => {
                return vec![Kind::Return { val: Some(Use(0, 0)) }];
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                let cond =
                    (i.flow_control() == FlowControl::ConditionalBranch).then(|| format!("{:?}", i.condition_code()).to_ascii_lowercase());
                let target = matches!(i.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
                    .then(|| i.near_branch_target());
                let mut uses = Vec::new();
                if i.flow_control() == FlowControl::IndirectBranch {
                    uses.push(self.operand(i, 0));
                    // A jump through a register or table may be a tail call: it passes the arguments on.
                    uses.extend(self.args.iter().chain(std::iter::once(&0)).map(|v| Expr::Use(*v, 0)));
                }
                return vec![Kind::Branch { cond, uses, target }];
            }
            _ => {}
        }
        if matches!(m, Mnemonic::Cmp | Mnemonic::Test) && i.op_count() == 2 {
            return vec![Kind::Flags { test: m == Mnemonic::Test, a: self.operand(i, 0), b: self.operand(i, 1) }];
        }
        // xor r, r / sub r, r: zero, independent of the old value.
        if matches!(m, Mnemonic::Xor | Mnemonic::Sub)
            && i.op_count() == 2
            && i.op_kind(0) == OpKind::Register
            && i.op_kind(1) == OpKind::Register
            && i.op_register(0) == i.op_register(1)
        {
            if let Some((v, w)) = self.full_def(i) {
                return vec![assign(v, w, Const(0))];
            }
        }
        let bin = |op: &'static str| -> Option<Vec<Kind>> {
            let (v, w) = self.full_def(i)?;
            Some(vec![assign(v, w, Bin(op, Box::new(self.operand(i, 0)), Box::new(self.operand(i, 1))))])
        };
        let out = match m {
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsxd | Mnemonic::Movsx if i.op_count() == 2 => {
                if i.op_kind(0) == OpKind::Memory {
                    Some(vec![Kind::Store { size: i.memory_size().size() as u8, addr: self.mem(i), val: self.operand(i, 1) }])
                } else if let Some((v, w)) = self.full_def(i) {
                    Some(vec![assign(v, w, self.operand(i, 1))])
                } else {
                    // `mov ax, …` / `mov al, …`: the low bits change, the rest of the register stays.
                    let r = i.op_register(0);
                    let low = !matches!(r, Register::AH | Register::BH | Register::CH | Register::DH);
                    let src_ok = i.op_kind(1) != OpKind::Register
                        || !matches!(i.op_register(1), Register::AH | Register::BH | Register::CH | Register::DH);
                    match (var_of(r), low && src_ok && m == Mnemonic::Mov) {
                        (Some(v), true) => {
                            let bits = r.size() as u32 * 8;
                            let mask = (1i64 << bits) - 1;
                            let src = match self.operand(i, 1) {
                                Expr::Use(sv, n) => Bin("&", Box::new(Expr::Use(sv, n)), Box::new(Const(mask))),
                                Expr::Const(c) => Const(c & mask),
                                e => e,
                            };
                            let keep = Bin("&", Box::new(Use(v, 0)), Box::new(Const(!mask)));
                            Some(vec![assign(v, self.bits as u8, Bin("|", Box::new(keep), Box::new(src)))])
                        }
                        _ => None,
                    }
                }
            }
            Mnemonic::Lea => self.full_def(i).map(|(v, w)| vec![assign(v, w, self.mem(i))]),
            Mnemonic::Add => bin("+"),
            Mnemonic::Sub => bin("-"),
            Mnemonic::And => bin("&"),
            Mnemonic::Or => bin("|"),
            Mnemonic::Xor => bin("^"),
            Mnemonic::Shl | Mnemonic::Sal => bin("<<"),
            Mnemonic::Shr => bin(">>"),
            Mnemonic::Sar => bin(">>s"),
            Mnemonic::Imul if i.op_count() == 2 => bin("*"),
            Mnemonic::Imul if i.op_count() == 3 => {
                self.full_def(i).map(|(v, w)| vec![assign(v, w, Bin("*", Box::new(self.operand(i, 1)), Box::new(self.operand(i, 2))))])
            }
            Mnemonic::Inc => self.full_def(i).map(|(v, w)| vec![assign(v, w, Bin("+", Box::new(self.operand(i, 0)), Box::new(Const(1))))]),
            Mnemonic::Dec => self.full_def(i).map(|(v, w)| vec![assign(v, w, Bin("-", Box::new(self.operand(i, 0)), Box::new(Const(1))))]),
            Mnemonic::Neg => self.full_def(i).map(|(v, w)| vec![assign(v, w, Expr::Un("-", Box::new(self.operand(i, 0))))]),
            Mnemonic::Not => self.full_def(i).map(|(v, w)| vec![assign(v, w, Expr::Un("~", Box::new(self.operand(i, 0))))]),
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => Some(Vec::new()),
            _ => None,
        };
        if let Some(k) = out {
            return k;
        }
        // Generic: what it reads and writes, from iced's instruction info.
        let used = info.info(i);
        let mut uses = Vec::new();
        let mut defs = Vec::new();
        for u in used.used_registers() {
            let Some(v) = var_of(u.register()) else { continue };
            match u.access() {
                OpAccess::Read | OpAccess::CondRead => uses.push(Expr::Use(v, 0)),
                OpAccess::Write | OpAccess::CondWrite => {
                    // A partial or conditional write keeps part of the old value: also a read.
                    if u.access() == OpAccess::CondWrite || u.register().size() < 4 {
                        uses.push(Expr::Use(v, 0));
                    }
                    defs.push((v, 0));
                }
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    uses.push(Expr::Use(v, 0));
                    defs.push((v, 0));
                }
                _ => {}
            }
        }
        uses.dedup();
        defs.dedup();
        // The instruction as written; the SSA values it reads are listed after it.
        let mut text = String::new();
        let mut fmt = iced_x86::IntelFormatter::new();
        fmt.options_mut().set_space_after_operand_separator(true);
        fmt.options_mut().set_hex_prefix("0x");
        fmt.options_mut().set_hex_suffix("");
        fmt.options_mut().set_uppercase_hex(false);
        fmt.format(i, &mut text);
        vec![Kind::Other { text, uses, defs }]
    }
}

// ------------------------------------------------------------------------------------------------
// Expressions: walking, printing, evaluating

impl Expr {
    fn uses_mut(&mut self, f: &mut dyn FnMut(&mut Var, &mut u32)) {
        match self {
            Expr::Use(v, n) => f(v, n),
            Expr::Bin(_, a, b) => {
                a.uses_mut(f);
                b.uses_mut(f);
            }
            Expr::Un(_, a) | Expr::Load(_, a) => a.uses_mut(f),
            Expr::Const(_) | Expr::Opaque(_) => {}
        }
    }

    fn uses(&self, out: &mut Vec<(Var, u32)>) {
        match self {
            Expr::Use(v, n) => out.push((*v, *n)),
            Expr::Bin(_, a, b) => {
                a.uses(out);
                b.uses(out);
            }
            Expr::Un(_, a) | Expr::Load(_, a) => a.uses(out),
            Expr::Const(_) | Expr::Opaque(_) => {}
        }
    }

    fn text_plain(e: &Expr, bits: u32) -> String {
        Self::text(e, bits, &HashMap::new(), false)
    }

    fn text(e: &Expr, bits: u32, sub: &HashMap<(Var, u32), String>, top: bool) -> String {
        let name = |v: Var| if bits == 32 && (v as usize) < 8 { NAMES32[v as usize] } else { NAMES64[v as usize] };
        match e {
            Expr::Const(c) => hex(*c),
            Expr::Use(v, n) => sub.get(&(*v, *n)).cloned().unwrap_or_else(|| {
                if *n == 0 && sub.is_empty() {
                    name(*v).to_string()
                } else {
                    format!("{}_{n}", name(*v))
                }
            }),
            Expr::Bin(op, a, b) => {
                let s = format!("{} {} {}", Self::text(a, bits, sub, false), op.trim_end_matches('s'), Self::text(b, bits, sub, false));
                if top {
                    s
                } else {
                    format!("({s})")
                }
            }
            Expr::Un(op, a) => format!("{op}{}", Self::text(a, bits, sub, false)),
            Expr::Load(size, a) => format!("*(u{} *){}", *size as u32 * 8, Self::text(a, bits, sub, false)),
            Expr::Opaque(s) => s.clone(),
        }
    }

    fn eval(&self, consts: &HashMap<(Var, u32), i64>) -> Option<i64> {
        Some(match self {
            Expr::Const(c) => *c,
            Expr::Use(v, n) => *consts.get(&(*v, *n))?,
            Expr::Bin(op, a, b) => {
                let (x, y) = (a.eval(consts)?, b.eval(consts)?);
                match *op {
                    "+" => x.wrapping_add(y),
                    "-" => x.wrapping_sub(y),
                    "*" => x.wrapping_mul(y),
                    "&" => x & y,
                    "|" => x | y,
                    "^" => x ^ y,
                    "<<" => x.wrapping_shl((y & 63) as u32),
                    ">>" => ((x as u64).wrapping_shr((y & 63) as u32)) as i64,
                    ">>s" => x.wrapping_shr((y & 63) as u32),
                    _ => return None,
                }
            }
            Expr::Un("-", a) => a.eval(consts)?.wrapping_neg(),
            Expr::Un("~", a) => !a.eval(consts)?,
            _ => return None,
        })
    }
}

/// Copy aliases: an SSA value → the value it copies.
type Copies = HashMap<(Var, u32), (Var, u32)>;
/// Follows a copy chain to its source.
type Resolve = dyn Fn((Var, u32), &Copies) -> (Var, u32);

/// Replaces uses of known constants with literals and uses of copies with their source.
fn propagate(e: &mut Expr, consts: &HashMap<(Var, u32), i64>, copies: &HashMap<(Var, u32), (Var, u32)>, resolve: &Resolve) {
    match e {
        Expr::Use(v, n) => {
            if let Some(c) = consts.get(&(*v, *n)) {
                *e = Expr::Const(*c);
            } else {
                let (rv, rn) = resolve((*v, *n), copies);
                match consts.get(&(rv, rn)) {
                    Some(c) => *e = Expr::Const(*c),
                    None => *e = Expr::Use(rv, rn),
                }
            }
        }
        Expr::Bin(_, a, b) => {
            propagate(a, consts, copies, resolve);
            propagate(b, consts, copies, resolve);
        }
        Expr::Un(_, a) | Expr::Load(_, a) => propagate(a, consts, copies, resolve),
        Expr::Const(_) | Expr::Opaque(_) => {}
    }
}

fn hex(c: i64) -> String {
    if (-9..=9).contains(&c) {
        c.to_string()
    } else if c < 0 {
        format!("-{:#x}", c.unsigned_abs())
    } else {
        format!("{c:#x}")
    }
}

fn mask(v: i64, width: u8) -> i64 {
    match width {
        32 => v as u32 as i64,
        16 => v as u16 as i64,
        8 => v as u8 as i64,
        _ => v,
    }
}

impl Kind {
    fn exprs_mut(&mut self, f: &mut dyn FnMut(&mut Expr)) {
        match self {
            Kind::Assign { expr, .. } => f(expr),
            Kind::Store { addr, val, .. } => {
                f(addr);
                f(val);
            }
            Kind::Call { args, .. } => args.iter_mut().for_each(f),
            Kind::Branch { uses, .. } | Kind::Other { uses, .. } => uses.iter_mut().for_each(f),
            Kind::Flags { a, b, .. } => {
                f(a);
                f(b);
            }
            Kind::Return { val } => {
                if let Some(v) = val {
                    f(v)
                }
            }
        }
    }

    fn defs_mut(&mut self, f: &mut dyn FnMut(&mut Var, &mut u32)) {
        match self {
            Kind::Assign { def, ver, .. } => f(def, ver),
            Kind::Call { ret, clobbers, .. } => {
                if let Some((v, n)) = ret {
                    f(v, n);
                }
                for (v, n) in clobbers {
                    f(v, n);
                }
            }
            Kind::Other { defs, .. } => defs.iter_mut().for_each(|(v, n)| f(v, n)),
            _ => {}
        }
    }

    fn uses(&self) -> Vec<(Var, u32)> {
        let mut out = Vec::new();
        let mut me = self.clone();
        me.exprs_mut(&mut |e| e.uses(&mut out));
        out
    }
}

/// 32-bit calls: when the caller does not pop the pushed arguments itself (`add esp, 4·n` right
/// after the call, cdecl), the callee did (stdcall, the Windows API) — model that as a stack-pointer
/// update after the call, so stack slots keep their names past it.
fn stdcall_cleanup(stmts: &mut Vec<Stmt>) {
    let mut pushes = 0i64;
    let mut i = 0;
    while i < stmts.len() {
        if stmts[i].push {
            pushes += 1;
        } else if matches!(stmts[i].kind, Kind::Call { .. }) {
            let caller_cleans = matches!(stmts.get(i + 1).map(|s| &s.kind), Some(Kind::Assign { def: RSP, expr: Expr::Bin("+", a, b), .. })
                if matches!(&**a, Expr::Use(RSP, _)) && matches!(&**b, Expr::Const(k) if *k == 4 * pushes));
            if pushes > 0 && !caller_cleans {
                let address = stmts[i].address;
                let kind = Kind::Assign {
                    def: RSP,
                    ver: 0,
                    expr: Expr::Bin("+", Box::new(Expr::Use(RSP, 0)), Box::new(Expr::Const(4 * pushes))),
                    width: 32,
                };
                stmts.insert(i + 1, Stmt { address, kind, dead: false, flags: false, push: false });
                i += 1;
            }
            pushes = 0;
        }
        i += 1;
    }
}

// ------------------------------------------------------------------------------------------------
// Construction

/// Builds the SSA form of a function from its decoded blocks (`start → (instructions, edges)`).
/// `volatile` lists the registers a call clobbers.
pub(crate) fn build(
    entry: u64,
    blocks: &BTreeMap<u64, (Vec<Ins>, Vec<Edge>)>,
    bits: u32,
    volatile: &[Register],
    args: &[Register],
) -> SsaFunction {
    let lifter = Lifter {
        bits,
        volatile: volatile.iter().filter_map(|r| var_of(*r)).collect(),
        args: args.iter().filter_map(|r| var_of(*r)).collect(),
    };
    let mut info = InstructionInfoFactory::new();
    let starts: Vec<u64> = blocks.keys().copied().collect();
    let index: HashMap<u64, usize> = starts.iter().enumerate().map(|(i, s)| (*s, i)).collect();
    let mut bl: Vec<Block> = starts
        .iter()
        .map(|s| {
            let (insns, succs) = &blocks[s];
            let mut stmts: Vec<Stmt> = Vec::new();
            for i in insns {
                let first = stmts.len();
                let sets_flags = i.rflags_modified() != 0;
                let is_push = i.mnemonic() == Mnemonic::Push;
                for mut k in lifter.lift(i, &mut info) {
                    // A direct jump out of the function is a tail call: it reads the arguments and rax.
                    if let Kind::Branch { target: Some(t), uses, .. } = &mut k {
                        if !blocks.contains_key(t) {
                            uses.extend(lifter.args.iter().chain(std::iter::once(&0)).map(|v| Expr::Use(*v, 0)));
                        }
                    }
                    stmts.push(Stmt { address: i.ip(), kind: k, dead: false, flags: false, push: false });
                }
                let grew = stmts.len() > first;
                if let Some(last) = stmts.last_mut().filter(|_| grew) {
                    last.flags = sets_flags;
                    last.push = is_push && matches!(last.kind, Kind::Store { .. });
                }
            }
            if bits == 32 {
                stdcall_cleanup(&mut stmts);
            }
            use crate::model::EdgeKind as K;
            let taken = succs.iter().find(|e| matches!(e.kind, K::True | K::Uncond)).map(|e| e.to);
            let fall = succs.iter().find(|e| matches!(e.kind, K::False | K::Fall)).map(|e| e.to);
            Block {
                start: *s,
                succs: succs.iter().map(|e| e.to).filter(|t| index.contains_key(t)).collect(),
                stmts,
                taken,
                fall,
                ..Default::default()
            }
        })
        .collect();
    for i in 0..bl.len() {
        for s in bl[i].succs.clone() {
            let j = index[&s];
            let st = bl[i].start;
            if !bl[j].preds.contains(&st) {
                bl[j].preds.push(st);
            }
        }
    }
    let n = bl.len();
    let Some(&e) = index.get(&entry) else {
        return SsaFunction {
            blocks: bl,
            bits,
            consts: HashMap::new(),
            unused: HashSet::new(),
            unused_defs: HashSet::new(),
            copies: HashMap::new(),
            stats: SsaStats::default(),
        };
    };

    // Reverse postorder from the entry; unreachable blocks keep no dominator.
    let mut order = Vec::new();
    let mut seen = vec![false; n];
    let mut stack = vec![(e, 0usize)];
    seen[e] = true;
    while let Some((b, k)) = stack.pop() {
        let succs: Vec<usize> = bl[b].succs.iter().map(|s| index[s]).collect();
        if k < succs.len() {
            stack.push((b, k + 1));
            let s = succs[k];
            if !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            order.push(b);
        }
    }
    order.reverse();
    let rpo: HashMap<usize, usize> = order.iter().enumerate().map(|(i, b)| (*b, i)).collect();
    let preds: Vec<Vec<usize>> = bl.iter().map(|b| b.preds.iter().map(|p| index[p]).filter(|p| rpo.contains_key(p)).collect()).collect();

    // Immediate dominators (Cooper, Harvey, Kennedy: "A Simple, Fast Dominance Algorithm").
    let mut idom: Vec<Option<usize>> = vec![None; n];
    idom[e] = Some(e);
    let mut changed = true;
    while changed {
        changed = false;
        for &b in order.iter().skip(1) {
            let mut new: Option<usize> = None;
            for &p in &preds[b] {
                if idom[p].is_none() {
                    continue;
                }
                new = Some(match new {
                    None => p,
                    Some(mut x) => {
                        let mut y = p;
                        while x != y {
                            while rpo[&x] > rpo[&y] {
                                x = idom[x].unwrap();
                            }
                            while rpo[&y] > rpo[&x] {
                                y = idom[y].unwrap();
                            }
                        }
                        x
                    }
                });
            }
            if new.is_some() && idom[b] != new {
                idom[b] = new;
                changed = true;
            }
        }
    }
    // Dominance frontiers.
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for b in 0..n {
        if preds[b].len() >= 2 && idom[b].is_some() {
            for &p in &preds[b] {
                let mut r = p;
                while Some(r) != idom[b] {
                    df[r].insert(b);
                    match idom[r] {
                        Some(x) if x != r => r = x,
                        _ => break,
                    }
                }
            }
        }
    }
    // Phi placement at the iterated dominance frontier of each register's definition blocks.
    let mut def_blocks: HashMap<Var, HashSet<usize>> = HashMap::new();
    for (bi, b) in bl.iter_mut().enumerate() {
        for s in b.stmts.iter_mut() {
            s.kind.defs_mut(&mut |v, _| {
                def_blocks.entry(*v).or_default().insert(bi);
            });
        }
    }
    for (v, defs) in &def_blocks {
        let mut has: HashSet<usize> = HashSet::new();
        let mut work: Vec<usize> = defs.iter().copied().collect();
        while let Some(x) = work.pop() {
            for &y in &df[x] {
                if has.insert(y) {
                    let args = preds[y].iter().map(|p| (bl[*p].start, 0)).collect();
                    bl[y].phis.push(Phi { var: *v, ver: 0, args, dead: false });
                    if !defs.contains(&y) {
                        work.push(y);
                    }
                }
            }
        }
    }
    for b in &mut bl {
        b.phis.sort_by_key(|p| p.var);
    }
    // Renaming along the dominator tree.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &b in &order {
        if let Some(d) = idom[b] {
            if d != b {
                children[d].push(b);
            }
        }
    }
    let mut counter = [0u32; 16];
    let mut stacks: Vec<Vec<u32>> = vec![vec![0]; 16]; // version 0 = value on entry
    rename(e, &mut bl, &children, &index, &mut counter, &mut stacks);

    let mut f = SsaFunction {
        blocks: bl,
        bits,
        consts: HashMap::new(),
        unused: HashSet::new(),
        unused_defs: HashSet::new(),
        copies: HashMap::new(),
        stats: SsaStats::default(),
    };
    f.blocks.retain(|b| b.start == entry || !b.preds.is_empty() || !b.stmts.is_empty());
    f.optimize();
    f
}

fn rename(
    b: usize,
    bl: &mut [Block],
    children: &[Vec<usize>],
    index: &HashMap<u64, usize>,
    counter: &mut [u32; 16],
    stacks: &mut Vec<Vec<u32>>,
) {
    let mut pushed: Vec<Var> = Vec::new();
    let fresh = |v: Var, counter: &mut [u32; 16], stacks: &mut Vec<Vec<u32>>, pushed: &mut Vec<Var>| -> u32 {
        counter[v as usize] += 1;
        let n = counter[v as usize];
        stacks[v as usize].push(n);
        pushed.push(v);
        n
    };
    for p in bl[b].phis.iter_mut() {
        p.ver = fresh(p.var, counter, stacks, &mut pushed);
    }
    for s in bl[b].stmts.iter_mut() {
        s.kind.exprs_mut(&mut |e| {
            e.uses_mut(&mut |v, n| *n = *stacks[*v as usize].last().unwrap());
        });
        let mut defs: Vec<Var> = Vec::new();
        s.kind.defs_mut(&mut |v, _| defs.push(*v));
        let mut vers: Vec<u32> = defs.iter().map(|v| fresh(*v, counter, stacks, &mut pushed)).collect();
        vers.reverse();
        s.kind.defs_mut(&mut |_, n| *n = vers.pop().unwrap());
    }
    let me = bl[b].start;
    for s in bl[b].succs.clone() {
        let j = index[&s];
        for p in bl[j].phis.iter_mut() {
            for (pred, ver) in p.args.iter_mut() {
                if *pred == me {
                    *ver = *stacks[p.var as usize].last().unwrap();
                }
            }
        }
    }
    for &c in &children[b] {
        rename(c, bl, children, index, counter, stacks);
    }
    for v in pushed {
        stacks[v as usize].pop();
    }
}

// ------------------------------------------------------------------------------------------------
// Passes and output

impl SsaFunction {
    fn optimize(&mut self) {
        // Constants and copies, to a fixpoint (phi of agreeing inputs included).
        let mut changed = true;
        while changed {
            changed = false;
            for b in &self.blocks {
                for p in &b.phis {
                    if self.consts.contains_key(&(p.var, p.ver)) {
                        continue;
                    }
                    let vals: Vec<Option<i64>> = p.args.iter().map(|(_, n)| self.consts.get(&(p.var, *n)).copied()).collect();
                    if let Some(Some(first)) = vals.first() {
                        if vals.iter().all(|v| *v == Some(*first)) {
                            self.consts.insert((p.var, p.ver), *first);
                            changed = true;
                        }
                    }
                }
                for s in &b.stmts {
                    if let Kind::Assign { def, ver, expr, width } = &s.kind {
                        if self.consts.contains_key(&(*def, *ver)) {
                            continue;
                        }
                        if let Some(v) = expr.eval(&self.consts) {
                            self.consts.insert((*def, *ver), mask(v, *width));
                            changed = true;
                        }
                    }
                }
            }
        }
        for b in &self.blocks {
            for s in &b.stmts {
                if let Kind::Assign { def, ver, expr: Expr::Use(v, n), width } = &s.kind {
                    if *width as u32 == self.bits || (*width == 64 && self.bits == 64) {
                        self.copies.insert((*def, *ver), (*v, *n));
                    }
                }
            }
        }
        // Liveness for the C view is decided on the IR as lifted: a value folded into its uses
        // below (a constant argument, a copy) is still needed by code that was not folded.
        self.mark_dead();
        self.unused = self.blocks.iter().flat_map(|b| b.stmts.iter().filter(|s| s.dead).map(|s| s.address)).collect();
        self.unused_defs = self
            .blocks
            .iter()
            .flat_map(|b| b.stmts.iter().filter(|s| s.dead))
            .filter_map(|s| if let Kind::Assign { def, .. } = &s.kind { Some((s.address, *def)) } else { None })
            .collect();
        for b in &mut self.blocks {
            b.phis.iter_mut().for_each(|p| p.dead = false);
            b.stmts.iter_mut().for_each(|s| s.dead = false);
        }
        // Propagate into the statements: known constants become literals, copies their source.
        let resolve = |k: (Var, u32), copies: &HashMap<(Var, u32), (Var, u32)>| {
            let mut t = k;
            let mut guard = 0;
            while let (Some(n), true) = (copies.get(&t), guard < 64) {
                t = *n;
                guard += 1;
            }
            t
        };
        let (consts, copies) = (&self.consts, &self.copies);
        for b in &mut self.blocks {
            for s in &mut b.stmts {
                s.kind.exprs_mut(&mut |e| propagate(e, consts, copies, &resolve));
            }
        }
        self.mark_dead();
        let mut st = SsaStats { blocks: self.blocks.len(), ..Default::default() };
        for b in &self.blocks {
            st.phis += b.phis.iter().filter(|p| !p.dead).count();
            st.values += b.phis.len();
            for s in &b.stmts {
                let mut c = s.kind.clone();
                c.defs_mut(&mut |_, _| st.values += 1);
                st.dead += usize::from(s.dead);
            }
        }
        st.constants = self.consts.len();
        st.copies = self.copies.len();
        self.stats = st;
    }

    /// Dead code: pure definitions without uses, iterated (a dead use frees its inputs).
    fn mark_dead(&mut self) {
        loop {
            let mut used: HashSet<(Var, u32)> = HashSet::new();
            for b in &self.blocks {
                for p in b.phis.iter().filter(|p| !p.dead) {
                    for (_, n) in &p.args {
                        used.insert((p.var, *n));
                    }
                }
                for s in b.stmts.iter().filter(|s| !s.dead) {
                    used.extend(s.kind.uses());
                }
            }
            let mut killed = false;
            for b in &mut self.blocks {
                for p in b.phis.iter_mut().filter(|p| !p.dead) {
                    if !used.contains(&(p.var, p.ver)) {
                        p.dead = true;
                        killed = true;
                    }
                }
                for s in b.stmts.iter_mut().filter(|s| !s.dead) {
                    if let Kind::Assign { def, ver, expr, .. } = &s.kind {
                        // rsp updates and loads stay: the stack and memory are not modelled.
                        if *def != RSP && !matches!(expr, Expr::Load(..)) && !used.contains(&(*def, *ver)) {
                            s.dead = true;
                            killed = true;
                        }
                    }
                }
            }
            if !killed {
                break;
            }
        }
    }

    fn name(&self, v: Var, n: u32) -> String {
        let base = if self.bits == 32 && (v as usize) < 8 { NAMES32[v as usize] } else { NAMES64[v as usize] };
        format!("{base}_{n}")
    }

    /// Text of each value as it reads after propagation: constants and copies substituted.
    fn substitutions(&self) -> HashMap<(Var, u32), String> {
        let mut sub = HashMap::new();
        for b in &self.blocks {
            for p in &b.phis {
                sub.insert((p.var, p.ver), self.name(p.var, p.ver));
                for (_, n) in &p.args {
                    sub.entry((p.var, *n)).or_insert_with(|| self.name(p.var, *n));
                }
            }
            for s in &b.stmts {
                for (v, n) in s.kind.uses() {
                    sub.entry((v, n)).or_insert_with(|| self.name(v, n));
                }
                let mut k = s.kind.clone();
                k.defs_mut(&mut |v, n| {
                    sub.entry((*v, *n)).or_insert_with(|| self.name(*v, *n));
                });
            }
        }
        for (k, c) in &self.consts {
            sub.insert(*k, hex(*c));
        }
        // Copies resolve through chains.
        for k in self.copies.keys() {
            let mut t = *k;
            let mut guard = 0;
            while let Some(n) = self.copies.get(&t) {
                t = *n;
                guard += 1;
                if guard > 64 {
                    break;
                }
            }
            if !self.consts.contains_key(k) {
                if let Some(c) = self.consts.get(&t) {
                    sub.insert(*k, hex(*c));
                } else {
                    sub.insert(*k, self.name(t.0, t.1));
                }
            }
        }
        sub
    }

    fn unused_def(&self, address: u64, var: Var) -> bool {
        self.unused_defs.contains(&(address, var))
    }

    /// Facts for the C view, keyed by (instruction address, register family name):
    /// definitions nothing reads, and definitions whose value is a known constant.
    pub fn facts(&self) -> SsaFacts {
        let mut f = SsaFacts::default();
        for b in &self.blocks {
            for s in &b.stmts {
                if let Kind::Assign { def, ver, .. } = &s.kind {
                    if *def == RSP {
                        continue;
                    }
                    let name = NAMES64[*def as usize];
                    if self.unused.contains(&s.address) && self.unused_def(s.address, *def) {
                        f.dead.insert((s.address, name));
                    }
                    if let Some(c) = self.consts.get(&(*def, *ver)) {
                        f.consts.insert((s.address, name), *c);
                    }
                }
            }
        }
        f
    }

    /// One text line per block header, phi and statement: `(indent, text, address, dead)`.
    pub fn lines(&self) -> Vec<(u8, String, Option<u64>, bool)> {
        let sub = self.substitutions();
        let t = |e: &Expr| Expr::text(e, self.bits, &sub, true);
        let mut out = Vec::new();
        for b in &self.blocks {
            let preds = if b.preds.is_empty() {
                String::new()
            } else {
                format!("  // from {}", b.preds.iter().map(|p| format!("{p:#x}")).collect::<Vec<_>>().join(", "))
            };
            out.push((0, format!("block_{:X}:{preds}", b.start), Some(b.start), false));
            for p in &b.phis {
                let args = p
                    .args
                    .iter()
                    .map(|(pr, n)| format!("{} [{pr:#x}]", sub.get(&(p.var, *n)).cloned().unwrap_or_else(|| self.name(p.var, *n))))
                    .collect::<Vec<_>>()
                    .join(", ");
                let c = self.consts.get(&(p.var, p.ver)).map(|c| format!("  // = {}", hex(*c))).unwrap_or_default();
                out.push((1, format!("{} = phi({args}){c}", self.name(p.var, p.ver)), None, p.dead));
            }
            for s in &b.stmts {
                let text = match &s.kind {
                    Kind::Assign { def, ver, expr, .. } => {
                        let c = match (self.consts.get(&(*def, *ver)), expr) {
                            (Some(c), e) if !matches!(e, Expr::Const(_)) => format!("  // = {}", hex(*c)),
                            _ => String::new(),
                        };
                        format!("{} = {}{c}", self.name(*def, *ver), t(expr))
                    }
                    Kind::Store { size, addr, val } => format!("*(u{} *)({}) = {}", *size as u32 * 8, t(addr), t(val)),
                    Kind::Flags { test, a, b } => format!("{}({}, {})", if *test { "test" } else { "cmp" }, t(a), t(b)),
                    Kind::Call { target, args, ret, .. } => {
                        let call = format!("call {target}({})", args.iter().map(&t).collect::<Vec<_>>().join(", "));
                        match ret {
                            Some((v, n)) => format!("{} = {call}", self.name(*v, *n)),
                            None => call,
                        }
                    }
                    Kind::Branch { cond, uses, .. } => {
                        let u = uses.iter().map(&t).collect::<Vec<_>>().join(", ");
                        match cond {
                            Some(c) => format!("branch if {c}"),
                            None if !u.is_empty() => format!("jump {u}"),
                            None => "jump".into(),
                        }
                    }
                    Kind::Return { val } => match val {
                        Some(v) => format!("return {}", t(v)),
                        None => "return".into(),
                    },
                    Kind::Other { text, uses, defs } => {
                        let d = defs.iter().map(|(v, n)| self.name(*v, *n)).collect::<Vec<_>>();
                        let u = uses.iter().map(&t).collect::<Vec<_>>();
                        let reads = if u.is_empty() { String::new() } else { format!("  // reads {}", u.join(", ")) };
                        if d.is_empty() {
                            format!("{text}{reads}")
                        } else {
                            format!("{} = [{text}]{reads}", d.join(", "))
                        }
                    }
                };
                out.push((1, text, Some(s.address), s.dead));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EdgeKind;
    use iced_x86::{Decoder, DecoderOptions};

    /// Assembles `blocks` (each: start address, instructions, successor starts) into decoded blocks.
    fn func(blocks: &[(u64, &[&str], &[u64])]) -> BTreeMap<u64, (Vec<Ins>, Vec<Edge>)> {
        let mut out = BTreeMap::new();
        for (start, insns, succs) in blocks {
            let mut ip = *start;
            let mut v = Vec::new();
            for text in *insns {
                let bytes = crate::asm_x86::assemble(text, ip, 64).unwrap_or_else(|e| panic!("{text}: {e}"));
                let mut d = Decoder::with_ip(64, &bytes, ip, DecoderOptions::NONE);
                let i = d.decode();
                ip += i.len() as u64;
                v.push(i);
            }
            out.insert(*start, (v, succs.iter().map(|t| Edge { to: *t, kind: EdgeKind::Uncond }).collect()));
        }
        out
    }

    fn text(f: &SsaFunction) -> String {
        f.lines()
            .iter()
            .map(|(ind, t, _, dead)| format!("{}{}{}", "  ".repeat(*ind as usize), if *dead { "(dead) " } else { "" }, t))
            .collect::<Vec<_>>()
            .join("\n")
    }

    const VOL: [Register; 7] = [Register::RAX, Register::RCX, Register::RDX, Register::R8, Register::R9, Register::R10, Register::R11];
    const ARGS: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];

    #[test]
    fn diamond_gets_a_phi() {
        // 0x100: mov eax, 1 ; test ecx, ecx ; jz 0x200      0x150: mov eax, 2       0x200: add eax, 3 ; ret
        let f = func(&[
            (0x100, &["mov eax, 1", "test ecx, ecx", "jz 0x200"], &[0x150, 0x200]),
            (0x150, &["mov eax, 2"], &[0x200]),
            (0x200, &["add eax, 3", "ret"], &[]),
        ]);
        let s = build(0x100, &f, 64, &VOL, &ARGS);
        let t = text(&s);
        assert!(t.contains("rax_3 = phi(1 [0x100], 2 [0x150])"), "{t}");
        assert!(t.contains("rax_4 = rax_3 + 3"), "{t}");
        assert!(t.contains("return rax_4"), "{t}");
        assert_eq!(s.stats.phis, 1);
    }

    #[test]
    fn agreeing_branches_fold_to_a_constant() {
        let f = func(&[
            (0x100, &["test ecx, ecx", "jz 0x200"], &[0x150, 0x200]),
            (0x150, &["mov eax, 5", "jmp 0x210"], &[0x210]),
            (0x200, &["mov eax, 5"], &[0x210]),
            (0x210, &["add eax, 3", "ret"], &[]),
        ]);
        let s = build(0x100, &f, 64, &VOL, &ARGS);
        let t = text(&s);
        assert!(t.contains("= phi(5 [0x150], 5 [0x200])  // = 5"), "{t}");
        assert!(t.contains("return 8"), "the sum is known after the join: {t}");
    }

    #[test]
    fn loops_carry_values_through_a_phi() {
        // 0x100: xor eax, eax       0x110 (loop): add eax, 2 ; dec ecx ; jnz 0x110       0x120: ret
        let f = func(&[
            (0x100, &["xor eax, eax"], &[0x110]),
            (0x110, &["add eax, 2", "dec ecx", "jnz 0x110"], &[0x110, 0x120]),
            (0x120, &["ret"], &[]),
        ]);
        let s = build(0x100, &f, 64, &VOL, &ARGS);
        let t = text(&s);
        assert!(t.contains("rax_2 = phi(0 [0x100], rax_3 [0x110])"), "{t}");
        assert!(t.contains("rcx_1 = phi(rcx_0 [0x100], rcx_2 [0x110])") || t.contains("rcx_1 = phi(rcx [0x100], rcx_2 [0x110])"), "{t}");
        assert!(!t.contains("// = "), "a loop counter is not a constant: {t}");
    }

    #[test]
    fn dead_definitions_and_copies() {
        let f = func(&[(0x100, &["mov edx, 7", "mov rax, rcx", "add rax, 1", "ret"], &[])]);
        let s = build(0x100, &f, 64, &VOL, &ARGS);
        let t = text(&s);
        assert!(t.contains("(dead) rdx_1 = 7"), "unused: {t}");
        assert!(t.contains("rax_2 = rcx_0 + 1") || t.contains("rax_2 = rcx + 1"), "the copy is propagated: {t}");
        assert_eq!(s.stats.dead, 2, "{t}"); // rdx_1 and the copy itself
    }

    #[test]
    fn calls_clobber_volatile_registers() {
        let f = func(&[(0x100, &["mov ecx, 3", "mov ebx, 4", "call 0x500", "add ecx, ebx", "ret"], &[])]);
        let s = build(0x100, &f, 64, &VOL, &ARGS);
        let t = text(&s);
        // rbx survives the call (constant 4), rcx does not.
        assert!(t.contains("rcx_3 = rcx_2 + 4"), "{t}");
        assert!(
            t.contains("rax_1 = call sub_500(3, rdx_0, r8_0, r9_0)") || t.contains("rax_1 = call sub_500(3, rdx, r8, r9)"),
            "the call reads the argument registers: {t}"
        );
    }

    #[test]
    fn argument_setup_before_a_call_or_tail_jump_is_live() {
        // mov ecx, 5 feeds the call: not dead. mov edx, 6 before a jump out of the function feeds it too.
        let f = func(&[(0x100, &["mov ecx, 5", "call 0x500", "mov edx, 6", "mov r10d, 7", "jmp 0x900"], &[])]);
        let s = build(0x100, &f, 64, &VOL, &ARGS);
        let facts = s.facts();
        let t = text(&s);
        assert!(!facts.dead.iter().any(|(_, r)| *r == "rcx"), "{t}");
        assert!(!facts.dead.iter().any(|(_, r)| *r == "rdx"), "{t}");
        assert!(facts.dead.iter().any(|(_, r)| *r == "r10"), "r10 is no argument register: {t}");
        assert_eq!(facts.consts.values().copied().filter(|v| *v == 5).count(), 1);
    }

    #[test]
    fn stack_and_memory() {
        let f = func(&[(0x100, &["push rbx", "mov rbx, [rcx+8]", "mov [rsp+0x10], rbx", "pop rbx", "ret"], &[])]);
        let t = text(&build(0x100, &f, 64, &VOL, &ARGS));
        assert!(t.contains("rsp_1 = rsp_0 - 8") || t.contains("rsp_1 = rsp - 8"), "{t}");
        assert!(t.contains("*(u64 *)") && t.contains("rbx_1 = *(u64 *)(rcx"), "{t}");
    }

    #[test]
    fn unreachable_blocks_and_odd_inputs_do_not_panic() {
        let f = func(&[(0x100, &["ret"], &[]), (0x200, &["mov eax, 1", "jmp 0x100"], &[0x100])]);
        let _ = build(0x100, &f, 64, &VOL, &ARGS).lines();
        let _ = build(0x999, &f, 64, &VOL, &ARGS).lines();
        let empty = BTreeMap::new();
        let _ = build(0x100, &empty, 64, &VOL, &ARGS).lines();
    }
}
