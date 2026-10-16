//! Pseudocode: a lightweight lifter from x86 / x86-64 to readable C-like text.
//!
//! This is deliberately simple — it is not a full decompiler. Each instruction
//! is translated to a statement, flags are folded into the conditional jump that
//! consumes them, calls receive arguments from the calling convention, strings
//! and names are inlined, and two structuring passes recover `if { }` regions
//! and `do { } while` loops. Anything else falls back to labels and `goto`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced_x86::{ConditionCode, Decoder, DecoderOptions, Instruction as Ins, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::model::{Arch, Format, StringEncoding, Token, TokenKind};
use crate::Binary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudoLine {
    /// Instruction address this line came from (for listing sync).
    pub address: Option<u64>,
    pub indent: u8,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pseudocode {
    pub address: u64,
    pub name: String,
    pub lines: Vec<PseudoLine>,
    pub note: Option<String>,
}

// ------------------------------------------------------------------------------------------------
// Token building

#[derive(Default)]
struct Line {
    toks: Vec<Token>,
}

impl Line {
    fn push(&mut self, t: impl Into<String>, k: TokenKind) -> &mut Self {
        let t = t.into();
        if let Some(last) = self.toks.last_mut() {
            if last.k == k && matches!(k, TokenKind::Punct | TokenKind::Text) {
                last.t.push_str(&t);
                return self;
            }
        }
        self.toks.push(Token { t, k });
        self
    }
    fn kw(&mut self, t: &str) -> &mut Self {
        self.push(t, TokenKind::Keyword)
    }
    fn p(&mut self, t: &str) -> &mut Self {
        self.push(t, TokenKind::Punct)
    }
    fn sp(&mut self) -> &mut Self {
        self.push(" ", TokenKind::Text)
    }
    fn extend(&mut self, e: Expr) -> &mut Self {
        for t in e.0 {
            self.push(t.t, t.k);
        }
        self
    }
}

/// A rendered expression (token list) plus whether it needs parentheses when nested.
#[derive(Clone, Default)]
struct Expr(Vec<Token>, bool);

impl Expr {
    fn tok(t: impl Into<String>, k: TokenKind) -> Self {
        Expr(vec![Token { t: t.into(), k }], false)
    }
    fn reg(r: &str) -> Self {
        Self::tok(r, TokenKind::Register)
    }
    fn num(v: i128) -> Self {
        let s = if v < 0 {
            if -v < 10 {
                format!("-{}", -v)
            } else {
                format!("-0x{:x}", -v)
            }
        } else if v < 10 {
            v.to_string()
        } else {
            format!("0x{v:x}")
        };
        Self::tok(s, TokenKind::Number)
    }
    fn binop(a: Expr, op: &str, b: Expr) -> Self {
        let mut v = a.wrap().0;
        v.push(Token { t: format!(" {op} "), k: TokenKind::Punct });
        v.extend(b.wrap().0);
        Expr(v, true)
    }
    fn wrap(self) -> Self {
        if !self.1 {
            return self;
        }
        let mut v = vec![Token { t: "(".into(), k: TokenKind::Punct }];
        v.extend(self.0);
        v.push(Token { t: ")".into(), k: TokenKind::Punct });
        Expr(v, false)
    }
    fn text(&self) -> String {
        self.0.iter().map(|t| t.t.as_str()).collect()
    }
}

// ------------------------------------------------------------------------------------------------

fn reg_name(r: Register) -> String {
    format!("{r:?}").to_lowercase()
}

fn size_type(bytes: usize) -> &'static str {
    match bytes {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        16 => "__m128",
        32 => "__m256",
        _ => "void",
    }
}

fn cond_op(cc: ConditionCode, signed_hint: bool) -> (&'static str, bool) {
    // (operator, is_signed)
    match cc {
        ConditionCode::e => ("==", signed_hint),
        ConditionCode::ne => ("!=", signed_hint),
        ConditionCode::b => ("<", false),
        ConditionCode::ae => (">=", false),
        ConditionCode::be => ("<=", false),
        ConditionCode::a => (">", false),
        ConditionCode::l => ("<", true),
        ConditionCode::ge => (">=", true),
        ConditionCode::le => ("<=", true),
        ConditionCode::g => (">", true),
        _ => ("?", false),
    }
}

fn negate(cc: ConditionCode) -> ConditionCode {
    use ConditionCode::*;
    match cc {
        o => no,
        no => o,
        b => ae,
        ae => b,
        e => ne,
        ne => e,
        be => a,
        a => be,
        s => ns,
        ns => s,
        p => np,
        np => p,
        l => ge,
        ge => l,
        le => g,
        g => le,
        None => None,
    }
}

/// The flag-producing instruction a conditional consumes.
#[derive(Clone)]
enum Flags {
    Cmp(Expr, Expr),
    Test(Expr, Expr),
    /// Result of arithmetic (`dec ecx; jnz`) compared against zero.
    Result(Expr),
}

struct Ctx<'a> {
    bin: &'a Binary,
    bits: u32,
    frame_reg: Option<Register>,
    args: Vec<Register>,
    labels: BTreeSet<u64>,
    /// Registers assigned since the last call, used to guess call arguments.
    written: Vec<Register>,
    pushes: Vec<Expr>,
}

impl Ctx<'_> {
    fn name_or(&self, va: u64, prefix: &str) -> Expr {
        if let Some(&si) = self.bin.string_by_va.get(&va).filter(|_| !self.bin.is_executable(va)) {
            let s = &self.bin.strings[si];
            let mut v: String = s.value.chars().take(80).collect();
            if s.value.chars().count() > 80 {
                v.push('…');
            }
            let p = if s.encoding == StringEncoding::Utf16 { "L" } else { "" };
            return Expr::tok(format!("{p}\"{}\"", v.escape_debug()), TokenKind::Address);
        }
        match self.bin.name_at(va) {
            Some(n) => Expr::tok(n, TokenKind::Symbol),
            None => Expr::tok(format!("{prefix}{va:X}"), TokenKind::Symbol),
        }
    }

    fn mem(&self, ins: &Ins, deref: bool) -> Expr {
        let size = ins.memory_size().size();
        let base = ins.memory_base();
        let seg = ins.memory_segment();
        if matches!(seg, Register::FS | Register::GS) && base == Register::None && ins.memory_index() == Register::None {
            let f = match (seg, size) {
                (Register::GS, 8) => "__readgsqword",
                (Register::GS, 4) => "__readgsdword",
                (Register::FS, 8) => "__readfsqword",
                (Register::FS, 4) => "__readfsdword",
                (Register::GS, _) => "__readgsbyte",
                _ => "__readfsbyte",
            };
            return Expr(vec![Token { t: f.into(), k: TokenKind::Keyword }, Token { t: "(".into(), k: TokenKind::Punct }], false)
                .cat(Expr::num(ins.memory_displacement64() as i128))
                .cat(Expr::tok(")", TokenKind::Punct));
        }
        let index = ins.memory_index();
        let disp = ins.memory_displacement64();
        // Absolute / RIP-relative: a global.
        if base == Register::RIP || base == Register::EIP || (base == Register::None && index == Register::None) {
            let addr = if base == Register::None { disp } else { ins.ip_rel_memory_address() };
            let name = self.name_or(addr, size_prefix(size));
            let literal = name.0.first().is_some_and(|t| t.k == TokenKind::Address);
            return if deref || literal { name } else { Expr(vec![Token { t: "&".into(), k: TokenKind::Punct }], false).cat(name) };
        }
        // Stack slots.
        let sdisp = disp as i64 as i128;
        if index == Register::None && (Some(base) == self.frame_reg || base == Register::RSP || base == Register::ESP) {
            let name = if base == Register::RSP || base == Register::ESP {
                format!("var_{:X}", sdisp)
            } else if sdisp < 0 {
                format!("var_{:X}", -sdisp)
            } else {
                format!("arg_{:X}", sdisp)
            };
            let e = Expr::tok(name, TokenKind::Register);
            return if deref { e } else { Expr(vec![Token { t: "&".into(), k: TokenKind::Punct }], false).cat(e) };
        }
        let mut addr = if base != Register::None { Some(Expr::reg(&reg_name(base))) } else { None };
        if index != Register::None {
            let mut ie = Expr::reg(&reg_name(index));
            let scale = ins.memory_index_scale();
            if scale > 1 {
                ie = Expr::binop(ie, "*", Expr::num(scale as i128));
            }
            addr = Some(match addr {
                Some(a) => Expr::binop(a, "+", ie),
                None => ie,
            });
        }
        let disp_s = if self.bits == 64 { disp as i64 as i128 } else { disp as u32 as i32 as i128 };
        if disp_s != 0 || addr.is_none() {
            addr = Some(match addr {
                Some(a) if disp_s < 0 => Expr::binop(a, "-", Expr::num(-disp_s)),
                Some(a) => Expr::binop(a, "+", Expr::num(disp_s)),
                None => Expr::num(disp_s),
            });
        }
        let addr = addr.unwrap();
        if !deref {
            return addr;
        }
        let mut v = vec![Token { t: format!("*({} *)", size_type(size)), k: TokenKind::Keyword }];
        v.extend(addr.wrap().0);
        Expr(v, false)
    }

    fn op(&self, ins: &Ins, i: u32) -> Expr {
        match ins.op_kind(i) {
            OpKind::Register => Expr::reg(&reg_name(ins.op_register(i))),
            OpKind::Memory => self.mem(ins, true),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => self.name_or(ins.near_branch_target(), "loc_"),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                let v = ins.immediate(i);
                // Address-like immediates become names (`push offset aText`).
                if v >= 0x1000 && self.bin.range_of(v).is_some() {
                    return self.name_or(v, "off_");
                }
                let signed = match ins.op_kind(i) {
                    OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate64 => v as i64 as i128,
                    OpKind::Immediate8to32 | OpKind::Immediate32 => v as u32 as i32 as i128,
                    _ => v as i128,
                };
                // Small negatives read better signed; masks read better unsigned.
                if (-4096..0).contains(&signed) {
                    Expr::num(signed)
                } else {
                    Expr::num(v as i128)
                }
            }
            _ => Expr::tok("?", TokenKind::Text),
        }
    }
}

trait Cat {
    fn cat(self, other: Expr) -> Expr;
}
impl Cat for Expr {
    fn cat(mut self, other: Expr) -> Expr {
        self.0.extend(other.0);
        self
    }
}

fn size_prefix(size: usize) -> &'static str {
    match size {
        1 => "byte_",
        2 => "word_",
        4 => "dword_",
        8 => "qword_",
        _ => "unk_",
    }
}

fn is_prologue_noise(ins: &Ins, frame: Option<Register>) -> bool {
    match ins.mnemonic() {
        Mnemonic::Push | Mnemonic::Pop => ins.op_kind(0) == OpKind::Register && is_callee_saved(ins.op_register(0)),
        Mnemonic::Sub | Mnemonic::Add => {
            ins.op_kind(0) == OpKind::Register
                && matches!(ins.op_register(0), Register::RSP | Register::ESP)
                && ins.op_kind(1) != OpKind::Register
        }
        Mnemonic::Mov => {
            ins.op_kind(0) == OpKind::Register
                && Some(ins.op_register(0)) == frame
                && ins.op_kind(1) == OpKind::Register
                && matches!(ins.op_register(1), Register::RSP | Register::ESP)
        }
        Mnemonic::Leave | Mnemonic::Nop | Mnemonic::Int3 | Mnemonic::Endbr64 | Mnemonic::Endbr32 => true,
        _ => false,
    }
}

fn is_callee_saved(r: Register) -> bool {
    matches!(
        r.full_register(),
        Register::RBX | Register::RBP | Register::RSI | Register::RDI | Register::R12 | Register::R13 | Register::R14 | Register::R15
    ) || matches!(r, Register::EBX | Register::EBP | Register::ESI | Register::EDI)
}

impl Binary {
    /// C-like pseudocode for the function containing `va` (x86 / x86-64).
    pub fn pseudocode(&self, va: u64) -> Option<Pseudocode> {
        let a = self.analysis.as_ref()?;
        let idx = self.function_index_containing(va)?;
        let f = &a.functions[idx];
        let name = self.function_name(f);
        if !matches!(self.info.arch, Arch::X86 | Arch::X86_64) {
            return Some(Pseudocode {
                address: f.address,
                name,
                lines: Vec::new(),
                note: Some(format!("Pseudocode for {} is on the roadmap; use the listing or graph view.", self.info.arch.label())),
            });
        }
        let bits = if self.info.arch == Arch::X86 { 32 } else { 64 };

        // Decode every block once.
        let mut blocks: BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)> = BTreeMap::new();
        for b in &f.blocks {
            let bytes = self.bytes_at(b.start)?;
            let len = ((b.end - b.start) as usize).min(bytes.len());
            let mut d = Decoder::with_ip(bits, &bytes[..len], b.start, DecoderOptions::NONE);
            let mut v = Vec::new();
            while d.can_decode() {
                let i = d.decode();
                if i.is_invalid() {
                    break;
                }
                v.push(i);
            }
            blocks.insert(b.start, (v, b.succs.clone()));
        }
        let all: Vec<&Ins> = blocks.values().flat_map(|(v, _)| v.iter()).collect();

        // Frame pointer: `mov rbp, rsp` in the entry block.
        let frame_reg = blocks.get(&f.address).and_then(|(v, _)| {
            v.iter().take(8).find_map(|i| {
                (i.mnemonic() == Mnemonic::Mov
                    && i.op_kind(0) == OpKind::Register
                    && i.op_kind(1) == OpKind::Register
                    && matches!(i.op_register(1), Register::RSP | Register::ESP))
                .then(|| i.op_register(0))
            })
        });

        // Arguments: calling-convention registers read before being written.
        let conv: &[Register] = match (bits, self.info.format) {
            (64, Format::Pe) => &[Register::RCX, Register::RDX, Register::R8, Register::R9],
            (64, _) => &[Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::R8, Register::R9],
            _ => &[],
        };
        let mut args = Vec::new();
        if !conv.is_empty() {
            let mut written = BTreeSet::new();
            for i in blocks.get(&f.address).map(|(v, _)| v.as_slice()).unwrap_or(&[]) {
                for o in 0..i.op_count() {
                    if i.op_kind(o) == OpKind::Register {
                        let r = i.op_register(o).full_register();
                        let is_dst = o == 0 && !matches!(i.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push);
                        let self_xor = i.mnemonic() == Mnemonic::Xor && i.op_count() == 2 && i.op_register(0) == i.op_register(1);
                        if !is_dst && !written.contains(&r) && conv.contains(&r) && !self_xor && !args.contains(&r) {
                            args.push(r);
                        }
                        if is_dst {
                            written.insert(r);
                        }
                    }
                    if i.op_kind(o) == OpKind::Memory {
                        for r in [i.memory_base(), i.memory_index()] {
                            let r = r.full_register();
                            if conv.contains(&r) && !written.contains(&r) && !args.contains(&r) {
                                args.push(r);
                            }
                        }
                    }
                }
                if i.mnemonic() == Mnemonic::Call {
                    break;
                }
            }
            // Keep the convention's order and fill gaps (an arg 3 implies args 1 and 2).
            let last = conv.iter().rposition(|r| args.contains(r));
            args = last.map(|l| conv[..=l].to_vec()).unwrap_or_default();
        }

        // Labels: every jump target inside the function.
        let mut labels = BTreeSet::new();
        for (_, succs) in blocks.values() {
            for e in succs {
                if e.kind != crate::model::EdgeKind::Fall {
                    labels.insert(e.to);
                }
            }
        }

        let mut ctx = Ctx { bin: self, bits, frame_reg, args: args.clone(), labels, written: Vec::new(), pushes: Vec::new() };
        let ret_ty = if all.iter().any(|i| i.mnemonic() == Mnemonic::Ret) && writes_rax_before_ret(&blocks) { "__int64" } else { "void" };

        let mut out: Vec<PseudoLine> = Vec::new();
        // Signature.
        let mut sig = Line::default();
        sig.push(ret_ty, TokenKind::Keyword).sp().push(name.clone(), TokenKind::Symbol).p("(");
        for (n, r) in args.iter().enumerate() {
            if n > 0 {
                sig.p(", ");
            }
            sig.push("__int64", TokenKind::Keyword).sp().push(reg_name(*r), TokenKind::Register);
        }
        sig.p(")");
        out.push(PseudoLine { address: Some(f.address), indent: 0, tokens: sig.toks });
        out.push(PseudoLine { address: None, indent: 0, tokens: vec![Token { t: "{".into(), k: TokenKind::Punct }] });

        let order: Vec<u64> = blocks.keys().copied().collect();
        let mut emitted = BTreeSet::new();
        emit_range(&mut ctx, &blocks, &order, 0, order.len(), 1, &mut out, &mut emitted);
        out.push(PseudoLine { address: None, indent: 0, tokens: vec![Token { t: "}".into(), k: TokenKind::Punct }] });

        // Keep only labels that some `goto` still targets.
        let mut used = BTreeSet::new();
        for l in &out {
            if let Some(i) = l.tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "goto") {
                if let Some(t) = l.tokens[i + 1..].iter().find(|t| t.k == TokenKind::Symbol) {
                    used.insert(t.t.clone());
                }
            }
        }
        out.retain(|l| {
            let is_label = l.tokens.len() == 2 && l.tokens[1].t == ":" && l.tokens[0].k == TokenKind::Symbol;
            !is_label || used.contains(&l.tokens[0].t)
        });
        let _ = &ctx.args;
        Some(Pseudocode { address: f.address, name, lines: out, note: None })
    }
}

fn writes_rax_before_ret(blocks: &BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)>) -> bool {
    blocks.values().any(|(v, _)| {
        v.last().is_some_and(|l| l.mnemonic() == Mnemonic::Ret)
            && v.iter().rev().skip(1).take(6).any(|i| {
                i.op_count() > 0
                    && i.op_kind(0) == OpKind::Register
                    && i.op_register(0).full_register() == Register::RAX
                    && i.mnemonic() != Mnemonic::Push
                    || i.mnemonic() == Mnemonic::Call
            })
    })
}

/// Emits blocks `order[from..to]` with simple structuring.
#[allow(clippy::too_many_arguments)]
fn emit_range(
    ctx: &mut Ctx,
    blocks: &BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)>,
    order: &[u64],
    from: usize,
    to: usize,
    indent: u8,
    out: &mut Vec<PseudoLine>,
    emitted: &mut BTreeSet<u64>,
) {
    let pos: HashMap<u64, usize> = order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
    let mut i = from;
    while i < to {
        let start = order[i];
        emitted.insert(start);
        let (insns, succs) = &blocks[&start];

        // do { } while: a later block in range jumps back here and nothing outside jumps into the body.
        let loop_end = (i..to).rev().find(|&j| {
            blocks[&order[j]].1.iter().any(|e| e.to == start && e.kind == crate::model::EdgeKind::True)
                && blocks[&order[j]].0.last().is_some_and(|l| l.condition_code() != ConditionCode::None)
        });
        if let Some(j) = loop_end.filter(|&j| j > i && single_entry(blocks, order, &pos, i, j + 1)) {
            if ctx.labels.contains(&start) && has_outside_jump_to(blocks, order, i, j + 1, start) {
                label(out, start, indent);
            }
            out.push(PseudoLine {
                address: Some(start),
                indent,
                tokens: vec![Token { t: "do".into(), k: TokenKind::Keyword }, Token { t: " {".into(), k: TokenKind::Punct }],
            });
            // Body without the final conditional jump.
            emit_range_tail_cond(ctx, blocks, order, i, j + 1, indent + 1, out, emitted);
            let (last_insns, _) = &blocks[&order[j]];
            let jcc = last_insns.last().unwrap();
            let mut l = Line::default();
            l.p("} ").kw("while").p(" (").extend(condition(ctx, last_insns, jcc.condition_code())).p(");");
            out.push(PseudoLine { address: Some(jcc.ip()), indent, tokens: l.toks });
            i = j + 1;
            continue;
        }

        if ctx.labels.contains(&start) && (i > from || has_outside_jump_to(blocks, order, from, to, start)) {
            label(out, start, indent);
        }

        let last = insns.last();
        let is_jcc = last.is_some_and(|l| {
            l.condition_code() != ConditionCode::None
                && matches!(l.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
        });
        let body_end = if is_jcc { insns.len() - 1 } else { insns.len() };
        emit_insns(ctx, &insns[..body_end], indent, out, &pos, order, i);

        if is_jcc {
            let jcc = last.unwrap();
            let target = jcc.near_branch_target();
            // if (!cond) { fallthrough blocks } when the jump skips forward over a single-entry region.
            if let Some(&tj) = pos.get(&target) {
                if tj > i + 1
                    && tj <= to
                    && single_entry(blocks, order, &pos, i + 1, tj)
                    && !region_escapes(blocks, order, i + 1, tj, target)
                {
                    let mut l = Line::default();
                    l.kw("if").p(" (").extend(condition(ctx, insns, negate(jcc.condition_code()))).p(") {");
                    out.push(PseudoLine { address: Some(jcc.ip()), indent, tokens: l.toks });
                    emit_range(ctx, blocks, order, i + 1, tj, indent + 1, out, emitted);
                    out.push(PseudoLine { address: None, indent, tokens: vec![Token { t: "}".into(), k: TokenKind::Punct }] });
                    i = tj;
                    continue;
                }
            }
            let mut l = Line::default();
            l.kw("if")
                .p(" (")
                .extend(condition(ctx, insns, jcc.condition_code()))
                .p(") ")
                .kw("goto")
                .sp()
                .extend(ctx.name_or(target, "loc_"))
                .p(";");
            out.push(PseudoLine { address: Some(jcc.ip()), indent, tokens: l.toks });
        } else if let Some(l) = last {
            // Unconditional jump to the block that follows anyway: drop it.
            if matches!(l.mnemonic(), Mnemonic::Jmp)
                && matches!(l.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
            {
                let t = l.near_branch_target();
                let next = order.get(i + 1).copied();
                if Some(t) != next || i + 1 >= to {
                    let mut line = Line::default();
                    if pos.contains_key(&t) {
                        line.kw("goto").sp().extend(ctx.name_or(t, "loc_")).p(";");
                    } else {
                        // Tail call.
                        line.kw("return").sp().extend(ctx.name_or(t, "sub_")).p("(").extend(args_expr(ctx)).p(");");
                    }
                    out.push(PseudoLine { address: Some(l.ip()), indent, tokens: line.toks });
                }
            }
        }
        let _ = succs;
        i += 1;
    }
}

/// Like `emit_range` but the very last block's terminating jcc is left for the caller (loop condition).
#[allow(clippy::too_many_arguments)]
fn emit_range_tail_cond(
    ctx: &mut Ctx,
    blocks: &BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)>,
    order: &[u64],
    from: usize,
    to: usize,
    indent: u8,
    out: &mut Vec<PseudoLine>,
    emitted: &mut BTreeSet<u64>,
) {
    if to - from > 1 {
        // Inner blocks: guard against recursing into the same loop by emitting them as straight code.
        let pos: HashMap<u64, usize> = order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        for k in from..to - 1 {
            let a = order[k];
            emitted.insert(a);
            if k > from && ctx.labels.contains(&a) {
                label(out, a, indent);
            }
            let (insns, _) = &blocks[&a];
            emit_insns_with_branches(ctx, insns, indent, out, &pos, order, k);
        }
    }
    let a = order[to - 1];
    emitted.insert(a);
    if to - 1 > from && ctx.labels.contains(&a) {
        label(out, a, indent);
    }
    let (insns, _) = &blocks[&a];
    let pos: HashMap<u64, usize> = order.iter().enumerate().map(|(i, a)| (*a, i)).collect();
    emit_insns(ctx, &insns[..insns.len().saturating_sub(1)], indent, out, &pos, order, to - 1);
}

fn emit_insns_with_branches(
    ctx: &mut Ctx,
    insns: &[Ins],
    indent: u8,
    out: &mut Vec<PseudoLine>,
    pos: &HashMap<u64, usize>,
    order: &[u64],
    here: usize,
) {
    let last = insns.last();
    let is_jcc = last.is_some_and(|l| {
        l.condition_code() != ConditionCode::None
            && matches!(l.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
    });
    let end = if is_jcc { insns.len() - 1 } else { insns.len() };
    emit_insns(ctx, &insns[..end], indent, out, pos, order, here);
    if is_jcc {
        let j = last.unwrap();
        let mut l = Line::default();
        l.kw("if")
            .p(" (")
            .extend(condition(ctx, insns, j.condition_code()))
            .p(") ")
            .kw("goto")
            .sp()
            .extend(ctx.name_or(j.near_branch_target(), "loc_"))
            .p(";");
        out.push(PseudoLine { address: Some(j.ip()), indent, tokens: l.toks });
    }
}

fn label(out: &mut Vec<PseudoLine>, at: u64, indent: u8) {
    out.push(PseudoLine {
        address: Some(at),
        indent: indent.saturating_sub(1),
        tokens: vec![Token { t: format!("loc_{at:X}"), k: TokenKind::Symbol }, Token { t: ":".into(), k: TokenKind::Punct }],
    });
}

fn single_entry(
    blocks: &BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)>,
    order: &[u64],
    pos: &HashMap<u64, usize>,
    from: usize,
    to: usize,
) -> bool {
    // No block outside [from, to) jumps into (from, to).
    let inside: BTreeSet<u64> = order[from..to].iter().copied().collect();
    for (a, (_, succs)) in blocks {
        let p = pos[a];
        if p >= from && p < to {
            continue;
        }
        for e in succs {
            if inside.contains(&e.to) && e.to != order[from] {
                return false;
            }
        }
    }
    true
}

fn region_escapes(blocks: &BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)>, order: &[u64], from: usize, to: usize, join: u64) -> bool {
    // A region "escapes" if it jumps backwards out of itself; forward exits past the join are fine as gotos.
    let first = order[from];
    order[from..to].iter().any(|a| blocks[a].1.iter().any(|e| e.to < first && e.to != join))
}

fn has_outside_jump_to(
    blocks: &BTreeMap<u64, (Vec<Ins>, Vec<crate::model::Edge>)>,
    order: &[u64],
    from: usize,
    to: usize,
    target: u64,
) -> bool {
    let inside: BTreeSet<u64> = order[from..to].iter().copied().collect();
    blocks.iter().any(|(a, (_, s))| !inside.contains(a) && s.iter().any(|e| e.to == target && e.kind != crate::model::EdgeKind::Fall))
}

fn args_expr(ctx: &Ctx) -> Expr {
    let mut e = Expr::default();
    if ctx.bits == 32 {
        for (n, p) in ctx.pushes.iter().rev().enumerate() {
            if n > 0 {
                e = e.cat(Expr::tok(", ", TokenKind::Punct));
            }
            e = e.cat(p.clone());
        }
        return e;
    }
    let conv: &[Register] = if ctx.bin.info.format == Format::Pe {
        &[Register::RCX, Register::RDX, Register::R8, Register::R9]
    } else {
        &[Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::R8, Register::R9]
    };
    let used = conv.iter().rposition(|r| ctx.written.contains(r)).map(|i| i + 1).unwrap_or(0);
    for (n, r) in conv[..used].iter().enumerate() {
        if n > 0 {
            e = e.cat(Expr::tok(", ", TokenKind::Punct));
        }
        e = e.cat(Expr::reg(&reg_name(*r)));
    }
    e
}

/// Arguments for a call with a known prototype: one per parameter, from the convention.
fn proto_args(ctx: &Ctx, p: &crate::protos::Proto) -> Expr {
    let n = p.params.iter().filter(|x| **x != "...").count();
    if ctx.bits == 32 {
        return args_expr(ctx);
    }
    let conv: &[Register] = if ctx.bin.info.format == Format::Pe {
        &[Register::RCX, Register::RDX, Register::R8, Register::R9]
    } else {
        &[Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::R8, Register::R9]
    };
    let mut e = Expr::default();
    for k in 0..n {
        if k > 0 {
            e = e.cat(Expr::tok(", ", TokenKind::Punct));
        }
        match conv.get(k) {
            Some(r) => e = e.cat(Expr::reg(&reg_name(*r))),
            // Win64 passes arguments 5+ at [rsp+0x20], [rsp+0x28], … — the same slots as `var_20`, `var_28`.
            None if ctx.bin.info.format == Format::Pe => e = e.cat(Expr::tok(format!("var_{:X}", 0x20 + 8 * (k - 4)), TokenKind::Register)),
            None => e = e.cat(Expr::tok(format!("stack_arg{}", k + 1), TokenKind::Register)),
        }
    }
    e
}

fn condition(ctx: &Ctx, insns: &[Ins], cc: ConditionCode) -> Expr {
    // Find the flag producer: the last flag-writing instruction before the jcc.
    let producer = insns.iter().rev().skip(1).find(|i| writes_flags(i));
    let flags = producer.map(|p| match p.mnemonic() {
        Mnemonic::Cmp => Flags::Cmp(ctx.op(p, 0), ctx.op(p, 1)),
        Mnemonic::Test => Flags::Test(ctx.op(p, 0), ctx.op(p, 1)),
        _ => Flags::Result(ctx.op(p, 0)),
    });
    match (flags, cc) {
        (Some(Flags::Cmp(a, b)), cc) if cond_op(cc, false).0 != "?" => {
            let (op, signed) = cond_op(cc, false);
            let a = if signed || op == "==" || op == "!=" {
                a
            } else {
                Expr(vec![Token { t: "(unsigned)".into(), k: TokenKind::Keyword }], false).cat(a.wrap())
            };
            Expr::binop(a, op, b)
        }
        (Some(Flags::Test(a, b)), ConditionCode::e | ConditionCode::ne) => {
            let eq = cc == ConditionCode::e;
            if a.text() == b.text() {
                Expr::binop(a, if eq { "==" } else { "!=" }, Expr::num(0))
            } else {
                Expr::binop(Expr::binop(a, "&", b), if eq { "==" } else { "!=" }, Expr::num(0))
            }
        }
        (
            Some(Flags::Test(a, b)),
            ConditionCode::s | ConditionCode::ns | ConditionCode::l | ConditionCode::ge | ConditionCode::le | ConditionCode::g,
        ) => {
            let v = if a.text() == b.text() { a } else { Expr::binop(a, "&", b) };
            let op = match cc {
                ConditionCode::s | ConditionCode::l => "<",
                ConditionCode::ns | ConditionCode::ge => ">=",
                ConditionCode::le => "<=",
                _ => ">",
            };
            Expr::binop(v, op, Expr::num(0))
        }
        (Some(Flags::Result(r)), ConditionCode::e | ConditionCode::ne | ConditionCode::s | ConditionCode::ns) => {
            let op = match cc {
                ConditionCode::e => "==",
                ConditionCode::ne => "!=",
                ConditionCode::s => "<",
                _ => ">=",
            };
            Expr::binop(r, op, Expr::num(0))
        }
        (_, cc) => Expr::tok(format!("__flags_{:?}", cc), TokenKind::Keyword),
    }
}

fn writes_flags(i: &Ins) -> bool {
    matches!(
        i.mnemonic(),
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Bt
            | Mnemonic::Imul
    )
}

fn emit_insns(
    ctx: &mut Ctx,
    insns: &[Ins],
    indent: u8,
    out: &mut Vec<PseudoLine>,
    _pos: &HashMap<u64, usize>,
    _order: &[u64],
    _here: usize,
) {
    for (n, ins) in insns.iter().enumerate() {
        if is_prologue_noise(ins, ctx.frame_reg) {
            continue;
        }
        // cmp/test feeding a following jcc/setcc/cmovcc are folded into that consumer.
        if matches!(ins.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
            continue;
        }
        let mut l = Line::default();
        let m = ins.mnemonic();
        let dst = || ctx.op(ins, 0);
        let src = |k: u32| ctx.op(ins, k);
        let dst_reg = (ins.op_count() > 0 && ins.op_kind(0) == OpKind::Register).then(|| ins.op_register(0).full_register());
        match m {
            Mnemonic::Mov => {
                l.extend(dst()).p(" = ").extend(src(1)).p(";");
            }
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
                let ty = match (m, ins.op_register(0).size()) {
                    (Mnemonic::Movzx, 4) => "(uint32_t)",
                    (Mnemonic::Movzx, _) => "(uint64_t)",
                    (_, 4) => "(int32_t)",
                    _ => "(int64_t)",
                };
                l.extend(dst()).p(" = ").kw(ty).extend(src(1).wrap()).p(";");
            }
            Mnemonic::Lea => {
                l.extend(dst()).p(" = ").extend(ctx.mem(ins, false)).p(";");
            }
            Mnemonic::Xor
                if ins.op_count() == 2
                    && ins.op_kind(0) == OpKind::Register
                    && ins.op_kind(1) == OpKind::Register
                    && ins.op_register(0) == ins.op_register(1) =>
            {
                l.extend(dst()).p(" = ").extend(Expr::num(0)).p(";");
            }
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror => {
                let op = match m {
                    Mnemonic::Add => "+=",
                    Mnemonic::Sub => "-=",
                    Mnemonic::And => "&=",
                    Mnemonic::Or => "|=",
                    Mnemonic::Xor => "^=",
                    Mnemonic::Shl => "<<=",
                    Mnemonic::Shr | Mnemonic::Sar => ">>=",
                    Mnemonic::Rol => "= __ROL__",
                    _ => "= __ROR__",
                };
                if op.starts_with("= __") {
                    l.extend(dst()).p(" = ").kw(&op[2..]).p("(").extend(dst()).p(", ").extend(src(1)).p(");");
                } else {
                    l.extend(dst()).p(&format!(" {op} ")).extend(src(1)).p(";");
                }
            }
            Mnemonic::Inc => {
                l.extend(dst()).p("++;");
            }
            Mnemonic::Dec => {
                l.extend(dst()).p("--;");
            }
            Mnemonic::Neg => {
                l.extend(dst()).p(" = -").extend(dst().wrap()).p(";");
            }
            Mnemonic::Not => {
                l.extend(dst()).p(" = ~").extend(dst().wrap()).p(";");
            }
            Mnemonic::Imul if ins.op_count() >= 2 => {
                if ins.op_count() == 3 {
                    l.extend(dst()).p(" = ").extend(Expr::binop(src(1), "*", src(2))).p(";");
                } else {
                    l.extend(dst()).p(" *= ").extend(src(1)).p(";");
                }
            }
            Mnemonic::Push => {
                ctx.pushes.push(src(0));
                continue;
            }
            Mnemonic::Pop => {
                l.extend(dst()).p(" = ").kw("__pop").p("();");
            }
            Mnemonic::Call => {
                let callee = if matches!(ins.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    ctx.name_or(ins.near_branch_target(), "sub_")
                } else {
                    let e = ctx.op(ins, 0);
                    if ins.op_kind(0) == OpKind::Memory && ins.is_ip_rel_memory_operand()
                        || ins.memory_base() == Register::None && ins.op_kind(0) == OpKind::Memory
                    {
                        e
                    } else {
                        Expr(vec![Token { t: "((void (*)())".into(), k: TokenKind::Keyword }], false)
                            .cat(e)
                            .cat(Expr::tok(")", TokenKind::Punct))
                    }
                };
                let reg = if ctx.bits == 64 { "rax" } else { "eax" };
                let proto = callee.0.first().and_then(|t| crate::protos::lookup(&t.t));
                let args = match proto {
                    Some(p) => proto_args(ctx, p),
                    None => args_expr(ctx),
                };
                l.push(reg, TokenKind::Register).p(" = ").extend(callee).p("(").extend(args).p(");");
                ctx.written.clear();
                ctx.pushes.clear();
                out.push(PseudoLine { address: Some(ins.ip()), indent, tokens: l.toks });
                continue;
            }
            Mnemonic::Ret => {
                let returns_value = insns[..n].iter().rev().take(6).any(|i| {
                    i.op_count() > 0 && i.op_kind(0) == OpKind::Register && i.op_register(0).full_register() == Register::RAX
                        || i.mnemonic() == Mnemonic::Call
                });
                if returns_value {
                    l.kw("return").sp().push(if ctx.bits == 64 { "rax" } else { "eax" }, TokenKind::Register).p(";");
                } else {
                    l.kw("return").p(";");
                }
            }
            Mnemonic::Jmp if !matches!(ins.op_kind(0), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) => {
                // `jmp [slot]` is a tail call (import thunks); `jmp reg` is a computed jump.
                if ins.op_kind(0) == OpKind::Memory {
                    l.kw("return").sp().extend(ctx.op(ins, 0)).p("(").extend(args_expr(ctx)).p(");");
                } else {
                    l.kw("goto").p(" *").extend(ctx.op(ins, 0)).p(";");
                }
            }
            Mnemonic::Jmp => continue, // direct jumps are handled by the block emitter
            _ if ins.condition_code() != ConditionCode::None && format!("{m:?}").starts_with("Set") => {
                l.extend(dst()).p(" = ").extend(condition(ctx, &insns[..=n], ins.condition_code())).p(";");
            }
            _ if ins.condition_code() != ConditionCode::None && format!("{m:?}").starts_with("Cmov") => {
                l.kw("if")
                    .p(" (")
                    .extend(condition(ctx, &insns[..=n], ins.condition_code()))
                    .p(") ")
                    .extend(dst())
                    .p(" = ")
                    .extend(src(1))
                    .p(";");
            }
            Mnemonic::Cmpxchg => {
                let reg = if ctx.bits == 64 { "rax" } else { "eax" };
                l.push(reg, TokenKind::Register)
                    .p(" = ")
                    .kw("_InterlockedCompareExchange")
                    .p("(&")
                    .extend(dst())
                    .p(", ")
                    .extend(src(1))
                    .p(", ")
                    .push(reg, TokenKind::Register)
                    .p(");");
            }
            Mnemonic::Xchg if ins.op_kind(0) == OpKind::Memory || ins.op_kind(1) == OpKind::Memory => {
                let (m_, r_) = if ins.op_kind(0) == OpKind::Memory { (0, 1) } else { (1, 0) };
                l.extend(src(r_)).p(" = ").kw("_InterlockedExchange").p("(&").extend(src(m_)).p(", ").extend(src(r_)).p(");");
            }
            Mnemonic::Rdtsc => {
                l.push("rax", TokenKind::Register).p(" = ").kw("__rdtsc").p("();");
            }
            Mnemonic::Cpuid => {
                l.kw("__cpuid").p("(").push("eax", TokenKind::Register).p(", ").push("ecx", TokenKind::Register).p(");");
            }
            Mnemonic::Cdq | Mnemonic::Cqo | Mnemonic::Cdqe | Mnemonic::Cwde => continue,
            Mnemonic::Ud2 | Mnemonic::Hlt => {
                l.kw("__fastfail").p("();");
            }
            _ => {
                let ops: Vec<String> = (0..ins.op_count()).map(|k| ctx.op(ins, k).text()).collect();
                l.kw("__asm").p(" { ").push(format!("{} {}", format!("{m:?}").to_lowercase(), ops.join(", ")), TokenKind::Text).p(" }");
            }
        }
        if let Some(r) = dst_reg {
            if !ctx.written.contains(&r) {
                ctx.written.push(r);
            }
        }
        out.push(PseudoLine { address: Some(ins.ip()), indent, tokens: l.toks });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn negate_roundtrip() {
        use iced_x86::ConditionCode::*;
        for c in [o, no, b, ae, e, ne, be, a, s, ns, p, np, l, ge, le, g] {
            assert_eq!(super::negate(super::negate(c)), c);
        }
    }
}
