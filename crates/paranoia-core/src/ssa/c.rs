//! C text generated from the SSA IR.
//!
//! * **Out of SSA**: a phi and its inputs are one variable (congruence classes); the entry value
//!   of an argument register is a parameter (`a1`…), every other class a local (`v1`…).
//! * **Stack**: the stack pointer is tracked as an offset from its value on entry, so stack memory
//!   becomes named slots (`var_10`, `arg_8`) and `rsp` arithmetic disappears.
//! * **Conditions** come from the last flag-setting statement before a branch (`cmp`, `test`, or
//!   arithmetic on a value).
//! * **Calls** receive the argument registers set before them (64-bit) or the values pushed for
//!   them (32-bit); a value used once, in the same block, is written in place of its variable.
//! * **Structure**: labels and gotos first, then forward `if (…) goto L;` regions become `if` blocks
//!   and the existing passes recover `do`/`while`/`for` loops.

use std::collections::{HashMap, HashSet};

use super::{Block, Expr, Kind, SsaFunction, Var, RSP};
use crate::model::{Token, TokenKind};
use crate::pseudo::PseudoLine;

/// rbx, rbp, rsi, rdi, r12–r15: preserved across calls; their saves and restores are bookkeeping.
const CALLEE_SAVED: [Var; 8] = [3, 5, 6, 7, 12, 13, 14, 15];

/// What the caller knows about the function.
pub(crate) struct COptions<'a> {
    pub name: &'a str,
    pub entry: u64,
    /// The function returns a value in rax / eax.
    pub returns: bool,
    /// Argument registers in calling-convention order (empty for 32-bit stack arguments).
    pub args: Vec<Var>,
    /// Name for a call target address (functions, imports).
    pub names: &'a dyn Fn(u64) -> Option<String>,
}

/// A global's name: its symbol, or IDA's size-based auto name (`dword_42AC2C`).
fn global_name(o: &COptions, addr: i64, size: u8) -> Option<String> {
    let a = u64::try_from(addr).ok().filter(|a| *a >= 0x1000)?;
    (o.names)(a).or_else(|| {
        let prefix = match size {
            1 => "byte_",
            2 => "word_",
            4 => "dword_",
            8 => "qword_",
            _ => "unk_",
        };
        Some(format!("{prefix}{a:X}"))
    })
}

fn tok(t: impl Into<String>, k: TokenKind) -> Token {
    Token { t: t.into(), k }
}

fn num(v: i64) -> Token {
    let t = if (-9..=9).contains(&v) {
        v.to_string()
    } else if v < 0 {
        format!("-{:#x}", v.unsigned_abs())
    } else {
        format!("{v:#x}")
    };
    tok(t, TokenKind::Number)
}

fn line(indent: u8, address: Option<u64>, tokens: Vec<Token>) -> PseudoLine {
    PseudoLine { address, indent, tokens: crate::pseudo_opt::merge(tokens) }
}

struct Dsu(HashMap<(Var, u32), (Var, u32)>);

impl Dsu {
    fn find(&mut self, x: (Var, u32)) -> (Var, u32) {
        let mut r = x;
        while let Some(&p) = self.0.get(&r) {
            if p == r {
                break;
            }
            r = p;
        }
        let mut c = x;
        while let Some(&p) = self.0.get(&c) {
            if p == r {
                break;
            }
            self.0.insert(c, r);
            c = p;
        }
        r
    }
    fn union(&mut self, a: (Var, u32), b: (Var, u32)) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.0.insert(ra.max(rb), ra.min(rb));
            self.0.entry(ra.min(rb)).or_insert(ra.min(rb));
        }
    }
}

struct Gen<'a> {
    f: &'a SsaFunction,
    o: &'a COptions<'a>,
    /// Stack pointer offset from its entry value, per rsp version.
    rsp: HashMap<u32, i64>,
    /// Other values that hold a stack address (a frame pointer, `lea rax, [rsp+…]`): their offset.
    ptr: HashMap<(Var, u32), i64>,
    /// Value → variable name (out-of-SSA class).
    names: HashMap<(Var, u32), String>,
    /// Values written in place of their use: value → its expression.
    inline: HashMap<(Var, u32), Expr>,
    params: Vec<String>,
    locals: Vec<String>,
}

impl Gen<'_> {
    fn reg_name(&self, v: Var) -> &'static str {
        self.f.names().get(v)
    }

    /// Stack offset of an address expression `rsp_n ± d`, if it is one.
    fn stack_off(&self, e: &Expr) -> Option<i64> {
        let base = |v: Var, n: u32| if v == RSP { self.rsp.get(&n).copied() } else { self.ptr.get(&(v, n)).copied() };
        match e {
            Expr::Use(v, n) => base(*v, *n),
            Expr::Bin(op @ ("+" | "-"), a, b) => match (&**a, &**b) {
                (Expr::Use(v, n), Expr::Const(d)) => {
                    let b = base(*v, *n)?;
                    Some(if *op == "+" { b + d } else { b - d })
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn slot(off: i64) -> String {
        if off < 0 {
            format!("var_{:X}", -off)
        } else {
            format!("arg_{off:X}")
        }
    }

    fn expr(&self, e: &Expr, top: bool, out: &mut Vec<Token>) {
        if let Some(off) = self.stack_off(e) {
            out.push(tok("&", TokenKind::Punct));
            out.push(tok(Self::slot(off), TokenKind::Register));
            return;
        }
        match e {
            Expr::Const(c) => out.push(num(*c)),
            Expr::Use(v, n) => {
                if let Some(x) = self.inline.get(&(*v, *n)) {
                    self.expr(x, top, out);
                } else if let Some(name) = self.names.get(&(*v, *n)) {
                    out.push(tok(name.clone(), TokenKind::Register));
                } else {
                    out.push(tok(self.reg_name(*v), TokenKind::Register));
                }
            }
            Expr::Bin("+" | "-", ..) if self.const_value(e, 0).is_some() => {
                out.push(num(self.const_value(e, 0).unwrap_or_default()));
            }
            Expr::Bin(op, a, b) => {
                if !top {
                    out.push(tok("(", TokenKind::Punct));
                }
                self.expr(a, false, out);
                out.push(tok(format!(" {} ", op.trim_end_matches('s')), TokenKind::Punct));
                self.expr(b, false, out);
                if !top {
                    out.push(tok(")", TokenKind::Punct));
                }
            }
            Expr::Un(op, a) => {
                out.push(tok(*op, TokenKind::Punct));
                self.expr(a, false, out);
            }
            Expr::Load(size, a) => {
                // A constant address, also one built in steps (`adrp` + `ldr [x1, #0x7c8]`).
                if let Some(addr) = self.const_value(a, 0) {
                    if let Some(n) = global_name(self.o, addr, *size) {
                        out.push(tok(n, TokenKind::Symbol));
                        return;
                    }
                }
                if let Some(off) = self.stack_off(a) {
                    out.push(tok(Self::slot(off), TokenKind::Register));
                } else {
                    out.push(tok(format!("*(uint{}_t *)", *size as u32 * 8), TokenKind::Keyword));
                    out.push(tok("(", TokenKind::Punct));
                    self.expr(a, true, out);
                    out.push(tok(")", TokenKind::Punct));
                }
            }
            Expr::Opaque(s) => out.push(tok(s.clone(), TokenKind::Text)),
        }
    }

    /// The value of an address expression made only of constants, `+` and `-` (through values
    /// written in place), e.g. an `adrp` page plus a load offset.
    fn const_value(&self, e: &Expr, depth: u8) -> Option<i64> {
        if depth > 8 {
            return None;
        }
        match e {
            Expr::Const(c) => Some(*c),
            Expr::Use(v, n) => self.inline.get(&(*v, *n)).and_then(|x| self.const_value(x, depth + 1)),
            Expr::Bin(op @ ("+" | "-"), a, b) => {
                let (x, y) = (self.const_value(a, depth + 1)?, self.const_value(b, depth + 1)?);
                Some(if *op == "+" { x.wrapping_add(y) } else { x.wrapping_sub(y) })
            }
            _ => None,
        }
    }

    fn e(&self, e: &Expr) -> Vec<Token> {
        let mut v = Vec::new();
        self.expr(e, true, &mut v);
        v
    }

    /// The condition a branch at the end of `b` tests, from the last flag setter before it.
    fn condition(&self, b: &Block, cc: &str) -> Vec<Token> {
        let setter = b.stmts.iter().rev().find(|s| s.flags);
        let op = |cc: &str| -> Option<(&'static str, bool)> {
            Some(match cc {
                "e" => ("==", false),
                "ne" => ("!=", false),
                "l" => ("<", false),
                "ge" => (">=", false),
                "g" => (">", false),
                "le" => ("<=", false),
                "b" => ("<", true),
                "ae" => (">=", true),
                "a" => (">", true),
                "be" => ("<=", true),
                _ => return None,
            })
        };
        let mut out = Vec::new();
        match setter.map(|s| &s.kind) {
            Some(Kind::Flags { test: false, a, b }) => {
                if let Some((o, unsigned)) = op(cc) {
                    if unsigned {
                        out.push(tok("(unsigned)", TokenKind::Keyword));
                    }
                    self.expr(a, false, &mut out);
                    out.push(tok(format!(" {o} "), TokenKind::Punct));
                    self.expr(b, false, &mut out);
                    return out;
                }
                if cc == "s" || cc == "ns" {
                    out.push(tok("(", TokenKind::Punct));
                    self.expr(a, false, &mut out);
                    out.push(tok(" - ", TokenKind::Punct));
                    self.expr(b, false, &mut out);
                    out.push(tok(if cc == "s" { ") < 0" } else { ") >= 0" }, TokenKind::Punct));
                    return out;
                }
            }
            Some(Kind::Flags { test: true, a, b }) => {
                let same = a == b;
                let rel = match cc {
                    "e" => Some(" == 0"),
                    "ne" => Some(" != 0"),
                    "s" if same => Some(" < 0"),
                    "ns" if same => Some(" >= 0"),
                    "le" if same => Some(" <= 0"),
                    "g" if same => Some(" > 0"),
                    _ => None,
                };
                if let Some(r) = rel {
                    if same {
                        self.expr(a, false, &mut out);
                    } else {
                        out.push(tok("(", TokenKind::Punct));
                        self.expr(a, false, &mut out);
                        out.push(tok(" & ", TokenKind::Punct));
                        self.expr(b, false, &mut out);
                        out.push(tok(")", TokenKind::Punct));
                    }
                    out.push(tok(r, TokenKind::Punct));
                    return out;
                }
            }
            Some(Kind::Assign { def, ver, .. }) if *def != RSP => {
                let rel = match cc {
                    "e" => Some(" == 0"),
                    "ne" => Some(" != 0"),
                    "s" => Some(" < 0"),
                    "ns" => Some(" >= 0"),
                    _ => None,
                };
                if let Some(r) = rel {
                    self.expr(&Expr::Use(*def, *ver), false, &mut out);
                    out.push(tok(r, TokenKind::Punct));
                    return out;
                }
            }
            _ => {}
        }
        out.push(tok(format!("__flags_{cc}"), TokenKind::Keyword));
        out
    }
}

/// Negates a condition: flips a top-level comparison, else wraps it in `!(…)`.
fn negate(c: &[Token]) -> Vec<Token> {
    let flips = [(" == ", " != "), (" != ", " == "), (" < ", " >= "), (" >= ", " < "), (" > ", " <= "), (" <= ", " > ")];
    let text: String = c.iter().map(|t| t.t.as_str()).collect();
    let mut depth = 0i32;
    let mut at: Vec<usize> = Vec::new();
    for (i, t) in c.iter().enumerate() {
        if t.k == TokenKind::Punct {
            for ch in t.t.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            if depth == 0 && flips.iter().any(|(a, _)| t.t.contains(a)) {
                at.push(i);
            }
        }
    }
    if at.len() == 1 && !text.contains("&&") && !text.contains("||") {
        let mut v = c.to_vec();
        let t = &mut v[at[0]];
        for (a, b) in flips {
            if t.t.contains(a) {
                t.t = t.t.replacen(a, b, 1);
                break;
            }
        }
        return v;
    }
    let mut v = vec![tok("!(", TokenKind::Punct)];
    v.extend(c.iter().cloned());
    v.push(tok(")", TokenKind::Punct));
    v
}

impl SsaFunction {
    /// The function as C-like lines generated from this SSA form.
    pub(crate) fn to_c(&self, o: &COptions) -> Vec<PseudoLine> {
        let f = self;
        // Stack pointer offsets.
        let mut rsp: HashMap<u32, i64> = HashMap::from([(0, 0)]);
        let mut changed = true;
        while changed {
            changed = false;
            for b in &f.blocks {
                for p in b.phis.iter().filter(|p| p.var == RSP) {
                    if rsp.contains_key(&p.ver) {
                        continue;
                    }
                    let offs: Vec<Option<i64>> = p.args.iter().map(|(_, n)| rsp.get(n).copied()).collect();
                    if let Some(Some(x)) = offs.first() {
                        if offs.iter().all(|y| *y == Some(*x)) {
                            rsp.insert(p.ver, *x);
                            changed = true;
                        }
                    }
                }
                for s in &b.stmts {
                    if let Kind::Assign { def: RSP, ver, expr, .. } = &s.kind {
                        if rsp.contains_key(ver) {
                            continue;
                        }
                        let off = match expr {
                            Expr::Use(RSP, n) => rsp.get(n).copied(),
                            Expr::Bin(op @ ("+" | "-"), a, c) => match (&**a, &**c) {
                                (Expr::Use(RSP, n), Expr::Const(d)) => rsp.get(n).map(|x| if *op == "+" { x + d } else { x - d }),
                                _ => None,
                            },
                            _ => None,
                        };
                        if let Some(x) = off {
                            rsp.insert(*ver, x);
                            changed = true;
                        }
                    }
                }
            }
        }

        // Out of SSA: a phi and its inputs are one variable.
        let mut dsu = Dsu(HashMap::new());
        for b in &f.blocks {
            for p in b.phis.iter().filter(|p| p.var != RSP) {
                for (_, n) in &p.args {
                    dsu.union((p.var, p.ver), (p.var, *n));
                }
            }
        }
        // How often each value is read, and where it is defined.
        let mut uses: HashMap<(Var, u32), usize> = HashMap::new();
        let mut phi_use: HashSet<(Var, u32)> = HashSet::new();
        for b in &f.blocks {
            for p in &b.phis {
                for (_, n) in &p.args {
                    phi_use.insert((p.var, *n));
                }
            }
            for s in b.stmts.iter().filter(|s| !s.dead) {
                for u in s.kind.uses() {
                    *uses.entry(u).or_default() += 1;
                }
            }
        }
        let mut g =
            Gen { f, o, rsp, ptr: HashMap::new(), names: HashMap::new(), inline: HashMap::new(), params: Vec::new(), locals: Vec::new() };
        // Values holding stack addresses, through assignments and agreeing phis.
        let mut more = true;
        while more {
            more = false;
            for b in &f.blocks {
                for p in b.phis.iter().filter(|p| p.var != RSP) {
                    if g.ptr.contains_key(&(p.var, p.ver)) {
                        continue;
                    }
                    let offs: Vec<Option<i64>> = p.args.iter().map(|(_, n)| g.ptr.get(&(p.var, *n)).copied()).collect();
                    if let Some(Some(x)) = offs.first() {
                        if offs.iter().all(|y| *y == Some(*x)) {
                            g.ptr.insert((p.var, p.ver), *x);
                            more = true;
                        }
                    }
                }
                for s in &b.stmts {
                    if let Kind::Assign { def, ver, expr, .. } = &s.kind {
                        if *def == RSP || g.ptr.contains_key(&(*def, *ver)) {
                            continue;
                        }
                        if let Some(off) = g.stack_off(expr) {
                            g.ptr.insert((*def, *ver), off);
                            more = true;
                        }
                    }
                }
            }
        }

        // Single-use values written in place: same block, read after, nothing in between that could
        // change what the expression reads (a store or a call, for loads).
        for b in &f.blocks {
            for (i, s) in b.stmts.iter().enumerate() {
                let Kind::Assign { def, ver, expr, .. } = &s.kind else { continue };
                if s.dead || *def == RSP || phi_use.contains(&(*def, *ver)) || uses.get(&(*def, *ver)) != Some(&1) {
                    continue;
                }
                if dsu.find((*def, *ver)) != (*def, *ver)
                    || f.blocks.iter().any(|bb| bb.phis.iter().any(|p| p.var == *def && dsu.find((p.var, p.ver)) == (*def, *ver)))
                {
                    continue;
                }
                let Some(j) =
                    b.stmts.iter().enumerate().skip(i + 1).find(|(_, t)| !t.dead && t.kind.uses().contains(&(*def, *ver))).map(|(j, _)| j)
                else {
                    continue;
                };
                let loads = {
                    let mut l = false;
                    fn has_load(e: &Expr, l: &mut bool) {
                        match e {
                            Expr::Load(..) => *l = true,
                            Expr::Bin(_, a, b) => {
                                has_load(a, l);
                                has_load(b, l);
                            }
                            Expr::Un(_, a) => has_load(a, l),
                            _ => {}
                        }
                    }
                    has_load(expr, &mut l);
                    l
                };
                // Reads of registers the expression uses must not be redefined in between. In SSA they
                // cannot be; memory can.
                let clobbered = loads
                    && b.stmts[i + 1..j].iter().any(|t| matches!(t.kind, Kind::Store { .. } | Kind::Call { .. } | Kind::Other { .. }));
                // Conditions are rendered at the branch, after every statement: keep flag inputs inline
                // only when used by the flags statement right before the branch.
                if !clobbered {
                    g.inline.insert((*def, *ver), expr.clone());
                }
            }
        }

        // Names: parameters for argument registers' entry values, locals for the rest.
        let mut seen_classes: HashMap<(Var, u32), String> = HashMap::new();
        let mut used_entry: Vec<Var> = Vec::new();
        for b in &f.blocks {
            // A call or a tail jump reads every argument register by convention; that alone does not
            // make them parameters of this function.
            for s in b.stmts.iter().filter(|s| !s.dead && !matches!(s.kind, Kind::Call { .. } | Kind::Branch { .. })) {
                for (v, n) in s.kind.uses() {
                    if n == 0 && v != RSP && !used_entry.contains(&v) {
                        used_entry.push(v);
                    }
                }
            }
        }
        let mut param_regs: Vec<Var> = o.args.iter().copied().filter(|a| used_entry.contains(a)).collect();
        // An argument implies the ones before it.
        if let Some(last) = param_regs.last().and_then(|l| o.args.iter().position(|a| a == l)) {
            param_regs = o.args[..=last].to_vec();
        }
        for (k, v) in param_regs.iter().enumerate() {
            let name = format!("a{}", k + 1);
            seen_classes.insert(dsu.find((*v, 0)), name.clone());
            g.params.push(name);
        }
        let mut next = 1;
        let mut name_of = |key: (Var, u32), dsu: &mut Dsu, g: &mut Gen| -> String {
            let root = dsu.find(key);
            if let Some(n) = seen_classes.get(&root) {
                return n.clone();
            }
            let n = if key.1 == 0 && root == key {
                // A register's value on entry that is not an argument (callee-saved, `this` in ecx…).
                g.reg_name(key.0).to_string()
            } else {
                let n = format!("v{next}");
                next += 1;
                g.locals.push(n.clone());
                n
            };
            seen_classes.insert(root, n.clone());
            n
        };
        let mut keys: Vec<(Var, u32)> = Vec::new();
        for b in &f.blocks {
            for p in b.phis.iter().filter(|p| p.var != RSP && !p.dead) {
                keys.push((p.var, p.ver));
                keys.extend(p.args.iter().map(|(_, n)| (p.var, *n)));
            }
            for s in b.stmts.iter().filter(|s| !s.dead) {
                let mut k = s.kind.clone();
                k.defs_mut(&mut |v, n| keys.push((*v, *n)));
                keys.extend(s.kind.uses());
            }
        }
        for k in keys {
            if k.0 == RSP || g.names.contains_key(&k) || g.inline.contains_key(&k) {
                continue;
            }
            let n = name_of(k, &mut dsu, &mut g);
            g.names.insert(k, n);
        }

        // Classes of values some statement really reads (phi inputs alone do not count).
        // The prologue's saves of callee-saved registers are bookkeeping and do not count as reads.
        let mut read_classes: HashSet<(Var, u32)> = HashSet::new();
        for b in &f.blocks {
            for s in b.stmts.iter().filter(|s| !s.dead) {
                if let Kind::Store { addr, val: Expr::Use(v, 0), .. } = &s.kind {
                    if CALLEE_SAVED.contains(v) && g.stack_off(addr).is_some() {
                        continue;
                    }
                }
                for u in s.kind.uses() {
                    read_classes.insert(dsu.find(u));
                }
            }
        }

        // Labels: blocks reached other than by falling into them.
        let order: Vec<u64> = f.blocks.iter().map(|b| b.start).collect();
        let next_of = |i: usize| order.get(i + 1).copied();
        let mut labels: HashSet<u64> = HashSet::new();
        for (i, b) in f.blocks.iter().enumerate() {
            if let Some(t) = b.taken.filter(|t| order.contains(t)) {
                labels.insert(t);
            }
            if let Some(fl) = b.fall.filter(|fl| order.contains(fl) && Some(*fl) != next_of(i)) {
                labels.insert(fl);
            }
            // A jump's own target, also when the graph has no edge for it.
            for st in &b.stmts {
                if let Kind::Branch { target: Some(t), .. } = &st.kind {
                    if order.contains(t) {
                        labels.insert(*t);
                    }
                }
            }
        }
        let lbl = |a: u64| format!("loc_{a:X}");
        let target_name = |a: u64| -> String {
            if order.contains(&a) {
                lbl(a)
            } else {
                // Outside this function: a function's name, else the raw address (a block label of
                // another function would have no label here).
                match (o.names)(a) {
                    Some(n) if !n.starts_with("loc_") => n,
                    _ => format!("*{a:#x}"),
                }
            }
        };

        let mut out: Vec<PseudoLine> = Vec::new();
        for (bi, b) in f.blocks.iter().enumerate() {
            if labels.contains(&b.start) {
                out.push(line(0, Some(b.start), vec![tok(lbl(b.start), TokenKind::Symbol), tok(":", TokenKind::Punct)]));
            }
            // 32-bit call arguments: values pushed since the last call, by statement index.
            let mut pending_push: Vec<usize> = Vec::new();
            let mut skip: HashSet<usize> = HashSet::new();
            let mut push_args: HashMap<usize, Vec<usize>> = HashMap::new();
            if f.bits == 32 {
                for (i, s) in b.stmts.iter().enumerate() {
                    if s.push {
                        pending_push.push(i);
                    } else if matches!(s.kind, Kind::Call { .. }) {
                        let mut args = std::mem::take(&mut pending_push);
                        args.reverse();
                        skip.extend(args.iter().copied());
                        push_args.insert(i, args);
                    }
                }
            }
            // 64-bit call arguments: argument registers set in this block since the last call.
            let mut set_since: HashSet<Var> = HashSet::new();
            for (i, s) in b.stmts.iter().enumerate() {
                if s.dead && !matches!(s.kind, Kind::Assign { .. }) {
                    continue;
                }
                let at = Some(s.address);
                match &s.kind {
                    Kind::Assign { def, ver, expr, .. } => {
                        if o.args.contains(def) {
                            set_since.insert(*def);
                        }
                        if s.dead || *def == RSP || g.inline.contains_key(&(*def, *ver)) {
                            continue;
                        }
                        // Restoring a callee-saved register in the epilogue: a stack load nobody reads.
                        if CALLEE_SAVED.contains(def)
                            && !read_classes.contains(&dsu.find((*def, *ver)))
                            && matches!(expr, Expr::Load(_, a) if g.stack_off(a).is_some())
                        {
                            continue;
                        }
                        let mut t = vec![
                            tok(g.names.get(&(*def, *ver)).cloned().unwrap_or_else(|| g.reg_name(*def).into()), TokenKind::Register),
                            tok(" = ", TokenKind::Punct),
                        ];
                        t.extend(g.e(expr));
                        t.push(tok(";", TokenKind::Punct));
                        out.push(line(1, at, t));
                    }
                    Kind::Store { size, addr, val } => {
                        if skip.contains(&i) {
                            continue;
                        }
                        // Saving a callee-saved register's entry value in the prologue.
                        if let (Expr::Use(v, 0), Some(_)) = (val, g.stack_off(addr)) {
                            if CALLEE_SAVED.contains(v) {
                                continue;
                            }
                        }
                        let mut t = Vec::new();
                        match g.stack_off(addr) {
                            Some(off) => t.push(tok(Gen::slot(off), TokenKind::Register)),
                            None => {
                                t.push(tok(format!("*(uint{}_t *)", *size as u32 * 8), TokenKind::Keyword));
                                t.push(tok("(", TokenKind::Punct));
                                t.extend(g.e(addr));
                                t.push(tok(")", TokenKind::Punct));
                            }
                        }
                        t.push(tok(" = ", TokenKind::Punct));
                        t.extend(g.e(val));
                        t.push(tok(";", TokenKind::Punct));
                        out.push(line(1, at, t));
                    }
                    Kind::Call { target, args, ret, .. } => {
                        let indirect = target.starts_with('[');
                        let mut t = Vec::new();
                        let ret_live = ret.is_some_and(|r| uses.get(&r).copied().unwrap_or(0) > 0 || phi_use.contains(&r));
                        if let (Some(r), true) = (ret, ret_live) {
                            if !g.inline.contains_key(r) {
                                t.push(tok(g.names.get(r).cloned().unwrap_or_else(|| g.reg_name(r.0).into()), TokenKind::Register));
                                t.push(tok(" = ", TokenKind::Punct));
                            }
                        }
                        let slot_name = match &args.first() {
                            Some(Expr::Load(size, a)) if indirect => match &**a {
                                Expr::Const(addr) => global_name(o, *addr, *size),
                                _ => None,
                            },
                            _ => None,
                        };
                        if let Some(n) = slot_name {
                            t.push(tok(n, TokenKind::Symbol));
                        } else if indirect {
                            t.push(tok("(*", TokenKind::Punct));
                            t.extend(g.e(&args[0]));
                            t.push(tok(")", TokenKind::Punct));
                        } else {
                            let addr = u64::from_str_radix(target.trim_start_matches("sub_"), 16).ok();
                            t.push(tok(addr.and_then(|a| (o.names)(a)).unwrap_or_else(|| target.clone()), TokenKind::Symbol));
                        }
                        t.push(tok("(", TokenKind::Punct));
                        let mut list: Vec<Vec<Token>> = Vec::new();
                        if f.bits == 32 {
                            for &pi in push_args.get(&i).map(Vec::as_slice).unwrap_or(&[]) {
                                if let Kind::Store { val, .. } = &b.stmts[pi].kind {
                                    list.push(g.e(val));
                                }
                            }
                        } else {
                            let abi = &args[usize::from(indirect)..];
                            let count = o.args.iter().rposition(|a| set_since.contains(a)).map_or(0, |p| p + 1);
                            for e in abi.iter().take(count) {
                                list.push(g.e(e));
                            }
                        }
                        for (k, a) in list.into_iter().enumerate() {
                            if k > 0 {
                                t.push(tok(", ", TokenKind::Punct));
                            }
                            t.extend(a);
                        }
                        t.push(tok(");", TokenKind::Punct));
                        set_since.clear();
                        out.push(line(1, at, t));
                    }
                    Kind::Branch { cond, uses: u, target } => {
                        match cond {
                            Some(cc) => {
                                let mut t = vec![tok("if", TokenKind::Keyword), tok(" (", TokenKind::Punct)];
                                t.extend(g.condition(b, cc));
                                t.push(tok(") ", TokenKind::Punct));
                                t.push(tok("goto", TokenKind::Keyword));
                                t.push(tok(" ", TokenKind::Text));
                                t.push(tok(target_name(b.taken.or(*target).unwrap_or(0)), TokenKind::Symbol));
                                t.push(tok(";", TokenKind::Punct));
                                out.push(line(1, at, t));
                                if let Some(fl) = b.fall.filter(|fl| Some(*fl) != next_of(bi)) {
                                    out.push(line(
                                        1,
                                        at,
                                        vec![
                                            tok("goto", TokenKind::Keyword),
                                            tok(" ", TokenKind::Text),
                                            tok(target_name(fl), TokenKind::Symbol),
                                            tok(";", TokenKind::Punct),
                                        ],
                                    ));
                                }
                            }
                            None => match target.or(b.taken) {
                                Some(tg) if order.contains(&tg) => {
                                    if Some(tg) != next_of(bi) {
                                        out.push(line(
                                            1,
                                            at,
                                            vec![
                                                tok("goto", TokenKind::Keyword),
                                                tok(" ", TokenKind::Text),
                                                tok(lbl(tg), TokenKind::Symbol),
                                                tok(";", TokenKind::Punct),
                                            ],
                                        ));
                                    }
                                }
                                Some(tg) => {
                                    // A jump out of the function: a tail call, with the arguments set for it.
                                    let callee = target_name(tg);
                                    if callee.starts_with('*') {
                                        out.push(line(
                                            1,
                                            at,
                                            vec![
                                                tok("goto", TokenKind::Keyword),
                                                tok(" ", TokenKind::Text),
                                                tok(callee, TokenKind::Address),
                                                tok(";", TokenKind::Punct),
                                            ],
                                        ));
                                    } else {
                                        let count = o.args.iter().rposition(|a| set_since.contains(a)).map_or(0, |p| p + 1);
                                        let mut call = vec![tok(callee, TokenKind::Symbol), tok("(", TokenKind::Punct)];
                                        for (k, e) in u.iter().take(count).enumerate() {
                                            if k > 0 {
                                                call.push(tok(", ", TokenKind::Punct));
                                            }
                                            call.extend(g.e(e));
                                        }
                                        call.push(tok(")", TokenKind::Punct));
                                        if o.returns {
                                            let mut t = vec![tok("return", TokenKind::Keyword), tok(" ", TokenKind::Text)];
                                            t.extend(call);
                                            t.push(tok(";", TokenKind::Punct));
                                            out.push(line(1, at, t));
                                        } else {
                                            call.push(tok(";", TokenKind::Punct));
                                            out.push(line(1, at, call));
                                            out.push(line(1, at, vec![tok("return", TokenKind::Keyword), tok(";", TokenKind::Punct)]));
                                        }
                                    }
                                }
                                None => {
                                    let mut t = vec![tok("goto", TokenKind::Keyword), tok(" *", TokenKind::Punct)];
                                    t.extend(u.first().map(|e| g.e(e)).unwrap_or_default());
                                    t.push(tok(";", TokenKind::Punct));
                                    out.push(line(1, at, t));
                                }
                            },
                        }
                    }
                    Kind::Return { val } => {
                        let mut t = vec![tok("return", TokenKind::Keyword)];
                        if o.returns {
                            if let Some(v) = val {
                                t.push(tok(" ", TokenKind::Text));
                                t.extend(g.e(v));
                            }
                        }
                        t.push(tok(";", TokenKind::Punct));
                        out.push(line(1, at, t));
                    }
                    Kind::Flags { .. } => {}
                    Kind::Other { text, defs, .. } => {
                        let live: Vec<String> = defs
                            .iter()
                            .filter(|d| d.0 != RSP && (uses.get(d).copied().unwrap_or(0) > 0 || phi_use.contains(d)))
                            .filter_map(|d| g.names.get(d).cloned())
                            .collect();
                        let mut t = Vec::new();
                        if let [one] = live.as_slice() {
                            t.push(tok(one.clone(), TokenKind::Register));
                            t.push(tok(" = ", TokenKind::Punct));
                            t.push(tok("__asm", TokenKind::Keyword));
                            t.push(tok(format!("(\"{text}\");"), TokenKind::Text));
                        } else {
                            t.push(tok("__asm", TokenKind::Keyword));
                            t.push(tok(format!(" {{ {text} }}"), TokenKind::Text));
                        }
                        out.push(line(1, at, t));
                    }
                }
            }
            // A block that ends without a branch and does not fall into the next one.
            if !matches!(b.stmts.last().map(|s| &s.kind), Some(Kind::Branch { .. } | Kind::Return { .. })) {
                if let Some(fl) = b.fall.or(b.taken).filter(|fl| Some(*fl) != next_of(bi) && order.contains(fl)) {
                    out.push(line(
                        1,
                        None,
                        vec![
                            tok("goto", TokenKind::Keyword),
                            tok(" ", TokenKind::Text),
                            tok(lbl(fl), TokenKind::Symbol),
                            tok(";", TokenKind::Punct),
                        ],
                    ));
                }
            }
        }

        structure_ifs(&mut out);
        structure_do_while(&mut out);
        drop_unused_labels(&mut out);
        crate::pseudo_types::recover_goto_loops(&mut out);
        crate::pseudo_types::recover_loops(&mut out);
        drop_unused_labels(&mut out);

        // Locals numbered in order of appearance.
        let mut renum: HashMap<String, String> = HashMap::new();
        for l in &out {
            for t in &l.tokens {
                if t.k == TokenKind::Register && g.locals.contains(&t.t) && !renum.contains_key(&t.t) {
                    let n = format!("v{}", renum.len() + 1);
                    renum.insert(t.t.clone(), n);
                }
            }
        }
        for l in &mut out {
            for t in &mut l.tokens {
                if t.k == TokenKind::Register {
                    if let Some(n) = renum.get(&t.t) {
                        t.t = n.clone();
                    }
                }
            }
        }
        let mut locals: Vec<String> = renum.values().cloned().collect();
        locals.sort_by_key(|n| n[1..].parse::<usize>().unwrap_or(0));
        g.locals = locals;

        // Signature and declarations.
        let mut sig = vec![
            tok(if o.returns { "__int64" } else { "void" }, TokenKind::Keyword),
            tok(" ", TokenKind::Text),
            tok(o.name, TokenKind::Symbol),
            tok("(", TokenKind::Punct),
        ];
        for (k, p) in g.params.iter().enumerate() {
            if k > 0 {
                sig.push(tok(", ", TokenKind::Punct));
            }
            sig.push(tok("int ", TokenKind::Keyword));
            sig.push(tok(p.clone(), TokenKind::Register));
        }
        sig.push(tok(")", TokenKind::Punct));
        let body_text: String = out.iter().flat_map(|l| l.tokens.iter().map(|t| t.t.as_str())).collect::<Vec<_>>().join(" ");
        let mut head = vec![line(0, Some(o.entry), sig), line(0, None, vec![tok("{", TokenKind::Punct)])];
        let mut slots: Vec<String> = Vec::new();
        for l in &out {
            for t in &l.tokens {
                if t.k == TokenKind::Register && (t.t.starts_with("var_") || t.t.starts_with("arg_")) && !slots.contains(&t.t) {
                    slots.push(t.t.clone());
                }
            }
        }
        slots.sort();
        for v in g
            .locals
            .iter()
            .filter(|v| body_text.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == v.as_str()))
            .chain(slots.iter())
        {
            head.push(line(
                1,
                None,
                vec![
                    tok("int", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok(v.clone(), TokenKind::Register),
                    tok(";", TokenKind::Punct),
                ],
            ));
        }
        if head.len() > 2 {
            head.push(line(1, None, Vec::new()));
        }
        head.extend(out);
        head.push(line(0, None, vec![tok("}", TokenKind::Punct)]));
        head
    }
}

fn goto_target(l: &PseudoLine) -> Option<&str> {
    let g = l.tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "goto")?;
    l.tokens[g + 1..].iter().find(|t| t.k == TokenKind::Symbol).map(|t| t.t.as_str())
}

fn is_label(l: &PseudoLine) -> bool {
    crate::pseudo_opt::is_label(l)
}

/// `if (C) goto L; S…; L:` with no jump into `S` from outside → `if (!C) { S… } L:`.
fn structure_ifs(lines: &mut Vec<PseudoLine>) {
    let mut changed = true;
    let mut guard = 0;
    while changed && guard < 10_000 {
        changed = false;
        guard += 1;
        for i in 0..lines.len() {
            let l = &lines[i];
            let is_if_goto = l.tokens.first().is_some_and(|t| t.k == TokenKind::Keyword && t.t == "if") && goto_target(l).is_some();
            if !is_if_goto {
                continue;
            }
            let target = goto_target(l).unwrap().to_string();
            let d = l.indent;
            // The label at depth d-1 that follows, with only deeper-or-equal lines in between.
            let mut j = i + 1;
            let mut ok = false;
            while j < lines.len() {
                let x = &lines[j];
                if is_label(x) && x.tokens[0].t == target && x.indent + 1 == d {
                    ok = true;
                    break;
                }
                if x.indent < d && !(is_label(x) && x.indent + 1 == d) {
                    break;
                }
                j += 1;
            }
            if !ok || j == i + 1 {
                continue;
            }
            // No label inside S may be reached from outside S.
            let inner: Vec<String> = lines[i + 1..j].iter().filter(|x| is_label(x)).map(|x| x.tokens[0].t.clone()).collect();
            let outside_jumps = lines
                .iter()
                .enumerate()
                .filter(|(k, _)| *k <= i || *k >= j)
                .filter_map(|(_, x)| goto_target(x))
                .any(|t| inner.iter().any(|n| n == t));
            if outside_jumps {
                continue;
            }
            // Build `if (!C) {`.
            let k = lines[i].tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "goto").unwrap();
            let mut cond: Vec<Token> = lines[i].tokens[1..k].to_vec();
            // strip " (" … ") "
            if let Some(f) = cond.first_mut() {
                f.t = f.t.trim_start_matches(" (").to_string();
            }
            if let Some(last) = cond.last_mut() {
                if last.t.ends_with(") ") {
                    last.t.truncate(last.t.len() - 2);
                }
            }
            cond.retain(|t| !t.t.is_empty());
            let mut head = vec![tok("if", TokenKind::Keyword), tok(" (", TokenKind::Punct)];
            head.extend(negate(&cond));
            head.push(tok(") {", TokenKind::Punct));
            let addr = lines[i].address;
            lines[i] = line(d, addr, head);
            for x in &mut lines[i + 1..j] {
                x.indent += 1;
            }
            lines.insert(j, line(d, None, vec![tok("}", TokenKind::Punct)]));
            changed = true;
            break;
        }
    }
}

/// `L: S…; if (C) goto L;` with no other jump into `S` → `do { S… } while (C);`.
fn structure_do_while(lines: &mut [PseudoLine]) {
    let mut changed = true;
    let mut guard = 0;
    while changed && guard < 10_000 {
        changed = false;
        guard += 1;
        for h in 0..lines.len() {
            if !is_label(&lines[h]) {
                continue;
            }
            let head = lines[h].tokens[0].t.clone();
            let d = lines[h].indent + 1;
            // The conditional back edge at depth d, before the block ends.
            let mut back = None;
            for (j, l) in lines.iter().enumerate().skip(h + 1) {
                if l.indent < d && !(is_label(l) && l.indent + 1 == d) {
                    break;
                }
                if l.indent == d
                    && l.tokens.first().is_some_and(|t| t.k == TokenKind::Keyword && t.t == "if")
                    && goto_target(l) == Some(head.as_str())
                {
                    back = Some(j);
                }
            }
            let Some(b) = back else { continue };
            // Only the back edge may target the head, and nothing outside may jump into the body.
            let others = lines.iter().enumerate().filter(|(k, _)| *k != b).filter_map(|(_, x)| goto_target(x)).any(|t| t == head);
            let inner: Vec<String> = lines[h + 1..b].iter().filter(|x| is_label(x)).map(|x| x.tokens[0].t.clone()).collect();
            let into = lines
                .iter()
                .enumerate()
                .filter(|(k, _)| *k < h || *k > b)
                .filter_map(|(_, x)| goto_target(x))
                .any(|t| inner.iter().any(|n| n == t));
            if others || into {
                continue;
            }
            let k = lines[b].tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "goto").unwrap();
            let mut cond: Vec<Token> = lines[b].tokens[1..k].to_vec();
            if let Some(f) = cond.first_mut() {
                f.t = f.t.trim_start_matches(" (").to_string();
            }
            if let Some(last) = cond.last_mut() {
                if last.t.ends_with(") ") {
                    last.t.truncate(last.t.len() - 2);
                }
            }
            cond.retain(|t| !t.t.is_empty());
            let mut tail = vec![tok("} ", TokenKind::Punct), tok("while", TokenKind::Keyword), tok(" (", TokenKind::Punct)];
            tail.extend(cond);
            tail.push(tok(");", TokenKind::Punct));
            let addr = lines[b].address;
            lines[b] = line(d, addr, tail);
            for x in &mut lines[h + 1..b] {
                x.indent += 1;
            }
            let at = lines[h].address;
            lines[h] = line(d, at, vec![tok("do", TokenKind::Keyword), tok(" {", TokenKind::Punct)]);
            changed = true;
            break;
        }
    }
}

fn drop_unused_labels(lines: &mut Vec<PseudoLine>) {
    let targets: HashSet<String> = lines.iter().filter_map(|l| goto_target(l).map(str::to_string)).collect();
    lines.retain(|l| !is_label(l) || targets.contains(&l.tokens[0].t));
}

#[cfg(test)]
mod tests {
    use super::super::build;
    use super::*;
    use crate::model::{Edge, EdgeKind};
    use iced_x86::{Decoder, DecoderOptions, Instruction as Ins, Register};
    use std::collections::BTreeMap;

    type Blocks = BTreeMap<u64, (Vec<Ins>, Vec<Edge>)>;

    /// Blocks: (start, instructions, [(successor, kind)]).
    /// A test block: start, instructions, successors with their edge kinds.
    type TestBlock<'a> = (u64, &'a [&'a str], &'a [(u64, EdgeKind)]);

    fn func(bits: u32, blocks: &[TestBlock]) -> Blocks {
        let mut out = BTreeMap::new();
        for (start, insns, succs) in blocks {
            let mut ip = *start;
            let mut v = Vec::new();
            for text in *insns {
                let bytes = crate::asm_x86::assemble(text, ip, bits).unwrap_or_else(|e| panic!("{text}: {e}"));
                let mut d = Decoder::with_ip(bits, &bytes, ip, DecoderOptions::NONE);
                let i = d.decode();
                ip += i.len() as u64;
                v.push(i);
            }
            out.insert(*start, (v, succs.iter().map(|(t, k)| Edge { to: *t, kind: *k }).collect()));
        }
        out
    }

    fn c(bits: u32, b: &Blocks, returns: bool) -> String {
        use Register as R;
        let vol: &[Register] = if bits == 64 { &[R::RAX, R::RCX, R::RDX, R::R8, R::R9, R::R10, R::R11] } else { &[R::EAX, R::ECX, R::EDX] };
        let args: &[Register] = if bits == 64 { &[R::RCX, R::RDX, R::R8, R::R9] } else { &[R::ECX, R::EDX] };
        let entry = *b.keys().next().unwrap();
        let s = build(entry, b, bits, vol, args);
        let names = |a: u64| (a == 0x500).then(|| "puts".to_string());
        let o = COptions { name: "f", entry, returns, args: if bits == 64 { vec![1, 2, 8, 9] } else { vec![] }, names: &names };
        s.to_c(&o)
            .iter()
            .map(|l| format!("{}{}", "    ".repeat(l.indent as usize), l.tokens.iter().map(|t| t.t.as_str()).collect::<String>()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn straight_line_with_parameters_and_a_call() {
        // f(a1, a2): return puts(a1 + a2 * 4) + 1
        let b = func(64, &[(0x100, &["lea rax, [rcx+rdx*4]", "mov rcx, rax", "call 0x500", "add rax, 1", "ret"], &[])]);
        let t = c(64, &b, true);
        assert!(t.contains("__int64 f(int a1, int a2)"), "{t}");
        assert!(t.contains("puts(a1 + (a2 * 4))"), "{t}");
        assert!(t.contains("return v") && t.contains(" + 1"), "{t}");
    }

    #[test]
    fn diamond_becomes_an_if_and_the_phi_one_variable() {
        // if (a1 == 0) v = 2 else v = 1; return v + 3
        let b = func(
            64,
            &[
                (0x100, &["mov eax, 1", "test ecx, ecx", "jnz 0x200"], &[(0x200, EdgeKind::True), (0x150, EdgeKind::False)]),
                (0x150, &["mov eax, 2"], &[(0x200, EdgeKind::Fall)]),
                (0x200, &["add eax, 3", "ret"], &[]),
            ],
        );
        let t = c(64, &b, true);
        assert!(t.contains("if (a1 == 0) {"), "{t}");
        assert!(t.contains("v1 = 1;") && t.contains("v1 = 2;"), "the phi and its inputs share one variable: {t}");
        assert!(!t.contains("goto"), "{t}");
    }

    #[test]
    fn loops_and_stack_slots() {
        // 32-bit: sum = 0; i = n; do { sum += i; } while (--i != 0); local in [esp+4]
        let b = func(
            32,
            &[
                (0x100, &["sub esp, 8", "mov ecx, [esp+0xc]", "xor eax, eax"], &[(0x110, EdgeKind::Fall)]),
                (0x110, &["add eax, ecx", "dec ecx", "jnz 0x110"], &[(0x110, EdgeKind::True), (0x120, EdgeKind::False)]),
                (0x120, &["mov [esp+4], eax", "add esp, 8", "ret"], &[]),
            ],
        );
        let t = c(32, &b, true);
        assert!(t.contains("arg_4"), "the argument slot is named: {t}");
        assert!(t.contains("do {") && t.contains("} while ("), "the back edge became a loop: {t}");
        assert!(t.contains("var_4 = "), "the local slot is named: {t}");
        assert!(!t.contains("esp"), "stack pointer arithmetic is hidden: {t}");
    }

    #[test]
    fn pushed_arguments_in_32_bit_code() {
        let b = func(32, &[(0x100, &["push 2", "push 1", "call 0x500", "add esp, 8", "ret"], &[])]);
        let t = c(32, &b, false);
        assert!(t.contains("puts(1, 2);"), "{t}");
        assert!(!t.contains("var_"), "pushes are arguments, not stores: {t}");
    }

    #[test]
    fn negation_flips_simple_comparisons() {
        let toks = |s: &[(&str, TokenKind)]| s.iter().map(|(t, k)| tok(*t, *k)).collect::<Vec<_>>();
        let n = negate(&toks(&[("a1", TokenKind::Register), (" == ", TokenKind::Punct), ("0", TokenKind::Number)]));
        assert_eq!(n.iter().map(|t| t.t.as_str()).collect::<String>(), "a1 != 0");
        let n = negate(&toks(&[("__flags_o", TokenKind::Keyword)]));
        assert_eq!(n.iter().map(|t| t.t.as_str()).collect::<String>(), "!(__flags_o)");
    }
}
