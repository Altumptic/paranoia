//! Variable recovery on the structured pseudocode: reaching definitions, then webs.
//!
//! A register is reused by the compiler for unrelated values. SSA gives each definition its own
//! name and merges names only where control flow joins them. Here that is done directly on the
//! pseudocode lines: a control-flow graph is built from the structure the decompiler emitted
//! (`if` / `else`, loops, `switch`, `goto`, labels, `break` / `continue`), reaching definitions
//! are computed per register, and definitions that reach a common use are merged into one
//! variable (a "web", which is what a phi node plus copy coalescing would give). Everything else
//! becomes its own variable, wherever it sits: inside branches and loop bodies too.
//!
//! The graph is deliberately an over-approximation (a `return` or `goto` still "falls through",
//! switch cases are reachable from the header). An extra edge can only merge variables, never
//! split one in two, so the result is always safe to print. If the structure cannot be read
//! (unbalanced braces, an unknown label) [`recover`] returns `None` and the caller keeps the
//! older, more conservative splitting.

use std::collections::{HashMap, HashSet};

use crate::model::TokenKind;
use crate::pseudo::PseudoLine;
use crate::pseudo_opt::{assignment, fam_of, is_label};

/// The variable (web) every register occurrence belongs to.
pub(crate) struct Webs {
    /// (family, line) of a plain full-width overwrite → its web key.
    defs: HashMap<(String, usize), String>,
    /// (family, line) of a line that reads the family → the web key of the value it reads.
    uses: HashMap<(String, usize), String>,
}

impl Webs {
    /// Variable key of the register `fam` appearing as token `tok` of `line`.
    pub(crate) fn key(&self, fam: &str, line: usize, tok: usize) -> String {
        if tok == 0 {
            if let Some(k) = self.defs.get(&(fam.to_string(), line)) {
                return k.clone();
            }
        }
        self.uses.get(&(fam.to_string(), line)).cloned().unwrap_or_else(|| format!("{fam}#0"))
    }

    /// Whether `line` starts a fresh value of `fam` (a plain overwrite).
    pub(crate) fn is_def(&self, fam: &str, line: usize) -> bool {
        self.defs.contains_key(&(fam.to_string(), line))
    }
}

fn is_kw(t: &crate::model::Token, s: &str) -> bool {
    t.k == TokenKind::Keyword && t.t == s
}

/// Brace structure of the lines: for each opening line, the line holding its `}`.
struct Blocks {
    end: HashMap<usize, usize>,
    /// For each line, the opening lines of the blocks that enclose it (outermost first).
    enclosing: Vec<Vec<usize>>,
}

fn blocks(lines: &[PseudoLine]) -> Option<Blocks> {
    let mut end = HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut enclosing = Vec::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        // Braces in order: `{ … }` inside one line (`__asm { int 0x29 }`) cancels out; what is left
        // closes blocks opened on earlier lines and opens blocks that end on later ones.
        let (mut opens, mut closes) = (0usize, 0usize);
        for c in l.tokens.iter().filter(|t| t.k == TokenKind::Punct).flat_map(|t| t.t.chars()) {
            match c {
                '{' => opens += 1,
                '}' if opens > 0 => opens -= 1,
                '}' => closes += 1,
                _ => {}
            }
        }
        for _ in 0..closes {
            end.insert(stack.pop()?, i);
        }
        // Lines inside a block, not the line that opens it.
        enclosing.push(stack.clone());
        for _ in 0..opens {
            stack.push(i);
        }
    }
    stack.is_empty().then_some(Blocks { end, enclosing })
}

/// Successors of every line (over-approximated, see the module docs).
#[allow(clippy::needless_range_loop)] // line indices address several parallel tables
fn flow_graph(lines: &[PseudoLine]) -> Option<Vec<Vec<usize>>> {
    let n = lines.len();
    let b = blocks(lines)?;
    let labels: HashMap<&str, usize> =
        lines.iter().enumerate().filter(|(_, l)| is_label(l)).map(|(i, l)| (l.tokens[0].t.as_str(), i)).collect();
    let mut succ: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    let is_else_close = |i: usize| {
        lines[i].tokens.iter().any(|t| is_kw(t, "else")) && lines[i].tokens.iter().any(|t| t.k == TokenKind::Punct && t.t.contains('}'))
    };
    // The end of an if / else-if / else chain that opens at line `h` (its last closing line).
    let chain_end = |h: usize| -> usize {
        let mut c = b.end[&h];
        while is_else_close(c) && b.end.contains_key(&c) {
            c = b.end[&c];
        }
        c
    };
    for i in 0..n {
        // Falling out of a `then` body skips the `else` body (and the rest of an else-if chain).
        if i + 1 < n && is_else_close(i + 1) && b.end.contains_key(&(i + 1)) {
            let after = chain_end(i + 1) + 1;
            if after < n {
                succ[i].insert(after);
            }
            continue;
        }
        if i + 1 < n {
            succ[i].insert(i + 1);
        }
    }
    for (&h, &c) in &b.end {
        if c + 1 < n {
            succ[h].insert(c + 1);
        }
        let toks = &lines[h].tokens;
        let looping = toks.iter().any(|t| is_kw(t, "while") || is_kw(t, "for") || is_kw(t, "do"));
        if looping {
            succ[c].insert(h);
        }
        if toks.iter().any(|t| is_kw(t, "switch")) {
            for j in h + 1..c {
                if lines[j].tokens.first().is_some_and(|t| is_kw(t, "case") || is_kw(t, "default")) {
                    succ[h].insert(j);
                }
            }
        }
    }
    for (i, l) in lines.iter().enumerate() {
        for (k, t) in l.tokens.iter().enumerate() {
            if is_kw(t, "goto") {
                let to = l.tokens[k + 1..].iter().find(|t| t.k == TokenKind::Symbol).and_then(|t| labels.get(t.t.as_str()))?;
                succ[i].insert(*to);
            }
            if is_kw(t, "break") || is_kw(t, "continue") {
                for &h in &b.enclosing[i] {
                    let ht = &lines[h].tokens;
                    if ht.iter().any(|t| is_kw(t, "while") || is_kw(t, "for") || is_kw(t, "do") || is_kw(t, "switch")) {
                        if let Some(&c) = b.end.get(&h) {
                            if c + 1 < n {
                                succ[i].insert(c + 1);
                            }
                        }
                        succ[i].insert(h);
                    }
                }
            }
        }
    }
    Some(succ.into_iter().map(|s| s.into_iter().collect()).collect())
}

struct Dsu(Vec<usize>);

impl Dsu {
    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while self.0[r] != r {
            r = self.0[r];
        }
        let mut c = x;
        while self.0[c] != r {
            let nx = self.0[c];
            self.0[c] = r;
            c = nx;
        }
        r
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        // The lower index wins, so the entry value (index 0) stays the root of its web.
        self.0[a.max(b)] = a.min(b);
    }
}

/// Reaching definitions and webs for every register that is plainly overwritten somewhere.
#[allow(clippy::needless_range_loop)] // line indices address several parallel tables
pub(crate) fn recover(lines: &[PseudoLine]) -> Option<Webs> {
    let n = lines.len();
    if n < 2 {
        return None;
    }
    let succ = flow_graph(lines)?;
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, s) in succ.iter().enumerate() {
        for &j in s {
            preds[j].push(i);
        }
    }
    // Plain overwrites `reg = expr;` whose right-hand side does not read the register, per family;
    // and every line that reads a family. Line 0 is the signature and takes no part.
    let mut def_lines: HashMap<String, Vec<usize>> = HashMap::new();
    let mut read_lines: HashMap<String, Vec<usize>> = HashMap::new();
    let mut address_taken: HashSet<String> = HashSet::new();
    for (i, l) in lines.iter().enumerate().skip(1) {
        let pure = assignment(l).and_then(|(lhs, expr)| {
            let (f, w) = fam_of(lhs)?;
            let reads_self = expr.iter().any(|t| fam_of(t).is_some_and(|x| x.0 == f));
            (w >= 32 && !f.starts_with("var_") && !reads_self).then_some(f)
        });
        if let Some(f) = &pure {
            def_lines.entry(f.clone()).or_default().push(i);
        }
        for (k, t) in l.tokens.iter().enumerate() {
            let Some((f, _)) = fam_of(t) else { continue };
            if f.starts_with("var_") || f == "rsp" || f == "rip" {
                continue;
            }
            if k > 0 && l.tokens[k - 1].t.ends_with('&') {
                address_taken.insert(f.clone());
            }
            if k == 0 && pure.as_deref() == Some(f.as_str()) {
                continue; // the overwritten register is written, not read
            }
            let v = read_lines.entry(f).or_default();
            if v.last() != Some(&i) {
                v.push(i);
            }
        }
    }
    let mut webs = Webs { defs: HashMap::new(), uses: HashMap::new() };
    for (fam, defs) in &def_lines {
        if address_taken.contains(fam) {
            continue; // aliased: one variable
        }
        // Definitions: 0 = the value on entry, then each overwrite in line order.
        let nd = defs.len() + 1;
        let words = nd.div_ceil(64);
        let def_index: HashMap<usize, usize> = defs.iter().enumerate().map(|(k, &l)| (l, k + 1)).collect();
        let mut out = vec![vec![0u64; words]; n];
        let mut inn = vec![vec![0u64; words]; n];
        inn[0][0] |= 1; // the entry value reaches line 0
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..n {
                if i > 0 {
                    let mut cur = vec![0u64; words];
                    for &p in &preds[i] {
                        for (c, o) in cur.iter_mut().zip(&out[p]) {
                            *c |= *o;
                        }
                    }
                    inn[i] = cur;
                }
                let new_out = match def_index.get(&i) {
                    Some(&d) => {
                        let mut v = vec![0u64; words];
                        v[d / 64] |= 1 << (d % 64);
                        v
                    }
                    None => inn[i].clone(),
                };
                if new_out != out[i] {
                    out[i] = new_out;
                    changed = true;
                }
            }
        }
        // Definitions that reach one use are one variable.
        let mut dsu = Dsu((0..nd).collect());
        let bits = |v: &[u64]| -> Vec<usize> { (0..nd).filter(|d| v[d / 64] >> (d % 64) & 1 == 1).collect() };
        let reads = read_lines.get(fam).map(Vec::as_slice).unwrap_or(&[]);
        for &i in reads {
            let reaching = bits(&inn[i]);
            for w in reaching.windows(2) {
                dsu.union(w[0], w[1]);
            }
        }
        // Names: the entry web is `fam#0`, the others count up in order of first definition.
        let mut web_no: HashMap<usize, usize> = HashMap::new();
        let root0 = dsu.find(0);
        web_no.insert(root0, 0);
        let mut next = 1;
        for d in 1..nd {
            let r = dsu.find(d);
            if let std::collections::hash_map::Entry::Vacant(e) = web_no.entry(r) {
                e.insert(next);
                next += 1;
            }
        }
        let key_of = |dsu: &mut Dsu, d: usize| format!("{fam}#{}", web_no[&dsu.find(d)]);
        for (k, &line) in defs.iter().enumerate() {
            webs.defs.insert((fam.clone(), line), key_of(&mut dsu, k + 1));
        }
        for &i in reads {
            let d = bits(&inn[i]).first().copied().unwrap_or(0);
            webs.uses.insert((fam.clone(), i), key_of(&mut dsu, d));
        }
    }
    Some(webs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Token;

    fn tok(t: &str, k: TokenKind) -> Token {
        Token { t: t.into(), k }
    }

    /// `reg = expr;` where `expr` is a list of tokens.
    fn set(reg: &str, expr: Vec<Token>) -> PseudoLine {
        let mut t = vec![tok(reg, TokenKind::Register), tok(" = ", TokenKind::Punct)];
        t.extend(expr);
        t.push(tok(";", TokenKind::Punct));
        PseudoLine { address: None, indent: 1, tokens: t }
    }
    fn num(n: &str) -> Vec<Token> {
        vec![tok(n, TokenKind::Number)]
    }
    fn reg(r: &str) -> Vec<Token> {
        vec![tok(r, TokenKind::Register)]
    }
    /// `callee(args…);` using the registers in `uses`.
    fn call(uses: &[&str]) -> PseudoLine {
        let mut t = vec![tok("foo", TokenKind::Symbol), tok("(", TokenKind::Punct)];
        for (i, u) in uses.iter().enumerate() {
            if i > 0 {
                t.push(tok(", ", TokenKind::Punct));
            }
            t.push(tok(u, TokenKind::Register));
        }
        t.push(tok(");", TokenKind::Punct));
        PseudoLine { address: None, indent: 1, tokens: t }
    }
    fn raw(indent: u8, toks: Vec<(&str, TokenKind)>) -> PseudoLine {
        PseudoLine { address: None, indent, tokens: toks.into_iter().map(|(t, k)| tok(t, k)).collect() }
    }
    fn head() -> PseudoLine {
        raw(0, vec![("void f()", TokenKind::Text)])
    }
    fn if_open(cond: &str) -> PseudoLine {
        raw(1, vec![("if", TokenKind::Keyword), (" (", TokenKind::Punct), (cond, TokenKind::Register), (") {", TokenKind::Punct)])
    }
    fn close() -> PseudoLine {
        raw(1, vec![("}", TokenKind::Punct)])
    }
    fn else_open() -> PseudoLine {
        raw(1, vec![("} ", TokenKind::Punct), ("else", TokenKind::Keyword), (" {", TokenKind::Punct)])
    }
    fn k(w: &Webs, f: &str, line: usize, tok: usize) -> String {
        w.key(f, line, tok)
    }

    #[test]
    fn sequential_overwrites_are_separate_variables() {
        let lines = vec![head(), set("rax", num("1")), call(&["rax"]), set("rax", num("2")), call(&["rax"])];
        let w = recover(&lines).unwrap();
        assert_ne!(k(&w, "rax", 2, 1), k(&w, "rax", 4, 1));
        assert_eq!(k(&w, "rax", 1, 0), k(&w, "rax", 2, 1));
        assert_eq!(k(&w, "rax", 3, 0), k(&w, "rax", 4, 1));
    }

    #[test]
    fn a_value_defined_in_both_branches_is_one_variable() {
        // rax = 1; if (rcx) { rax = 2; } use(rax): the join merges both definitions.
        let lines = vec![head(), set("rax", num("1")), if_open("rcx"), set("rax", num("2")), close(), call(&["rax"])];
        let w = recover(&lines).unwrap();
        assert_eq!(k(&w, "rax", 1, 0), k(&w, "rax", 3, 0), "both definitions reach the use after the if");
        assert_eq!(k(&w, "rax", 5, 1), k(&w, "rax", 1, 0));
    }

    #[test]
    fn if_else_branches_that_each_redefine_are_merged_only_if_used_after() {
        // if (rcx) { rax = 1; use } else { rax = 2; use }: no use after the join, so two variables.
        let lines =
            vec![head(), if_open("rcx"), set("rax", num("1")), call(&["rax"]), else_open(), set("rax", num("2")), call(&["rax"]), close()];
        let w = recover(&lines).unwrap();
        assert_ne!(k(&w, "rax", 3, 1), k(&w, "rax", 6, 1), "the then-branch value never reaches the else-branch");
        // ... and with a use after the join, the two definitions are one variable.
        let mut more = lines.clone();
        more.push(call(&["rax"]));
        let w = recover(&more).unwrap();
        assert_eq!(k(&w, "rax", 3, 1), k(&w, "rax", 6, 1));
        assert_eq!(k(&w, "rax", 8, 1), k(&w, "rax", 3, 1));
    }

    #[test]
    fn a_loop_carries_its_value_around() {
        // rax = 0; while (rcx) { use(rax); rax = f(); }: the definition in the loop reaches the use at its top.
        let wh =
            raw(1, vec![("while", TokenKind::Keyword), (" (", TokenKind::Punct), ("rcx", TokenKind::Register), (") {", TokenKind::Punct)]);
        let mut call_def = set("rax", vec![tok("g", TokenKind::Symbol), tok("()", TokenKind::Punct)]);
        call_def.indent = 2;
        let mut u = call(&["rax"]);
        u.indent = 2;
        let lines = vec![head(), set("rax", num("0")), wh, u, call_def, close()];
        let w = recover(&lines).unwrap();
        assert_eq!(k(&w, "rax", 1, 0), k(&w, "rax", 4, 0), "the loop-carried value is the same variable");
        assert_eq!(k(&w, "rax", 3, 1), k(&w, "rax", 1, 0));
    }

    #[test]
    fn a_redefinition_inside_a_loop_body_before_its_use_is_its_own_variable() {
        // while (rcx) { rax = g(); use(rax); }  and a later unrelated rax = 5; use(rax)
        let wh =
            raw(1, vec![("while", TokenKind::Keyword), (" (", TokenKind::Punct), ("rcx", TokenKind::Register), (") {", TokenKind::Punct)]);
        let mut d = set("rax", vec![tok("g", TokenKind::Symbol), tok("()", TokenKind::Punct)]);
        d.indent = 2;
        let mut u = call(&["rax"]);
        u.indent = 2;
        let lines = vec![head(), wh, d, u, close(), set("rax", num("5")), call(&["rax"])];
        let w = recover(&lines).unwrap();
        assert_ne!(k(&w, "rax", 3, 1), k(&w, "rax", 6, 1), "two unrelated lifetimes of rax");
    }

    #[test]
    fn gotos_join_values() {
        // if (rcx) goto L; rax = 1; L: use(rax): the entry value and the definition both reach L.
        let g = raw(
            1,
            vec![
                ("if", TokenKind::Keyword),
                (" (", TokenKind::Punct),
                ("rcx", TokenKind::Register),
                (") ", TokenKind::Punct),
                ("goto", TokenKind::Keyword),
                (" ", TokenKind::Text),
                ("L", TokenKind::Symbol),
                (";", TokenKind::Punct),
            ],
        );
        let label = raw(0, vec![("L", TokenKind::Symbol), (":", TokenKind::Punct)]);
        let lines = vec![head(), g, set("rax", num("1")), label, call(&["rax"])];
        let w = recover(&lines).unwrap();
        assert_eq!(k(&w, "rax", 4, 1), "rax#0", "merged with the entry value");
        assert_eq!(k(&w, "rax", 2, 0), "rax#0");
        // An unknown label makes the structure unreadable: callers fall back.
        let bad =
            raw(1, vec![("goto", TokenKind::Keyword), (" ", TokenKind::Text), ("nowhere", TokenKind::Symbol), (";", TokenKind::Punct)]);
        assert!(recover(&[head(), bad]).is_none());
    }

    #[test]
    fn self_referencing_updates_stay_in_their_variable() {
        // rax = 1; rax = rax + 2; use(rax): one variable
        let lines = vec![
            head(),
            set("rax", num("1")),
            set("rax", vec![tok("rax", TokenKind::Register), tok(" + ", TokenKind::Punct), tok("2", TokenKind::Number)]),
            call(&["rax"]),
        ];
        let w = recover(&lines).unwrap();
        assert_eq!(k(&w, "rax", 1, 0), k(&w, "rax", 3, 1));
        assert_eq!(k(&w, "rax", 2, 1), k(&w, "rax", 1, 0));
    }

    #[test]
    fn unbalanced_braces_are_refused() {
        assert!(recover(&[head(), if_open("rcx"), set("rax", num("1"))]).is_none());
        assert!(recover(&[head(), close()]).is_none());
    }

    #[test]
    fn registers_are_independent() {
        let lines = vec![head(), set("rax", num("1")), set("rbx", reg("rax")), set("rax", num("2")), call(&["rax", "rbx"])];
        let w = recover(&lines).unwrap();
        assert_ne!(k(&w, "rax", 2, 2), k(&w, "rax", 4, 1));
        assert_eq!(k(&w, "rbx", 2, 0), k(&w, "rbx", 4, 3));
    }
}
