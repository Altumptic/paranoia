//! Clean-up passes over lifted pseudocode lines:
//!
//! * **expression propagation** — `edx = 0x80000000; … CreateFileW(rcx, rdx, …)`
//!   becomes `CreateFileW(L"a.txt", GENERIC_READ, …)` when the register is used
//!   exactly once and is dead afterwards;
//! * **dead call results** — `rax = CloseHandle(rcx);` → `CloseHandle(rcx);`;
//! * **symbolic arguments** — numbers passed to known APIs become constants.
//!
//! The passes work on the token lines and are deliberately conservative: any
//! label, loop or backward jump on the way stops a rewrite.

use std::collections::{HashMap, HashSet};

use crate::model::{Token, TokenKind};
use crate::pseudo::PseudoLine;

/// Register family (`eax`, `ax`, `al` → `rax`) and width in bits.
pub(crate) fn family(name: &str) -> Option<(String, u32)> {
    const LEGACY: [(&str, [&str; 4]); 8] = [
        ("rax", ["rax", "eax", "ax", "al"]),
        ("rbx", ["rbx", "ebx", "bx", "bl"]),
        ("rcx", ["rcx", "ecx", "cx", "cl"]),
        ("rdx", ["rdx", "edx", "dx", "dl"]),
        ("rsi", ["rsi", "esi", "si", "sil"]),
        ("rdi", ["rdi", "edi", "di", "dil"]),
        ("rbp", ["rbp", "ebp", "bp", "bpl"]),
        ("rsp", ["rsp", "esp", "sp", "spl"]),
    ];
    for (f, names) in LEGACY {
        if let Some(i) = names.iter().position(|n| *n == name) {
            return Some((f.to_string(), [64, 32, 16, 8][i]));
        }
    }
    if matches!(name, "ah" | "bh" | "ch" | "dh") {
        return Some((format!("r{}x", &name[..1]), 8));
    }
    if let Some(rest) = name.strip_prefix('r') {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            let width = match &rest[digits.len()..] {
                "" => 64,
                "d" => 32,
                "w" => 16,
                "b" | "l" => 8,
                _ => return None,
            };
            return Some((format!("r{digits}"), width));
        }
    }
    // Stack variables behave like registers for propagation (outgoing argument slots).
    if name.starts_with("var_") {
        return Some((name.to_string(), 64));
    }
    None
}

pub(crate) fn fam_of(t: &Token) -> Option<(String, u32)> {
    (t.k == TokenKind::Register).then(|| family(&t.t)).flatten()
}

pub(crate) fn is_label(l: &PseudoLine) -> bool {
    l.tokens.len() == 2 && l.tokens[1].t == ":" && l.tokens[0].k == TokenKind::Symbol
}

pub(crate) fn has_kw(l: &PseudoLine, kw: &str) -> bool {
    l.tokens.iter().any(|t| t.k == TokenKind::Keyword && t.t == kw)
}

fn opens_or_closes(l: &PseudoLine) -> bool {
    l.tokens.iter().any(|t| t.k == TokenKind::Punct && (t.t.contains('{') || t.t.contains('}')))
}

/// Index of the callee token when the line performs a call (`f(` / `((void (*)())`).
pub(crate) fn call_at(l: &PseudoLine) -> Option<usize> {
    l.tokens.windows(2).position(|w| {
        (w[0].k == TokenKind::Symbol && w[1].k == TokenKind::Punct && w[1].t.starts_with('('))
            || (w[0].k == TokenKind::Keyword && w[0].t.starts_with("((void"))
    })
}

/// `reg = expr;` → (reg token, expression tokens). Compound assignments return None.
pub(crate) fn assignment(l: &PseudoLine) -> Option<(&Token, Vec<Token>)> {
    let [lhs, eq, rest @ ..] = l.tokens.as_slice() else { return None };
    if lhs.k != TokenKind::Register || eq.k != TokenKind::Punct || !eq.t.starts_with(" = ") {
        return None;
    }
    let mut expr = Vec::new();
    let head = &eq.t[3..];
    if !head.is_empty() {
        expr.push(Token { t: head.to_string(), k: TokenKind::Punct });
    }
    expr.extend(rest.iter().cloned());
    let last = expr.last_mut()?;
    if !last.t.ends_with(';') {
        return None;
    }
    last.t.pop();
    if last.t.is_empty() {
        expr.pop();
    }
    (!expr.is_empty()).then_some((lhs, expr))
}

/// How a line touches register family `fam`.
enum Touch {
    None,
    /// Plain full-width overwrite whose right-hand side does not read `fam`.
    Kill,
    Use(usize),
}

fn touch(l: &PseudoLine, fam: &str, volatile: &[&str]) -> Touch {
    if let Some((lhs, expr)) = assignment(l) {
        if let Some((f, w)) = family(&lhs.t) {
            if f == fam && w >= 32 && !expr.iter().any(|t| fam_of(t).is_some_and(|x| x.0 == fam)) {
                return Touch::Kill;
            }
        }
    }
    let uses = l.tokens.iter().filter(|t| fam_of(t).is_some_and(|x| x.0 == fam)).count();
    if uses > 0 {
        return Touch::Use(uses);
    }
    if call_at(l).is_some() && volatile.contains(&fam) {
        return Touch::Kill;
    }
    Touch::None
}

/// Whether `fam`'s value at the end of line `from` is never read again.
fn dead_after(
    lines: &[PseudoLine],
    from: usize,
    fam: &str,
    base_indent: u8,
    labels: &HashMap<String, usize>,
    start: usize,
    volatile: &[&str],
) -> bool {
    for (w, l) in lines.iter().enumerate().skip(from + 1) {
        if has_kw(l, "while") {
            if matches!(touch(l, fam, volatile), Touch::Use(_)) {
                return false;
            }
            // The back edge re-enters the loop head: the value must be overwritten there before any read.
            let Some(d) = (0..w).rev().find(|&d| lines[d].indent == l.indent && has_kw(&lines[d], "do")) else { return false };
            if d < start && !killed_first(&lines[d + 1..=start], fam, l.indent + 1, volatile) {
                return false;
            }
            continue;
        }
        if let Some(g) = l.tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "goto") {
            let target = l.tokens[g + 1..].iter().find(|t| t.k == TokenKind::Symbol).and_then(|t| labels.get(&t.t).copied());
            match target {
                None => return false,
                // A jump back above the definition re-runs it: the value must be overwritten first.
                Some(at) if at <= start => {
                    if !killed_first(&lines[at + 1..=start], fam, lines[at].indent + 1, volatile) {
                        return false;
                    }
                }
                Some(_) => {}
            }
        }
        match touch(l, fam, volatile) {
            Touch::Use(_) => return false,
            Touch::Kill if l.indent <= base_indent => return true,
            _ => {}
        }
        if has_kw(l, "return") && l.indent <= base_indent {
            return true;
        }
    }
    true
}

/// Whether `fam` is overwritten (at `indent` or shallower) before any read in `lines`.
fn killed_first(lines: &[PseudoLine], fam: &str, indent: u8, volatile: &[&str]) -> bool {
    // Paths joining at labels on the way are checked by their own jumps.
    for l in lines {
        match touch(l, fam, volatile) {
            Touch::Use(_) => return false,
            Touch::Kill if l.indent <= indent => return true,
            _ => {}
        }
    }
    false
}

/// Whether the token at `pos` is the target of an assignment (`x = …`, `x += …`, `x++`).
fn is_written(toks: &[Token], pos: usize) -> bool {
    let Some(next) = toks.get(pos + 1).filter(|t| t.k == TokenKind::Punct) else { return false };
    let n = next.t.as_str();
    (n.starts_with(" = ") && !n.starts_with(" =="))
        || [" += ", " -= ", " &= ", " |= ", " ^= ", " *= ", " /= ", " <<= ", " >>= ", "++", "--"].iter().any(|op| n.starts_with(op))
}

fn is_operator_expr(expr: &[Token]) -> bool {
    expr.len() > 1 && expr.iter().any(|t| t.k == TokenKind::Punct && t.t.trim().len() < t.t.len() && t.t.trim() != ",")
}

/// Constants may be copied into several uses inside one straight-line run.
fn propagate_constant(
    lines: &mut Vec<PseudoLine>,
    i: usize,
    fam: &str,
    expr: &[Token],
    labels: &HashMap<String, usize>,
    volatile: &[&str],
) -> bool {
    let mut uses = Vec::new();
    let mut last = i;
    for (j, l) in lines.iter().enumerate().skip(i + 1) {
        if is_label(l) || l.indent != lines[i].indent || has_kw(l, "while") || has_kw(l, "goto") {
            break;
        }
        match touch(l, fam, volatile) {
            Touch::Use(_) => {
                uses.push(j);
                last = j;
            }
            Touch::Kill => {
                last = j;
                break;
            }
            Touch::None => {}
        }
        if opens_or_closes(l) {
            break;
        }
    }
    if uses.is_empty()
        || !dead_after(lines, last, fam, lines[i].indent, labels, i, volatile) && !matches!(touch(&lines[last], fam, volatile), Touch::Kill)
    {
        return false;
    }
    // Every use must be a read (not the target of a compound assignment).
    for &j in &uses {
        let t = &lines[j].tokens;
        if (0..t.len()).any(|p| fam_of(&t[p]).is_some_and(|f| f.0 == fam) && is_written(t, p)) {
            return false;
        }
        if fam_of(&t[0]).is_some_and(|f| f.0 == fam)
            && t.get(1).is_some_and(|x| x.k == TokenKind::Punct && !x.t.starts_with(" = ") && !x.t.starts_with(" =="))
        {
            return false;
        }
        if t.iter().any(|x| fam_of(x).is_some_and(|f| f.0 == fam && f.1 < 32)) {
            return false;
        }
    }
    for &j in &uses {
        let toks = std::mem::take(&mut lines[j].tokens);
        let mut new = Vec::with_capacity(toks.len());
        for t in toks {
            if fam_of(&t).is_some_and(|f| f.0 == fam) {
                new.extend(expr.iter().cloned());
            } else {
                new.push(t);
            }
        }
        lines[j].tokens = fold(merge(new));
    }
    lines.remove(i);
    true
}

/// Folds `n + m` / `n - m` between plain delimiters.
fn fold(mut v: Vec<Token>) -> Vec<Token> {
    let mut k = 0;
    while k + 2 < v.len() {
        let delim_before = k == 0 || {
            let p = &v[k - 1].t;
            p.ends_with('(') || p.ends_with(", ") || p.ends_with(" = ")
        };
        let delim_after = v.get(k + 3).is_none_or(|t| t.t.starts_with(')') || t.t.starts_with(',') || t.t.starts_with(';'));
        if delim_before
            && delim_after
            && v[k].k == TokenKind::Number
            && v[k + 2].k == TokenKind::Number
            && matches!(v[k + 1].t.as_str(), " + " | " - ")
        {
            if let (Some(a), Some(b)) = (parse_c_number(&v[k].t), parse_c_number(&v[k + 2].t)) {
                let r = if v[k + 1].t == " + " { a.wrapping_add(b) } else { a.wrapping_sub(b) };
                let s = if (-9..10).contains(&r) {
                    r.to_string()
                } else if r < 0 {
                    format!("-{:#x}", r.unsigned_abs())
                } else {
                    format!("{r:#x}")
                };
                v.splice(k..k + 3, [Token { t: s, k: TokenKind::Number }]);
                continue;
            }
        }
        k += 1;
    }
    v
}

/// One forward pass of expression propagation; returns whether anything changed.
fn propagate_once(lines: &mut Vec<PseudoLine>, volatile: &[&str]) -> bool {
    let mut labels: HashMap<String, usize> =
        lines.iter().enumerate().filter(|(_, l)| is_label(l)).map(|(i, l)| (l.tokens[0].t.clone(), i)).collect();
    let addressed: HashSet<String> = lines
        .iter()
        .flat_map(|l| l.tokens.windows(2).filter(|w| w[0].t.ends_with('&') && w[1].t.starts_with("var_")).map(|w| w[1].t.clone()))
        .collect();
    let mut changed = false;
    let mut i = 0;
    while i < lines.len() {
        if try_at(lines, i, &labels, &addressed, volatile) {
            changed = true;
            for at in labels.values_mut() {
                if *at > i {
                    *at -= 1;
                }
            }
            // The rewritten use may now be propagatable into the line before.
            i = i.saturating_sub(1);
            continue;
        }
        i += 1;
    }
    changed
}

/// Propagates the definition on line `i` into its use, removing line `i` on success.
fn try_at(lines: &mut Vec<PseudoLine>, i: usize, labels: &HashMap<String, usize>, addressed: &HashSet<String>, volatile: &[&str]) -> bool {
    let Some((lhs, expr)) = assignment(&lines[i]) else { return false };
    let Some((fam, width)) = family(&lhs.t) else { return false };
    if addressed.contains(&fam) || expr.iter().any(|t| fam_of(t).is_some_and(|x| x.0 == fam)) {
        return false;
    }
    let is_call = call_at(&lines[i]).is_some();
    let reads_memory = expr.iter().enumerate().any(|(k, t)| {
        (t.k == TokenKind::Keyword && t.t.starts_with("*("))
            || (t.k == TokenKind::Register && t.t.starts_with("var_"))
            || (t.k == TokenKind::Symbol && !(k > 0 && expr[k - 1].t.ends_with('&')))
    });
    if let [t] = expr.as_slice() {
        if t.k == TokenKind::Number && propagate_constant(lines, i, &fam, &expr, labels, volatile) {
            return true;
        }
    }
    let expr_fams: HashSet<String> = expr.iter().filter_map(fam_of).map(|f| f.0).collect();
    // The single use: the next line touching the family, through harmless lines only.
    let mut use_at = None;
    for (j, l) in lines.iter().enumerate().skip(i + 1) {
        if is_label(l) {
            break;
        }
        match touch(l, &fam, volatile) {
            Touch::Use(1) => {
                use_at = Some(j);
                break;
            }
            Touch::Use(_) | Touch::Kill => break,
            Touch::None => {}
        }
        // Calls are never reordered: their use must be the very next line.
        if is_call || opens_or_closes(l) || call_at(l).is_some() || l.indent != lines[i].indent {
            break;
        }
        // Harmless: plain register assignments that leave the expression's inputs alone.
        match assignment(l) {
            Some((t, _)) => {
                let f = family(&t.t).map(|f| f.0);
                if f.as_ref().is_none_or(|f| expr_fams.contains(f)) || (reads_memory && t.t.starts_with("var_")) {
                    break;
                }
            }
            None => break,
        }
    }
    let Some(j) = use_at else { return false };
    if has_kw(&lines[j], "while") || !dead_after(lines, j, &fam, lines[i].indent, labels, i, volatile) {
        return false;
    }
    let Some(pos) = lines[j].tokens.iter().position(|t| fam_of(t).is_some_and(|x| x.0 == fam)) else { return false };
    let use_width = family(&lines[j].tokens[pos].t).map(|f| f.1).unwrap_or(64);
    if (use_width < 32 || width < 32) && use_width != width {
        return false;
    }
    // A use on the left of `=` / `+=` is a write through a compound op — leave it.
    if pos == 0
        && lines[j]
            .tokens
            .get(1)
            .is_some_and(|t| t.k == TokenKind::Punct && t.t.trim_start().starts_with(|c: char| "+-*/&|^<>=".contains(c)))
        && !lines[j].tokens[1].t.starts_with(" = ")
    {
        return false;
    }
    if (0..lines[j].tokens.len()).any(|p| fam_of(&lines[j].tokens[p]).is_some_and(|f| f.0 == fam) && is_written(&lines[j].tokens, p)) {
        return false;
    }
    let toks = &lines[j].tokens;
    let before = pos.checked_sub(1).map(|k| toks[k].t.as_str()).unwrap_or("");
    let after = toks.get(pos + 1).map(|t| t.t.as_str()).unwrap_or("");
    let standalone = (before.ends_with('(') || before.ends_with(", ") || before.ends_with(" = "))
        && (after.starts_with(')') || after.starts_with(',') || after.starts_with(';'));
    let mut repl = expr.clone();
    if is_operator_expr(&repl) && !standalone {
        repl.insert(0, Token { t: "(".into(), k: TokenKind::Punct });
        repl.push(Token { t: ")".into(), k: TokenKind::Punct });
    }
    let mut new = toks[..pos].to_vec();
    new.extend(repl);
    new.extend(toks[pos + 1..].iter().cloned());
    lines[j].tokens = fold(merge(new));
    lines.remove(i);
    true
}

/// Re-merges adjacent punctuation so lines stay compact after edits.
pub(crate) fn merge(v: Vec<Token>) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::with_capacity(v.len());
    for t in v {
        if let Some(last) = out.last_mut() {
            if last.k == t.k && matches!(t.k, TokenKind::Punct | TokenKind::Text) {
                last.t.push_str(&t.t);
                continue;
            }
        }
        out.push(t);
    }
    out
}

/// `rax = f(...);` → `f(...);` when the result is never read.
fn drop_dead_results(lines: &mut [PseudoLine], volatile: &[&str]) {
    let labels: HashMap<String, usize> =
        lines.iter().enumerate().filter(|(_, l)| is_label(l)).map(|(i, l)| (l.tokens[0].t.clone(), i)).collect();
    for i in 0..lines.len() {
        let l = &lines[i];
        if call_at(l) != Some(2) || !matches!(l.tokens[0].t.as_str(), "rax" | "eax") || l.tokens[1].t != " = " {
            continue;
        }
        if dead_after(lines, i, "rax", lines[i].indent, &labels, i, volatile) {
            lines[i].tokens.drain(..2);
        }
    }
}

/// Numbers passed to known APIs become symbolic constants.
fn symbolize_args(bin: &crate::Binary, lines: &mut [PseudoLine]) {
    for l in lines.iter_mut() {
        let Some(c) = call_at(l) else { continue };
        let name = l.tokens[c].t.clone();
        let Some(proto) = crate::protos::lookup(&name) else { continue };
        let mut depth = 0i32;
        let mut arg = 0usize;
        for k in c + 1..l.tokens.len() {
            let t = &l.tokens[k];
            if matches!(t.k, TokenKind::Punct | TokenKind::Keyword) {
                for ch in t.t.chars() {
                    match ch {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        ',' if depth == 1 => arg += 1,
                        _ => {}
                    }
                }
                if depth <= 0 && k > c + 1 {
                    break;
                }
                continue;
            }
            if t.k != TokenKind::Number || depth != 1 {
                continue;
            }
            let before = &l.tokens[k - 1].t;
            let after = l.tokens.get(k + 1).map(|t| t.t.as_str()).unwrap_or("");
            if !(before.ends_with('(') || before.ends_with(", ")) || !(after.starts_with(',') || after.starts_with(')')) {
                continue;
            }
            let Some(p) = proto.params.get(arg) else { continue };
            let pname = crate::protos::param_name(p);
            let Some(e) = crate::operands::param_enum(&name, pname) else { continue };
            let v = parse_c_number(&t.t);
            if let Some(s) = v.and_then(|v| bin.enum_text(e, v, 32)) {
                l.tokens[k] = Token { t: s, k: TokenKind::Symbol };
            }
        }
    }
}

pub(crate) fn parse_c_number(s: &str) -> Option<i64> {
    let (neg, s) = s.strip_prefix('-').map(|r| (true, r)).unwrap_or((false, s));
    let v = match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok()? as i64,
        None => s.parse::<i64>().ok()?,
    };
    Some(if neg { -v } else { v })
}

/// Runs all clean-up passes.
pub(crate) fn optimize(bin: &crate::Binary, lines: &mut Vec<PseudoLine>, sysv: bool, bits: u32) {
    let volatile: &[&str] = match (bits, sysv) {
        (32, _) => &["rax", "rcx", "rdx"],
        (_, true) => &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
        _ => &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
    };
    for _ in 0..3 {
        if !propagate_once(lines, volatile) {
            break;
        }
    }
    drop_dead_results(lines, volatile);
    symbolize_args(bin, lines);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(indent: u8, toks: &[(&str, TokenKind)]) -> PseudoLine {
        PseudoLine { address: None, indent, tokens: toks.iter().map(|(t, k)| Token { t: t.to_string(), k: *k }).collect() }
    }

    fn text(l: &PseudoLine) -> String {
        l.tokens.iter().map(|t| t.t.as_str()).collect()
    }

    #[test]
    fn propagates_arguments_into_calls() {
        use TokenKind::*;
        let mut v = vec![
            line(1, &[("ecx", Register), (" = ", Punct), ("0x10", Number), (";", Punct)]),
            line(1, &[("edx", Register), (" = ", Punct), ("0", Number), (";", Punct)]),
            line(
                1,
                &[
                    ("rax", Register),
                    (" = ", Punct),
                    ("f", Symbol),
                    ("(", Punct),
                    ("rcx", Register),
                    (", ", Punct),
                    ("rdx", Register),
                    (");", Punct),
                ],
            ),
            line(1, &[("return", Keyword), (";", Punct)]),
        ];
        let volatile = ["rax", "rcx", "rdx"];
        while propagate_once(&mut v, &volatile) {}
        drop_dead_results(&mut v, &volatile);
        assert_eq!(v.len(), 2);
        assert_eq!(text(&v[0]), "f(0x10, 0);");
    }

    #[test]
    fn keeps_values_used_twice() {
        use TokenKind::*;
        let mut v = vec![
            line(1, &[("ecx", Register), (" = ", Punct), ("var_8", Register), (";", Punct)]),
            line(1, &[("eax", Register), (" = ", Punct), ("ecx", Register), (";", Punct)]),
            line(1, &[("edx", Register), (" = ", Punct), ("ecx", Register), (";", Punct)]),
        ];
        let volatile = ["rax", "rcx", "rdx"];
        while propagate_once(&mut v, &volatile) {}
        assert_eq!(text(&v[0]), "ecx = var_8;");
        // Constants are copied into every use.
        let mut v = vec![
            line(1, &[("r9d", Register), (" = ", Punct), ("0", Number), (";", Punct)]),
            line(1, &[("r8d", Register), (" = ", Punct), ("r9", Register), (" + ", Punct), ("1", Number), (";", Punct)]),
            line(1, &[("f", Symbol), ("(", Punct), ("r8", Register), (", ", Punct), ("r9", Register), (");", Punct)]),
        ];
        while propagate_once(&mut v, &volatile) {}
        assert_eq!(v.len(), 1);
        assert_eq!(text(&v[0]), "f(1, 0);");
    }
}
