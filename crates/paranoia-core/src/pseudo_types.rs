//! Final pseudocode passes: loop recovery (`while`, `for`) and typed variables.
//!
//! Registers become variables (`a1…` for parameters, `v1…` for the rest) and every
//! variable is declared with a type: from API prototypes first (`HANDLE` from
//! `CreateFileW`, `DWORD` for a `&var` passed as `LPDWORD`), then from the stack
//! frame's access sizes, then from the register width.

use std::collections::{BTreeMap, HashMap};

use crate::model::{Token, TokenKind};
use crate::pseudo::PseudoLine;
use crate::pseudo_opt::{assignment, call_at, family, has_kw, is_label};

fn text(toks: &[Token]) -> String {
    toks.iter().map(|t| t.t.as_str()).collect()
}

fn line(indent: u8, toks: Vec<Token>) -> PseudoLine {
    PseudoLine { address: None, indent, tokens: toks }
}

fn tok(t: impl Into<String>, k: TokenKind) -> Token {
    Token { t: t.into(), k }
}

/// The condition tokens of `if (C) {` / `} while (C);`.
fn condition(l: &PseudoLine, kw: &str) -> Option<Vec<Token>> {
    let k = l.tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == kw)?;
    let open = l.tokens.get(k + 1)?;
    let last = l.tokens.last()?;
    if !open.t.starts_with(" (") {
        return None;
    }
    let mut c: Vec<Token> = l.tokens[k + 1..].to_vec();
    // Strip the leading " (" and the trailing ") {" / ");".
    let first = &mut c[0];
    first.t = first.t[2..].to_string();
    let suffix = if last.t.ends_with(") {") {
        ") {"
    } else if last.t.ends_with(");") {
        ");"
    } else {
        return None;
    };
    let n = c.len() - 1;
    let lt = &mut c[n];
    lt.t.truncate(lt.t.len() - suffix.len());
    c.retain(|t| !t.t.is_empty());
    Some(c)
}

/// `if (C) { do { B } while (C); }` → `while (C) { B }`, and with `x = init;` before it and
/// `x++;` / `x += n;` closing the body → `for (x = init; C; x++) { B }`.
pub(crate) fn recover_loops(lines: &mut Vec<PseudoLine>) {
    let mut i = 0;
    while i + 1 < lines.len() {
        let ind = lines[i].indent;
        let is_guard =
            lines[i].tokens.first().is_some_and(|t| t.k == TokenKind::Keyword && t.t == "if") && text(&lines[i].tokens).ends_with(") {");
        let next_is_do = has_kw(&lines[i + 1], "do") && lines[i + 1].indent == ind + 1;
        if !(is_guard && next_is_do) {
            i += 1;
            continue;
        }
        // The `} while (...)` closing this do, then the `}` closing the if.
        let Some(w) = (i + 2..lines.len()).find(|&j| lines[j].indent <= ind + 1 && !is_label(&lines[j])) else { break };
        let closes = lines.get(w + 1).is_some_and(|l| l.indent == ind && text(&l.tokens) == "}");
        let (Some(c1), Some(c2)) = (condition(&lines[i], "if"), condition(&lines[w], "while")) else {
            i += 1;
            continue;
        };
        if lines[w].indent != ind + 1 || !closes || text(&c1) != text(&c2) {
            i += 1;
            continue;
        }
        // Rewrite: while (C) { body }
        let addr = lines[i].address;
        let mut head = vec![tok("while", TokenKind::Keyword), tok(" (", TokenKind::Punct)];
        head.extend(c1.clone());
        head.push(tok(") {", TokenKind::Punct));
        lines[i] = PseudoLine { address: addr, indent: ind, tokens: head };
        lines.remove(w); // `} while (C);` — the if's `}` now closes the while
        lines.remove(i + 1); // `do {`
        let body_end = w - 1; // index of the closing `}` after removals
        for l in &mut lines[i + 1..body_end] {
            l.indent -= 1;
        }
        to_for(lines, i);
        i += 1;
    }
}

/// Negates a condition: flips a single top-level comparison, otherwise wraps it in `!( )`.
fn negate_cond(c: &[Token]) -> Vec<Token> {
    const OPS: [(&str, &str); 6] = [(" == ", " != "), (" != ", " == "), (" <= ", " > "), (" >= ", " < "), (" < ", " >= "), (" > ", " <= ")];
    let mut depth = 0i32;
    let mut found: Option<(usize, usize, &str)> = None;
    let mut count = 0;
    for (i, t) in c.iter().enumerate() {
        if t.k != TokenKind::Punct {
            if t.k == TokenKind::Keyword {
                depth += t.t.matches('(').count() as i32 - t.t.matches(')').count() as i32;
            }
            continue;
        }
        let s = &t.t;
        let mut pos = 0;
        while pos < s.len() {
            let rest = &s[pos..];
            if depth == 0 {
                if rest.starts_with(" && ") || rest.starts_with(" || ") {
                    count += 2;
                }
                if let Some((op, _)) = OPS.iter().find(|(op, _)| rest.starts_with(op)) {
                    count += 1;
                    found = Some((i, pos, op));
                    pos += op.len();
                    continue;
                }
            }
            let ch = rest.chars().next().unwrap();
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            pos += ch.len_utf8();
        }
    }
    if let (1, Some((i, pos, op))) = (count, found) {
        let flipped = OPS.iter().find(|(o, _)| *o == op).unwrap().1;
        let mut v = c.to_vec();
        let t = &mut v[i].t;
        t.replace_range(pos..pos + op.len(), flipped);
        return v;
    }
    let mut v = vec![tok("!(", TokenKind::Punct)];
    v.extend(c.iter().cloned());
    v.push(tok(")", TokenKind::Punct));
    crate::pseudo_opt::merge(v)
}

/// `loc_H: body; goto loc_H; loc_E:` → `while (1) { body }` (or `while (!C)` when the body starts
/// with `if (C) goto loc_E;`), with jumps to the header becoming `continue` and to the exit `break`.
pub(crate) fn recover_goto_loops(lines: &mut Vec<PseudoLine>) {
    let goto_target = |l: &PseudoLine| -> Option<String> {
        let g = l.tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "goto")?;
        l.tokens[g + 1..].iter().find(|t| t.k == TokenKind::Symbol).map(|t| t.t.clone())
    };
    let mut h = 0;
    while h + 2 < lines.len() {
        if !is_label(&lines[h]) {
            h += 1;
            continue;
        }
        let head = lines[h].tokens[0].t.clone();
        let d = lines[h].indent + 1;
        // The back edge: the last `goto head;` at depth d inside the same block.
        let mut back = None;
        for (j, l) in lines.iter().enumerate().skip(h + 1) {
            if l.indent < d - 1 || (l.indent == d - 1 && !is_label(l)) {
                break;
            }
            if l.indent == d && text(&l.tokens) == format!("goto {head};") {
                back = Some(j);
            }
        }
        let Some(b) = back.filter(|&b| b > h + 1) else {
            h += 1;
            continue;
        };
        // Nothing outside may jump into the body (the header itself is fine from before it only via fallthrough).
        let inner_labels: Vec<String> = lines[h + 1..b].iter().filter(|l| is_label(l)).map(|l| l.tokens[0].t.clone()).collect();
        let enters = lines
            .iter()
            .enumerate()
            .any(|(j, l)| (j < h || j > b) && goto_target(l).is_some_and(|t| t == head || inner_labels.contains(&t)));
        if enters {
            h += 1;
            continue;
        }
        let exit = lines.get(b + 1).filter(|l| is_label(l)).map(|l| l.tokens[0].t.clone());
        lines[b] = PseudoLine { address: lines[b].address, indent: d, tokens: vec![tok("}", TokenKind::Punct)] };
        for l in &mut lines[h + 1..b] {
            if let Some(t) = goto_target(l) {
                let jump = if t == head {
                    Some("continue")
                } else if Some(&t) == exit.as_ref() {
                    Some("break")
                } else {
                    None
                };
                if let Some(kw) = jump {
                    if let Some(g) = l.tokens.iter().position(|x| x.k == TokenKind::Keyword && x.t == "goto") {
                        l.tokens.truncate(g);
                        l.tokens.push(tok(kw, TokenKind::Keyword));
                        l.tokens.push(tok(";", TokenKind::Punct));
                    }
                }
            }
            l.indent += 1;
        }
        // `while (1) {` replaces the header label; a leading `if (C) break;` becomes the loop test.
        let first = &lines[h + 1];
        let leading_test = first.indent == d + 1
            && first.tokens.first().is_some_and(|t| t.k == TokenKind::Keyword && t.t == "if")
            && text(&first.tokens).ends_with(") break;");
        let cond = if leading_test {
            let l = &lines[h + 1];
            let g = l.tokens.iter().position(|t| t.k == TokenKind::Keyword && t.t == "break");
            g.and_then(|g| {
                let mut c: Vec<Token> = l.tokens[1..g].to_vec();
                let f = c.first_mut()?;
                f.t = f.t.strip_prefix(" (")?.to_string();
                let last = c.last_mut()?;
                last.t = last.t.strip_suffix(") ")?.to_string();
                c.retain(|t| !t.t.is_empty());
                Some(negate_cond(&c))
            })
        } else {
            None
        };
        let mut whl = vec![tok("while", TokenKind::Keyword), tok(" (", TokenKind::Punct)];
        match &cond {
            Some(c) => whl.extend(c.iter().cloned()),
            None => whl.push(tok("1", TokenKind::Number)),
        }
        whl.push(tok(") {", TokenKind::Punct));
        let addr = lines[h].address;
        let header = PseudoLine { address: addr, indent: d, tokens: crate::pseudo_opt::merge(whl) };
        let still_used = lines.iter().any(|l| goto_target(l).is_some_and(|t| t == head));
        if cond.is_some() {
            lines.remove(h + 1);
        }
        if still_used {
            lines.insert(h + 1, header);
            h += 1;
        } else {
            lines[h] = header;
        }
        to_for(lines, h);
        h += 1;
    }
}

/// `x = init; while (C) { …; x++; }` → `for (x = init; C; x++) { … }`. The initialisation may sit
/// a few plain assignments above the loop as long as they leave `x` alone.
fn to_for(lines: &mut Vec<PseudoLine>, w: usize) {
    if w == 0 {
        return;
    }
    let ind = lines[w].indent;
    let Some(c) = condition(&lines[w], "while") else { return };
    let Some(end) = (w + 1..lines.len()).find(|&j| lines[j].indent <= ind && !is_label(&lines[j])) else { return };
    if end < w + 2 || lines[end].indent != ind || text(&lines[end].tokens) != "}" {
        return;
    }
    let fam = |s: &str| family(s).map(|f| f.0);
    // The step: last body statement, `x++`, `x--`, `x += n` or `x -= n`.
    let step = &lines[end - 1];
    let Some(v) = step.tokens.first().filter(|t| t.k == TokenKind::Register).and_then(|t| fam(&t.t)) else { return };
    let rest = text(&step.tokens[1..]);
    let step_ok = step.indent == ind + 1 && (rest == "++;" || rest == "--;" || rest.starts_with(" += ") || rest.starts_with(" -= "));
    let mentions = |l: &PseudoLine| l.tokens.iter().any(|t| t.k == TokenKind::Register && fam(&t.t).as_ref() == Some(&v));
    let in_cond = c.iter().any(|t| t.k == TokenKind::Register && fam(&t.t).as_ref() == Some(&v));
    // `continue` inside the body would skip the step in a `for`.
    let has_continue = lines[w + 1..end].iter().any(|l| has_kw(l, "continue"));
    if !step_ok || !in_cond || has_continue {
        return;
    }
    let mut init_at = None;
    for k in (w.saturating_sub(4)..w).rev() {
        let l = &lines[k];
        let Some((lhs, expr)) = assignment(l) else { break };
        if l.indent != ind {
            break;
        }
        if lhs.k == TokenKind::Register && fam(&lhs.t).as_ref() == Some(&v) {
            if !expr.iter().any(|t| t.k == TokenKind::Register && fam(&t.t).as_ref() == Some(&v)) {
                init_at = Some(k);
            }
            break;
        }
        if mentions(l) || call_at(l).is_some() {
            break;
        }
    }
    let Some(k) = init_at else { return };
    let mut init_toks = lines[k].tokens.clone();
    init_toks.last_mut().unwrap().t.pop();
    let mut step_toks = step.tokens.clone();
    step_toks.last_mut().unwrap().t.pop();
    let mut head = vec![tok("for", TokenKind::Keyword), tok(" (", TokenKind::Punct)];
    head.extend(init_toks);
    head.push(tok("; ", TokenKind::Punct));
    head.extend(c);
    head.push(tok("; ", TokenKind::Punct));
    head.extend(step_toks);
    head.push(tok(") {", TokenKind::Punct));
    let addr = lines[w].address;
    lines.remove(end - 1);
    lines[w] = PseudoLine { address: addr, indent: ind, tokens: crate::pseudo_opt::merge(head) };
    lines.remove(k);
}

/// Size-based C type.
fn int_type(bytes: u32) -> &'static str {
    match bytes {
        1 => "char",
        2 => "__int16",
        4 => "int",
        8 => "__int64",
        16 => "__m128i",
        _ => "__int64",
    }
}

/// Parameter type from a prototype string (`LPCWSTR lpFileName` → `LPCWSTR`).
fn param_type(p: &str) -> String {
    let name = crate::protos::param_name(p);
    p.strip_suffix(name).unwrap_or(p).trim().trim_end_matches("[]").trim().to_string()
}

/// What a pointer parameter points to (`LPDWORD` → `DWORD`, `PHKEY` → `HKEY`, `int *` → `int`).
fn pointee(ty: &str) -> Option<String> {
    if let Some(t) = ty.strip_suffix('*') {
        let t = t.trim().trim_start_matches("const ").trim();
        return (!t.is_empty() && t != "void" && t != "char" && t != "wchar_t").then(|| t.to_string());
    }
    let rest = ty.strip_prefix("LP").or_else(|| ty.strip_prefix('P'))?;
    let simple = rest.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let opaque = ["VOID", "CVOID", "STR", "CSTR", "WSTR", "CWSTR", "TSTR", "CTSTR", ""];
    (simple && !opaque.contains(&rest)).then(|| rest.to_string())
}

pub(crate) struct Signature<'a> {
    pub name: &'a str,
    pub ret: &'a str,
    /// Parameter registers in calling-convention order (`rcx`, `rdx`, …).
    pub params: Vec<String>,
    pub fastcall: bool,
    /// Stack slot sizes from the frame view, by variable name.
    pub stack: BTreeMap<String, u32>,
    /// Scratch registers: reused for unrelated values, so API types are not pinned on them.
    pub volatile: &'a [&'a str],
}

/// Top-level overwrites of each register that start a new, independent variable:
/// no jump crosses the line in either direction, so no path sees both values.
fn split_points(lines: &[PseudoLine]) -> HashMap<String, Vec<usize>> {
    let labels: HashMap<&str, usize> =
        lines.iter().enumerate().filter(|(_, l)| is_label(l)).map(|(i, l)| (l.tokens[0].t.as_str(), i)).collect();
    let mut jumps: Vec<(usize, usize)> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        for (k, t) in l.tokens.iter().enumerate() {
            if t.k == TokenKind::Keyword && t.t == "goto" {
                if let Some(&to) = l.tokens[k + 1..].iter().find(|t| t.k == TokenKind::Symbol).and_then(|t| labels.get(t.t.as_str())) {
                    jumps.push((i, to));
                }
            }
        }
    }
    let crosses = |k: usize| jumps.iter().any(|&(a, b)| (a < k && b >= k) || (a >= k && b < k));
    let mut out: HashMap<String, Vec<usize>> = HashMap::new();
    for (k, l) in lines.iter().enumerate().skip(1) {
        if l.indent != 1 {
            continue;
        }
        let Some((lhs, expr)) = assignment(l) else { continue };
        let Some((f, w)) = family(&lhs.t) else { continue };
        if w < 32 || f.starts_with("var_") || expr.iter().any(|t| t.k == TokenKind::Register && family(&t.t).is_some_and(|x| x.0 == f)) {
            continue;
        }
        if !crosses(k) {
            out.entry(f).or_default().push(k);
        }
    }
    out
}

/// Renames registers to `a1…`/`v1…`, infers types and writes declarations + signature.
pub(crate) fn type_variables(lines: &mut Vec<PseudoLine>, sig: &Signature) {
    let splits = split_points(lines);
    // Variable key of a register occurrence: family + segment.
    let reg_key = |f: &str, line: usize| -> String {
        let seg = splits.get(f).map(|v| v.iter().filter(|&&k| k <= line).count()).unwrap_or(0);
        format!("{f}#{seg}")
    };
    let starts_segment = |f: &str, line: usize| splits.get(f).is_some_and(|v| v.contains(&line));

    // 1. Variables and their widths, in order of appearance.
    let mut order: Vec<(String, String)> = Vec::new(); // (key, family)
    let mut first_line: HashMap<String, usize> = HashMap::new();
    let mut widths: HashMap<String, u32> = HashMap::new();
    let mut stack_vars: Vec<String> = Vec::new();
    let mut stack_args: Vec<String> = Vec::new();
    for (i, l) in lines.iter().enumerate().skip(1) {
        for t in &l.tokens {
            if t.k != TokenKind::Register {
                continue;
            }
            if t.t.starts_with("var_") {
                if !stack_vars.contains(&t.t) {
                    stack_vars.push(t.t.clone());
                }
                continue;
            }
            if t.t.starts_with("arg_") {
                if !stack_args.contains(&t.t) {
                    stack_args.push(t.t.clone());
                }
                continue;
            }
            let Some((f, w)) = family(&t.t) else { continue };
            if matches!(f.as_str(), "rsp" | "rip") {
                continue;
            }
            let k = reg_key(&f, i);
            if !first_line.contains_key(&k) {
                first_line.insert(k.clone(), i);
                order.push((k.clone(), f.clone()));
            }
            let e = widths.entry(k).or_insert(0);
            *e = (*e).max(w);
        }
    }
    let param_keys: Vec<String> = sig.params.iter().map(|p| format!("{p}#0")).collect();

    // 2. Names.
    let mut names: HashMap<String, String> = HashMap::new();
    for (n, p) in param_keys.iter().enumerate() {
        names.insert(p.clone(), format!("a{}", n + 1));
    }
    let mut next = 1;
    for (k, _) in &order {
        if !names.contains_key(k) {
            names.insert(k.clone(), format!("v{next}"));
            next += 1;
        }
    }

    // 3. Type hints from prototyped calls. Scratch registers only take a type when the
    //    variable is born from that call's result.
    let mut hints: HashMap<String, String> = HashMap::new();
    let key_at = |t: &Token, line: usize| -> Option<(String, Option<String>)> {
        if t.k != TokenKind::Register {
            return None;
        }
        if t.t.starts_with("var_") || t.t.starts_with("arg_") {
            return Some((t.t.clone(), None));
        }
        family(&t.t).map(|f| (reg_key(&f.0, line), Some(f.0)))
    };
    for (i, l) in lines.iter().enumerate() {
        let Some(c) = call_at(l) else { continue };
        let Some(proto) = crate::protos::lookup(&l.tokens[c].t) else { continue };
        if c == 2 && l.tokens[1].t == " = " && proto.ret != "void" {
            if let Some((k, f)) = key_at(&l.tokens[0], i) {
                let fresh =
                    f.as_deref().is_none_or(|f| !sig.volatile.contains(&f) || starts_segment(f, i) || first_line.get(&k) == Some(&i));
                if fresh {
                    hints.entry(k).or_insert_with(|| proto.ret.to_string());
                }
            }
        }
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
            let Some(p) = proto.params.get(arg) else { continue };
            let before = &l.tokens[k - 1].t;
            let after = l.tokens.get(k + 1).map(|t| t.t.as_str()).unwrap_or("");
            if depth != 1 || !(after.starts_with(',') || after.starts_with(')')) {
                continue;
            }
            let Some((name, f)) = key_at(t, i) else { continue };
            // Arguments only type stable variables (params, non-volatile registers, stack slots).
            if f.as_deref().is_some_and(|f| sig.volatile.contains(&f)) && !param_keys.contains(&name) {
                continue;
            }
            let ty = param_type(p);
            if before.ends_with("(&") || before.ends_with(", &") {
                if let Some(pt) = pointee(&ty) {
                    hints.entry(name).or_insert(pt);
                }
            } else if before.ends_with('(') || before.ends_with(", ") {
                hints.entry(name).or_insert(ty);
            }
        }
    }

    // 4. Rewrite register tokens.
    for (i, l) in lines.iter_mut().enumerate().skip(1) {
        let mut out = Vec::with_capacity(l.tokens.len());
        for t in std::mem::take(&mut l.tokens) {
            let renamed = (t.k == TokenKind::Register && !t.t.starts_with("var_") && !t.t.starts_with("arg_"))
                .then(|| family(&t.t))
                .flatten()
                .and_then(|(f, w)| {
                    let k = reg_key(&f, i);
                    names.get(&k).map(|n| (n.clone(), w, k))
                });
            match renamed {
                Some((n, w, k)) => {
                    let full = widths.get(&k).copied().unwrap_or(64);
                    let high = matches!(t.t.as_str(), "ah" | "bh" | "ch" | "dh");
                    let wrap = match w {
                        8 if high => Some("BYTE1"),
                        8 if full > 8 => Some("LOBYTE"),
                        16 if full > 16 => Some("LOWORD"),
                        _ => None,
                    };
                    match wrap {
                        Some(m) => {
                            out.push(tok(m, TokenKind::Keyword));
                            out.push(tok("(", TokenKind::Punct));
                            out.push(tok(n, TokenKind::Register));
                            out.push(tok(")", TokenKind::Punct));
                        }
                        None => out.push(tok(n, TokenKind::Register)),
                    }
                }
                None => out.push(t),
            }
        }
        l.tokens = crate::pseudo_opt::merge(out);
    }

    // 5. Declarations.
    let type_of = |k: &str, width_bytes: u32| hints.get(k).cloned().unwrap_or_else(|| int_type(width_bytes).to_string());
    let mut decls: Vec<PseudoLine> = Vec::new();
    for v in &stack_vars {
        let size = sig.stack.get(v).copied().unwrap_or(8);
        let mut toks = Vec::new();
        if size > 16 && !hints.contains_key(v) {
            toks.push(tok("char", TokenKind::Keyword));
            toks.push(tok(" ", TokenKind::Text));
            toks.push(tok(v.clone(), TokenKind::Register));
            toks.push(tok(format!("[{size}];"), TokenKind::Punct));
        } else {
            toks.push(tok(type_of(v, size), TokenKind::Keyword));
            toks.push(tok(" ", TokenKind::Text));
            toks.push(tok(v.clone(), TokenKind::Register));
            toks.push(tok(";", TokenKind::Punct));
        }
        decls.push(line(1, toks));
    }
    for (k, f) in &order {
        if param_keys.contains(k) {
            continue;
        }
        let n = &names[k];
        let w = widths.get(k).copied().unwrap_or(64) / 8;
        decls.push(line(
            1,
            vec![
                tok(type_of(k, w), TokenKind::Keyword),
                tok(" ", TokenKind::Text),
                tok(n.clone(), TokenKind::Register),
                tok("; ", TokenKind::Punct),
                tok(format!("// {f}"), TokenKind::Text),
            ],
        ));
    }

    // 6. Signature.
    let mut s = vec![tok(sig.ret, TokenKind::Keyword), tok(" ", TokenKind::Text)];
    if sig.fastcall {
        s.push(tok("__fastcall", TokenKind::Keyword));
        s.push(tok(" ", TokenKind::Text));
    }
    s.push(tok(sig.name, TokenKind::Symbol));
    s.push(tok("(", TokenKind::Punct));
    let params = param_keys.iter().map(|k| (k.clone(), names[k].clone(), widths.get(k).copied().unwrap_or(64) / 8));
    for (n, p) in params.chain(stack_args.iter().map(|a| (a.clone(), a.clone(), 4))).enumerate() {
        if n > 0 {
            s.push(tok(", ", TokenKind::Punct));
        }
        s.push(tok(type_of(&p.0, p.2), TokenKind::Keyword));
        s.push(tok(" ", TokenKind::Text));
        s.push(tok(p.1, TokenKind::Register));
    }
    s.push(tok(")", TokenKind::Punct));
    lines[0].tokens = s;
    if !decls.is_empty() {
        decls.push(line(1, Vec::new()));
        let at = 2.min(lines.len());
        lines.splice(at..at, decls);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(indent: u8, toks: &[(&str, TokenKind)]) -> PseudoLine {
        PseudoLine { address: None, indent, tokens: toks.iter().map(|(t, k)| tok(*t, *k)).collect() }
    }

    #[test]
    fn guarded_do_while_becomes_for() {
        use TokenKind::*;
        let mut v = vec![
            l(1, &[("ecx", Register), (" = ", Punct), ("0", Number), (";", Punct)]),
            l(1, &[("if", Keyword), (" (", Punct), ("ecx", Register), (" < ", Punct), ("edx", Register), (") {", Punct)]),
            l(2, &[("do", Keyword), (" {", Punct)]),
            l(3, &[("f", Symbol), ("();", Punct)]),
            l(3, &[("ecx", Register), ("++;", Punct)]),
            l(2, &[("} ", Punct), ("while", Keyword), (" (", Punct), ("ecx", Register), (" < ", Punct), ("edx", Register), (");", Punct)]),
            l(1, &[("}", Punct)]),
        ];
        recover_loops(&mut v);
        let t: Vec<String> = v.iter().map(|x| "  ".repeat(x.indent as usize) + &text(&x.tokens)).collect();
        assert_eq!(t, vec!["  for (ecx = 0; ecx < edx; ecx++) {", "    f();", "  }"]);
    }

    #[test]
    fn label_loops_become_while() {
        use TokenKind::*;
        let mut v = vec![
            l(0, &[("void", Keyword)]),
            l(1, &[("rcx", Register), (" = ", Punct), ("0", Number), (";", Punct)]),
            l(0, &[("loc_10", Symbol), (":", Punct)]),
            l(
                1,
                &[
                    ("if", Keyword),
                    (" (", Punct),
                    ("rcx", Register),
                    (" == ", Punct),
                    ("rdx", Register),
                    (") ", Punct),
                    ("goto", Keyword),
                    (" ", Punct),
                    ("loc_20", Symbol),
                    (";", Punct),
                ],
            ),
            l(1, &[("f", Symbol), ("(", Punct), ("rcx", Register), (");", Punct)]),
            l(1, &[("rcx", Register), ("++;", Punct)]),
            l(1, &[("goto", Keyword), (" ", Punct), ("loc_10", Symbol), (";", Punct)]),
            l(0, &[("loc_20", Symbol), (":", Punct)]),
            l(1, &[("return", Keyword), (";", Punct)]),
        ];
        recover_goto_loops(&mut v);
        let t: Vec<String> = v.iter().map(|x| "  ".repeat(x.indent as usize) + &text(&x.tokens)).collect();
        assert_eq!(t[1], "  for (rcx = 0; rcx != rdx; rcx++) {");
        assert_eq!(t[2], "    f(rcx);");
        assert_eq!(t[3], "  }");
    }

    #[test]
    fn negation() {
        use TokenKind::*;
        let c = vec![tok("a", Register), tok(" < ", Punct), tok("b", Register)];
        assert_eq!(text(&negate_cond(&c)), "a >= b");
        let c = vec![tok("a", Register), tok(" < ", Punct), tok("b", Register), tok(" && ", Punct), tok("c", Register)];
        assert_eq!(text(&negate_cond(&c)), "!(a < b && c)");
    }

    #[test]
    fn pointer_parameters() {
        assert_eq!(pointee("LPDWORD").as_deref(), Some("DWORD"));
        assert_eq!(pointee("PHKEY").as_deref(), Some("HKEY"));
        assert_eq!(pointee("LPVOID"), None);
        assert_eq!(pointee("int *").as_deref(), Some("int"));
        assert_eq!(param_type("LPCWSTR lpFileName"), "LPCWSTR");
    }
}
