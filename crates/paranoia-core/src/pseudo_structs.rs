//! Struct member access in pseudocode (IDA's `->field`).
//!
//! A variable typed `NAME *` (with `Y` in the pseudocode view, or through a copy such as
//! `v3 = a1;`) turns `*(uint32_t *)(v + 0x1c)` into `v->lpFileName`: direct and nested fields, array elements, and
//! `&v->field` for lea results passed to calls. The pass runs after variable
//! recovery, so it works on the final names (`a1`, `v3`, `var_8`) and rewrites
//! the signature and declarations to match.

use std::collections::{BTreeMap, HashMap};

use crate::model::{Token, TokenKind};
use crate::pseudo::PseudoLine;
use crate::pseudo_opt::{assignment, call_at, merge, parse_c_number};
use crate::types::{StructDef, TypeSource};

/// One rendered path segment.
enum Part {
    /// A field name, joined to the previous part with `->` (first) or `.`.
    Field(String),
    /// A constant array index.
    Index(i128),
    /// A variable array index (the token as written).
    IndexVar(Token),
}

/// Cast size from a `*(uint32_t *)` keyword token.
fn cast_size(kw: &str) -> Option<u64> {
    match kw.strip_prefix("*(")?.strip_suffix(" *)")? {
        "uint8_t" => Some(1),
        "uint16_t" => Some(2),
        "uint32_t" => Some(4),
        "uint64_t" => Some(8),
        "__m128" => Some(16),
        "__m256" => Some(32),
        _ => None,
    }
}

/// `MY_STRUCT *` / `struct MY_STRUCT *` → `MY_STRUCT`, only when declared.
fn struct_ptr(ty: &str, lib: &dyn TypeSource) -> Option<String> {
    let t = ty.trim().trim_start_matches("const ").trim();
    let t = t.strip_suffix('*')?.trim();
    let t = t.trim_start_matches("struct ").trim();
    lib.struct_def(t).is_some().then(|| t.to_string())
}

/// An address expression: (base, displacement, scaled index).
type Addr = (String, i128, Option<(String, i128)>);

/// The address expression inside a deref: `base`, `base + n`, `base - n`,
/// `base + n + i * s`.
fn address(toks: &[Token]) -> Option<Addr> {
    let mut it = toks.iter();
    let base = match it.next()? {
        t if t.k == TokenKind::Register => t.t.clone(),
        _ => return None,
    };
    let mut disp = 0i128;
    let mut index: Option<(String, i128)> = None;
    while let Some(op) = it.next() {
        let add = if op.k == TokenKind::Punct && op.t == " + " {
            true
        } else if op.k == TokenKind::Punct && op.t == " - " {
            false
        } else {
            return None;
        };
        let t = it.next()?;
        match t.k {
            TokenKind::Number => {
                let v = parse_c_number(&t.t)?;
                disp += if add { v as i128 } else { -(v as i128) };
            }
            TokenKind::Register if add && index.is_none() => {
                let mul = it.next()?;
                if !(mul.k == TokenKind::Punct && mul.t == " * ") {
                    return None;
                }
                let s = it.next()?;
                if s.k != TokenKind::Number {
                    return None;
                }
                let scale = parse_c_number(&s.t)?;
                if scale <= 0 {
                    return None;
                }
                index = Some((t.t.clone(), scale as i128));
            }
            _ => return None,
        }
    }
    Some((base, disp, index))
}

/// Resolves an access to (offset, size, scaled index) inside `s` into field path parts.
/// A `size` of 0 matches any field (taking an address with `&`).
fn resolve(s: &StructDef, off: i128, size: u64, idx: &Option<(String, i128)>, lib: &dyn TypeSource) -> Option<Vec<Part>> {
    if off < 0 {
        return None;
    }
    let off = off as u64;
    let size_ok = |elem: u64| size == 0 || elem == size;
    for f in &s.fields {
        if f.offset == off {
            if let Some((reg, scale)) = idx.as_ref() {
                if f.count > 1 && f.elem_size as i128 == *scale {
                    if let Some(mut sub) =
                        f.nested.as_deref().and_then(|n| lib.struct_def(n)).and_then(|ns| resolve(ns, 0, size, &None, lib))
                    {
                        let mut out = vec![Part::Field(f.name.clone()), Part::IndexVar(Token { t: reg.clone(), k: TokenKind::Register })];
                        out.append(&mut sub);
                        return Some(out);
                    }
                    return Some(vec![Part::Field(f.name.clone()), Part::IndexVar(Token { t: reg.clone(), k: TokenKind::Register })]);
                }
                continue;
            }
            if size_ok(f.elem_size) {
                return match f.count > 1 {
                    true => Some(vec![Part::Field(f.name.clone()), Part::Index(0)]),
                    false => Some(vec![Part::Field(f.name.clone())]),
                };
            }
        }
        // A constant index inside an array field (`ctx + 0x18` with `DWORD ids[4]` at 0x14).
        if idx.is_none() && f.count > 1 && size_ok(f.elem_size) && off > f.offset && off < f.offset + f.elem_size * f.count {
            let d = off - f.offset;
            if d.is_multiple_of(f.elem_size) {
                return Some(vec![Part::Field(f.name.clone()), Part::Index(d as i128 / f.elem_size as i128)]);
            }
        }
        // A member of a nested struct (or an element of an array of structs).
        if let Some(ns) = f.nested.as_deref().and_then(|n| lib.struct_def(n)) {
            let elem = ns.size.max(1);
            let (base_off, index) = match idx.as_ref() {
                // `ctx->arr[i].x`: the index walks the array, the displacement picks the member.
                Some((reg, scale)) if f.count > 1 && *scale == elem as i128 => {
                    if off < f.offset || off - f.offset >= elem {
                        continue;
                    }
                    (f.offset, Some(Part::IndexVar(Token { t: reg.clone(), k: TokenKind::Register })))
                }
                // A scaled index we cannot represent must never be silently dropped.
                Some(_) => continue,
                None => {
                    if f.count > 1 && off >= f.offset && off < f.offset + elem * f.count {
                        let d = off - f.offset;
                        (f.offset + d % elem, Some(Part::Index((d / elem) as i128)))
                    } else if off >= f.offset && off < f.offset + elem {
                        (f.offset, None)
                    } else {
                        continue;
                    }
                }
            };
            if let Some(mut sub) = resolve(ns, (off - base_off) as i128, size, &None, lib) {
                let mut out = vec![Part::Field(f.name.clone())];
                if let Some(i) = index {
                    out.push(i);
                }
                out.append(&mut sub);
                return Some(out);
            }
        }
    }
    None
}

/// Renders `->`/`.`/`[]` parts as tokens.
fn parts_tokens(parts: &[Part]) -> Vec<Token> {
    let mut out = Vec::new();
    for (n, p) in parts.iter().enumerate() {
        match p {
            Part::Field(name) => {
                out.push(Token { t: if n == 0 { "->".into() } else { ".".into() }, k: TokenKind::Punct });
                out.push(Token { t: name.clone(), k: TokenKind::Symbol });
            }
            Part::Index(i) => {
                out.push(Token { t: "[".into(), k: TokenKind::Punct });
                out.push(Token { t: i.to_string(), k: TokenKind::Number });
                out.push(Token { t: "]".into(), k: TokenKind::Punct });
            }
            Part::IndexVar(t) => {
                out.push(Token { t: "[".into(), k: TokenKind::Punct });
                out.push(t.clone());
                out.push(Token { t: "]".into(), k: TokenKind::Punct });
            }
        }
    }
    out
}

/// The token range of a parenthesized group opened at `open` (a bare `(` token):
/// the index just past its matching `)`.
fn close_of(toks: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (k, t) in toks.iter().enumerate().skip(open) {
        if !matches!(t.k, TokenKind::Punct | TokenKind::Keyword) {
            continue;
        }
        for c in t.t.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        }
        if depth == 0 {
            return Some(k);
        }
    }
    None
}

/// Rewrites one deref cast (`*(uint32_t *)(a1 + 0x1c)`) starting at token `p` (the cast keyword).
/// Returns the replacement tokens and the index just past the consumed group.
fn rewrite_deref(toks: &[Token], p: usize, types: &HashMap<String, String>, lib: &dyn TypeSource) -> Option<(Vec<Token>, usize)> {
    let size = cast_size(&toks[p].t)?;
    let (inner, end): (&[Token], usize) = match toks.get(p + 1) {
        // `*(uint32_t *)a1`: offset zero, no parentheses.
        Some(t) if t.k == TokenKind::Register => (&toks[p + 1..p + 2], p + 2),
        Some(t) if t.k == TokenKind::Punct && t.t == "(" => {
            let close = close_of(toks, p + 1)?;
            (&toks[p + 2..close], close + 1)
        }
        _ => return None,
    };
    let (base, disp, idx) = address(inner)?;
    let name = types.get(&base)?;
    let s = lib.struct_def(struct_ptr(name, lib)?.as_str())?;
    let parts = resolve(s, disp, size, &idx, lib)?;
    let mut out = vec![Token { t: base, k: TokenKind::Register }];
    out.extend(parts_tokens(&parts));
    Some((out, end))
}

/// Rewrites a bare `base + off` (a lea result) into `&base->field`.
fn rewrite_lea(toks: &[Token], p: usize, types: &HashMap<String, String>, lib: &dyn TypeSource) -> Option<(Vec<Token>, usize)> {
    let base = &toks[p];
    let add = toks.get(p + 1)?;
    if !(add.k == TokenKind::Punct && add.t == " + ") {
        return None;
    }
    let num = toks.get(p + 2)?;
    if num.k != TokenKind::Number {
        return None;
    }
    let off = parse_c_number(&num.t)? as i128;
    let name = types.get(&base.t)?;
    let s = lib.struct_def(struct_ptr(name, lib)?.as_str())?;
    let parts = resolve(s, off, 0, &None, lib)?;
    let mut out = vec![Token { t: "&".into(), k: TokenKind::Punct }, base.clone()];
    out.extend(parts_tokens(&parts));
    Some((out, p + 3))
}

/// Rewrites the type token before typed variables in the signature and in declarations.
fn rewrite_decls(lines: &mut [PseudoLine], types: &HashMap<String, String>) {
    let mut hits: Vec<(usize, usize, String)> = Vec::new();
    for (n, l) in lines.iter().enumerate() {
        let is_sig = n == 0;
        let is_decl = n > 0 && l.indent == 1 && l.tokens.len() >= 3 && l.tokens[1].k == TokenKind::Text && l.tokens[1].t == " ";
        if !is_sig && !is_decl {
            continue;
        }
        for k in 0..l.tokens.len().saturating_sub(2) {
            let a = &l.tokens[k];
            let b = &l.tokens[k + 1];
            let c = &l.tokens[k + 2];
            if a.k == TokenKind::Keyword && b.t == " " && c.k == TokenKind::Register {
                // Never rewrite array declarations (`char var_20[64];`).
                let array = l.tokens.get(k + 3).is_some_and(|t| t.t.starts_with('['));
                if let (false, Some(ty)) = (array, types.get(&c.t)) {
                    hits.push((n, k, ty.clone()));
                }
            }
        }
    }
    for (n, k, ty) in hits {
        lines[n].tokens[k] = Token { t: ty, k: TokenKind::Keyword };
    }
}

/// The resolved variable types of a function: user-typed (`Y`) struct pointers plus
/// The pointed-to struct of a pointer field (`struct PKT *next` → `("PKT", "PKT *")`).
fn ptr_field(s: &StructDef, off: i128, size: u64, lib: &dyn TypeSource) -> Option<String> {
    if off < 0 {
        return None;
    }
    let off = off as u64;
    let f = s.fields.iter().find(|f| f.offset == off && f.pointer && f.elem_size == size)?;
    let name = f.ty.trim_end_matches('*').trim();
    lib.struct_def(name).is_some().then(|| format!("{name} *"))
}

/// `v = *(uint64_t *)(base + off)` where `base` is a typed struct pointer and `off` is
/// a pointer field of a declared struct: the loaded value has the field's pointer type.
fn loaded_ptr_type(expr: &[Token], types: &HashMap<String, String>, lib: &dyn TypeSource) -> Option<String> {
    let size = cast_size(&expr.first()?.t)?;
    if !matches!(size, 4 | 8) {
        return None;
    }
    let inner: &[Token] = match expr.get(1) {
        Some(t) if t.k == TokenKind::Punct && t.t == "(" => {
            let close = close_of(expr, 1)?;
            &expr[2..close]
        }
        // `*(uint64_t *)v`: a field at offset zero.
        Some(t) if t.k == TokenKind::Register => &expr[1..2],
        _ => return None,
    };
    let (base, disp, idx) = address(inner)?;
    // Indexed loads are left to the conservative path.
    if idx.is_some() {
        return None;
    }
    let s = lib.struct_def(struct_ptr(types.get(&base)?, lib)?.as_str())?;
    ptr_field(s, disp, size, lib)
}

/// The resolved variable types of a function: user-typed (`Y`) struct pointers plus
/// everything inherited through single-assignment copies (`v3 = a1;`) and through
/// struct pointer fields (`v4 = *(uint64_t *)(a1 + 0x28)` with `PKT *next` declared).
pub(crate) fn resolved_var_types(lines: &[PseudoLine], lib: &dyn TypeSource, user: &BTreeMap<String, String>) -> HashMap<String, String> {
    let mut types: HashMap<String, String> =
        user.iter().filter(|(_, ty)| struct_ptr(ty, lib).is_some()).map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut writes: HashMap<String, usize> = HashMap::new();
    for l in lines.iter() {
        if let Some((lhs, _)) = assignment(l) {
            *writes.entry(lhs.t.clone()).or_default() += 1;
        }
    }
    for l in lines.iter() {
        let Some((lhs, expr)) = assignment(l) else { continue };
        if writes.get(&lhs.t).copied().unwrap_or(0) != 1 || types.contains_key(&lhs.t) {
            continue;
        }
        // A plain copy (`v3 = a1;`).
        if let [src] = expr.as_slice() {
            if src.k == TokenKind::Register {
                if let Some(ty) = types.get(&src.t) {
                    types.insert(lhs.t.clone(), ty.clone());
                    continue;
                }
            }
        }
        // A loaded struct pointer field (`v4 = *(uint64_t *)(a1 + 0x28)`).
        if let Some(ty) = loaded_ptr_type(&expr, &types, lib) {
            types.insert(lhs.t.clone(), ty);
        }
    }
    types
}

/// A decimal / hex number token the way the decompiler prints constants.
fn num_token(v: i128) -> Token {
    let t = if v < 0 {
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
    Token { t, k: TokenKind::Number }
}

/// `sizeof` of the struct a typed pointer variable points to, with the pointer type as written.
fn pointee_size(var: &str, types: &HashMap<String, String>, lib: &dyn TypeSource) -> Option<(i128, String)> {
    let ty = types.get(var)?;
    let name = struct_ptr(ty, lib)?;
    let size = lib.struct_def(&name)?.size as i128;
    (size > 0).then(|| (size, ty.trim().to_string()))
}

/// Byte arithmetic on a typed pointer. C scales `p + n` by `sizeof(*p)`, but the machine code
/// added bytes, so a plain `p += 8` on a `T *` would be wrong. When the byte count is a multiple
/// of the struct size it becomes an element count (`p += 2`); otherwise the byte cast is explicit.
fn step_line(toks: &[Token], types: &HashMap<String, String>, lib: &dyn TypeSource) -> Option<Vec<Token>> {
    let v = toks.first().filter(|t| t.k == TokenKind::Register)?;
    let (size, ty) = pointee_size(&v.t, types, lib)?;
    let (sign, bytes) = match toks {
        [_, op, num, end] if end.t == ";" && num.k == TokenKind::Number && (op.t == " += " || op.t == " -= ") => {
            (if op.t == " += " { 1 } else { -1 }, parse_c_number(&num.t)? as i128)
        }
        [_, end] if end.t == "++;" => (1, 1),
        [_, end] if end.t == "--;" => (-1, 1),
        _ => return None,
    };
    let reg = Token { t: v.t.clone(), k: TokenKind::Register };
    let punct = |t: &str| Token { t: t.into(), k: TokenKind::Punct };
    if bytes % size == 0 {
        let k = bytes / size;
        return Some(match (sign, k) {
            (1, 1) => vec![reg, punct("++;")],
            (_, 1) => vec![reg, punct("--;")],
            (1, _) => vec![reg, punct(" += "), num_token(k), punct(";")],
            _ => vec![reg, punct(" -= "), num_token(k), punct(";")],
        });
    }
    Some(vec![
        reg.clone(),
        punct(" = "),
        Token { t: format!("({ty})"), k: TokenKind::Keyword },
        punct("("),
        Token { t: "(uint8_t *)".into(), k: TokenKind::Keyword },
        reg,
        punct(if sign > 0 { " + " } else { " - " }),
        num_token(bytes),
        punct(");"),
    ])
}

/// `p + n` / `p - n` inside an expression, for a typed pointer `p`. Inside a raw dereference the
/// byte meaning is kept (`*(uint32_t *)((uint8_t *)p + 0x40)`); elsewhere it follows the same
/// element-or-explicit-cast rule as [`step_line`].
fn rewrite_ptr_arith(
    toks: &[Token],
    p: usize,
    out: &[Token],
    types: &HashMap<String, String>,
    lib: &dyn TypeSource,
) -> Option<(Vec<Token>, usize)> {
    let v = toks.get(p)?;
    let (size, ty) = pointee_size(&v.t, types, lib)?;
    let op = toks.get(p + 1).filter(|t| t.k == TokenKind::Punct && (t.t == " + " || t.t == " - "))?;
    let num = toks.get(p + 2).filter(|t| t.k == TokenKind::Number)?;
    let bytes = parse_c_number(&num.t)? as i128;
    // `p + n + i * 8` is a larger expression: leave it alone.
    if toks
        .get(p + 3)
        .is_some_and(|t| t.k == TokenKind::Punct && (t.t.starts_with(" + ") || t.t.starts_with(" - ") || t.t.starts_with(" * ")))
    {
        return None;
    }
    let reg = Token { t: v.t.clone(), k: TokenKind::Register };
    let in_deref = out.len() >= 2
        && out[out.len() - 1].k == TokenKind::Punct
        && out[out.len() - 1].t.ends_with('(')
        && out[out.len() - 2].k == TokenKind::Keyword
        && out[out.len() - 2].t.starts_with("*(");
    let bytes_cast = Token { t: "(uint8_t *)".into(), k: TokenKind::Keyword };
    if in_deref {
        return Some((vec![bytes_cast, reg, op.clone(), num.clone()], p + 3));
    }
    if bytes % size == 0 {
        return Some((vec![reg, op.clone(), num_token(bytes / size)], p + 3));
    }
    let punct = |t: &str| Token { t: t.into(), k: TokenKind::Punct };
    Some((
        vec![Token { t: format!("({ty})"), k: TokenKind::Keyword }, punct("("), bytes_cast, reg, op.clone(), num.clone(), punct(")")],
        p + 3,
    ))
}

/// Applies struct member access to a function's pseudocode lines.
pub(crate) fn member_access(lines: &mut [PseudoLine], lib: &dyn TypeSource, user: &BTreeMap<String, String>) {
    if !lib.has_structs() {
        return;
    }
    let types = resolved_var_types(lines, lib, user);
    if types.is_empty() {
        return;
    }

    // Rewrite deref casts and lea results.
    for l in lines.iter_mut() {
        if let Some(t) = step_line(&l.tokens, &types, lib) {
            l.tokens = merge(t);
            continue;
        }
        let is_call = call_at(l).is_some();
        let mut out: Vec<Token> = Vec::with_capacity(l.tokens.len());
        let mut p = 0;
        while p < l.tokens.len() {
            let t = l.tokens[p].clone();
            if t.k == TokenKind::Keyword && t.t.starts_with("*(") {
                if let Some((repl, end)) = rewrite_deref(&l.tokens, p, &types, lib) {
                    out.extend(repl);
                    p = end;
                    continue;
                }
            }
            if t.k == TokenKind::Register && types.contains_key(&t.t) {
                // As a whole assignment RHS (`v3 = a1 + 0x1c;`) or a call argument (`f(a1 + 0x1c)`).
                let rhs = p == 2
                    && l.tokens[0].k == TokenKind::Register
                    && l.tokens[0].t != t.t
                    && l.tokens[1].k == TokenKind::Punct
                    && l.tokens[1].t.starts_with(" = ")
                    && !l.tokens[1].t.starts_with(" ==");
                let in_call = is_call && {
                    let before = out.last().map(|x| x.t.as_str()).unwrap_or("");
                    let after = l.tokens.get(p + 3).map(|x| x.t.as_str()).unwrap_or("");
                    (before.ends_with('(') || before.ends_with(", "))
                        && l.tokens.get(p + 1).is_some_and(|x| x.k == TokenKind::Punct && x.t == " + ")
                        && l.tokens.get(p + 2).is_some_and(|x| x.k == TokenKind::Number)
                        && (after.starts_with(',') || after.starts_with(')'))
                };
                if rhs || in_call {
                    if let Some((repl, end)) = rewrite_lea(&l.tokens, p, &types, lib) {
                        out.extend(repl);
                        p = end;
                        continue;
                    }
                }
                if let Some((repl, end)) = rewrite_ptr_arith(&l.tokens, p, &out, &types, lib) {
                    out.extend(repl);
                    p = end;
                    continue;
                }
            }
            out.push(t);
            p += 1;
        }
        l.tokens = merge(out);
    }

    rewrite_decls(lines, &types);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(t: &str, k: TokenKind) -> Token {
        Token { t: t.into(), k }
    }
    fn line(indent: u8, toks: Vec<Token>) -> PseudoLine {
        PseudoLine { address: None, indent, tokens: toks }
    }
    /// `v = EXPR;` with EXPR as (kind, text) pairs.
    fn assign(v: &str, expr: Vec<(String, TokenKind)>) -> PseudoLine {
        let mut toks = vec![tok(v, TokenKind::Register), tok(" = ", TokenKind::Punct)];
        toks.extend(expr.into_iter().map(|(t, k)| tok(&t, k)));
        toks.push(tok(";", TokenKind::Punct));
        line(1, toks)
    }
    fn deref(ty: &str, base: &str, disp: &str, idx: Option<(&str, i64)>) -> Vec<(String, TokenKind)> {
        let mut v = vec![(format!("*({ty} *)"), TokenKind::Keyword), ("(".into(), TokenKind::Punct), (base.into(), TokenKind::Register)];
        if !disp.is_empty() {
            v.push((" + ".into(), TokenKind::Punct));
            v.push((disp.into(), TokenKind::Number));
        }
        if let Some((var, scale)) = idx {
            v.push((" + ".into(), TokenKind::Punct));
            v.push((var.into(), TokenKind::Register));
            v.push((" * ".into(), TokenKind::Punct));
            v.push((scale.to_string(), TokenKind::Number));
        }
        v.push((")".into(), TokenKind::Punct));
        v
    }
    fn lib() -> crate::types::TypeLibrary {
        crate::types::parse(
            "typedef struct _POINT { LONG x; LONG y; } POINT;
             struct PKT { BYTE kind; DWORD crc; char *name; POINT where; DWORD ids[4]; struct PKT *next; };",
            8,
        )
        .unwrap()
    }
    fn user() -> BTreeMap<String, String> {
        BTreeMap::from([("a1".into(), "PKT *".into())])
    }
    fn apply(lines: Vec<PseudoLine>) -> Vec<String> {
        let mut v = lines;
        member_access(&mut v, &lib(), &user());
        v.iter().map(|l| l.tokens.iter().map(|t| t.t.as_str()).collect()).collect()
    }

    #[test]
    fn pointer_steps_follow_c_semantics() {
        // sizeof(PKT) = 48 on 64-bit
        let size = lib().structs["PKT"].size;
        assert_eq!(size, 48);
        let step = |op: &str, n: &str| {
            let toks =
                vec![tok("a1", TokenKind::Register), tok(op, TokenKind::Punct), tok(n, TokenKind::Number), tok(";", TokenKind::Punct)];
            let mut v = vec![line(1, toks)];
            member_access(&mut v, &lib(), &user());
            v[0].tokens.iter().map(|t| t.t.as_str()).collect::<String>()
        };
        assert_eq!(step(" += ", "0x30"), "a1++;");
        assert_eq!(step(" += ", "0x60"), "a1 += 2;");
        assert_eq!(step(" -= ", "0x30"), "a1--;");
        assert_eq!(step(" += ", "8"), "a1 = (PKT *)((uint8_t *)a1 + 8);");
        assert_eq!(step(" -= ", "0x14"), "a1 = (PKT *)((uint8_t *)a1 - 0x14);");
        // x86 `inc` moves one byte
        let mut v = vec![line(1, vec![tok("a1", TokenKind::Register), tok("++;", TokenKind::Punct)])];
        member_access(&mut v, &lib(), &user());
        assert_eq!(v[0].tokens.iter().map(|t| t.t.as_str()).collect::<String>(), "a1 = (PKT *)((uint8_t *)a1 + 1);");
    }

    #[test]
    fn pointer_sums_in_expressions() {
        let sum = |n: &str| {
            vec![("a1".to_string(), TokenKind::Register), (" + ".to_string(), TokenKind::Punct), (n.to_string(), TokenKind::Number)]
        };
        assert_eq!(apply(vec![assign("v1", sum("0x60"))])[0], "v1 = a1 + 2;");
        assert_eq!(apply(vec![assign("v1", sum("0x50"))])[0], "v1 = (PKT *)((uint8_t *)a1 + 0x50);");
        // a raw dereference of an unknown offset keeps its byte meaning
        assert_eq!(apply(vec![assign("v1", deref("uint32_t", "a1", "0x50", None))])[0], "v1 = *(uint32_t *)((uint8_t *)a1 + 0x50);");
    }

    #[test]
    fn direct_field() {
        let v = apply(vec![assign("v1", deref("uint32_t", "a1", "0x4", None))]);
        assert_eq!(v[0], "v1 = a1->crc;");
    }

    #[test]
    fn offset_zero_without_parens() {
        let v = apply(vec![assign("v1", deref("uint8_t", "a1", "", None))]);
        assert_eq!(v[0], "v1 = a1->kind;");
    }

    #[test]
    fn array_with_variable_and_constant_index() {
        let v =
            apply(vec![assign("v1", deref("uint32_t", "a1", "0x18", Some(("i", 4)))), assign("v2", deref("uint32_t", "a1", "0x1c", None))]);
        assert_eq!(v[0], "v1 = a1->ids[i];");
        assert_eq!(v[1], "v2 = a1->ids[1];");
    }

    #[test]
    fn nested_struct_descent() {
        let v = apply(vec![assign("v1", deref("uint32_t", "a1", "0x10", None))]);
        assert_eq!(v[0], "v1 = a1->where.x;");
    }

    #[test]
    fn array_of_structs_with_variable_index() {
        let l = crate::types::parse("struct REC { DWORD x; DWORD y; }; struct LOG { DWORD n; REC r[4]; };", 8).unwrap();
        let mut v = vec![assign("v1", deref("uint32_t", "a1", "0x4", None)), assign("v2", deref("uint32_t", "a1", "0x4", Some(("i", 8))))];
        member_access(&mut v, &l, &BTreeMap::from([("a1".to_string(), "LOG *".to_string())]));
        let t: Vec<String> = v.iter().map(|x| x.tokens.iter().map(|t| t.t.as_str()).collect()).collect();
        assert_eq!(t[0], "v1 = a1->r[0].x;");
        assert_eq!(t[1], "v2 = a1->r[i].x;");
    }

    #[test]
    fn pointer_field_followed() {
        let v = apply(vec![assign("v1", deref("uint64_t", "a1", "0x28", None))]);
        assert_eq!(v[0], "v1 = a1->next;");
    }

    #[test]
    fn propagation_through_copy() {
        let copy = assign("v3", vec![("a1".into(), TokenKind::Register)]);
        let v = apply(vec![copy, assign("v1", deref("uint32_t", "v3", "0x4", None))]);
        assert_eq!(v[1], "v1 = v3->crc;");
        // A twice-written variable must not inherit the type.
        let v = apply(vec![
            assign("v3", vec![("a1".into(), TokenKind::Register)]),
            assign("v3", vec![("0".into(), TokenKind::Number)]),
            assign("v1", deref("uint32_t", "v3", "0x4", None)),
        ]);
        assert_eq!(v[2], "v1 = *(uint32_t *)(v3 + 0x4);");
    }

    #[test]
    fn lea_into_call_argument() {
        let call = line(
            1,
            vec![
                tok("f", TokenKind::Symbol),
                tok("(", TokenKind::Punct),
                tok("a1", TokenKind::Register),
                tok(" + ", TokenKind::Punct),
                tok("0x8", TokenKind::Number),
                tok(");", TokenKind::Punct),
            ],
        );
        let v = apply(vec![
            call,
            assign("v3", vec![("a1".into(), TokenKind::Register), (" + ".into(), TokenKind::Punct), ("0x8".into(), TokenKind::Number)]),
        ]);
        assert_eq!(v[0], "f(&a1->name);");
        assert_eq!(v[1], "v3 = &a1->name;");
    }

    #[test]
    fn signature_and_declarations_are_typed() {
        let mut v = vec![
            line(
                0,
                vec![
                    tok("__int64", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok("__fastcall", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok("f", TokenKind::Symbol),
                    tok("(", TokenKind::Punct),
                    tok("__int64", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok("a1", TokenKind::Register),
                    tok(", ", TokenKind::Punct),
                    tok("__int64", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok("a2", TokenKind::Register),
                    tok(")", TokenKind::Punct),
                ],
            ),
            line(
                1,
                vec![
                    tok("__int64", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok("v3", TokenKind::Register),
                    tok("; ", TokenKind::Punct),
                    tok("// rbx", TokenKind::Text),
                ],
            ),
        ];
        member_access(&mut v, &lib(), &user());
        let sig: String = v[0].tokens.iter().map(|t| t.t.as_str()).collect();
        assert!(sig.contains("PKT * a1"), "{sig}");
        assert!(sig.contains("__int64 a2"), "{sig}");
    }

    #[test]
    fn unknown_type_and_size_mismatch_are_untouched() {
        let mut v = vec![assign("v1", deref("uint32_t", "a1", "0x4", None))];
        member_access(&mut v, &lib(), &BTreeMap::new());
        let t: String = v[0].tokens.iter().map(|x| x.t.as_str()).collect();
        assert_eq!(t, "v1 = *(uint32_t *)(a1 + 0x4);");
        // Wrong access size for the field: no member, and on a typed pointer the byte offset is explicit
        // (a bare `a1 + 0x4` would read as four elements in C).
        let v = apply(vec![assign("v1", deref("uint16_t", "a1", "0x4", None))]);
        assert_eq!(v[0], "v1 = *(uint16_t *)((uint8_t *)a1 + 0x4);");
        // A negative displacement is never a member.
        let neg = vec![
            ("*(uint32_t *)".to_string(), TokenKind::Keyword),
            ("(".to_string(), TokenKind::Punct),
            ("a1".to_string(), TokenKind::Register),
            (" - ".to_string(), TokenKind::Punct),
            ("0x4".to_string(), TokenKind::Number),
            (")".to_string(), TokenKind::Punct),
        ];
        let v = apply(vec![assign("v1", neg)]);
        assert_eq!(v[0], "v1 = *(uint32_t *)((uint8_t *)a1 - 0x4);");
        // Unknown offsets stay raw byte accesses.
        let v = apply(vec![assign("v1", deref("uint32_t", "a1", "0x99", None))]);
        assert_eq!(v[0], "v1 = *(uint32_t *)((uint8_t *)a1 + 0x99);");
    }

    #[test]
    fn pointer_fields_chain() {
        // `struct PKT *next` at 0x28: the loaded pointer is a `PKT *` itself, so the
        // next dereference renders as a member access and chains further.
        let v = apply(vec![
            assign("v1", deref("uint64_t", "a1", "0x28", None)),
            assign("v2", deref("uint64_t", "v1", "0x28", None)),
            assign("v3", deref("uint32_t", "v2", "0x4", None)),
        ]);
        assert_eq!(v[0], "v1 = a1->next;");
        assert_eq!(v[1], "v2 = v1->next;");
        assert_eq!(v[2], "v3 = v2->crc;");
    }

    #[test]
    fn non_struct_pointer_field_is_not_typed() {
        // `char *name` at 0x8: the field renders, but its value has no struct type.
        let v = apply(vec![assign("v1", deref("uint64_t", "a1", "0x8", None)), assign("v2", deref("uint32_t", "v1", "0x4", None))]);
        assert_eq!(v[0], "v1 = a1->name;");
        assert_eq!(v[1], "v2 = *(uint32_t *)(v1 + 0x4);");
    }

    #[test]
    fn declarations_follow_pointer_fields() {
        // The declaration of the chained variable is typed like the field's pointee.
        let mut lines = vec![
            assign("v1", deref("uint64_t", "a1", "0x28", None)),
            PseudoLine {
                address: None,
                indent: 1,
                tokens: vec![
                    tok("__int64", TokenKind::Keyword),
                    tok(" ", TokenKind::Text),
                    tok("v1", TokenKind::Register),
                    tok(";", TokenKind::Punct),
                ],
            },
        ];
        lines.push(assign("v2", deref("uint32_t", "v1", "0x4", None)));
        member_access(&mut lines, &lib(), &user());
        let decl: String = lines[1].tokens.iter().map(|t| t.t.as_str()).collect();
        assert_eq!(decl, "PKT * v1;");
    }
}
