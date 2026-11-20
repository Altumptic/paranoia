//! Function prototypes set by the user: `int __stdcall f(HANDLE h, char *buf, DWORD n)`.
//!
//! The decompiler guesses a function's parameters from the registers it reads; a prototype from
//! the user (the documentation, the header, a guess made by reading the code) replaces the guess:
//! the signature line carries the return type, the calling convention and every parameter's type and
//! name, the body uses the names, and typed struct pointers turn loads into `->field` access.
//!
//! This module parses the C text and rewrites the signature line; `Binary::set_prototype` stores
//! it and the two pseudocode generators call [`apply`].

use std::collections::BTreeMap;

use crate::model::{Token, TokenKind};
use crate::pseudo::PseudoLine;

/// One parameter: its C type as written (`char *`) and its name, when given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Param {
    pub ty: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Proto {
    pub ret: String,
    pub conv: Option<String>,
    pub params: Vec<Param>,
    pub variadic: bool,
}

/// Calling-convention words, spelled as the signature prints them (`WINAPI` is `__stdcall`).
const CONVS: &[(&str, &str)] = &[
    ("__stdcall", "__stdcall"),
    ("__cdecl", "__cdecl"),
    ("__fastcall", "__fastcall"),
    ("__thiscall", "__thiscall"),
    ("__vectorcall", "__vectorcall"),
    ("WINAPI", "__stdcall"),
    ("APIENTRY", "__stdcall"),
    ("CALLBACK", "__stdcall"),
];

/// Words of a C type that are never a declarator name.
const TYPE_WORDS: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "bool", "_Bool", "__int8", "__int16", "__int32",
    "__int64", "const", "volatile", "struct", "union", "enum",
];

pub(crate) const MAX_PARAMS: usize = 32;
const MAX_LEN: usize = 512;

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Words of a declaration with every `*` as a word of its own.
fn words(s: &str) -> Vec<String> {
    let spaced = s.replace('*', " * ");
    spaced.split_whitespace().map(str::to_string).collect()
}

/// The words as one type: single spaces, stars joined (`char **`).
fn join_type(w: &[String]) -> String {
    let mut out = String::new();
    for x in w {
        if !(out.is_empty() || x == "*" && out.ends_with('*')) {
            out.push(' ');
        }
        out.push_str(x);
    }
    out
}

/// Splits `const char *buf` into (`const char *`, Some(`buf`)); a lone type has no name.
fn split_decl(w: &[String]) -> (Vec<String>, Option<String>) {
    if let [.., prev, last] = w {
        let tag = matches!(prev.as_str(), "struct" | "union" | "enum");
        if is_ident(last) && !TYPE_WORDS.contains(&last.as_str()) && !tag {
            return (w[..w.len() - 1].to_vec(), Some(last.clone()));
        }
    }
    (w.to_vec(), None)
}

/// Splits on commas that are not inside parentheses.
fn split_commas(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut from) = (Vec::new(), 0i32, 0);
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[from..i]);
                from = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[from..]);
    out
}

/// Reads a C function declaration. The function's own name, if written, is ignored (rename the
/// function instead); parameter names are optional.
pub(crate) fn parse(text: &str) -> Result<Proto, String> {
    let s = text.trim().trim_end_matches(';').trim();
    if s.is_empty() {
        return Err("the prototype is empty".into());
    }
    if s.len() > MAX_LEN {
        return Err(format!("the prototype is longer than {MAX_LEN} characters"));
    }
    if let Some(bad) = s.chars().find(|c| !(c.is_ascii_alphanumeric() || " _*,()[].".contains(*c))) {
        return Err(format!("`{bad}` cannot appear in a prototype"));
    }
    let open = s.find('(').ok_or("expected a parameter list in parentheses, like int f(char *s, int n)")?;
    let close = s.rfind(')').filter(|c| *c > open).ok_or("the parameter list is missing its closing parenthesis")?;
    if !s[close + 1..].trim().is_empty() {
        return Err("nothing may follow the parameter list".into());
    }

    // Return type, convention and (ignored) name.
    let mut head = words(&s[..open]);
    let mut conv = None;
    head.retain(|w| match CONVS.iter().find(|(k, _)| k == w) {
        Some((_, c)) => {
            conv = Some(c.to_string());
            false
        }
        None => true,
    });
    let (ret_words, _name) = if head.len() >= 2 { split_decl(&head) } else { (head.clone(), None) };
    if ret_words.is_empty() || ret_words.iter().all(|w| w == "*") {
        return Err("the return type is missing (write void if there is none)".into());
    }

    // Parameters.
    let inner = s[open + 1..close].trim();
    let mut params = Vec::new();
    let mut variadic = false;
    if !inner.is_empty() && inner != "void" {
        for (i, piece) in split_commas(inner).into_iter().enumerate() {
            let piece = piece.trim();
            if piece.is_empty() {
                return Err(format!("parameter {} is empty", i + 1));
            }
            if variadic {
                return Err("`...` must be the last parameter".into());
            }
            if piece == "..." {
                variadic = true;
                continue;
            }
            if piece.contains('(') {
                // A function pointer, `int (*cb)(int, int)`: the type keeps a `(*)` where the name goes.
                let one_line = piece.split_whitespace().collect::<Vec<_>>().join(" ");
                let star = one_line.find("(*").ok_or_else(|| format!("parameter {} is not a form a prototype can have", i + 1))?;
                let end = one_line[star..]
                    .find(')')
                    .map(|e| star + e)
                    .ok_or_else(|| format!("parameter {} has an unclosed parenthesis", i + 1))?;
                let name = one_line[star + 2..end].trim();
                let ty = format!("{}(*){}", &one_line[..star], &one_line[end + 1..]);
                params.push(Param { ty, name: (!name.is_empty()).then(|| name.to_string()) });
                continue;
            }
            let (ty, name) = split_decl(&words(piece));
            if ty.is_empty() || ty.iter().all(|w| w == "*") {
                return Err(format!("parameter {} has no type", i + 1));
            }
            params.push(Param { ty: join_type(&ty), name });
        }
    }
    if params.len() > MAX_PARAMS {
        return Err(format!("more than {MAX_PARAMS} parameters"));
    }
    // Names: valid, not the decompiler's own (`a1`, `v3`, `var_8`), and distinct.
    let mut seen = std::collections::HashSet::new();
    for p in &params {
        if let Some(n) = &p.name {
            crate::pseudo_types::check_var_name(n)?;
            if !seen.insert(n.clone()) {
                return Err(format!("two parameters are called `{n}`"));
            }
        }
    }
    Ok(Proto { ret: join_type(&ret_words), conv, params, variadic })
}

impl Proto {
    /// Types by generated parameter name (`a1`, `a2`, …), for struct member access.
    pub fn types(&self) -> BTreeMap<String, String> {
        self.params.iter().enumerate().map(|(i, p)| (format!("a{}", i + 1), p.ty.clone())).collect()
    }

    /// Names by generated parameter name, for the parameters that have one.
    pub fn names(&self) -> BTreeMap<String, String> {
        self.params.iter().enumerate().filter_map(|(i, p)| p.name.clone().map(|n| (format!("a{}", i + 1), n))).collect()
    }
}

fn tok(t: &str, k: TokenKind) -> Token {
    Token { t: t.to_string(), k }
}

/// Rewrites the signature line (the first line: `RET [conv] name(params)`) to the prototype. Parameters
/// the old signature had beyond the new list become local declarations, so the body still compiles
/// in the reader's head. Does nothing when the line has an unexpected shape.
pub(crate) fn apply(lines: &mut Vec<PseudoLine>, p: &Proto) {
    let Some(first) = lines.first() else { return };
    let toks = &first.tokens;
    let Some(name_at) = toks.iter().position(|t| t.k == TokenKind::Symbol) else { return };
    let Some(open) = toks.iter().enumerate().skip(name_at).find(|(_, t)| t.k == TokenKind::Punct && t.t == "(").map(|(i, _)| i) else {
        return;
    };
    let Some(close) = toks.iter().rposition(|t| t.k == TokenKind::Punct && t.t == ")") else { return };
    if close <= open {
        return;
    }

    // The old parameters: tokens up to the name, and the name (`a1`).
    let mut old: Vec<(Vec<Token>, String)> = Vec::new();
    let mut seg: Vec<Token> = Vec::new();
    let mut flush = |seg: &mut Vec<Token>| {
        if let Some(at) = seg.iter().rposition(|t| t.k == TokenKind::Register) {
            let name = seg[at].t.clone();
            old.push((seg[..at].to_vec(), name));
        }
        seg.clear();
    };
    for t in &toks[open + 1..close] {
        if t.k == TokenKind::Punct && t.t.starts_with(',') {
            flush(&mut seg);
        } else {
            seg.push(t.clone());
        }
    }
    flush(&mut seg);

    // The convention the decompiler printed stays unless the prototype names one.
    let existing_conv = toks[..name_at]
        .iter()
        .find(|t| t.k == TokenKind::Keyword && t.t.starts_with("__") && t.t != "__int64" && !t.t.starts_with("__int"))
        .map(|t| t.t.clone());
    let conv = p.conv.clone().or(existing_conv);

    let mut head = vec![tok(&p.ret, TokenKind::Keyword), tok(" ", TokenKind::Text)];
    if let Some(c) = &conv {
        head.push(tok(c, TokenKind::Keyword));
        head.push(tok(" ", TokenKind::Text));
    }
    let mut sig = head;
    sig.extend(toks[name_at..=open].iter().cloned());
    if p.params.is_empty() && !p.variadic {
        sig.push(tok("void", TokenKind::Keyword));
    }
    for (i, param) in p.params.iter().enumerate() {
        if i > 0 {
            sig.push(tok(", ", TokenKind::Punct));
        }
        // The generated name; the user's own name is applied with the other renames.
        let var = tok(&format!("a{}", i + 1), TokenKind::Register);
        match param.ty.split_once("(*)") {
            // `int (*)(int)` becomes `int (*a1)(int)`.
            Some((before, after)) => {
                sig.push(tok(&format!("{before}(*"), TokenKind::Keyword));
                sig.push(var);
                sig.push(tok(&format!("){after}"), TokenKind::Keyword));
            }
            None => {
                sig.push(tok(&param.ty, TokenKind::Keyword));
                sig.push(tok(" ", TokenKind::Text));
                sig.push(var);
            }
        }
    }
    if p.variadic {
        sig.push(tok(if p.params.is_empty() { "..." } else { ", ..." }, TokenKind::Punct));
    }
    sig.extend(toks[close..].iter().cloned());
    let indent = first.indent;
    let address = first.address;
    lines[0] = PseudoLine { address, indent, tokens: sig };

    // Old parameters past the new list are now ordinary locals.
    let extra: Vec<&(Vec<Token>, String)> =
        old.iter().filter(|(_, n)| n.strip_prefix('a').and_then(|d| d.parse::<usize>().ok()).is_some_and(|k| k > p.params.len())).collect();
    if !extra.is_empty() {
        if let Some(brace) = lines.iter().position(|l| l.tokens.len() == 1 && l.tokens[0].t == "{") {
            let decls: Vec<PseudoLine> = extra
                .iter()
                .map(|(ty, name)| {
                    let mut t = ty.clone();
                    t.push(tok(name, TokenKind::Register));
                    t.push(tok(";", TokenKind::Punct));
                    PseudoLine { address: None, indent: 1, tokens: t }
                })
                .collect();
            for (i, d) in decls.into_iter().enumerate() {
                lines.insert(brace + 1 + i, d);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// A small deterministic generator, so a failure can be reproduced.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn hostile_text_does_not_panic() {
        let pieces = [
            "int",
            "char",
            "*",
            "const",
            "struct",
            "foo",
            "(",
            ")",
            ",",
            ";",
            "...",
            "[",
            "]",
            "10",
            "__stdcall",
            " ",
            "\u{e9}",
            "\0",
            "(*",
            "fn)",
            "void",
            "unsigned",
            "long",
            "long",
            "{",
            "}",
            "//",
            "/*",
        ];
        let mut rng = Rng(0xfeed_5eed_0102_0304);
        for _ in 0..20_000 {
            let n = 1 + (rng.next() % 24) as usize;
            let text: String = (0..n)
                .map(|_| pieces[(rng.next() % pieces.len() as u64) as usize])
                .collect::<Vec<_>>()
                .join(if rng.next() & 1 == 0 { " " } else { "" });
            if let Ok(p) = parse(&text) {
                let _ = p.names();
                let _ = p.types();
                let mut lines = Vec::new();
                apply(&mut lines, &p);
            }
        }
        let _ = parse(&"(".repeat(100_000));
        let _ = parse(&"int *".repeat(100_000));
        let _ = parse(&format!("int f({})", "int a,".repeat(100_000)));
    }

    use super::*;

    fn p(s: &str) -> Proto {
        parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    fn text(l: &PseudoLine) -> String {
        l.tokens.iter().map(|t| t.t.as_str()).collect()
    }

    #[test]
    fn a_windows_prototype() {
        let x = p("BOOL WINAPI WriteIt(HANDLE hFile, const char *buf, DWORD n, LPDWORD written);");
        assert_eq!(x.ret, "BOOL");
        assert_eq!(x.conv.as_deref(), Some("__stdcall"));
        assert_eq!(
            x.params.iter().map(|q| (q.ty.as_str(), q.name.as_deref())).collect::<Vec<_>>(),
            vec![("HANDLE", Some("hFile")), ("const char *", Some("buf")), ("DWORD", Some("n")), ("LPDWORD", Some("written"))]
        );
        assert_eq!(x.types()["a2"], "const char *");
        assert_eq!(x.names()["a4"], "written");
    }

    #[test]
    fn names_are_optional_and_the_functions_own_name_is_ignored() {
        let x = p("unsigned long (char *, struct node *, unsigned int)");
        assert_eq!(x.ret, "unsigned long");
        assert_eq!(
            x.params.iter().map(|q| (q.ty.as_str(), q.name.as_deref())).collect::<Vec<_>>(),
            vec![("char *", None), ("struct node *", None), ("unsigned int", None)]
        );
        let y = p("void *  my_alloc ( size_t n )");
        assert_eq!((y.ret.as_str(), y.params[0].name.as_deref()), ("void *", Some("n")));
        assert_eq!(p("struct node * find(struct node *head, int key)").ret, "struct node *");
        assert!(p("int main(void)").params.is_empty());
        assert!(p("int f()").params.is_empty());
        assert!(p("int printf(const char *fmt, ...)").variadic);
        let z = p("void on(int (*cb)(int, int), void **out)");
        assert_eq!((z.params[0].ty.as_str(), z.params[0].name.as_deref()), ("int (*)(int, int)", Some("cb")));
        assert_eq!(z.params[1].ty, "void **");
    }

    #[test]
    fn bad_prototypes_say_what_is_wrong() {
        for (s, want) in [
            ("", "empty"),
            ("int f", "parameter list"),
            ("(int a)", "return type"),
            ("int f(int a) { x }", "cannot appear"),
            ("int f(int a, int a)", "two parameters"),
            ("int f(int a1)", "reserved"),
            ("int f(int while)", "keyword"),
            ("int f(int a,, int b)", "empty"),
            ("int f(..., int a)", "last"),
            ("int f(int a) extra", "nothing may follow"),
        ] {
            let e = parse(s).unwrap_err();
            assert!(e.contains(want), "{s}: {e}");
        }
        let many = format!("int f({})", (0..40).map(|i| format!("int p{i}")).collect::<Vec<_>>().join(", "));
        assert!(parse(&many).unwrap_err().contains("more than"));
        assert!(parse(&format!("int f({})", "x".repeat(600))).unwrap_err().contains("longer"));
    }

    fn line(indent: u8, toks: &[(&str, TokenKind)]) -> PseudoLine {
        PseudoLine { address: None, indent, tokens: toks.iter().map(|(t, k)| tok(t, *k)).collect() }
    }

    fn x86_function() -> Vec<PseudoLine> {
        use TokenKind::*;
        vec![
            line(
                0,
                &[
                    ("__int64", Keyword),
                    (" ", Text),
                    ("__fastcall", Keyword),
                    (" ", Text),
                    ("sub_401000", Symbol),
                    ("(", Punct),
                    ("__int64", Keyword),
                    (" ", Text),
                    ("a1", Register),
                    (", ", Punct),
                    ("__int64", Keyword),
                    (" ", Text),
                    ("a2", Register),
                    (", ", Punct),
                    ("__int64", Keyword),
                    (" ", Text),
                    ("a3", Register),
                    (")", Punct),
                ],
            ),
            line(0, &[("{", Punct)]),
            line(1, &[("return", Keyword), (" ", Text), ("a1", Register), (" + ", Punct), ("a3", Register), (";", Punct)]),
            line(0, &[("}", Punct)]),
        ]
    }

    #[test]
    fn the_signature_is_rewritten_and_extra_parameters_become_locals() {
        let mut l = x86_function();
        apply(&mut l, &p("int __stdcall f(char *s, DWORD n)"));
        assert_eq!(text(&l[0]), "int __stdcall sub_401000(char * a1, DWORD a2)");
        // a3 was a parameter and no longer is: declared as a local, so the body is still self-contained.
        assert_eq!(text(&l[2]), "__int64 a3;");
        assert_eq!(l[2].indent, 1);
        assert_eq!(text(&l[3]), "return a1 + a3;");
        // The generated parameter names are what the renames then act on.
        assert_eq!(p("int f(char *s, DWORD n)").names()["a1"], "s");
    }

    #[test]
    fn more_parameters_none_and_variadic() {
        let mut l = x86_function();
        apply(&mut l, &p("void f(int a, int b, int c, int d)"));
        assert_eq!(text(&l[0]), "void __fastcall sub_401000(int a1, int a2, int a3, int a4)");
        assert_eq!(l.len(), 4, "nothing becomes a local");
        let mut l = x86_function();
        apply(&mut l, &p("int f(void)"));
        assert_eq!(text(&l[0]), "int __fastcall sub_401000(void)");
        assert_eq!(text(&l[2]), "__int64 a1;");
        let mut l = x86_function();
        apply(&mut l, &p("int f(const char *fmt, ...)"));
        assert_eq!(text(&l[0]), "int __fastcall sub_401000(const char * a1, ...)");
        let mut l = x86_function();
        apply(&mut l, &p("void on(int (*cb)(int, int), int n)"));
        assert_eq!(text(&l[0]), "void __fastcall sub_401000(int (*a1)(int, int), int a2)");
        // An unexpected first line is left alone.
        let mut odd = vec![line(0, &[("nothing", TokenKind::Text)])];
        apply(&mut odd, &p("int f(int a)"));
        assert_eq!(text(&odd[0]), "nothing");
    }
}
