//! Local types (IDA's "Local Types"): C struct / enum declarations parsed into
//! layouts that can be applied to data.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    /// Declared type as written (`DWORD`, `char *`, `POINT`).
    pub ty: String,
    pub offset: u64,
    /// Size of one element.
    pub elem_size: u64,
    /// Array length (1 for scalars).
    pub count: u64,
    /// Name of a nested struct type, if the field is one.
    pub nested: Option<String>,
    pub pointer: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructDef {
    pub name: String,
    pub size: u64,
    pub align: u64,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumDef {
    pub name: String,
    pub members: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TypeLibrary {
    /// The declarations as the user wrote them (re-parsed on load).
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub structs: BTreeMap<String, StructDef>,
    #[serde(default)]
    pub enums: BTreeMap<String, EnumDef>,
}

/// Read-only access to struct / enum definitions, whichever layers they come from.
pub trait TypeSource {
    fn struct_def(&self, name: &str) -> Option<&StructDef>;
    fn enum_def(&self, name: &str) -> Option<&EnumDef>;
    fn has_structs(&self) -> bool;
}

impl TypeSource for TypeLibrary {
    fn struct_def(&self, name: &str) -> Option<&StructDef> {
        self.structs.get(name)
    }
    fn enum_def(&self, name: &str) -> Option<&EnumDef> {
        self.enums.get(name)
    }
    fn has_structs(&self) -> bool {
        !self.structs.is_empty()
    }
}

/// The user's Local Types layered over the types recovered from debug info (DWARF / PDB):
/// a user definition wins over a debug-info one with the same name. Debug-info types are
/// runtime data (there can be thousands) and are never saved with the annotations.
#[derive(Clone, Copy)]
pub struct TypeView<'a> {
    pub user: &'a TypeLibrary,
    pub debug: &'a TypeLibrary,
}

impl TypeSource for TypeView<'_> {
    fn struct_def(&self, name: &str) -> Option<&StructDef> {
        self.user.structs.get(name).or_else(|| self.debug.structs.get(name))
    }
    fn enum_def(&self, name: &str) -> Option<&EnumDef> {
        self.user.enums.get(name).or_else(|| self.debug.enums.get(name))
    }
    fn has_structs(&self) -> bool {
        !self.user.structs.is_empty() || !self.debug.structs.is_empty()
    }
}

/// One match of a type-name search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeHit {
    pub name: String,
    /// `struct` or `enum`.
    pub kind: String,
    pub size: u64,
    /// Where it came from: `user` or `debug`.
    pub origin: String,
}

impl TypeView<'_> {
    /// Names matching `query` (prefix matches first, then substring), user types before debug ones.
    pub fn search(&self, query: &str, limit: usize) -> Vec<TypeHit> {
        let q = query.trim().to_ascii_lowercase();
        let mut hits: Vec<(u8, TypeHit)> = Vec::new();
        for (lib, origin) in [(self.user, "user"), (self.debug, "debug")] {
            let structs = lib.structs.iter().map(|(n, s)| (n, "struct", s.size));
            let enums = lib.enums.keys().map(|n| (n, "enum", 0));
            for (name, kind, size) in structs.chain(enums) {
                let low = name.to_ascii_lowercase();
                let rank = if q.is_empty() || low.starts_with(&q) {
                    0
                } else if low.contains(&q) {
                    1
                } else {
                    continue;
                };
                // A user type hides a debug type of the same name.
                if origin == "debug" && (self.user.structs.contains_key(name) || self.user.enums.contains_key(name)) {
                    continue;
                }
                hits.push((
                    rank + u8::from(origin == "debug") * 2,
                    TypeHit { name: name.clone(), kind: kind.into(), size, origin: origin.into() },
                ));
            }
        }
        hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.len().cmp(&b.1.name.len())).then_with(|| a.1.name.cmp(&b.1.name)));
        hits.into_iter().take(limit).map(|h| h.1).collect()
    }
}

/// A union parses into fields that all start at offset 0; the model doesn't record
/// whether a definition was written as `union`, so the layout decides it again.
fn is_union(s: &StructDef) -> bool {
    s.fields.len() > 1 && s.fields.iter().all(|f| f.offset == 0)
}

/// One field of a C declaration, as [`parse`] accepts it (`DWORD ids[4];`, `char *name;`).
fn field_decl(f: &Field) -> String {
    let mut out = String::from("  ");
    if f.pointer {
        // `Field::ty` keeps the ` *` (`char *`), the parser wants it between type and name.
        out.push_str(f.ty.trim_end_matches('*').trim());
        out.push_str(" *");
    } else {
        out.push_str(&f.ty);
        out.push(' ');
    }
    out.push_str(&f.name);
    if f.count != 1 {
        out.push_str(&format!("[{}]", f.count));
    }
    out.push_str(";\n");
    out
}

impl TypeLibrary {
    /// Whether a struct or enum with this name is defined here.
    pub(crate) fn has_type(&self, name: &str) -> bool {
        self.structs.contains_key(name) || self.enums.contains_key(name)
    }

    /// The local types a C variable declaration names: `MY_STRUCT *p` and
    /// `struct MY_STRUCT x` both name `MY_STRUCT`; words that aren't defined here are
    /// ignored, so scalars and the C keywords don't matter.
    fn names_in(&self, declaration: &str, out: &mut BTreeSet<String>) {
        for word in declaration.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if !word.is_empty() && self.has_type(word) {
                out.insert(word.to_string());
            }
        }
    }

    /// C declarations for the local types that the given variable declarations name,
    /// plus the structs and enums those definitions use in their fields, dependencies
    /// first. [`parse`] accepts the text, so it can go straight to
    /// [`Binary::set_types`](crate::Binary::set_types). Empty when none of the names is
    /// defined here.
    ///
    /// This is what function memory keeps per remembered function: the declarations its
    /// typed pseudocode variables would otherwise miss in another file.
    pub fn declarations_for<'a>(&self, variable_types: impl IntoIterator<Item = &'a str>) -> String {
        let mut names = BTreeSet::new();
        for ty in variable_types {
            self.names_in(ty, &mut names);
        }
        // A struct or enum held by value inside another one has to be declared first.
        // A pointer field doesn't: it needs no declaration of the pointee.
        let mut queued: Vec<String> = names.iter().cloned().collect();
        while let Some(name) = queued.pop() {
            let Some(s) = self.structs.get(&name) else { continue };
            for f in &s.fields {
                if f.pointer {
                    continue;
                }
                let dep = f.nested.as_deref().or_else(|| self.enums.contains_key(f.ty.trim()).then(|| f.ty.trim()));
                if let Some(dep) = dep.filter(|n| self.has_type(n)) {
                    if names.insert(dep.to_string()) {
                        queued.push(dep.to_string());
                    }
                }
            }
        }
        self.declarations_named(&names)
    }

    /// C declarations for exactly these names, no expansion: dependencies among them
    /// first. Used when the target may define some of the types already and those
    /// definitions must win.
    pub(crate) fn declarations_named(&self, names: &BTreeSet<String>) -> String {
        let mut out = String::new();
        // Enums go first: a field of enum type names a type declared later otherwise.
        for name in names {
            let Some(e) = self.enums.get(name) else { continue };
            out.push_str("enum ");
            out.push_str(&e.name);
            out.push_str(" {\n");
            for (member, value) in &e.members {
                out.push_str(&format!("  {member} = {value},\n"));
            }
            out.push_str("};\n");
        }
        let mut done = BTreeSet::new();
        for name in names {
            self.emit_struct(name, names, &mut done, &mut out);
        }
        out
    }

    fn emit_struct(&self, name: &str, names: &BTreeSet<String>, done: &mut BTreeSet<String>, out: &mut String) {
        if done.contains(name) {
            return;
        }
        let Some(s) = self.structs.get(name) else { return };
        // Inserted before the recursion: a self-referential definition can't come from
        // `parse`, and this keeps hostile hand-edited JSON from looping.
        done.insert(name.to_string());
        for f in &s.fields {
            if let Some(dep) = f.nested.as_deref().filter(|d| names.contains(*d)) {
                self.emit_struct(dep, names, done, out);
            }
        }
        out.push_str(if is_union(s) { "union " } else { "struct " });
        out.push_str(&s.name);
        out.push_str(" {\n");
        for f in &s.fields {
            out.push_str(&field_decl(f));
        }
        out.push_str("};\n");
    }

    /// Adds the definitions from `other` that this library doesn't define yet. A type the
    /// user already has wins, so a remembered declaration never overwrites a local one
    /// (the layouts may differ). Returns how many definitions were added.
    pub fn add_missing(&mut self, other: &TypeLibrary) -> usize {
        let mut added = 0;
        for (name, def) in &other.structs {
            if self.has_type(name) {
                continue;
            }
            self.structs.insert(name.clone(), def.clone());
            added += 1;
        }
        for (name, def) in &other.enums {
            if self.has_type(name) {
                continue;
            }
            self.enums.insert(name.clone(), def.clone());
            added += 1;
        }
        added
    }
}

fn scalar(ty: &str, ptr: u64) -> Option<u64> {
    let t = ty
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("volatile ")
        .trim_start_matches("unsigned ")
        .trim_start_matches("signed ")
        .trim();
    Some(match t {
        "char" | "int8_t" | "uint8_t" | "BYTE" | "UCHAR" | "CHAR" | "BOOLEAN" | "bool" | "_Bool" | "__int8" | "u8" | "i8" => 1,
        "short" | "int16_t" | "uint16_t" | "WORD" | "USHORT" | "SHORT" | "wchar_t" | "WCHAR" | "__int16" | "u16" | "i16" => 2,
        "int" | "long" | "int32_t" | "uint32_t" | "DWORD" | "UINT" | "ULONG" | "LONG" | "INT" | "BOOL" | "float" | "__int32" | "u32"
        | "i32" | "NTSTATUS" | "HRESULT" => 4,
        "long long" | "int64_t" | "uint64_t" | "QWORD" | "ULONGLONG" | "LONGLONG" | "DWORD64" | "ULONG64" | "__int64" | "double"
        | "u64" | "i64" | "LARGE_INTEGER" | "FILETIME" => 8,
        "size_t" | "ssize_t" | "intptr_t" | "uintptr_t" | "ptrdiff_t" | "SIZE_T" | "ULONG_PTR" | "DWORD_PTR" | "UINT_PTR" | "LONG_PTR"
        | "HANDLE" | "HMODULE" | "HINSTANCE" | "HWND" | "PVOID" | "LPVOID" | "LPCVOID" | "LPSTR" | "LPCSTR" | "LPWSTR" | "LPCWSTR"
        | "void*" => ptr,
        "GUID" => 16,
        _ => return None,
    })
}

/// Strips `//` and `/* */` comments.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Parses C declarations. `ptr_size` is 4 or 8.
pub fn parse(source: &str, ptr_size: u64) -> Result<TypeLibrary, String> {
    let src = strip_comments(source);
    let mut lib = TypeLibrary { source: source.to_string(), ..Default::default() };
    let mut rest = src.as_str();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let typedef = rest.starts_with("typedef");
        let after = if typedef { rest["typedef".len()..].trim_start() } else { rest };
        let is_struct = after.starts_with("struct") || after.starts_with("union");
        let is_union = after.starts_with("union");
        let is_enum = after.starts_with("enum");
        if !is_struct && !is_enum {
            // Skip anything we do not understand up to the next ';'.
            match rest.find(';') {
                Some(p) => {
                    rest = &rest[p + 1..];
                    continue;
                }
                None => break,
            }
        }
        let kw = if is_enum {
            "enum"
        } else if is_union {
            "union"
        } else {
            "struct"
        };
        let after_kw = after[kw.len()..].trim_start();
        let open = after_kw.find('{').ok_or_else(|| format!("expected '{{' after {kw}"))?;
        let tag = after_kw[..open].trim().to_string();
        let mut depth = 0;
        let mut close = None;
        for (i, c) in after_kw[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.ok_or("unbalanced braces")?;
        let body = &after_kw[open + 1..close];
        let tail = &after_kw[close + 1..];
        let semi = tail.find(';').ok_or("missing ';' after declaration")?;
        let alias = tail[..semi].trim().trim_start_matches('*').trim().to_string();
        let name = if !alias.is_empty() && typedef { alias.split(',').next().unwrap_or("").trim().to_string() } else { tag.clone() };
        if name.is_empty() {
            return Err("anonymous types need a typedef name".into());
        }
        rest = &tail[semi + 1..];

        if is_enum {
            let mut v = 0i64;
            let mut members = Vec::new();
            for m in body.split(',') {
                let m = m.trim();
                if m.is_empty() {
                    continue;
                }
                let (n, val) = match m.split_once('=') {
                    Some((n, e)) => {
                        let e = e.trim();
                        let parsed = if let Some(h) = e.strip_prefix("0x").or_else(|| e.strip_prefix("0X")) {
                            i64::from_str_radix(h, 16).ok()
                        } else {
                            e.parse().ok()
                        };
                        (n.trim(), parsed.ok_or_else(|| format!("enum value `{e}` must be a number"))?)
                    }
                    None => (m, v),
                };
                members.push((n.to_string(), val));
                v = val + 1;
            }
            lib.enums.insert(name.clone(), EnumDef { name, members });
            continue;
        }

        let mut fields = Vec::new();
        let mut offset = 0u64;
        let mut align = 1u64;
        let mut size = 0u64;
        for decl in body.split(';') {
            let decl = decl.trim();
            if decl.is_empty() {
                continue;
            }
            // `TYPE name[N]`, `TYPE *name`, `struct X name`
            let decl = decl.trim_start_matches("struct ").trim_start_matches("union ").trim_start_matches("enum ");
            let (ty_part, name_part) = match decl.rfind(|c: char| c.is_whitespace() || c == '*') {
                Some(p) => (&decl[..=p], decl[p + 1..].trim()),
                None => return Err(format!("cannot parse field `{decl}`")),
            };
            let pointer = ty_part.contains('*');
            let ty = ty_part.replace('*', " ").split_whitespace().collect::<Vec<_>>().join(" ");
            let (fname, count) = match name_part.split_once('[') {
                Some((n, rest)) => {
                    let n_s = rest.trim_end_matches(']').trim();
                    let c = if let Some(h) = n_s.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { n_s.parse().ok() };
                    (n.trim(), c.ok_or_else(|| format!("array size `{n_s}` must be a number"))?)
                }
                None => (name_part, 1),
            };
            let (elem, al, nested) = if pointer {
                (ptr_size, ptr_size, None)
            } else if let Some(s) = scalar(&ty, ptr_size) {
                (s, s.min(ptr_size.max(8)), None)
            } else if let Some(sd) = lib.structs.get(&ty) {
                (sd.size, sd.align, Some(ty.clone()))
            } else if lib.enums.contains_key(&ty) {
                (4, 4, None)
            } else {
                return Err(format!("unknown type `{ty}` in {name} (declare it first)"));
            };
            let al = al.max(1);
            align = align.max(al);
            let off = if is_union { 0 } else { offset.div_ceil(al) * al };
            fields.push(Field {
                name: fname.to_string(),
                ty: if pointer { format!("{ty} *") } else { ty },
                offset: off,
                elem_size: elem,
                count,
                nested,
                pointer,
            });
            if is_union {
                size = size.max(elem * count);
            } else {
                offset = off + elem * count;
                size = offset;
            }
        }
        let size = size.div_ceil(align) * align;
        lib.structs.insert(name.clone(), StructDef { name, size, align, fields });
    }
    Ok(lib)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_types_shadow_debug_types() {
        let user = parse("struct Packet { DWORD a; DWORD b; };", 8).unwrap();
        let mut debug = parse("struct Packet { BYTE a; }; struct Packet2 { QWORD q; }; enum Mode { A, B };", 8).unwrap();
        debug.source.clear();
        let v = TypeView { user: &user, debug: &debug };
        // The user's definition wins, and the debug one with the same name is not listed.
        assert_eq!(v.struct_def("Packet").unwrap().size, 8);
        assert!(v.struct_def("Packet2").is_some() && v.enum_def("Mode").is_some());
        assert!(v.struct_def("Nope").is_none() && v.has_structs());
        let hits = v.search("packet", 10);
        let names: Vec<_> = hits.iter().map(|h| (h.name.as_str(), h.origin.as_str())).collect();
        assert_eq!(names, [("Packet", "user"), ("Packet2", "debug")]);
        // Substring matches come after prefix matches; the limit applies.
        assert_eq!(v.search("ode", 10)[0].name, "Mode");
        assert_eq!(v.search("", 1).len(), 1);
    }

    #[test]
    fn layout() {
        let lib = parse(
            "// header
             typedef struct _POINT { LONG x; LONG y; } POINT;
             struct Packet { BYTE kind; DWORD length; char *data; POINT where; WORD flags[3]; };
             enum Color { Red, Green = 5, Blue };",
            8,
        )
        .unwrap();
        let p = &lib.structs["Packet"];
        let off: Vec<u64> = p.fields.iter().map(|f| f.offset).collect();
        assert_eq!(off, vec![0, 4, 8, 16, 24]);
        assert_eq!(p.size, 32);
        assert_eq!(lib.structs["POINT"].size, 8);
        assert_eq!(lib.enums["Color"].members, vec![("Red".into(), 0), ("Green".into(), 5), ("Blue".into(), 6)]);
        assert!(parse("struct A { Foo f; };", 8).is_err());
    }

    const MEMORY_SOURCE: &str = "
        typedef struct _POINT { LONG x; LONG y; } POINT;
        enum Mode { READ = 1, WRITE = 2 };
        union Value { DWORD dw; BYTE b[4]; };
        struct PKT {
            BYTE kind;
            DWORD crc;
            char *name;
            struct PKT *next;
            POINT where;
            Mode mode;
            DWORD ids[4];
            Value val;
        };
        struct Unrelated { QWORD q; };
    ";

    #[test]
    fn declarations_for_a_variable_round_trip() {
        let lib = parse(MEMORY_SOURCE, 8).unwrap();
        // `PKT *` pulls in the types its definition needs by value, and nothing else.
        let text = lib.declarations_for(["PKT *", "int", "char *"]);
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("struct ").or_else(|| l.strip_prefix("union ")).or_else(|| l.strip_prefix("enum ")))
            .map(|l| l.trim_end_matches(" {").trim())
            .collect();
        assert_eq!(names, ["Mode", "POINT", "Value", "PKT"], "{text}");
        // The text parses, and the layouts come back exactly: offsets, sizes, alignments.
        let again = parse(&text, 8).unwrap();
        for name in ["POINT", "Value", "PKT"] {
            assert_eq!(again.structs.get(name), lib.structs.get(name), "{name}\n{text}");
        }
        assert_eq!(again.enums.get("Mode"), lib.enums.get("Mode"));
        assert!(!again.structs.contains_key("Unrelated"), "unreferenced types are not carried");
        // A plain pointer sizes nothing out of the local types.
        assert_eq!(lib.declarations_for(["int *", "DWORD", "void"]), "");
    }

    #[test]
    fn declarations_named_does_not_expand() {
        let lib = parse(MEMORY_SOURCE, 8).unwrap();
        let names = std::collections::BTreeSet::from(["PKT".to_string()]);
        let text = lib.declarations_named(&names);
        assert!(!text.contains("struct POINT"), "no expansion: {text}");
        // Recall appends this after a source that already defines the dependencies (that
        // is why they aren't repeated), and the merged editor text parses.
        let mut existing = String::from(
            "typedef struct _POINT { LONG x; LONG y; } POINT;\nenum Mode { READ = 1, WRITE = 2 };\nunion Value { DWORD dw; BYTE b[4]; };\n",
        );
        existing.push_str(&text);
        let again = parse(&existing, 8).unwrap();
        assert_eq!(again.structs["PKT"], lib.structs["PKT"]);
        assert_eq!(again.structs.len(), 3, "POINT, Value and the recalled PKT");
        assert_eq!(again.enums.len(), 1);
    }

    #[test]
    fn add_missing_keeps_the_users_definition() {
        let mut user = parse("struct PKT { BYTE only; };", 8).unwrap();
        let recalled = parse(MEMORY_SOURCE, 8).unwrap();
        let added = user.add_missing(&recalled);
        assert_eq!(added, 4, "the four types the user doesn't have");
        assert_eq!(user.structs["PKT"].size, 1, "a user type of the same name wins");
        assert_eq!(user.structs["POINT"].size, 8);
        assert!(user.enums.contains_key("Mode"));
        assert!(user.structs["Unrelated"].fields.iter().any(|f| f.name == "q"));
    }

    #[test]
    fn hostile_declarations_do_not_panic() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let pieces = [
            "struct ",
            "union ",
            "enum ",
            "typedef ",
            "A",
            "B",
            "{",
            "}",
            ";",
            "[",
            "]",
            "*",
            "int ",
            "char ",
            "x",
            "=",
            ",",
            "9999999999",
            "-1",
            "
",
            "A a;",
            "struct A a;",
        ];
        for _ in 0..3000 {
            let n = (x % 40) as usize;
            let src: String = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    pieces[(x % pieces.len() as u64) as usize]
                })
                .collect();
            let _ = parse(&src, 8);
        }
        // Self-referential and deeply nested types terminate.
        let _ = parse("struct A { struct A inner; };", 8);
        let _ = parse("struct A { int x[4294967295]; struct A y[4294967295]; };", 8);
    }
}
