//! Local types (IDA's "Local Types"): C struct / enum declarations parsed into
//! layouts that can be applied to data.

use std::collections::BTreeMap;

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
