//! Struct / union / enum definitions from a PDB's type stream (TPI), as debug-info types:
//! the same layer DWARF types go into, usable by `Y` and by the decompiler's member access.
//!
//! Only C-like names are imported (`PKT`, `_IMAGE_DOS_HEADER`). C++ templates, namespaced and
//! anonymous types (`std::vector<int>`, `<unnamed-tag>`) are skipped: they cannot be spelled in
//! the C declarations the rest of the tool works with.

use std::collections::HashMap;

use pdb::{FallibleIterator, ItemFinder, PrimitiveKind, TypeData, TypeIndex};

use crate::types::{EnumDef, Field, StructDef, TypeLibrary};

const MAX_DEPTH: u32 = 8;

struct Resolved {
    size: u64,
    ty: String,
    nested: Option<String>,
    pointer: bool,
    count: u64,
}

/// A type name the C-side of the tool can use.
fn c_name(raw: &str) -> Option<String> {
    let ok = !raw.is_empty()
        && !raw.starts_with("__unnamed")
        && raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !raw.chars().next().is_some_and(|c| c.is_ascii_digit());
    ok.then(|| raw.to_string())
}

fn primitive_name(k: PrimitiveKind) -> Option<(&'static str, u64)> {
    use PrimitiveKind as P;
    Some(match k {
        P::Void => ("void", 1),
        P::Char | P::RChar => ("char", 1),
        P::UChar => ("unsigned char", 1),
        P::WChar | P::RChar16 => ("wchar_t", 2),
        P::RChar32 => ("uint32_t", 4),
        P::I8 => ("int8_t", 1),
        P::U8 => ("uint8_t", 1),
        P::Short | P::I16 => ("int16_t", 2),
        P::UShort | P::U16 => ("uint16_t", 2),
        P::Long | P::I32 => ("int32_t", 4),
        P::ULong | P::U32 => ("uint32_t", 4),
        P::Quad | P::I64 => ("int64_t", 8),
        P::UQuad | P::U64 => ("uint64_t", 8),
        P::F32 => ("float", 4),
        P::F64 => ("double", 8),
        P::F80 => ("long double", 10),
        P::Bool8 => ("bool", 1),
        P::Bool16 => ("uint16_t", 2),
        P::Bool32 | P::HRESULT => ("int32_t", 4),
        P::Bool64 => ("uint64_t", 8),
        _ => return None,
    })
}

struct Reader<'a, 't> {
    finder: &'a ItemFinder<'t, TypeIndex>,
    /// Name → index of the complete (non-forward) definition.
    defs: &'a HashMap<String, TypeIndex>,
}

impl<'t> Reader<'_, 't> {
    fn data(&self, idx: TypeIndex) -> Option<TypeData<'t>> {
        self.finder.find(idx).ok()?.parse().ok()
    }

    /// Size of the complete definition named `name`.
    fn def_size(&self, name: &str) -> Option<u64> {
        match self.data(*self.defs.get(name)?)? {
            TypeData::Class(c) => Some(c.size),
            TypeData::Union(u) => Some(u.size),
            _ => None,
        }
    }

    /// The name a pointer to `idx` is spelled with, and how many `*` come after it.
    fn pointee(&self, idx: TypeIndex, depth: u32) -> (String, usize) {
        if depth > MAX_DEPTH {
            return ("void".into(), 0);
        }
        match self.data(idx) {
            Some(TypeData::Class(c)) => (c_name(&c.name.to_string()).unwrap_or_else(|| "void".into()), 0),
            Some(TypeData::Union(u)) => (c_name(&u.name.to_string()).unwrap_or_else(|| "void".into()), 0),
            Some(TypeData::Enumeration(e)) => (c_name(&e.name.to_string()).unwrap_or_else(|| "void".into()), 0),
            Some(TypeData::Primitive(p)) => {
                let n = primitive_name(p.kind).map_or("void", |n| n.0);
                (n.into(), usize::from(p.indirection.is_some()))
            }
            Some(TypeData::Modifier(m)) => self.pointee(m.underlying_type, depth + 1),
            Some(TypeData::Pointer(p)) => {
                let (n, stars) = self.pointee(p.underlying_type, depth + 1);
                (n, stars + 1)
            }
            _ => ("void".into(), 0),
        }
    }

    fn resolve(&self, idx: TypeIndex, depth: u32) -> Option<Resolved> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.data(idx)? {
            TypeData::Primitive(p) => {
                let (name, size) = primitive_name(p.kind)?;
                if let Some(ind) = p.indirection {
                    let ptr = match ind {
                        pdb::Indirection::Near64 => 8,
                        pdb::Indirection::Near128 => 16,
                        pdb::Indirection::Near16 => 2,
                        _ => 4,
                    };
                    return Some(Resolved { size: ptr, ty: format!("{name} *"), nested: None, pointer: true, count: 1 });
                }
                Some(Resolved { size, ty: name.into(), nested: None, pointer: false, count: 1 })
            }
            TypeData::Class(c) => {
                let name = c_name(&c.name.to_string())?;
                let size = if c.properties.forward_reference() { self.def_size(&name)? } else { c.size };
                (size > 0).then(|| Resolved { size, ty: name.clone(), nested: Some(name), pointer: false, count: 1 })
            }
            TypeData::Union(u) => {
                let name = c_name(&u.name.to_string())?;
                let size = if u.properties.forward_reference() { self.def_size(&name)? } else { u.size };
                (size > 0).then(|| Resolved { size, ty: name.clone(), nested: Some(name), pointer: false, count: 1 })
            }
            TypeData::Enumeration(e) => {
                let name = c_name(&e.name.to_string())?;
                let size = self.resolve(e.underlying_type, depth + 1).map_or(4, |r| r.size);
                Some(Resolved { size, ty: name, nested: None, pointer: false, count: 1 })
            }
            TypeData::Pointer(p) => {
                let (name, stars) = self.pointee(p.underlying_type, 0);
                let size = match p.attributes.size() {
                    0 => 8,
                    n => u64::from(n),
                };
                Some(Resolved { size, ty: format!("{name} {}", "*".repeat(stars + 1)), nested: None, pointer: true, count: 1 })
            }
            TypeData::Modifier(m) => self.resolve(m.underlying_type, depth + 1),
            TypeData::Array(a) => {
                let elem = self.resolve(a.element_type, depth + 1)?;
                // Dimensions are byte sizes; the last one is the whole array.
                let total = u64::from(*a.dimensions.last()?);
                let count = (total / elem.size.max(1)).max(1);
                Some(Resolved { size: elem.size, ty: elem.ty, nested: elem.nested, pointer: elem.pointer, count })
            }
            TypeData::Procedure(_) | TypeData::MemberFunction(_) => {
                Some(Resolved { size: 8, ty: "void *".into(), nested: None, pointer: true, count: 1 })
            }
            _ => None,
        }
    }

    /// The members of a field list (following continuations); base classes are flattened in.
    fn collect_fields(&self, list: TypeIndex, base: u64, depth: u32, out: &mut Vec<Field>) {
        if depth > 4 {
            return;
        }
        let mut next = Some(list);
        let mut guard = 0;
        while let Some(i) = next.take() {
            guard += 1;
            if guard > 256 {
                return;
            }
            let Some(TypeData::FieldList(fl)) = self.data(i) else { return };
            for f in &fl.fields {
                match f {
                    TypeData::Member(m) => {
                        let Some(name) = c_name(&m.name.to_string()) else { continue };
                        let Some(r) = self.resolve(m.field_type, 0) else { continue };
                        out.push(Field {
                            name,
                            ty: r.ty,
                            offset: base + m.offset,
                            elem_size: r.size.max(1),
                            count: r.count.max(1),
                            nested: r.nested,
                            pointer: r.pointer,
                        });
                    }
                    TypeData::BaseClass(b) => {
                        let Some(TypeData::Class(c)) = self.data(b.base_class) else { continue };
                        let def = if c.properties.forward_reference() {
                            c_name(&c.name.to_string()).and_then(|n| self.defs.get(&n).copied())
                        } else {
                            Some(b.base_class)
                        };
                        if let Some(TypeData::Class(c)) = def.and_then(|d| self.data(d)) {
                            if let Some(fields) = c.fields {
                                self.collect_fields(fields, base + u64::from(b.offset), depth + 1, out);
                            }
                        }
                    }
                    _ => {}
                }
            }
            next = fl.continuation;
        }
    }

    fn enum_members(&self, list: TypeIndex) -> Vec<(String, i64)> {
        use pdb::Variant as V;
        let mut out = Vec::new();
        let mut next = Some(list);
        let mut guard = 0;
        while let Some(i) = next.take() {
            guard += 1;
            if guard > 256 {
                break;
            }
            let Some(TypeData::FieldList(fl)) = self.data(i) else { break };
            for f in &fl.fields {
                if let TypeData::Enumerate(e) = f {
                    let v = match e.value {
                        V::U8(x) => i64::from(x),
                        V::U16(x) => i64::from(x),
                        V::U32(x) => i64::from(x),
                        V::U64(x) => x as i64,
                        V::I8(x) => i64::from(x),
                        V::I16(x) => i64::from(x),
                        V::I32(x) => i64::from(x),
                        V::I64(x) => x,
                    };
                    out.push((e.name.to_string().into_owned(), v));
                }
            }
            next = fl.continuation;
        }
        out
    }
}

/// Reads every importable struct / union / enum from the PDB's type stream.
pub(crate) fn read_types<'s, S: pdb::Source<'s> + 's>(pdb: &mut pdb::PDB<'s, S>) -> Result<TypeLibrary, String> {
    let ti = pdb.type_information().map_err(|e| e.to_string())?;
    let mut finder = ti.finder();
    let mut iter = ti.iter();
    let mut defs: HashMap<String, TypeIndex> = HashMap::new();
    let mut order: Vec<(String, TypeIndex)> = Vec::new();
    while let Some(item) = iter.next().map_err(|e| e.to_string())? {
        finder.update(&iter);
        let Ok(data) = item.parse() else { continue };
        let (name, fwd) = match &data {
            TypeData::Class(c) => (c.name.to_string().into_owned(), c.properties.forward_reference()),
            TypeData::Union(u) => (u.name.to_string().into_owned(), u.properties.forward_reference()),
            TypeData::Enumeration(e) => (e.name.to_string().into_owned(), e.properties.forward_reference()),
            _ => continue,
        };
        if fwd {
            continue;
        }
        let Some(name) = c_name(&name) else { continue };
        if !defs.contains_key(&name) {
            defs.insert(name.clone(), item.index());
            order.push((name, item.index()));
        }
    }

    let rd = Reader { finder: &finder, defs: &defs };
    let mut lib = TypeLibrary::default();
    for (name, idx) in order {
        match rd.data(idx) {
            Some(TypeData::Class(c)) => {
                let Some(list) = c.fields else { continue };
                if c.size == 0 {
                    continue;
                }
                let mut fields = Vec::new();
                rd.collect_fields(list, 0, 0, &mut fields);
                fields.retain(|f| f.offset < c.size);
                if fields.is_empty() {
                    continue;
                }
                let align = fields.iter().map(|f| f.elem_size.min(8)).max().unwrap_or(1).max(1);
                lib.structs.insert(name.clone(), StructDef { name, size: c.size, align, fields });
            }
            Some(TypeData::Union(u)) => {
                if u.size == 0 {
                    continue;
                }
                let mut fields = Vec::new();
                rd.collect_fields(u.fields, 0, 0, &mut fields);
                fields.retain(|f| f.offset < u.size);
                if fields.is_empty() {
                    continue;
                }
                let align = fields.iter().map(|f| f.elem_size.min(8)).max().unwrap_or(1).max(1);
                lib.structs.insert(name.clone(), StructDef { name, size: u.size, align, fields });
            }
            Some(TypeData::Enumeration(e)) => {
                let members = rd.enum_members(e.fields);
                if !members.is_empty() {
                    lib.enums.insert(name.clone(), EnumDef { name, members });
                }
            }
            _ => {}
        }
    }
    Ok(lib)
}
