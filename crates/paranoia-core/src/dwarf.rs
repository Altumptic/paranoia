//! DWARF debug information (ELF, Mach-O, and MinGW / Rust-gnu PE files):
//! function names and bounds, global variables, the line table, and local types
//! (structs, unions and enums with their fields and layouts).

use std::collections::HashMap;

use gimli::{AttributeValue, EndianSlice, RunTimeEndian, SectionId};

use crate::model::Section;
use crate::types::{EnumDef, Field, StructDef, TypeLibrary};

#[derive(Debug, Default)]
pub struct DwarfInfo {
    /// `(start, end, linkage or plain name)`.
    pub functions: Vec<(u64, Option<u64>, String)>,
    pub globals: Vec<(u64, String)>,
    pub files: Vec<String>,
    /// `(address, file index, line)`, sorted by address.
    pub lines: Vec<(u64, u32, u32)>,
    pub units: usize,
    /// Struct, union and enum definitions carried by the debug info.
    pub types: TypeLibrary,
}

const SHF_COMPRESSED: u64 = 0x800;

/// Parses whatever DWARF the image carries; `None` when there is none.
pub fn load(data: &[u8], sections: &[Section], big_endian: bool) -> Option<DwarfInfo> {
    let find = |name: &str| -> &[u8] {
        let macho = format!("__{}", name.trim_start_matches('.'));
        sections
            .iter()
            .find(|s| (s.name == name || s.name == macho) && s.flags & SHF_COMPRESSED == 0)
            .and_then(|s| data.get(s.offset as usize..(s.offset + s.raw_size) as usize))
            .unwrap_or(&[])
    };
    if find(".debug_info").is_empty() {
        return None;
    }
    let endian = if big_endian { RunTimeEndian::Big } else { RunTimeEndian::Little };
    let dwarf = gimli::Dwarf::load(|id: SectionId| -> Result<_, gimli::Error> { Ok(EndianSlice::new(find(id.name()), endian)) }).ok()?;

    let mut out = DwarfInfo::default();
    let mut file_ids: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        out.units += 1;
        let name_of = |e: &gimli::DebuggingInformationEntry<EndianSlice<'_, RunTimeEndian>>| -> Option<String> {
            for at in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name, gimli::DW_AT_name] {
                if let Some(v) = e.attr_value(at) {
                    if let Ok(s) = dwarf.attr_string(&unit, v) {
                        return Some(s.to_string_lossy().into_owned());
                    }
                }
            }
            None
        };
        // One pass collects function boundaries, globals and the raw local-type DIEs;
        // the types are resolved afterwards, once every definition in the unit is known.
        let mut t = TypeCollect::default();
        let mut frames: Vec<(i64, Frame)> = Vec::new();
        let mut entries = unit.entries();
        while let Ok(Some(e)) = entries.next_dfs() {
            let depth = e.depth() as i64;
            while frames.last().is_some_and(|(d, _)| *d >= depth) {
                frames.pop();
            }
            match e.tag() {
                gimli::DW_TAG_subprogram => {
                    let Some(low) = e.attr_value(gimli::DW_AT_low_pc).and_then(|v| dwarf.attr_address(&unit, v).ok().flatten()) else {
                        continue;
                    };
                    if low == 0 {
                        continue;
                    }
                    let high = match e.attr_value(gimli::DW_AT_high_pc) {
                        Some(AttributeValue::Udata(n)) => Some(low + n),
                        Some(v) => dwarf.attr_address(&unit, v).ok().flatten(),
                        None => None,
                    };
                    // Out-of-line definitions name themselves through their declaration.
                    let mut name = name_of(e);
                    if name.is_none() {
                        for at in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
                            if let Some(AttributeValue::UnitRef(off)) = e.attr_value(at) {
                                if let Ok(decl) = unit.entry(off) {
                                    name = name_of(&decl);
                                    if name.is_some() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if let Some(n) = name {
                        out.functions.push((low, high.filter(|&h| h > low), n));
                    }
                }
                gimli::DW_TAG_variable => {
                    let Some(AttributeValue::Exprloc(expr)) = e.attr_value(gimli::DW_AT_location) else { continue };
                    let bytes = expr.0.slice();
                    let size = unit.encoding().address_size as usize;
                    let addr = match bytes.first() {
                        // DW_OP_addr <address>
                        Some(0x03) if bytes.len() == 1 + size => {
                            let raw = &bytes[1..];
                            let mut v = 0u64;
                            for (i, b) in raw.iter().enumerate() {
                                v |= (*b as u64) << if big_endian { 8 * (size - 1 - i) } else { 8 * i };
                            }
                            Some(v)
                        }
                        // DW_OP_addrx <uleb index>
                        Some(0xa1) => {
                            let mut r = EndianSlice::new(&bytes[1..], endian);
                            gimli::Reader::read_uleb128(&mut r)
                                .ok()
                                .and_then(|i| dwarf.address(&unit, gimli::DebugAddrIndex(i as usize)).ok())
                        }
                        _ => None,
                    };
                    if let (Some(a), Some(n)) = (addr.filter(|&a| a != 0), name_of(e)) {
                        out.globals.push((a, n));
                    }
                }
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type => {
                    let Some(name) = die_name(&dwarf, &unit, e) else { continue };
                    let off = e.offset().0;
                    t.heads.insert(off, Head { name, size: udata(e, gimli::DW_AT_byte_size).unwrap_or(0), is_enum: false });
                    frames.push((depth, Frame::Struct(off)));
                }
                gimli::DW_TAG_enumeration_type => {
                    let Some(name) = die_name(&dwarf, &unit, e) else { continue };
                    let off = e.offset().0;
                    t.heads.insert(off, Head { name, size: udata(e, gimli::DW_AT_byte_size).unwrap_or(4), is_enum: true });
                    frames.push((depth, Frame::Enum(off)));
                }
                gimli::DW_TAG_array_type => frames.push((depth, Frame::Array(e.offset().0))),
                gimli::DW_TAG_subrange_type => {
                    if let Some((_, Frame::Array(off))) = frames.last() {
                        let n = udata(e, gimli::DW_AT_count)
                            .or_else(|| sdata(e, gimli::DW_AT_upper_bound).filter(|v| *v >= 0).map(|v| (v as u64).saturating_add(1)))
                            .unwrap_or(1);
                        t.array_counts.entry(*off).or_default().push(n);
                    }
                }
                gimli::DW_TAG_member => {
                    let Some((_, Frame::Struct(off))) = frames.last() else { continue };
                    // Bit fields cannot be represented as plain fields yet.
                    if udata(e, gimli::DW_AT_bit_size).is_some() {
                        continue;
                    }
                    let Some(name) = die_name(&dwarf, &unit, e) else { continue };
                    let type_ref = match e.attr_value(gimli::DW_AT_type) {
                        Some(AttributeValue::UnitRef(o)) => Some(o.0),
                        _ => None,
                    };
                    let offset = member_offset(e).unwrap_or(0);
                    t.members.entry(*off).or_default().push(MemberRaw { name, offset, type_ref });
                }
                gimli::DW_TAG_enumerator => {
                    let Some((_, Frame::Enum(off))) = frames.last() else { continue };
                    if let (Some(name), Some(v)) = (die_name(&dwarf, &unit, e), sdata(e, gimli::DW_AT_const_value)) {
                        t.enumerators.entry(*off).or_default().push((name, v));
                    }
                }
                _ => {}
            }
        }
        // Local types: structs, unions and enums with their fields.
        build_types(&t, &dwarf, &unit, &mut out.types);
        // Line table.
        if let Some(program) = unit.line_program.clone() {
            let comp_dir = unit.comp_dir.map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
            let mut rows = program.rows();
            let mut last_file = (u64::MAX, 0u32);
            while let Ok(Some((header, row))) = rows.next_row() {
                if row.end_sequence() {
                    continue;
                }
                let Some(line) = row.line() else { continue };
                let fi = if row.file_index() == last_file.0 {
                    last_file.1
                } else {
                    let path = row.file(header).map(|f| {
                        let file = dwarf.attr_string(&unit, f.path_name()).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                        let dir = f
                            .directory(header)
                            .and_then(|d| dwarf.attr_string(&unit, d).ok())
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        join_path(&comp_dir, &dir, &file)
                    });
                    let path = path.unwrap_or_else(|| "?".into());
                    let next = file_ids.len() as u32;
                    let id = *file_ids.entry(path.clone()).or_insert_with(|| {
                        out.files.push(path);
                        next
                    });
                    last_file = (row.file_index(), id);
                    id
                };
                out.lines.push((row.address(), fi, line.get().min(u32::MAX as u64) as u32));
            }
        }
    }
    out.lines.sort_unstable_by_key(|l| l.0);
    out.lines.dedup_by_key(|l| l.0);
    Some(out)
}

// ------------------------------------------------------------------------------------------------
// Local types

/// A struct / union / enum definition inside one unit, keyed by DIE offset.
struct Head {
    name: String,
    size: u64,
    is_enum: bool,
}

struct MemberRaw {
    name: String,
    offset: u64,
    type_ref: Option<usize>,
}

#[derive(Default)]
struct TypeCollect {
    heads: HashMap<usize, Head>,
    members: HashMap<usize, Vec<MemberRaw>>,
    enumerators: HashMap<usize, Vec<(String, i64)>>,
    array_counts: HashMap<usize, Vec<u64>>,
}

/// An enclosing container DIE, used to attach members to their parent.
enum Frame {
    Struct(usize),
    Enum(usize),
    Array(usize),
}

const MAX_TYPE_DEPTH: u32 = 6;

/// The reader the type helpers work with (as everywhere in this module).
type Reader<'a> = EndianSlice<'a, RunTimeEndian>;

/// A DWARF attribute as an unsigned integer (any integer form).
fn udata(e: &gimli::DebuggingInformationEntry<Reader<'_>>, at: gimli::DwAt) -> Option<u64> {
    match e.attr_value(at)? {
        AttributeValue::Udata(v) | AttributeValue::Data8(v) => Some(v),
        AttributeValue::Data1(v) => Some(v as u64),
        AttributeValue::Data2(v) => Some(v as u64),
        AttributeValue::Data4(v) => Some(v as u64),
        AttributeValue::Sdata(v) if v >= 0 => Some(v as u64),
        _ => None,
    }
}

/// A DWARF attribute as a signed integer (any integer form).
fn sdata(e: &gimli::DebuggingInformationEntry<Reader<'_>>, at: gimli::DwAt) -> Option<i64> {
    match e.attr_value(at)? {
        AttributeValue::Udata(v) | AttributeValue::Data8(v) => Some(v as i64),
        AttributeValue::Data1(v) => Some(v as i64),
        AttributeValue::Data2(v) => Some(v as i64),
        AttributeValue::Data4(v) => Some(v as i64),
        AttributeValue::Sdata(v) => Some(v),
        _ => None,
    }
}

fn die_name<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    e: &gimli::DebuggingInformationEntry<Reader<'a>>,
) -> Option<String> {
    let v = e.attr_value(gimli::DW_AT_name)?;
    dwarf.attr_string(unit, v).ok().map(|s| s.to_string_lossy().into_owned())
}

/// `DW_AT_data_member_location` in both the constant and `DW_OP_plus_uconst` forms.
fn member_offset(e: &gimli::DebuggingInformationEntry<Reader<'_>>) -> Option<u64> {
    match e.attr_value(gimli::DW_AT_data_member_location)? {
        AttributeValue::Exprloc(expr) => {
            let bytes = expr.0.slice();
            if bytes.first() != Some(&0x23) {
                return None; // only DW_OP_plus_uconst maps to one constant offset
            }
            let mut v = 0u64;
            let mut shift = 0u32;
            for b in &bytes[1..] {
                if shift > 63 {
                    return None;
                }
                v |= ((b & 0x7f) as u64) << shift;
                if b & 0x80 == 0 {
                    return Some(v);
                }
                shift += 7;
            }
            None
        }
        _ => udata(e, gimli::DW_AT_data_member_location),
    }
}

/// A resolved member type.
struct Resolved {
    size: u64,
    ty: String,
    nested: Option<String>,
    pointer: bool,
    count: u64,
}

/// Name a pointer points at (`PKT`, `char`, `void`), for the `PKT *` spelling.
fn pointee_name<'a>(
    c: &TypeCollect,
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    pointer: &gimli::DebuggingInformationEntry<Reader<'a>>,
    depth: u32,
) -> Option<String> {
    let Some(AttributeValue::UnitRef(off)) = pointer.attr_value(gimli::DW_AT_type) else {
        return Some("void".into());
    };
    if depth > MAX_TYPE_DEPTH {
        return Some("void".into());
    }
    let Ok(e) = unit.entry(off) else { return Some("void".into()) };
    let name = match e.tag() {
        gimli::DW_TAG_structure_type
        | gimli::DW_TAG_union_type
        | gimli::DW_TAG_class_type
        | gimli::DW_TAG_enumeration_type
        | gimli::DW_TAG_base_type
        | gimli::DW_TAG_typedef => c.heads.get(&off.0).map(|h| h.name.clone()).or_else(|| die_name(dwarf, unit, &e)),
        _ => None,
    };
    Some(name.filter(|n| !n.is_empty()).unwrap_or_else(|| "void".into()))
}

fn resolve_type<'a>(
    c: &TypeCollect,
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    off: usize,
    addr_size: u64,
    depth: u32,
) -> Option<Resolved> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let e = unit.entry(gimli::UnitOffset(off)).ok()?;
    match e.tag() {
        gimli::DW_TAG_pointer_type => {
            let name = pointee_name(c, dwarf, unit, &e, depth)?;
            Some(Resolved { size: addr_size.max(4), ty: format!("{name} *"), nested: None, pointer: true, count: 1 })
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type => {
            let h = c.heads.get(&off)?;
            Some(Resolved { size: h.size, ty: h.name.clone(), nested: Some(h.name.clone()), pointer: false, count: 1 })
        }
        gimli::DW_TAG_enumeration_type => {
            let h = c.heads.get(&off)?;
            Some(Resolved { size: h.size, ty: h.name.clone(), nested: None, pointer: false, count: 1 })
        }
        gimli::DW_TAG_base_type => {
            let size = udata(&e, gimli::DW_AT_byte_size).unwrap_or(8);
            let name = die_name(dwarf, unit, &e).unwrap_or_else(|| "int".into());
            Some(Resolved { size, ty: name, nested: None, pointer: false, count: 1 })
        }
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => match e.attr_value(gimli::DW_AT_type)? {
            AttributeValue::UnitRef(o) => resolve_type(c, dwarf, unit, o.0, addr_size, depth + 1),
            _ => None,
        },
        gimli::DW_TAG_array_type => {
            let AttributeValue::UnitRef(elem_off) = e.attr_value(gimli::DW_AT_type)? else { return None };
            let elem = resolve_type(c, dwarf, unit, elem_off.0, addr_size, depth + 1)?;
            let count: u64 = c.array_counts.get(&off)?.iter().copied().fold(1u64, |acc, n| acc.saturating_mul(n));
            Some(Resolved { size: elem.size, ty: elem.ty, nested: elem.nested, pointer: elem.pointer, count: count.max(1) })
        }
        gimli::DW_TAG_subroutine_type => {
            Some(Resolved { size: addr_size.max(4), ty: "void *".into(), nested: None, pointer: true, count: 1 })
        }
        _ => None,
    }
}

/// Resolves the collected DIEs of one unit into struct and enum definitions.
fn build_types<'a>(c: &TypeCollect, dwarf: &gimli::Dwarf<Reader<'a>>, unit: &gimli::Unit<Reader<'a>>, lib: &mut TypeLibrary) {
    let addr_size = u64::from(unit.encoding().address_size);
    for (off, head) in &c.heads {
        if head.is_enum || head.size == 0 || head.name.is_empty() {
            continue;
        }
        let Some(raw) = c.members.get(off) else { continue };
        let mut fields = Vec::with_capacity(raw.len());
        for m in raw {
            let Some(type_ref) = m.type_ref else { continue };
            let Some(r) = resolve_type(c, dwarf, unit, type_ref, addr_size, 0) else { continue };
            fields.push(Field {
                name: m.name.clone(),
                ty: r.ty,
                offset: m.offset,
                elem_size: r.size.max(1),
                count: r.count.max(1),
                nested: r.nested,
                pointer: r.pointer,
            });
        }
        if fields.is_empty() {
            continue;
        }
        let align = fields.iter().map(|f| f.elem_size.min(8)).max().unwrap_or(1).max(1);
        lib.structs.entry(head.name.clone()).or_insert(StructDef { name: head.name.clone(), size: head.size, align, fields });
    }
    for (off, head) in &c.heads {
        if !head.is_enum {
            continue;
        }
        let Some(members) = c.enumerators.get(off) else { continue };
        if members.is_empty() {
            continue;
        }
        lib.enums.entry(head.name.clone()).or_insert(EnumDef { name: head.name.clone(), members: members.clone() });
    }
}

fn join_path(comp_dir: &str, dir: &str, file: &str) -> String {
    let p = join_raw(comp_dir, dir, file);
    // Windows toolchains mix separators (`C:\toolchain\lib/rustlib/src`): use the native one throughout.
    if p.get(1..2) == Some(":") || p.starts_with("\\\\") {
        p.replace('/', "\\")
    } else {
        p
    }
}

fn join_raw(comp_dir: &str, dir: &str, file: &str) -> String {
    let absolute = |p: &str| p.starts_with('/') || p.starts_with('\\') || p.get(1..2) == Some(":");
    if absolute(file) {
        return file.to_string();
    }
    let dir = if dir.is_empty() || absolute(dir) { dir.to_string() } else { format!("{comp_dir}/{dir}") };
    if dir.is_empty() {
        file.to_string()
    } else {
        format!("{}/{file}", dir.trim_end_matches(['/', '\\']))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn paths() {
        assert_eq!(super::join_path("/src", "lib", "a.c"), "/src/lib/a.c");
        assert_eq!(super::join_path("/src", "/usr/include", "stdio.h"), "/usr/include/stdio.h");
        assert_eq!(super::join_path("C:\\w", "src", "main.rs"), "C:\\w\\src\\main.rs");
    }
}
