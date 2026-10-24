//! DWARF debug information (ELF, Mach-O, and MinGW / Rust-gnu PE files):
//! function names and bounds, global variables and the line table.

use gimli::{AttributeValue, EndianSlice, RunTimeEndian, SectionId};

use crate::model::Section;

#[derive(Debug, Default)]
pub struct DwarfInfo {
    /// `(start, end, linkage or plain name)`.
    pub functions: Vec<(u64, Option<u64>, String)>,
    pub globals: Vec<(u64, String)>,
    pub files: Vec<String>,
    /// `(address, file index, line)`, sorted by address.
    pub lines: Vec<(u64, u32, u32)>,
    pub units: usize,
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
        let name_of = |e: &gimli::DebuggingInformationEntry<EndianSlice<RunTimeEndian>>| -> Option<String> {
            for at in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name, gimli::DW_AT_name] {
                if let Ok(Some(v)) = e.attr_value(at) {
                    if let Ok(s) = dwarf.attr_string(&unit, v) {
                        return Some(s.to_string_lossy().into_owned());
                    }
                }
            }
            None
        };
        let mut entries = unit.entries();
        while let Ok(Some((_, e))) = entries.next_dfs() {
            match e.tag() {
                gimli::DW_TAG_subprogram => {
                    let Some(low) =
                        e.attr_value(gimli::DW_AT_low_pc).ok().flatten().and_then(|v| dwarf.attr_address(&unit, v).ok().flatten())
                    else {
                        continue;
                    };
                    if low == 0 {
                        continue;
                    }
                    let high = match e.attr_value(gimli::DW_AT_high_pc).ok().flatten() {
                        Some(AttributeValue::Udata(n)) => Some(low + n),
                        Some(v) => dwarf.attr_address(&unit, v).ok().flatten(),
                        None => None,
                    };
                    // Out-of-line definitions name themselves through their declaration.
                    let mut name = name_of(e);
                    if name.is_none() {
                        for at in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
                            if let Ok(Some(AttributeValue::UnitRef(off))) = e.attr_value(at) {
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
                    let Ok(Some(AttributeValue::Exprloc(expr))) = e.attr_value(gimli::DW_AT_location) else { continue };
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
                _ => {}
            }
        }
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
