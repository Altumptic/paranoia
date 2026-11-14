use goblin::pe::{self, PE};

use super::{Loaded, MapRange, Seed};
use crate::model::*;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;

const DLL_HIGH_ENTROPY_VA: u16 = 0x0020;
const DLL_DYNAMIC_BASE: u16 = 0x0040;
const DLL_FORCE_INTEGRITY: u16 = 0x0080;
const DLL_NX_COMPAT: u16 = 0x0100;
const DLL_NO_SEH: u16 = 0x0400;
const DLL_APPCONTAINER: u16 = 0x1000;
const DLL_GUARD_CF: u16 = 0x4000;

pub fn load(bytes: &[u8]) -> goblin::error::Result<Loaded> {
    let pe = PE::parse(bytes)?;
    let mut out = Loaded::default();

    let machine = pe.header.coff_header.machine;
    out.arch = Some(match machine {
        pe::header::COFF_MACHINE_X86 => Arch::X86,
        pe::header::COFF_MACHINE_X86_64 => Arch::X86_64,
        pe::header::COFF_MACHINE_ARM64 => Arch::Arm64,
        pe::header::COFF_MACHINE_ARM | pe::header::COFF_MACHINE_ARMNT => Arch::Arm,
        _ => Arch::Unknown,
    });
    out.bits = if pe.is_64 { 64 } else { 32 };
    out.image_base = pe.image_base;
    out.entry = if pe.entry != 0 { pe.image_base + pe.entry as u64 } else { 0 };

    let is_dotnet = pe.clr_data.is_some();
    out.kind = match (pe.is_lib, is_dotnet) {
        (true, true) => ".NET assembly (DLL)".into(),
        (false, true) => ".NET assembly (EXE)".into(),
        (true, false) => "Dynamic-link library".into(),
        (false, false) => "Executable".into(),
    };

    // Headers -------------------------------------------------------------
    let coff = &pe.header.coff_header;
    out.header("Machine", format!("{:#06x} ({})", machine, pe::header::machine_to_str(machine)));
    out.header("Sections", coff.number_of_sections.to_string());
    out.header("Timestamp", format_timestamp(coff.time_date_stamp));
    out.header("Characteristics", format!("{:#06x}", coff.characteristics));
    if let Some(name) = pe.name {
        out.header("Internal name", name);
    }

    let mut dll_chars = 0u16;
    if let Some(opt) = &pe.header.optional_header {
        let w = &opt.windows_fields;
        dll_chars = w.dll_characteristics;
        out.header("Image base", format!("{:#x}", w.image_base));
        out.header("Entry point (RVA)", format!("{:#x}", pe.entry));
        out.header("Subsystem", subsystem_name(w.subsystem).to_string());
        out.header("OS version", format!("{}.{}", w.major_operating_system_version, w.minor_operating_system_version));
        out.header("Linker", format!("{}.{}", opt.standard_fields.major_linker_version, opt.standard_fields.minor_linker_version));
        out.header("Size of image", format!("{:#x}", w.size_of_image));
        out.header("Checksum", format!("{:#010x}", w.check_sum));
        out.header("DLL characteristics", format!("{:#06x}", w.dll_characteristics));
    }
    if let Some(debug) = &pe.debug_data {
        if let Some(pdb) = &debug.codeview_pdb70_debug_info {
            let path = String::from_utf8_lossy(pdb.filename).trim_end_matches('\0').to_string();
            out.header("PDB path", path);
            out.header("PDB GUID", format_guid(&pdb.signature, pdb.age));
        }
    }
    if let Some(rich) = &pe.header.rich_header {
        out.header("Rich header", format!("present, key {:#010x}", rich.key));
    }

    // Mitigations ---------------------------------------------------------
    let has = |flag: u16| dll_chars & flag != 0;
    out.mitigation("ASLR", has(DLL_DYNAMIC_BASE), "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE");
    if pe.is_64 {
        out.mitigation("High-entropy VA", has(DLL_HIGH_ENTROPY_VA), "64-bit ASLR address space");
    }
    out.mitigation("DEP / NX", has(DLL_NX_COMPAT), "IMAGE_DLLCHARACTERISTICS_NX_COMPAT");
    out.mitigation("Control Flow Guard", has(DLL_GUARD_CF), "IMAGE_DLLCHARACTERISTICS_GUARD_CF");
    if !pe.is_64 {
        out.mitigation("SafeSEH / No SEH", has(DLL_NO_SEH) || pe.load_config_data.is_some(), "structured exception handler hardening");
    }
    out.mitigation("Force integrity", has(DLL_FORCE_INTEGRITY), "signature checked at load time");
    out.mitigation("AppContainer", has(DLL_APPCONTAINER), "must run inside an AppContainer");
    let signed = pe.header.optional_header.and_then(|o| o.data_directories.get_certificate_table().map(|d| d.size > 0)).unwrap_or(false);
    out.mitigation("Authenticode", signed, if signed { "certificate table present" } else { "not signed" });

    // Sections ------------------------------------------------------------
    for s in &pe.sections {
        let name = s.name().map(str::to_string).unwrap_or_else(|_| String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string());
        let c = s.characteristics;
        let perms = Perms {
            r: c & IMAGE_SCN_MEM_READ != 0,
            w: c & IMAGE_SCN_MEM_WRITE != 0,
            x: c & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0,
        };
        let vaddr = pe.image_base + s.virtual_address as u64;
        let vsize = if s.virtual_size == 0 { s.size_of_raw_data } else { s.virtual_size } as u64;
        let raw_size = (s.size_of_raw_data as u64).min(bytes.len().saturating_sub(s.pointer_to_raw_data as usize) as u64);
        out.sections.push(Section {
            name: name.clone(),
            segment: None,
            vaddr,
            vsize,
            offset: s.pointer_to_raw_data as u64,
            raw_size,
            perms,
            entropy: 0.0,
            flags: c as u64,
        });
        out.ranges.push(MapRange {
            name,
            vaddr,
            vsize,
            offset: s.pointer_to_raw_data as u64,
            file_size: raw_size.min(vsize.max(raw_size)),
            perms,
        });
    }
    // The PE headers themselves are mapped at the image base.
    if let Some(opt) = &pe.header.optional_header {
        let hs = opt.windows_fields.size_of_headers as u64;
        out.ranges.push(MapRange {
            name: "HEADER".into(),
            vaddr: pe.image_base,
            vsize: hs,
            offset: 0,
            file_size: hs.min(bytes.len() as u64),
            perms: Perms { r: true, w: false, x: false },
        });
    }

    // Imports -------------------------------------------------------------
    let mut imphash_parts = Vec::new();
    for imp in &pe.imports {
        let ordinal = imp.name.starts_with("ORDINAL ").then_some(imp.ordinal);
        // goblin names ordinal imports "ORDINAL n"; use an identifier that reads as code.
        out.imports.push(Import {
            name: if ordinal.is_some() { format!("Ordinal_{}", imp.ordinal) } else { imp.name.to_string() },
            library: imp.dll.to_string(),
            address: pe.image_base + imp.offset as u64,
            ordinal,
        });
        let lib = imp.dll.to_ascii_lowercase();
        let lib = lib.rsplit_once('.').filter(|(_, ext)| matches!(*ext, "dll" | "ocx" | "sys")).map(|(b, _)| b.to_string()).unwrap_or(lib);
        let func = match ordinal {
            Some(o) => format!("ord{o}"),
            None => imp.name.to_ascii_lowercase(),
        };
        imphash_parts.push(format!("{lib}.{func}"));
    }
    if !imphash_parts.is_empty() {
        use md5::Digest;
        out.imphash = Some(hex::encode(md5::Md5::digest(imphash_parts.join(",").as_bytes())));
    }
    out.libraries = pe.libraries.iter().map(|s| s.to_string()).collect();

    // Exports -------------------------------------------------------------
    let ordinal_base = pe.export_data.as_ref().map(|e| e.export_directory_table.ordinal_base).unwrap_or(1);
    let addr_table = pe.export_data.as_ref().map(|e| &e.export_address_table);
    for (i, exp) in pe.exports.iter().enumerate() {
        let address = pe.image_base + exp.rva as u64;
        let forward = exp.reexport.as_ref().map(|r| match r {
            pe::export::Reexport::DLLName { export, lib } => format!("{lib}!{export}"),
            pe::export::Reexport::DLLOrdinal { ordinal, lib } => format!("{lib}!#{ordinal}"),
        });
        let ordinal = addr_table.and_then(|t| {
            t.iter().position(|e| match e {
                pe::export::ExportAddressTableEntry::ExportRVA(r) => *r as usize == exp.rva,
                pe::export::ExportAddressTableEntry::ForwarderRVA(r) => *r as usize == exp.rva,
            })
        });
        out.exports.push(Export {
            name: exp.name.map(str::to_string).unwrap_or_else(|| format!("export_{i}")),
            address,
            ordinal: ordinal.map(|o| o as u32 + ordinal_base),
            forward: forward.clone(),
        });
        if forward.is_none() {
            out.seeds.push(Seed { address, source: FunctionSource::Export, end: None });
        }
    }

    // Function seeds --------------------------------------------------------
    if out.entry != 0 {
        out.seeds.push(Seed { address: out.entry, source: FunctionSource::Entry, end: None });
    }
    // `.pdata` (x64 / ARM64 unwind table): parsed by hand with bounds checks because goblin's
    // iterator trusts the directory size and panics on truncated tables.
    if let Some(dir) = pe.header.optional_header.and_then(|o| o.data_directories.get_exception_table().copied()) {
        if let Some(off) = rva_to_offset(&pe.sections, dir.virtual_address) {
            let table = bytes.get(off..).unwrap_or(&[]);
            let table = &table[..(dir.size as usize).min(table.len())];
            let arm64 = machine == pe::header::COFF_MACHINE_ARM64;
            let stride = if arm64 { 8 } else { 12 };
            let mut chunk_parents = std::collections::HashSet::new();
            for e in table.chunks_exact(stride).take(1_000_000) {
                let begin = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                let end = if arm64 {
                    // ARM64 packs the function length (in instructions) into the unwind word when Flag != 0.
                    let w = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
                    (w & 3 != 0).then(|| begin + ((w >> 2) & 0x7ff) * 4)
                } else {
                    Some(u32::from_le_bytes([e[4], e[5], e[6], e[7]]))
                };
                if begin == 0 || end.is_some_and(|end| end <= begin) {
                    continue;
                }
                // x64: entries whose unwind info is chained (UNW_FLAG_CHAININFO) describe a chunk of
                // the parent function (shrink-wrapped or cold code), not a function of their own.
                if !arm64 {
                    let unwind = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
                    if let Some(parent) = chained_parent(bytes, &pe.sections, unwind) {
                        chunk_parents.insert(pe.image_base + parent as u64);
                        continue;
                    }
                }
                out.seeds.push(Seed {
                    address: pe.image_base + begin as u64,
                    source: FunctionSource::ExceptionTable,
                    end: end.map(|e| pe.image_base + e as u64),
                });
            }
            // Functions with separated chunks are not bounded by their primary range.
            for s in out.seeds.iter_mut().filter(|s| chunk_parents.contains(&s.address)) {
                s.end = None;
            }
        }
    }
    if let Some(tls) = &pe.tls_data {
        for cb in &tls.callbacks {
            out.seeds.push(Seed { address: *cb, source: FunctionSource::Entry, end: None });
            out.symbols.push(Symbol {
                name: format!("TlsCallback_{:x}", cb),
                address: *cb,
                size: 0,
                kind: SymbolKind::Function,
                global: false,
            });
        }
    }
    if is_dotnet {
        out.warnings.push(".NET assembly: native disassembly only covers the loader stub; IL decompilation is planned.".into());
    }

    out.pointers = base_relocation_targets(bytes, &pe);

    // GNU ld (MinGW, Rust's `-gnu` targets) leaves the COFF symbol table in the file.
    let (names, functions) = coff_symbols(bytes, &pe, &mut out);
    if names > 0 {
        out.header("COFF symbols", format!("{names} names, {functions} functions"));
    }

    Ok(out)
}

/// Most relocations read from one image; a large DLL has a few hundred thousand.
const MAX_RELOCATIONS: usize = 8_000_000;

/// The addresses the base relocations point at: each relocation patches a stored address, and
/// the value stored there is where it points. Parsed by hand with bounds checks, like `.pdata`.
fn base_relocation_targets(bytes: &[u8], pe: &PE<'_>) -> Vec<u64> {
    let Some(dir) = pe.header.optional_header.and_then(|o| o.data_directories.get_base_relocation_table().copied()) else {
        return Vec::new();
    };
    let Some(start) = rva_to_offset(&pe.sections, dir.virtual_address) else { return Vec::new() };
    let table = &bytes[start.min(bytes.len())..];
    let table = &table[..(dir.size as usize).min(table.len())];
    let wide = pe.is_64;
    let image_end = pe.image_base.saturating_add(
        pe.sections.iter().map(|s| s.virtual_address as u64 + s.virtual_size.max(s.size_of_raw_data) as u64).max().unwrap_or(0),
    );
    let mut out = Vec::new();
    let (mut at, mut seen) = (0usize, 0usize);
    while at + 8 <= table.len() && seen < MAX_RELOCATIONS {
        let page = u32::from_le_bytes([table[at], table[at + 1], table[at + 2], table[at + 3]]);
        let size = u32::from_le_bytes([table[at + 4], table[at + 5], table[at + 6], table[at + 7]]) as usize;
        if size < 8 || at + size > table.len() {
            break;
        }
        for entry in table[at + 8..at + size].chunks_exact(2) {
            seen += 1;
            let e = u16::from_le_bytes([entry[0], entry[1]]);
            // HIGHLOW (3) in a 32-bit image, DIR64 (10) in a 64-bit one.
            if e >> 12 != if wide { 10 } else { 3 } {
                continue;
            }
            let Some(off) = page.checked_add((e & 0x0fff) as u32).and_then(|rva| rva_to_offset(&pe.sections, rva)) else { continue };
            let value = if wide {
                bytes.get(off..off + 8).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            } else {
                bytes.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
            };
            if let Some(v) = value.filter(|v| *v >= pe.image_base && *v < image_end) {
                out.push(v);
            }
        }
        at += size;
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Most COFF records a file may declare. A real image has some hundreds of thousands at most.
const MAX_COFF_SYMBOLS: usize = 4_000_000;
/// Longest symbol name read from the string table (Rust's mangled names reach a few hundred).
const MAX_COFF_NAME: usize = 4096;
const COFF_RECORD: usize = 18;
/// Storage classes that name a definition: external and static.
const SYM_CLASS_EXTERNAL: u8 = 2;
const SYM_CLASS_STATIC: u8 = 3;
/// `IMAGE_SYM_DTYPE_FUNCTION` in the high nibble of the type field.
const SYM_TYPE_FUNCTION: u16 = 0x20;

/// One section as the COFF reader needs it.
struct CoffSection {
    virtual_address: u32,
    /// The larger of the virtual and raw sizes: no symbol points past it.
    size: u32,
    code: bool,
}

/// A symbol read from the COFF table.
#[derive(Debug, PartialEq, Eq)]
struct CoffSymbol {
    name: String,
    address: u64,
    function: bool,
    global: bool,
}

/// Reads the COFF symbol table into `out.symbols` and seeds. Returns how many names and how many
/// of them are functions. A name from the table replaces the synthetic `TlsCallback_` one.
fn coff_symbols(bytes: &[u8], pe: &PE<'_>, out: &mut Loaded) -> (usize, usize) {
    let header = &pe.header.coff_header;
    let sections: Vec<CoffSection> = pe
        .sections
        .iter()
        .map(|s| CoffSection {
            virtual_address: s.virtual_address,
            size: s.virtual_size.max(s.size_of_raw_data),
            code: s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0,
        })
        .collect();
    let found =
        read_coff_symbols(bytes, header.pointer_to_symbol_table as usize, header.number_of_symbol_table as usize, &sections, pe.image_base);
    let functions = found.iter().filter(|s| s.function).count();
    let named: std::collections::HashSet<u64> = found.iter().filter(|s| s.function).map(|s| s.address).collect();
    out.symbols.retain(|s| !(s.name.starts_with("TlsCallback_") && named.contains(&s.address)));
    for sym in &found {
        let kind = if sym.function { SymbolKind::Function } else { SymbolKind::Object };
        if sym.function {
            out.seeds.push(Seed { address: sym.address, source: FunctionSource::Symbol, end: None });
        }
        out.symbols.push(Symbol { name: sym.name.clone(), address: sym.address, size: 0, kind, global: sym.global });
    }
    (found.len(), functions)
}

/// The COFF symbol table at `table` with `count` 18-byte records, followed by the string table.
///
/// In a linked image a symbol's value is the offset from the start of its section. A function is a
/// symbol of function type in an executable section; an external symbol in code without a type
/// (assembly labels) counts too, but a static untyped one is a local label and is skipped, like
/// section and file records (names starting with a dot). Everything is bounds-checked against
/// `bytes`: a damaged or hostile table gives fewer symbols, never a panic.
fn read_coff_symbols(bytes: &[u8], table: usize, count: usize, sections: &[CoffSection], image_base: u64) -> Vec<CoffSymbol> {
    if table == 0 || count == 0 || count > MAX_COFF_SYMBOLS {
        return Vec::new();
    }
    let Some(table_end) = count.checked_mul(COFF_RECORD).and_then(|n| n.checked_add(table)) else { return Vec::new() };
    if table_end > bytes.len() {
        return Vec::new();
    }
    let strings = &bytes[table_end..];
    let name_at = |offset: usize| -> Option<String> {
        let rest = strings.get(offset..)?;
        let len = rest.iter().take(MAX_COFF_NAME).position(|&b| b == 0)?;
        std::str::from_utf8(&rest[..len]).ok().map(str::to_owned)
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0usize;
    while i < count {
        let rec = &bytes[table + i * COFF_RECORD..table + (i + 1) * COFF_RECORD];
        i += 1 + rec[17] as usize;
        let (class, typ) = (rec[16], u16::from_le_bytes([rec[14], rec[15]]));
        if class != SYM_CLASS_EXTERNAL && class != SYM_CLASS_STATIC {
            continue;
        }
        let section_number = i16::from_le_bytes([rec[12], rec[13]]);
        let Some(section) = usize::try_from(section_number).ok().and_then(|n| n.checked_sub(1)).and_then(|n| sections.get(n)) else {
            continue;
        };
        let name = if rec[..4] == [0; 4] {
            name_at(u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]) as usize)
        } else {
            let end = rec[..8].iter().position(|&b| b == 0).unwrap_or(8);
            std::str::from_utf8(&rec[..end]).ok().map(str::to_owned)
        };
        let Some(name) = name.filter(|n| !n.is_empty() && !n.starts_with('.')) else { continue };
        let value = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
        let Some(rva) = section.virtual_address.checked_add(value) else { continue };
        if value >= section.size {
            continue;
        }
        let address = image_base + rva as u64;
        let function = section.code && (typ & 0xf0 == SYM_TYPE_FUNCTION || (typ == 0 && class == SYM_CLASS_EXTERNAL));
        if !function && (section.code || class != SYM_CLASS_EXTERNAL) {
            continue;
        }
        if seen.insert((address, name.clone())) {
            out.push(CoffSymbol { name, address, function, global: class == SYM_CLASS_EXTERNAL });
        }
    }
    out
}

/// For x64 unwind info chained to another entry (UNW_FLAG_CHAININFO), the RVA of the root function.
fn chained_parent(bytes: &[u8], sections: &[goblin::pe::section_table::SectionTable], unwind: u32) -> Option<u32> {
    let mut unwind = unwind;
    let mut parent = None;
    for _ in 0..32 {
        let entry = if unwind & 1 == 1 {
            // The low bit marks a direct pointer to the parent RUNTIME_FUNCTION.
            rva_to_offset(sections, unwind & !1)?
        } else {
            let o = rva_to_offset(sections, unwind)?;
            let head = bytes.get(o..o + 4)?;
            if (head[0] >> 3) & 4 == 0 {
                return parent;
            }
            let codes = (head[2] as usize + 1) & !1;
            o + 4 + 2 * codes
        };
        let rf = bytes.get(entry..entry + 12)?;
        parent = Some(u32::from_le_bytes([rf[0], rf[1], rf[2], rf[3]]));
        unwind = u32::from_le_bytes([rf[8], rf[9], rf[10], rf[11]]);
    }
    parent
}

fn rva_to_offset(sections: &[goblin::pe::section_table::SectionTable], rva: u32) -> Option<usize> {
    sections.iter().find_map(|s| {
        let size = s.virtual_size.max(s.size_of_raw_data);
        (rva >= s.virtual_address && rva < s.virtual_address.saturating_add(size))
            .then(|| (s.pointer_to_raw_data + (rva - s.virtual_address)) as usize)
    })
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "Unknown",
    }
}

fn format_guid(g: &[u8; 16], age: u32) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{}-{} (age {age})",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        hex::encode_upper(&g[8..10]),
        hex::encode_upper(&g[10..16])
    )
}

/// Formats a Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` without pulling in a date crate.
pub(crate) fn format_timestamp(ts: u32) -> String {
    if ts == 0 || ts == 0xffff_ffff {
        return format!("{ts:#x} (not set / reproducible build)");
    }
    let secs = ts as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    fn record(name: &[u8; 8], value: u32, section: i16, typ: u16, class: u8, aux: u8) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(name);
        r.extend_from_slice(&value.to_le_bytes());
        r.extend_from_slice(&section.to_le_bytes());
        r.extend_from_slice(&typ.to_le_bytes());
        r.push(class);
        r.push(aux);
        r
    }

    fn short(s: &str) -> [u8; 8] {
        let mut n = [0u8; 8];
        n[..s.len()].copy_from_slice(s.as_bytes());
        n
    }

    fn long(offset: u32) -> [u8; 8] {
        let mut n = [0u8; 8];
        n[4..].copy_from_slice(&offset.to_le_bytes());
        n
    }

    fn sections() -> Vec<CoffSection> {
        vec![
            CoffSection { virtual_address: 0x1000, size: 0x800, code: true },
            CoffSection { virtual_address: 0x2000, size: 0x100, code: false },
        ]
    }

    /// A table with the usual shapes: a typed function, a long name from the string table, an
    /// untyped static label, a section symbol, a data symbol, and a symbol with an aux record.
    #[test]
    fn coff_table_gives_functions_and_data() {
        let mut t = Vec::new();
        t.extend(record(&short("main"), 0x10, 1, 0x20, 2, 0));
        t.extend(record(&long(4), 0x40, 1, 0x20, 3, 0));
        t.extend(record(&short("label"), 0x50, 1, 0, 3, 0));
        t.extend(record(&short(".text"), 0, 1, 0, 3, 1));
        t.extend(record(&short("auxrec"), 0, 0, 0, 0, 0)); // the aux record of `.text`
        t.extend(record(&short("table"), 0x20, 2, 0, 2, 0));
        t.extend(record(&short("noext"), 0x20, 1, 0, 2, 0));
        let count = t.len() / COFF_RECORD;
        let mut file = vec![0u8; 8];
        let table = file.len();
        file.extend(&t);
        let name = b"_ZN4core3fmt5write17h0123456789abcdefE\0";
        file.extend((4 + name.len() as u32).to_le_bytes());
        file.extend(name);
        let got = read_coff_symbols(&file, table, count, &sections(), 0x1_4000_0000);
        let summary: Vec<(&str, u64, bool, bool)> = got.iter().map(|s| (s.name.as_str(), s.address, s.function, s.global)).collect();
        assert_eq!(
            summary,
            vec![
                ("main", 0x1_4000_1010, true, true),
                ("_ZN4core3fmt5write17h0123456789abcdefE", 0x1_4000_1040, true, false),
                ("table", 0x1_4000_2020, false, true),
                ("noext", 0x1_4000_1020, true, true),
            ]
        );
    }

    #[test]
    fn hostile_coff_tables_are_ignored_cleanly() {
        let secs = sections();
        // No table, a count beyond the file, and a count that overflows the arithmetic.
        assert!(read_coff_symbols(&[0; 64], 0, 3, &secs, 0).is_empty());
        assert!(read_coff_symbols(&[0; 64], 8, 100, &secs, 0).is_empty());
        assert!(read_coff_symbols(&[0; 64], usize::MAX - 4, 2, &secs, 0).is_empty());
        assert!(read_coff_symbols(&[0; 64], 8, usize::MAX, &secs, 0).is_empty());
        // A name offset outside the string table, a value past its section, an unterminated name.
        let mut t = record(&long(9999), 0x10, 1, 0x20, 2, 0);
        t.extend(record(&short("far"), 0xffff_fff0, 1, 0x20, 2, 0));
        t.extend(record(&long(4), 0x10, 1, 0x20, 2, 0));
        let count = t.len() / COFF_RECORD;
        let mut file = t.clone();
        file.extend(8u32.to_le_bytes());
        file.extend(b"noend");
        assert!(read_coff_symbols(&file, 0, count, &secs, 0).is_empty());
        // Random damage to a valid table never panics.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2000 {
            let mut f = file.clone();
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed as usize) % f.len();
                f[at] = (seed >> 32) as u8;
            }
            let _ = read_coff_symbols(&f, 0, count, &secs, 0);
        }
    }

    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_timestamp(86_400), "1970-01-02 00:00:00 UTC");
    }
}
