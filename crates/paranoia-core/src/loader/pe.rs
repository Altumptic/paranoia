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

    Ok(out)
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
    use super::format_timestamp;

    #[test]
    fn timestamps() {
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_timestamp(86_400), "1970-01-02 00:00:00 UTC");
    }
}
