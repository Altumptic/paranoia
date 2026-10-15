use goblin::elf::{dynamic, header, program_header as ph, section_header as sh, sym, Elf};

use super::{Loaded, MapRange, Seed};
use crate::model::*;

pub fn load(bytes: &[u8]) -> goblin::error::Result<Loaded> {
    let elf = Elf::parse(bytes)?;
    let mut out = Loaded::default();
    let h = &elf.header;

    out.arch = Some(match h.e_machine {
        header::EM_386 => Arch::X86,
        header::EM_X86_64 => Arch::X86_64,
        header::EM_ARM => Arch::Arm,
        header::EM_AARCH64 => Arch::Arm64,
        header::EM_MIPS => Arch::Mips,
        header::EM_PPC | header::EM_PPC64 => Arch::PowerPc,
        header::EM_RISCV => Arch::RiscV,
        _ => Arch::Unknown,
    });
    out.bits = if elf.is_64 { 64 } else { 32 };
    out.big_endian = !elf.little_endian;
    out.entry = elf.entry;

    let pie = h.e_type == header::ET_DYN && elf.interpreter.is_some();
    out.kind = match h.e_type {
        header::ET_EXEC => "Executable".into(),
        header::ET_DYN if pie => "Position-independent executable".into(),
        header::ET_DYN => "Shared object".into(),
        header::ET_REL => "Relocatable object".into(),
        header::ET_CORE => "Core dump".into(),
        t => format!("Type {t:#x}"),
    };

    out.header("Class", if elf.is_64 { "ELF64" } else { "ELF32" });
    out.header("Data", if elf.little_endian { "little-endian" } else { "big-endian" });
    out.header("OS/ABI", osabi_name(h.e_ident[header::EI_OSABI]).to_string());
    out.header("Type", header::et_to_str(h.e_type).to_string());
    out.header("Machine", format!("{} ({})", header::machine_to_str(h.e_machine), h.e_machine));
    out.header("Entry point", format!("{:#x}", elf.entry));
    out.header("Program headers", h.e_phnum.to_string());
    out.header("Section headers", h.e_shnum.to_string());
    out.header("Flags", format!("{:#x}", h.e_flags));
    if let Some(interp) = elf.interpreter {
        out.header("Interpreter", interp);
    }
    if let Some(soname) = elf.soname {
        out.header("SONAME", soname);
    }
    if !elf.runpaths.is_empty() || !elf.rpaths.is_empty() {
        let paths: Vec<&str> = elf.runpaths.iter().chain(elf.rpaths.iter()).copied().collect();
        out.header("RUNPATH", paths.join(":"));
    }

    // Segments -> address mapping. Image base is the lowest PT_LOAD vaddr.
    let mut base = u64::MAX;
    for p in elf.program_headers.iter().filter(|p| p.p_type == ph::PT_LOAD) {
        base = base.min(p.p_vaddr);
        out.ranges.push(MapRange {
            name: format!("LOAD@{:#x}", p.p_vaddr),
            vaddr: p.p_vaddr,
            vsize: p.p_memsz,
            offset: p.p_offset,
            file_size: p.p_filesz,
            perms: Perms { r: p.is_read(), w: p.is_write(), x: p.is_executable() },
        });
    }
    out.image_base = if base == u64::MAX { 0 } else { base };

    // Sections.
    for s in &elf.section_headers {
        if s.sh_type == sh::SHT_NULL {
            continue;
        }
        let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("").to_string();
        let raw_size = if s.sh_type == sh::SHT_NOBITS { 0 } else { s.sh_size };
        out.sections.push(Section {
            name,
            segment: None,
            vaddr: s.sh_addr,
            vsize: s.sh_size,
            offset: s.sh_offset,
            raw_size: raw_size.min(bytes.len().saturating_sub(s.sh_offset as usize) as u64),
            perms: Perms {
                r: s.sh_flags & sh::SHF_ALLOC as u64 != 0,
                w: s.sh_flags & sh::SHF_WRITE as u64 != 0,
                x: s.sh_flags & sh::SHF_EXECINSTR as u64 != 0,
            },
            entropy: 0.0,
            flags: s.sh_flags,
        });
        // Relocatable objects have no segments: map allocated sections directly.
        if h.e_type == header::ET_REL && s.sh_flags & sh::SHF_ALLOC as u64 != 0 {
            out.ranges.push(MapRange {
                name: out.sections.last().unwrap().name.clone(),
                vaddr: s.sh_addr,
                vsize: s.sh_size,
                offset: s.sh_offset,
                file_size: raw_size,
                perms: out.sections.last().unwrap().perms,
            });
        }
    }

    // Symbols: static symtab first, then the dynamic one.
    let mut seen = std::collections::HashSet::new();
    for (tab, strtab) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
        for s in tab.iter() {
            let Some(name) = strtab.get_at(s.st_name).filter(|n| !n.is_empty()) else { continue };
            if s.st_shndx == sh::SHN_UNDEF as usize || s.st_value == 0 {
                continue;
            }
            let kind = match s.st_type() {
                sym::STT_FUNC | sym::STT_GNU_IFUNC => SymbolKind::Function,
                sym::STT_OBJECT | sym::STT_TLS => SymbolKind::Object,
                sym::STT_SECTION => SymbolKind::Section,
                sym::STT_FILE => SymbolKind::File,
                _ => SymbolKind::Other,
            };
            if !seen.insert((name, s.st_value)) {
                continue;
            }
            let global = matches!(s.st_bind(), sym::STB_GLOBAL | sym::STB_WEAK);
            out.symbols.push(Symbol { name: name.to_string(), address: s.st_value, size: s.st_size, kind, global });
            if kind == SymbolKind::Function {
                let end = (s.st_size > 0).then(|| s.st_value + s.st_size);
                out.seeds.push(Seed { address: s.st_value, source: FunctionSource::Symbol, end });
            }
        }
    }

    // Exports: defined global dynamic symbols.
    for s in elf.dynsyms.iter() {
        if s.st_shndx == sh::SHN_UNDEF as usize || s.st_value == 0 || !matches!(s.st_bind(), sym::STB_GLOBAL | sym::STB_WEAK) {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(s.st_name).filter(|n| !n.is_empty()) {
            out.exports.push(Export { name: name.to_string(), address: s.st_value, ordinal: None, forward: None });
        }
    }

    // Imports: relocations against undefined dynamic symbols. The relocation offset
    // is the GOT slot the PLT stub (or code) loads the target from.
    let lib_hint = if elf.libraries.len() == 1 { elf.libraries[0] } else { "" };
    let mut imported = std::collections::HashSet::new();
    for rel in elf.pltrelocs.iter().chain(elf.dynrelas.iter()).chain(elf.dynrels.iter()) {
        let Some(s) = elf.dynsyms.get(rel.r_sym) else { continue };
        if s.st_shndx != sh::SHN_UNDEF as usize {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(s.st_name).filter(|n| !n.is_empty()) else { continue };
        if !imported.insert(name) {
            continue;
        }
        out.imports.push(Import { name: name.to_string(), library: lib_hint.to_string(), address: rel.r_offset, ordinal: None });
    }
    out.libraries = elf.libraries.iter().map(|s| s.to_string()).collect();

    // Mitigations (checksec semantics).
    let nx = elf.program_headers.iter().find(|p| p.p_type == ph::PT_GNU_STACK).map(|p| !p.is_executable()).unwrap_or(false);
    let relro_seg = elf.program_headers.iter().any(|p| p.p_type == ph::PT_GNU_RELRO);
    let bind_now = elf.dynamic.as_ref().is_some_and(|d| {
        d.dyns.iter().any(|e| {
            e.d_tag == dynamic::DT_BIND_NOW
                || (e.d_tag == dynamic::DT_FLAGS && e.d_val & dynamic::DF_BIND_NOW != 0)
                || (e.d_tag == dynamic::DT_FLAGS_1 && e.d_val & dynamic::DF_1_NOW != 0)
        })
    });
    let imports_have = |needle: &str| out.imports.iter().any(|i| i.name.starts_with(needle));
    let canary = imports_have("__stack_chk_fail") || out.symbols.iter().any(|s| s.name.starts_with("__stack_chk_fail"));
    let fortify = out.imports.iter().any(|i| i.name.starts_with("__") && i.name.ends_with("_chk") && i.name != "__stack_chk_fail");
    let pie_flag = h.e_type == header::ET_DYN;
    let relro = match (relro_seg, bind_now) {
        (true, true) => "Full RELRO",
        (true, false) => "Partial RELRO",
        _ => "No RELRO",
    };
    out.mitigation("PIE", pie_flag, if pie_flag { "position-independent" } else { "fixed load address" });
    out.mitigation("NX", nx, "PT_GNU_STACK not executable");
    out.mitigation("RELRO", relro_seg, relro);
    out.mitigation("Stack canary", canary, "__stack_chk_fail referenced");
    out.mitigation("FORTIFY_SOURCE", fortify, "*_chk libc wrappers referenced");
    let stripped = elf.syms.is_empty();
    out.mitigation("Stripped", stripped, if stripped { "no static symbol table" } else { "static symbols present" });

    if out.entry != 0 {
        out.seeds.push(Seed { address: out.entry, source: FunctionSource::Entry, end: None });
    }
    Ok(out)
}

fn osabi_name(v: u8) -> &'static str {
    match v {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        97 => "ARM",
        255 => "Standalone",
        _ => "Other",
    }
}
