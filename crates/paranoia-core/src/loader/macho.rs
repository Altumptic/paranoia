use goblin::mach::{constants::cputype as cpu, header, load_command::CommandVariant, Mach, MachO, SingleArch};

use super::macho_bind::{bind_opcodes, chained_fixups, Seg};
use super::{Loaded, MapRange, Seed};
use crate::model::*;

const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;

pub fn load(bytes: &[u8]) -> goblin::error::Result<Loaded> {
    match Mach::parse(bytes)? {
        Mach::Binary(m) => load_single(bytes, &m),
        Mach::Fat(fat) => {
            // Prefer arm64, then x86-64, then whatever comes first.
            let arches: Vec<_> = fat.iter_arches().filter_map(Result::ok).collect();
            let pick = arches
                .iter()
                .position(|a| a.cputype == cpu::CPU_TYPE_ARM64)
                .or_else(|| arches.iter().position(|a| a.cputype == cpu::CPU_TYPE_X86_64))
                .unwrap_or(0);
            let names: Vec<&str> =
                arches.iter().map(|a| cpu::get_arch_name_from_types(a.cputype, a.cpusubtype & 0x00ff_ffff).unwrap_or("?")).collect();
            match fat.get(pick)? {
                SingleArch::MachO(_) => {
                    let fa = &arches[pick];
                    let (start, len) = (fa.offset as usize, fa.size as usize);
                    let slice = &bytes[start..(start + len).min(bytes.len())];
                    let m = MachO::parse(slice, 0)?;
                    let mut out = load_single(slice, &m)?;
                    out.slice = Some((start, slice.len()));
                    out.headers.insert(
                        0,
                        KeyValue { key: "Universal binary".into(), value: format!("{} (analyzing {})", names.join(", "), names[pick]) },
                    );
                    Ok(out)
                }
                SingleArch::Archive(_) => {
                    Err(goblin::error::Error::Malformed("static archive inside universal binary is not supported yet".into()))
                }
            }
        }
    }
}

fn load_single(bytes: &[u8], m: &MachO) -> goblin::error::Result<Loaded> {
    let mut out = Loaded::default();
    let h = &m.header;
    out.arch = Some(match h.cputype {
        cpu::CPU_TYPE_X86 => Arch::X86,
        cpu::CPU_TYPE_X86_64 => Arch::X86_64,
        cpu::CPU_TYPE_ARM => Arch::Arm,
        cpu::CPU_TYPE_ARM64 | cpu::CPU_TYPE_ARM64_32 => Arch::Arm64,
        cpu::CPU_TYPE_POWERPC | cpu::CPU_TYPE_POWERPC64 => Arch::PowerPc,
        _ => Arch::Unknown,
    });
    out.bits = if m.is_64 { 64 } else { 32 };
    out.big_endian = !m.little_endian;
    out.kind = match h.filetype {
        header::MH_EXECUTE => "Executable",
        header::MH_DYLIB => "Dynamic library",
        header::MH_BUNDLE => "Bundle",
        header::MH_OBJECT => "Object file",
        header::MH_DYLINKER => "Dynamic linker",
        header::MH_KEXT_BUNDLE => "Kernel extension",
        header::MH_CORE => "Core dump",
        _ => "Mach-O image",
    }
    .into();

    out.header("CPU", cpu::get_arch_name_from_types(h.cputype, h.cpusubtype & 0x00ff_ffff).unwrap_or("unknown").to_string());
    out.header("File type", header::filetype_to_str(h.filetype).to_string());
    out.header("Load commands", h.ncmds.to_string());
    out.header("Flags", format!("{:#x}", h.flags));
    if let Some(name) = m.name {
        out.header("Install name", name);
    }

    // Segments and sections.
    let mut text_vmaddr = 0u64;
    for seg in m.segments.iter() {
        let segname = seg.name().unwrap_or("").to_string();
        if segname == "__TEXT" {
            text_vmaddr = seg.vmaddr;
        }
        let perms =
            Perms { r: seg.initprot & VM_PROT_READ != 0, w: seg.initprot & VM_PROT_WRITE != 0, x: seg.initprot & VM_PROT_EXECUTE != 0 };
        if segname != "__PAGEZERO" {
            out.ranges.push(MapRange {
                name: segname.clone(),
                vaddr: seg.vmaddr,
                vsize: seg.vmsize,
                offset: seg.fileoff,
                file_size: seg.filesize,
                perms,
            });
        }
        for (sect, _) in seg.sections()?.iter() {
            let zerofill = matches!(sect.flags & 0xff, 0x1 | 0xc | 0x12);
            let code = sect.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
            out.sections.push(Section {
                name: sect.name().unwrap_or("").to_string(),
                segment: Some(segname.clone()),
                vaddr: sect.addr,
                vsize: sect.size,
                offset: sect.offset as u64,
                raw_size: if zerofill { 0 } else { sect.size.min(bytes.len().saturating_sub(sect.offset as usize) as u64) },
                perms: Perms { x: perms.x && code, ..perms },
                entropy: 0.0,
                flags: sect.flags as u64,
            });
        }
    }
    out.image_base = text_vmaddr;
    // goblin already resolves LC_MAIN's offset against __TEXT, so `entry` is a VA either way.
    out.entry = m.entry;

    let mut min_os = None;
    let mut uuid = None;
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::Uuid(u) => uuid = Some(hex::encode_upper(u.uuid)),
            CommandVariant::BuildVersion(b) => min_os = Some(format!("{} {}", platform_name(b.platform), version(b.minos))),
            CommandVariant::VersionMinMacosx(v) => min_os = Some(format!("macOS {}", version(v.version))),
            CommandVariant::VersionMinIphoneos(v) => min_os = Some(format!("iOS {}", version(v.version))),
            _ => {}
        }
    }
    if let Some(u) = uuid {
        out.header("UUID", u);
    }
    if let Some(v) = min_os {
        out.header("Minimum OS", v);
    }
    if !m.rpaths.is_empty() {
        out.header("RPATH", m.rpaths.join(":"));
    }

    // Symbols.
    for (name, nl) in m.symbols().flatten() {
        if name.is_empty() || nl.n_type & N_STAB != 0 || nl.n_type & N_TYPE != N_SECT {
            continue;
        }
        let in_code = out.sections.get(nl.n_sect.wrapping_sub(1)).is_some_and(|s| s.perms.x);
        let kind = if in_code { SymbolKind::Function } else { SymbolKind::Object };
        out.symbols.push(Symbol { name: name.to_string(), address: nl.n_value, size: 0, kind, global: nl.n_type & N_EXT != 0 });
        if in_code {
            out.seeds.push(Seed { address: nl.n_value, source: FunctionSource::Symbol, end: None });
        }
    }

    // Imports: dyld bind opcodes (classic) or chained fixups (macOS 12+ / iOS 15+).
    let segs: Vec<Seg> =
        m.segments.iter().map(|s| Seg { vmaddr: s.vmaddr, vmsize: s.vmsize, fileoff: s.fileoff, filesize: s.filesize }).collect();
    let ptr = if m.is_64 { 8 } else { 4 };
    let blob = |off: u32, size: u32| {
        let start = (off as usize).min(bytes.len());
        &bytes[start..start.saturating_add(size as usize).min(bytes.len())]
    };
    let mut binds = Vec::new();
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) => {
                binds.extend(bind_opcodes(blob(d.bind_off, d.bind_size), &segs, ptr, false));
                binds.extend(bind_opcodes(blob(d.lazy_bind_off, d.lazy_bind_size), &segs, ptr, true));
            }
            CommandVariant::DyldChainedFixups(d) => binds.extend(chained_fixups(bytes, blob(d.dataoff, d.datasize), &segs, text_vmaddr)),
            _ => {}
        }
    }
    let mut seen = std::collections::HashSet::new();
    for b in binds {
        if !seen.insert(b.address) {
            continue;
        }
        let library = match b.ordinal {
            o if o > 0 => m.libs.get(o as usize).copied().unwrap_or("?"),
            0 => "self",
            -1 => "main executable",
            -2 => "flat lookup",
            _ => "weak lookup",
        };
        out.imports.push(Import { name: b.name, library: library.to_string(), address: b.address, ordinal: None });
    }

    // Exports come from our own bounds-checked trie walker: goblin indexes the dylib
    // list with an unchecked ordinal and panics on hostile input.
    let trie = m.load_commands.iter().find_map(|lc| match &lc.command {
        CommandVariant::DyldInfo(d) | CommandVariant::DyldInfoOnly(d) if d.export_size > 0 => Some((d.export_off, d.export_size)),
        CommandVariant::DyldExportsTrie(d) if d.datasize > 0 => Some((d.dataoff, d.datasize)),
        _ => None,
    });
    if let Some((off, size)) = trie {
        let start = (off as usize).min(bytes.len());
        let data = &bytes[start..start.saturating_add(size as usize).min(bytes.len())];
        for e in walk_export_trie(data, &m.libs) {
            let address = e.address.map(|a| text_vmaddr.wrapping_add(a)).unwrap_or(0);
            if address != 0
                && e.forward.is_none()
                && out.sections.iter().any(|s| s.perms.x && address >= s.vaddr && address < s.vaddr + s.vsize)
            {
                out.seeds.push(Seed { address, source: FunctionSource::Export, end: None });
            }
            out.exports.push(Export { name: e.name, address, ordinal: None, forward: e.forward });
        }
    }
    out.libraries = m.libs.iter().filter(|l| **l != "self").map(|s| s.to_string()).collect();

    // Mitigations.
    let pie = h.flags & header::MH_PIE != 0;
    let no_heap_exec = h.flags & header::MH_NO_HEAP_EXECUTION != 0;
    let allow_stack_exec = h.flags & header::MH_ALLOW_STACK_EXECUTION != 0;
    let canary = out.imports.iter().any(|i| i.name.contains("__stack_chk_fail"));
    let arc = out.imports.iter().any(|i| i.name.contains("objc_release"));
    let signed = m.load_commands.iter().any(|lc| matches!(lc.command, CommandVariant::CodeSignature(_)));
    let encrypted = m.load_commands.iter().any(|lc| match &lc.command {
        CommandVariant::EncryptionInfo32(e) => e.cryptid != 0,
        CommandVariant::EncryptionInfo64(e) => e.cryptid != 0,
        _ => false,
    });
    out.mitigation("PIE", pie, "MH_PIE");
    out.mitigation("NX stack", !allow_stack_exec, "MH_ALLOW_STACK_EXECUTION not set");
    out.mitigation("NX heap", no_heap_exec, "MH_NO_HEAP_EXECUTION");
    out.mitigation("Stack canary", canary, "__stack_chk_fail referenced");
    out.mitigation("ARC", arc, "objc_release referenced");
    out.mitigation("Code signature", signed, "LC_CODE_SIGNATURE");
    if encrypted {
        out.mitigation("Encrypted", true, "FairPlay encrypted segment (cryptid != 0)");
        out.warnings.push("Binary is encrypted (cryptid != 0); code in the encrypted range is not meaningful.".into());
    }

    if out.entry != 0 {
        out.seeds.push(Seed { address: out.entry, source: FunctionSource::Entry, end: None });
    }
    Ok(out)
}

fn version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

fn platform_name(p: u32) -> &'static str {
    match p {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "Mac Catalyst",
        7 => "iOS Simulator",
        11 => "visionOS",
        _ => "platform",
    }
}

struct TrieExport {
    name: String,
    /// Offset from the start of `__TEXT`.
    address: Option<u64>,
    forward: Option<String>,
}

fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as u64) << shift;
        }
        shift += 7;
        if b & 0x80 == 0 {
            return Some(v);
        }
        if shift > 70 {
            return None;
        }
    }
}

fn cstr<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let rest = data.get(*pos..)?;
    let len = rest.iter().position(|&b| b == 0)?;
    *pos += len + 1;
    Some(&rest[..len])
}

/// Iterative walk of a dyld export trie with cycle and size limits.
fn walk_export_trie(data: &[u8], libs: &[&str]) -> Vec<TrieExport> {
    const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
    let mut out = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<(usize, Vec<u8>)> = vec![(0, Vec::new())];
    while let Some((node, prefix)) = stack.pop() {
        if !visited.insert(node) || out.len() > 500_000 || prefix.len() > 4096 {
            continue;
        }
        let mut pos = node;
        let Some(terminal_size) = uleb(data, &mut pos) else { continue };
        let children_at = pos.saturating_add(terminal_size as usize);
        if terminal_size > 0 {
            let name = String::from_utf8_lossy(&prefix).into_owned();
            if let Some(flags) = uleb(data, &mut pos) {
                if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
                    let ordinal = uleb(data, &mut pos).unwrap_or(0) as usize;
                    let sym = cstr(data, &mut pos).map(|s| String::from_utf8_lossy(s).into_owned()).filter(|s| !s.is_empty());
                    // libs[0] is "self"; ordinals are 1-based into the remaining list.
                    let lib = libs.get(ordinal).copied().unwrap_or("?");
                    out.push(TrieExport { forward: Some(format!("{lib}!{}", sym.as_deref().unwrap_or(&name))), name, address: None });
                } else {
                    // Regular and stub-and-resolver exports both start with the address.
                    let address = uleb(data, &mut pos);
                    out.push(TrieExport { name, address, forward: None });
                }
            }
        }
        let mut pos = children_at;
        let Some(&count) = data.get(pos) else { continue };
        pos += 1;
        for _ in 0..count {
            let Some(edge) = cstr(data, &mut pos) else { break };
            let Some(child) = uleb(data, &mut pos) else { break };
            let mut p = prefix.clone();
            p.extend_from_slice(edge);
            if (child as usize) < data.len() {
                stack.push((child as usize, p));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_trie() {
        // root: no terminal, 1 child "_f" -> node at 6; node: terminal (flags 0, addr 0x10), 0 children.
        let data = [0x00, 0x01, b'_', b'f', 0x00, 0x06, 0x02, 0x00, 0x10, 0x00];
        let e = walk_export_trie(&data, &["self"]);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "_f");
        assert_eq!(e[0].address, Some(0x10));
        // A self-referencing child must not loop forever.
        let cyclic = [0x00, 0x01, b'a', 0x00, 0x00];
        assert!(walk_export_trie(&cyclic, &[]).is_empty());
    }
}
