//! Executable format loaders. Each loader turns raw bytes into a [`Loaded`]
//! image: a normalized, format-agnostic description of the binary.

mod elf;
mod macho;
mod macho_bind;
mod pe;

use crate::model::*;
use crate::Error;

/// A contiguous region of the virtual address space backed (partially) by file bytes.
#[derive(Debug, Clone)]
pub struct MapRange {
    #[allow(dead_code)] // kept for diagnostics / future segment views
    pub name: String,
    pub vaddr: u64,
    pub vsize: u64,
    pub offset: u64,
    pub file_size: u64,
    pub perms: Perms,
}

impl MapRange {
    pub fn contains(&self, va: u64) -> bool {
        va >= self.vaddr && va < self.vaddr.saturating_add(self.vsize.max(self.file_size))
    }
}

/// A function start known before any code is decoded.
#[derive(Debug, Clone, Copy)]
pub struct Seed {
    pub address: u64,
    pub source: FunctionSource,
    /// Known end address (exclusive), e.g. from `.pdata` or a sized symbol.
    pub end: Option<u64>,
}

#[derive(Debug, Default)]
pub struct Loaded {
    pub kind: String,
    pub arch: Option<Arch>,
    pub bits: u8,
    pub big_endian: bool,
    pub entry: u64,
    pub image_base: u64,
    pub sections: Vec<Section>,
    /// Address-space mapping used for VA <-> file offset translation.
    pub ranges: Vec<MapRange>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub symbols: Vec<Symbol>,
    pub libraries: Vec<String>,
    pub mitigations: Vec<Mitigation>,
    pub headers: Vec<KeyValue>,
    pub seeds: Vec<Seed>,
    pub warnings: Vec<String>,
    pub imphash: Option<String>,
    /// Byte range of the selected slice inside the original file (fat Mach-O).
    pub slice: Option<(usize, usize)>,
}

impl Loaded {
    pub(crate) fn header(&mut self, key: &str, value: impl Into<String>) {
        self.headers.push(KeyValue { key: key.into(), value: value.into() });
    }

    pub(crate) fn mitigation(&mut self, name: &str, enabled: bool, detail: impl Into<String>) {
        self.mitigations.push(Mitigation { name: name.into(), enabled, detail: detail.into() });
    }
}

pub fn detect(bytes: &[u8]) -> Option<Format> {
    if bytes.len() < 4 {
        return None;
    }
    match &bytes[..4] {
        [0x7f, b'E', b'L', b'F'] => Some(Format::Elf),
        [b'M', b'Z', ..] => Some(Format::Pe),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => {
            Some(Format::MachO)
        }
        _ => None,
    }
}

pub fn load(bytes: &[u8]) -> Result<(Format, Loaded), Error> {
    let format = detect(bytes).ok_or(Error::UnknownFormat)?;
    // Java class files share the 0xCAFEBABE magic with fat Mach-O; goblin rejects them for us.
    let loaded = match format {
        Format::Pe => pe::load(bytes),
        Format::Elf => elf::load(bytes),
        Format::MachO => macho::load(bytes),
    }
    .map_err(|e| Error::Malformed(format.label(), e.to_string()))?;
    Ok((format, loaded))
}

/// 32-bit ARM marks Thumb code with the low address bit. Windows on ARM and
/// modern Linux (armhf) binaries are Thumb-2 throughout, so a Thumb entry point
/// switches the whole image to Thumb; code addresses lose their mode bit.
pub(crate) fn fix_arm_thumb(l: &mut Loaded, format: Format) {
    let thumb = l.entry & 1 == 1 || format == Format::Pe;
    if thumb {
        l.arch = Some(Arch::Thumb);
    }
    l.entry &= !1;
    for s in &mut l.seeds {
        s.address &= !1;
        s.end = s.end.map(|e| e & !1);
    }
    for s in l.symbols.iter_mut().filter(|s| s.kind == SymbolKind::Function) {
        s.address &= !1;
    }
    let code = |va: u64, l: &Loaded| l.ranges.iter().any(|r| r.perms.x && va >= r.vaddr && va < r.vaddr + r.vsize);
    let fixed: Vec<u64> =
        l.exports.iter().map(|e| if e.address & 1 == 1 && code(e.address, l) { e.address & !1 } else { e.address }).collect();
    for (e, a) in l.exports.iter_mut().zip(fixed) {
        e.address = a;
    }
}
