//! Firmware and raw images: files with no executable header.
//!
//! A microcontroller image is just bytes (`.bin`), or bytes with addresses in a text container
//! (Intel HEX, Motorola S-record). Nothing in the file says which CPU it is for or where it is
//! loaded, so the caller says ([`RawOptions`]); this module can also *guess* both, from the one
//! structure that is nearly always there on Cortex-M: the vector table ([`guess`]).
//!
//! What it gives the analysis: one mapped range per segment, the entry point, and for Cortex-M the
//! reset and exception/interrupt handlers as named functions (`Reset_Handler`, `HardFault_Handler`,
//! …), found from the vector table instead of from calls.
//!
//! The guesses are heuristics and are reported as such; a wrong base address shows up at once as
//! pointers that lead nowhere, and the caller can override it.

use std::collections::BTreeMap;

use crate::loader::{Loaded, MapRange, Seed};
use crate::model::*;

/// What the caller knows about a raw image.
#[derive(Debug, Clone)]
pub struct RawOptions {
    pub arch: Arch,
    pub bits: u8,
    pub big_endian: bool,
    /// Address of the first byte of a plain `.bin`. Ignored for HEX and S-record files, which carry addresses.
    pub base: u64,
    /// Entry point; the vector table's reset handler or the container's start address when absent.
    pub entry: Option<u64>,
}

impl RawOptions {
    /// Options for a CPU name (`arm64`, `thumb`, `riscv32`, …) with its usual word size and byte order.
    pub fn for_arch(name: &str, base: u64) -> Result<RawOptions, String> {
        let (arch, bits) = parse_arch(name).ok_or_else(|| format!("unknown architecture `{name}` (try: {})", ARCH_NAMES.join(", ")))?;
        Ok(RawOptions { arch, bits, big_endian: arch == Arch::PowerPc, base, entry: None })
    }
}

/// The names `parse_arch` accepts, for messages.
pub const ARCH_NAMES: &[&str] = &["x86", "x86-64", "arm", "thumb", "arm64", "mips", "mips64", "ppc", "ppc64", "riscv32", "riscv64"];

/// A CPU name to (architecture, bits). `thumb` is Cortex-M and other Thumb-2-only cores.
pub fn parse_arch(name: &str) -> Option<(Arch, u8)> {
    Some(match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "x86" | "i386" | "x86-32" => (Arch::X86, 32),
        "x86-64" | "x64" | "amd64" => (Arch::X86_64, 64),
        "arm" | "arm32" => (Arch::Arm, 32),
        "thumb" | "thumb2" | "cortex-m" | "cortexm" => (Arch::Thumb, 32),
        "arm64" | "aarch64" => (Arch::Arm64, 64),
        "mips" | "mips32" => (Arch::Mips, 32),
        "mips64" => (Arch::Mips, 64),
        "ppc" | "ppc32" | "powerpc" => (Arch::PowerPc, 32),
        "ppc64" => (Arch::PowerPc, 64),
        "riscv" | "riscv32" | "rv32" => (Arch::RiscV, 32),
        "riscv64" | "rv64" => (Arch::RiscV, 64),
        _ => return None,
    })
}

/// Bytes at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub addr: u64,
    pub data: Vec<u8>,
}

/// A decoded text container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub kind: &'static str,
    pub segments: Vec<Segment>,
    pub entry: Option<u64>,
}

/// Largest image accepted (a corrupt file must not make us allocate without bound).
pub const MAX_IMAGE: usize = 256 << 20;

/// Whether `bytes` start like a PE, ELF or Mach-O file. Anything else is a candidate for a raw image.
pub fn has_header(bytes: &[u8]) -> bool {
    crate::loader::detect(bytes).is_some()
}

/// Which text container `bytes` is, if any.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    let head = &bytes[..bytes.len().min(256)];
    let text = std::str::from_utf8(head).ok().or_else(|| std::str::from_utf8(&head[..head.len().saturating_sub(3)]).ok())?;
    let line = text.trim_start_matches('\u{feff}').trim_start().lines().next()?.trim_end();
    let hex = |s: &str| s.len() >= 10 && s.len() & 1 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if let Some(rest) = line.strip_prefix(':') {
        return hex(rest).then_some("Intel HEX");
    }
    let mut c = line.chars();
    if c.next() == Some('S') && c.next().is_some_and(|d| d.is_ascii_digit()) {
        let rest = &line[2..];
        return (rest.len() >= 6 && rest.len() % 2 == 0 && rest.bytes().all(|b| b.is_ascii_hexdigit())).then_some("S-record");
    }
    None
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() & 1 == 1 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Sorts the pieces by address and joins the ones that touch or overlap (later pieces win).
fn coalesce(pieces: Vec<(u64, Vec<u8>)>) -> Result<Vec<Segment>, String> {
    let total: usize = pieces.iter().map(|p| p.1.len()).sum();
    if total > MAX_IMAGE {
        return Err(format!("the image is larger than {} MiB", MAX_IMAGE >> 20));
    }
    let mut order: Vec<usize> = (0..pieces.len()).collect();
    order.sort_by_key(|&i| pieces[i].0);
    let mut out: Vec<Segment> = Vec::new();
    // Pieces are applied in address order, and in file order at the same address, so a later
    // record overwrites an earlier one where they overlap.
    for &i in &order {
        let (addr, data) = &pieces[i];
        match out.last_mut() {
            Some(s) if *addr <= s.addr + s.data.len() as u64 => {
                let at = (*addr - s.addr) as usize;
                let end = at + data.len();
                if end > s.data.len() {
                    s.data.resize(end, 0);
                }
                s.data[at..end].copy_from_slice(data);
            }
            _ => out.push(Segment { addr: *addr, data: data.clone() }),
        }
    }
    Ok(out)
}

/// Intel HEX: `:LLAAAATT<data>CC` records with a two's-complement checksum.
pub fn decode_hex(bytes: &[u8]) -> Result<Decoded, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut upper = 0u64;
    let mut entry = None;
    let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut seen_end = false;
    for (n, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let at = n + 1;
        if seen_end {
            return Err(format!("line {at}: data after the end-of-file record"));
        }
        let body = line.strip_prefix(':').ok_or_else(|| format!("line {at}: a record starts with ':'"))?;
        let b = hex_bytes(body).ok_or_else(|| format!("line {at}: not hexadecimal"))?;
        if b.len() < 5 || b.len() != 5 + b[0] as usize {
            return Err(format!("line {at}: the length field does not match the record"));
        }
        if b.iter().fold(0u8, |a, x| a.wrapping_add(*x)) != 0 {
            return Err(format!("line {at}: checksum mismatch"));
        }
        let (len, off, ty, data) = (b[0] as usize, u16::from_be_bytes([b[1], b[2]]) as u64, b[3], &b[4..4 + b[0] as usize]);
        match ty {
            0x00 => {
                if len > 0 {
                    pieces.push((upper + off, data.to_vec()));
                }
            }
            0x01 => seen_end = true,
            0x02 if len == 2 => upper = (u16::from_be_bytes([data[0], data[1]]) as u64) << 4,
            0x04 if len == 2 => upper = (u16::from_be_bytes([data[0], data[1]]) as u64) << 16,
            0x03 if len == 4 => {
                entry = Some(((u16::from_be_bytes([data[0], data[1]]) as u64) << 4) + u16::from_be_bytes([data[2], data[3]]) as u64)
            }
            0x05 if len == 4 => entry = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64),
            other => return Err(format!("line {at}: unsupported record type {other:#04x} or bad length")),
        }
    }
    if pieces.is_empty() {
        return Err("no data records".into());
    }
    Ok(Decoded { kind: "Intel HEX", segments: coalesce(pieces)?, entry })
}

/// Motorola S-record: `S<t><count><address><data><checksum>`, checksum = ones' complement of the byte sum.
pub fn decode_srec(bytes: &[u8]) -> Result<Decoded, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut entry = None;
    let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
    for (n, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let at = n + 1;
        let rest = line.strip_prefix('S').ok_or_else(|| format!("line {at}: a record starts with 'S'"))?;
        let ty = rest.chars().next().filter(char::is_ascii_digit).ok_or_else(|| format!("line {at}: no record type"))?;
        let b = hex_bytes(&rest[1..]).ok_or_else(|| format!("line {at}: not hexadecimal"))?;
        if b.is_empty() || b.len() != 1 + b[0] as usize || b[0] < 3 {
            return Err(format!("line {at}: the count field does not match the record"));
        }
        let sum = b[..b.len() - 1].iter().fold(0u8, |a, x| a.wrapping_add(*x));
        if !sum != b[b.len() - 1] {
            return Err(format!("line {at}: checksum mismatch"));
        }
        let alen = match ty {
            '0' | '1' | '5' | '9' => 2,
            '2' | '6' | '8' => 3,
            '3' | '7' => 4,
            other => return Err(format!("line {at}: unsupported record type S{other}")),
        };
        let body = &b[1..b.len() - 1];
        if body.len() < alen {
            return Err(format!("line {at}: the record is too short for its address"));
        }
        let addr = body[..alen].iter().fold(0u64, |a, x| a << 8 | *x as u64);
        match ty {
            '1' | '2' | '3' => pieces.push((addr, body[alen..].to_vec())),
            '7' | '8' | '9' => entry = Some(addr),
            _ => {}
        }
    }
    if pieces.is_empty() {
        return Err("no data records".into());
    }
    Ok(Decoded { kind: "S-record", segments: coalesce(pieces)?, entry })
}

/// Decodes a text container if `bytes` is one.
pub fn decode(bytes: &[u8]) -> Option<Result<Decoded, String>> {
    match sniff(bytes)? {
        "Intel HEX" => Some(decode_hex(bytes)),
        _ => Some(decode_srec(bytes)),
    }
}

// ------------------------------------------------------------------------------------------------
// Cortex-M
// ------------------------------------------------------------------------------------------------

/// The exception handlers every Cortex-M vector table starts with (after the initial stack pointer).
const CORE_VECTORS: [(usize, &str); 14] = [
    (1, "Reset_Handler"),
    (2, "NMI_Handler"),
    (3, "HardFault_Handler"),
    (4, "MemManage_Handler"),
    (5, "BusFault_Handler"),
    (6, "UsageFault_Handler"),
    (11, "SVC_Handler"),
    (12, "DebugMon_Handler"),
    (14, "PendSV_Handler"),
    (15, "SysTick_Handler"),
    (7, "Reserved7"),
    (8, "Reserved8"),
    (9, "Reserved9"),
    (10, "Reserved10"),
];

/// A Cortex-M vector table: the initial stack pointer and the handler words after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorTable {
    pub address: u64,
    pub sp: u32,
    /// Word `i` of the table (`i >= 1`), as written (Thumb bit included); 0 = unused.
    pub words: Vec<u32>,
}

impl VectorTable {
    /// The handlers with their names; vectors that share one address are all the default handler.
    pub fn handlers(&self) -> Vec<(u64, String)> {
        let mut uses: BTreeMap<u64, usize> = BTreeMap::new();
        for w in self.words.iter().skip(1).filter(|w| **w & 1 == 1) {
            *uses.entry((*w & !1) as u64).or_default() += 1;
        }
        let mut names: BTreeMap<u64, String> = BTreeMap::new();
        for (i, w) in self.words.iter().enumerate().skip(1) {
            if *w & 1 == 0 {
                continue;
            }
            let addr = (*w & !1) as u64;
            if names.contains_key(&addr) {
                continue;
            }
            let name = if i == 1 {
                "Reset_Handler".to_string()
            } else if uses[&addr] >= 3 {
                "Default_Handler".to_string()
            } else if let Some((_, n)) = CORE_VECTORS.iter().find(|(k, n)| *k == i && !n.starts_with("Reserved")) {
                n.to_string()
            } else if i >= 16 {
                format!("IRQ{}_Handler", i - 16)
            } else {
                format!("Vector{i}_Handler")
            };
            names.insert(addr, name);
        }
        names.into_iter().collect()
    }
}

fn word(data: &[u8], i: usize, big: bool) -> Option<u32> {
    let b: [u8; 4] = data.get(i * 4..i * 4 + 4)?.try_into().ok()?;
    Some(if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
}

/// Initial stack pointers point into RAM: SRAM at 0x2000_0000 on nearly every part, 0x1000_0000
/// for tightly-coupled memory, and a few parts use the low or the 0x3000_0000 region.
fn plausible_sp(sp: u32) -> bool {
    sp & 3 == 0 && ((0x1000_0000..0x4000_0000).contains(&sp) || ((0x0000_1000..0x0100_0000).contains(&sp) && sp & 0xf == 0))
}

/// Reads a Cortex-M vector table at the start of `data`, assuming the image is loaded at `base`.
/// Needs a RAM-looking stack pointer and valid Thumb handlers (odd, inside the image) for
/// reset, NMI and HardFault; stops at the first word that is neither 0 nor such a handler.
pub fn cortex_m_table(data: &[u8], base: u64) -> Option<VectorTable> {
    let len = data.len() as u64;
    let sp = word(data, 0, false)?;
    if !plausible_sp(sp) {
        return None;
    }
    let inside = |w: u32| w & 1 == 1 && (w as u64 & !1) >= base && (w as u64 & !1) < base + len;
    let mut words = vec![sp];
    for i in 1..data.len() / 4 {
        let w = word(data, i, false)?;
        if w == 0 || inside(w) {
            words.push(w);
        } else {
            break;
        }
        if i >= 16 + 240 {
            break;
        }
    }
    while words.len() > 4 && *words.last()? == 0 {
        words.pop();
    }
    // Reset, NMI and HardFault must be real handlers; a table with fewer than a few entries is noise.
    (words.len() >= 4 && (1..=3).all(|i| inside(words[i]))).then_some(VectorTable { address: base, sp, words })
}

// ------------------------------------------------------------------------------------------------
// Guessing the base address
// ------------------------------------------------------------------------------------------------

/// What `guess` found.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Guess {
    pub arch: Option<Arch>,
    /// The `--arch` name that selects `arch` (`thumb`, `arm64`, `x86-64`, `ppc64`, …).
    pub arch_name: Option<String>,
    pub bits: Option<u8>,
    pub big_endian: bool,
    pub base: Option<u64>,
    /// The image starts with a Cortex-M vector table.
    pub cortex_m: bool,
    /// Why, in words, for the user to judge.
    pub notes: Vec<String>,
}

/// Offsets where a run of at least five printable characters ending in NUL starts.
fn string_starts(data: &[u8]) -> Vec<bool> {
    let mut starts = vec![false; data.len()];
    let mut i = 0;
    while i < data.len() {
        let text = |b: u8| (0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\t' | b'\r');
        let mut j = i;
        while j < data.len() && text(data[j]) {
            j += 1;
        }
        if j - i >= 5 && j < data.len() && data[j] == 0 && (i == 0 || !text(data[i - 1])) {
            starts[i] = true;
        }
        i = j.max(i) + 1;
    }
    starts
}

/// Pointers into the image that land on the start of a string, for a given base.
fn string_pointers(data: &[u8], starts: &[bool], base: u64, big: bool) -> usize {
    let len = data.len() as u64;
    (0..data.len() / 4)
        .filter_map(|i| word(data, i, big))
        .filter(|w| (*w as u64) >= base && (*w as u64) < base + len && starts[(*w as u64 - base) as usize])
        .count()
}

/// Whether `data` begins with a Cortex-M vector table, whatever the base: stack in RAM, odd handler
/// addresses that all lie near each other. Returns the handler addresses (Thumb bit cleared).
fn cortex_m_handlers_anywhere(data: &[u8]) -> Option<Vec<u32>> {
    let sp = word(data, 0, false)?;
    let reset = word(data, 1, false)?;
    if !plausible_sp(sp) || reset & 1 == 0 {
        return None;
    }
    let near = |w: u32| w & 1 == 1 && (w as i64 - reset as i64).unsigned_abs() < 0x0400_0000;
    let mut hs = vec![reset & !1];
    for i in 2..(data.len() / 4).min(16 + 240) {
        let w = word(data, i, false)?;
        if w == 0 {
            continue;
        }
        if !near(w) {
            break;
        }
        hs.push(w & !1);
    }
    (hs.len() >= 3 && (2..=3).all(|i| word(data, i, false).is_some_and(near))).then_some(hs)
}

/// Guesses what a raw image is. Cortex-M images are recognised by their vector table and given a
/// base address that makes every handler fall inside the image; other images get a base only when
/// pointers to strings pick one out clearly (at least 8, and at least twice as many as the runner-up).
pub fn guess(data: &[u8]) -> Guess {
    let mut g = Guess::default();
    let starts = string_starts(data);
    let len = data.len() as u64;
    if let Some(hs) = cortex_m_handlers_anywhere(data) {
        g.arch = Some(Arch::Thumb);
        g.arch_name = Some("thumb".into());
        g.bits = Some(32);
        g.cortex_m = true;
        let (m, mx) = (*hs.iter().min().unwrap() as u64, *hs.iter().max().unwrap() as u64);
        let table_bytes = 4 * (hs.len() as u64 + 2);
        let mut best: Option<(usize, u64, u64)> = None;
        for align in [0x10_0000u64, 0x1_0000, 0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100] {
            let b = m & !(align - 1);
            if b + len <= mx || m < b + table_bytes {
                continue;
            }
            let score = string_pointers(data, &starts, b, false);
            // Highest string-pointer count wins; among equals, the roundest base (largest alignment, found first).
            if best.is_none_or(|(s, _, _)| score > s) {
                best = Some((score, b, align));
            }
        }
        match best {
            Some((score, b, align)) => {
                g.base = Some(b);
                g.notes.push(format!(
                    "Cortex-M vector table: {} handlers between {:#x} and {:#x}; base {:#x} is the roundest ({:#x}-aligned) address that keeps all of them inside the image{}",
                    hs.len(),
                    m,
                    mx,
                    b,
                    align,
                    if score > 0 { format!(", with {score} pointers to strings") } else { String::new() }
                ));
            }
            None => g.notes.push("Cortex-M vector table found, but no base address keeps all its handlers inside the image".into()),
        }
        return g;
    }
    // Not Cortex-M: which CPU, from the function-boundary patterns of its machine code.
    let mut big = false;
    if let Some(a) = crate::archguess::guess_arch(data) {
        g.arch = Some(a.arch);
        g.arch_name = Some(a.name.to_string());
        g.bits = Some(a.bits);
        g.big_endian = a.big_endian;
        big = a.big_endian;
        g.notes.push(format!(
            "machine-code patterns say {} ({} function-boundary marks{}; the runner-up has {})",
            a.arch.label(),
            a.hits,
            if a.big_endian { ", big-endian" } else { "" },
            a.runner_up
        ));
    }
    // Generic: candidate bases near the most common high halves of the 32-bit words.
    let mut highs: BTreeMap<u32, usize> = BTreeMap::new();
    for i in 0..data.len() / 4 {
        if let Some(w) = word(data, i, big) {
            if w >= 0x1000 && w != 0xffff_ffff {
                *highs.entry(w >> 16).or_default() += 1;
            }
        }
    }
    let mut top: Vec<(u32, usize)> = highs.into_iter().collect();
    top.sort_by_key(|t| std::cmp::Reverse(t.1));
    let mut scored: Vec<(usize, u64)> = Vec::new();
    for (h, _) in top.iter().take(3) {
        for k in 0..=16u64 {
            let b = ((*h as u64) << 16).saturating_sub(k * 0x1000);
            scored.push((string_pointers(data, &starts, b, big), b));
        }
    }
    scored.sort_by_key(|s| (std::cmp::Reverse(s.0), s.1));
    if let Some(&(s, b)) = scored.first() {
        let runner = scored.iter().find(|x| x.1 != b).map_or(0, |x| x.0);
        if s >= 8 && s >= 2 * runner {
            g.base = Some(b);
            g.notes.push(format!("{s} pointers to strings agree on base {b:#x} (the next best base has {runner})"));
        }
    }
    g
}

// ------------------------------------------------------------------------------------------------
// Building the loaded image
// ------------------------------------------------------------------------------------------------

/// What `Binary` needs: the flat bytes and the loader's description of them.
pub(crate) struct Built {
    pub data: Vec<u8>,
    pub loaded: Loaded,
}

/// A plain `.bin`, or the segments of a decoded container, as a mapped image.
pub(crate) fn build(kind: &str, segments: Vec<Segment>, container_entry: Option<u64>, opts: &RawOptions) -> Result<Built, String> {
    if segments.is_empty() || segments.iter().all(|s| s.data.is_empty()) {
        return Err("the image is empty".into());
    }
    let mut data = Vec::new();
    let mut l =
        Loaded { kind: kind.to_string(), arch: Some(opts.arch), bits: opts.bits, big_endian: opts.big_endian, ..Default::default() };
    for (i, s) in segments.iter().enumerate() {
        let offset = data.len() as u64;
        data.extend_from_slice(&s.data);
        let name = if segments.len() == 1 { ".image".to_string() } else { format!(".seg{i}") };
        let perms = Perms { r: true, w: false, x: true };
        l.sections.push(Section {
            name: name.clone(),
            segment: None,
            vaddr: s.addr,
            vsize: s.data.len() as u64,
            offset,
            raw_size: s.data.len() as u64,
            perms,
            entropy: 0.0,
            flags: 0,
        });
        l.ranges.push(MapRange { name, vaddr: s.addr, vsize: s.data.len() as u64, offset, file_size: s.data.len() as u64, perms });
    }
    l.image_base = segments.iter().map(|s| s.addr).min().unwrap_or(0);
    l.header("Image", format!("{} byte(s) in {} segment(s) from {:#x}", data.len(), segments.len(), l.image_base));
    l.header(
        "Architecture given",
        format!("{} ({} bit, {}-endian)", opts.arch.label(), opts.bits, if opts.big_endian { "big" } else { "little" }),
    );

    // Cortex-M: the vector table gives the entry point and the handlers.
    let mut entry = opts.entry.or(container_entry);
    if opts.arch == Arch::Thumb && !opts.big_endian {
        if let Some(first) = segments.first() {
            if let Some(t) = cortex_m_table(&first.data, first.addr) {
                l.header("Vector table", format!("{} vectors at {:#x}, initial SP {:#x}", t.words.len(), t.address, t.sp));
                l.symbols.push(Symbol {
                    name: "__vectors".into(),
                    address: t.address,
                    size: 4 * t.words.len() as u64,
                    kind: SymbolKind::Object,
                    global: true,
                });
                for (addr, name) in t.handlers() {
                    l.symbols.push(Symbol { name: name.clone(), address: addr, size: 0, kind: SymbolKind::Function, global: true });
                    l.seeds.push(Seed { address: addr, source: FunctionSource::Symbol, end: None });
                }
                if entry.is_none() {
                    entry = Some(t.words[1] as u64);
                }
                l.kind = format!("{kind} (Cortex-M firmware)");
            }
        }
    }
    let entry = entry.unwrap_or(l.image_base);
    // Thumb addresses carry the mode in bit 0; the image's own addresses do not.
    l.entry = if opts.arch == Arch::Thumb { entry & !1 } else { entry };
    if opts.arch == Arch::Arm {
        l.entry = entry; // `fix_arm_thumb` reads the mode from bit 0
    }
    if !l.ranges.iter().any(|r| l.entry >= r.vaddr && l.entry < r.vaddr + r.vsize) {
        l.warnings.push(format!(
            "The entry point {:#x} is outside the image; analysis starts from the vector table or by scanning, if there is one.",
            l.entry
        ));
    }
    l.warnings.push(
        "Raw image: the architecture and base address come from you, not from the file. A wrong base shows as pointers that lead nowhere."
            .into(),
    );
    Ok(Built { data, loaded: l })
}

/// Segments of a plain binary at `base`.
pub(crate) fn plain(bytes: &[u8], base: u64) -> Result<Vec<Segment>, String> {
    if bytes.len() > MAX_IMAGE {
        return Err(format!("the image is larger than {} MiB", MAX_IMAGE >> 20));
    }
    Ok(vec![Segment { addr: base, data: bytes.to_vec() }])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `:LLAAAATT<data>CC` with the right checksum.
    fn hex_line(addr: u16, ty: u8, data: &[u8]) -> String {
        let mut b = vec![data.len() as u8, (addr >> 8) as u8, addr as u8, ty];
        b.extend_from_slice(data);
        let sum = b.iter().fold(0u8, |a, x| a.wrapping_add(*x));
        b.push(0u8.wrapping_sub(sum));
        format!(":{}", b.iter().map(|x| format!("{x:02X}")).collect::<String>())
    }

    fn srec_line(ty: char, alen: usize, addr: u64, data: &[u8]) -> String {
        let mut b = vec![(alen + data.len() + 1) as u8];
        for i in (0..alen).rev() {
            b.push((addr >> (8 * i)) as u8);
        }
        b.extend_from_slice(data);
        let sum = b.iter().fold(0u8, |a, x| a.wrapping_add(*x));
        b.push(!sum);
        format!("S{ty}{}", b.iter().map(|x| format!("{x:02X}")).collect::<String>())
    }

    /// A tiny Cortex-M image at `base`: vector table (reset, NMI, HardFault, SysTick, two IRQs that share
    /// a handler) then code, with a few strings and pointers to them.
    fn cortex_image(base: u32, size: usize) -> Vec<u8> {
        let mut img = vec![0u8; size];
        let put = |img: &mut Vec<u8>, i: usize, w: u32| img[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        let reset = base + 0x100;
        put(&mut img, 0, 0x2000_8000);
        put(&mut img, 1, reset | 1);
        put(&mut img, 2, (base + 0x120) | 1);
        put(&mut img, 3, (base + 0x130) | 1);
        put(&mut img, 15, (base + 0x140) | 1);
        for i in 16..20 {
            put(&mut img, i, (base + 0x150) | 1);
        }
        // reset: push {r7, lr}; bl .+0; pop {r7, pc}
        img[0x100..0x108].copy_from_slice(&[0x80, 0xb5, 0x00, 0xf0, 0x00, 0xf8, 0x80, 0xbd]);
        for off in [0x120, 0x130, 0x140, 0x150] {
            img[off..off + 2].copy_from_slice(&[0x70, 0x47]); // bx lr
        }
        // strings and a pointer table to them
        let strings = ["hello world", "firmware v1.2", "error: bad crc", "uart0 ready", "boot ok!!"];
        let mut at = 0x200;
        let mut ptr = 0x300;
        for s in strings {
            img[at..at + s.len()].copy_from_slice(s.as_bytes());
            put(&mut img, ptr / 4, base + at as u32);
            ptr += 4;
            at += s.len() + 1;
        }
        img
    }

    #[test]
    fn intel_hex_with_extended_addresses_and_a_start_address() {
        let text = [
            hex_line(0, 0x04, &[0x08, 0x00]),
            hex_line(0x0010, 0x00, &[1, 2, 3, 4]),
            hex_line(0x0014, 0x00, &[5, 6]),
            hex_line(0x0100, 0x00, &[9]),
            hex_line(0, 0x05, &0x0800_0011u32.to_be_bytes()),
            hex_line(0, 0x01, &[]),
        ]
        .join("\r\n");
        assert_eq!(sniff(text.as_bytes()), Some("Intel HEX"));
        let d = decode_hex(text.as_bytes()).unwrap();
        assert_eq!(d.entry, Some(0x0800_0011));
        assert_eq!(
            d.segments,
            vec![Segment { addr: 0x0800_0010, data: vec![1, 2, 3, 4, 5, 6] }, Segment { addr: 0x0800_0100, data: vec![9] }]
        );
        // The text, damaged: a changed data byte fails the checksum, and the error names the line.
        let bad = text.replacen("01020304", "01020305", 1);
        assert!(decode_hex(bad.as_bytes()).unwrap_err().contains("line 2: checksum"));
        assert!(decode_hex(b"hello").unwrap_err().contains("line 1"));
        assert!(decode_hex(format!("{}\n{}", hex_line(0, 0x01, &[]), hex_line(0, 0, &[1])).as_bytes()).is_err());
    }

    #[test]
    fn segment_addresses_with_overlap_are_resolved_later_wins() {
        let text = [hex_line(0x10, 0, &[1, 2, 3, 4]), hex_line(0x12, 0, &[9, 9, 9]), hex_line(0, 1, &[])].join("\n");
        let d = decode_hex(text.as_bytes()).unwrap();
        assert_eq!(d.segments, vec![Segment { addr: 0x10, data: vec![1, 2, 9, 9, 9] }]);
    }

    #[test]
    fn s_records_of_all_address_sizes() {
        for (ty, alen, end) in [('1', 2, '9'), ('2', 3, '8'), ('3', 4, '7')] {
            let text =
                [srec_line('0', 2, 0, b"hdr"), srec_line(ty, alen, 0x1000, &[0xde, 0xad, 0xbe, 0xef]), srec_line(end, alen, 0x1001, &[])]
                    .join("\n");
            assert_eq!(sniff(text.as_bytes()), Some("S-record"));
            let d = decode_srec(text.as_bytes()).unwrap();
            assert_eq!(d.segments, vec![Segment { addr: 0x1000, data: vec![0xde, 0xad, 0xbe, 0xef] }]);
            assert_eq!(d.entry, Some(0x1001));
        }
        let bad = srec_line('1', 2, 0x1000, &[1, 2]).replace("0102", "0103");
        assert!(decode_srec(bad.as_bytes()).unwrap_err().contains("checksum"));
        assert!(decode_srec(b"S5030001FB\n").is_err()); // no data
    }

    #[test]
    fn sniffing_leaves_normal_files_and_prose_alone() {
        assert_eq!(sniff(b"MZ\x90\x00"), None);
        assert_eq!(sniff(b"\x7fELF\x02\x01"), None);
        assert_eq!(sniff(b"Sorry, this is not it"), None);
        assert_eq!(sniff(b":not hex at all"), None);
        assert_eq!(sniff(&[0u8; 64]), None);
    }

    #[test]
    fn cortex_m_vector_table_names_the_handlers() {
        let base = 0x0800_2000;
        let img = cortex_image(base, 0x400);
        let t = cortex_m_table(&img, base as u64).unwrap();
        assert_eq!(t.sp, 0x2000_8000);
        let h: BTreeMap<u64, String> = t.handlers().into_iter().collect();
        assert_eq!(h[&(base as u64 + 0x100)], "Reset_Handler");
        assert_eq!(h[&(base as u64 + 0x120)], "NMI_Handler");
        assert_eq!(h[&(base as u64 + 0x130)], "HardFault_Handler");
        assert_eq!(h[&(base as u64 + 0x140)], "SysTick_Handler");
        assert_eq!(h[&(base as u64 + 0x150)], "Default_Handler", "four vectors share one handler");
        // At the wrong base the handlers fall outside the image: not a table.
        assert!(cortex_m_table(&img, 0x2000_0000).is_none());
        // Random bytes are not a table.
        assert!(cortex_m_table(&[0x5a; 256], 0).is_none());
    }

    #[test]
    fn the_base_is_guessed_from_the_vector_table() {
        for base in [0x0800_0000u32, 0x0800_2000, 0x0000_0000, 0x1000_0000] {
            let img = cortex_image(base, 0x400);
            let g = guess(&img);
            assert!(g.cortex_m, "{base:#x}");
            assert_eq!(g.arch, Some(Arch::Thumb));
            assert_eq!(g.base, Some(base as u64), "{base:#x}: {:?}", g.notes);
        }
        assert_eq!(guess(&[0u8; 512]), Guess::default());
    }

    #[test]
    fn a_base_is_guessed_from_string_pointers_in_other_images() {
        // A pointer table to ten strings, no vector table: base 0x0010_0000 (an AArch64-sized word is not needed).
        let base = 0x0010_0000u32;
        let mut img = vec![0xa5u8; 0x800];
        let mut at = 0x400;
        for i in 0..10 {
            let s = format!("message number {i}");
            img[at..at + s.len()].copy_from_slice(s.as_bytes());
            img[at + s.len()] = 0;
            img[i * 4..i * 4 + 4].copy_from_slice(&(base + at as u32).to_le_bytes());
            at += s.len() + 1;
        }
        let g = guess(&img);
        assert!(!g.cortex_m);
        assert_eq!(g.base, Some(base as u64), "{:?}", g.notes);
    }

    #[test]
    fn building_an_image_maps_every_segment_and_finds_the_entry() {
        let base = 0x0800_0000u32;
        let img = cortex_image(base, 0x400);
        let opts = RawOptions::for_arch("thumb", base as u64).unwrap();
        let b = build("Raw image", plain(&img, base as u64).unwrap(), None, &opts).unwrap();
        assert_eq!(b.loaded.entry, base as u64 + 0x100);
        assert_eq!(b.loaded.kind, "Raw image (Cortex-M firmware)");
        assert!(b.loaded.symbols.iter().any(|s| s.name == "Reset_Handler" && s.address == base as u64 + 0x100));
        assert_eq!(b.loaded.seeds.len(), 5);
        // Two segments keep their own addresses and file offsets.
        let two = vec![Segment { addr: 0x1000, data: vec![1; 16] }, Segment { addr: 0x9000, data: vec![2; 8] }];
        let b = build("Intel HEX", two, Some(0x9000), &RawOptions::for_arch("arm64", 0).unwrap()).unwrap();
        assert_eq!(b.loaded.ranges.len(), 2);
        assert_eq!((b.loaded.ranges[1].vaddr, b.loaded.ranges[1].offset), (0x9000, 16));
        assert_eq!(b.loaded.entry, 0x9000);
        assert!(build("Raw image", vec![], None, &opts).is_err());
    }

    /// The image as Intel HEX: 16-byte records after an extended-linear-address record.
    fn as_intel_hex(img: &[u8], base: u32, start: Option<u32>) -> String {
        let mut lines = vec![hex_line(0, 0x04, &((base >> 16) as u16).to_be_bytes())];
        for (n, chunk) in img.chunks(16).enumerate() {
            lines.push(hex_line((base as u16).wrapping_add((n * 16) as u16), 0x00, chunk));
        }
        if let Some(s) = start {
            lines.push(hex_line(0, 0x05, &s.to_be_bytes()));
        }
        lines.push(hex_line(0, 0x01, &[]));
        lines.join(
            "
",
        )
    }

    #[test]
    fn a_cortex_m_image_is_analysed_from_its_vector_table() {
        let base = 0x0800_0000u32;
        let img = cortex_image(base, 0x400);
        let opts = RawOptions::for_arch("thumb", base as u64).unwrap();
        let mut b = crate::Binary::load_raw("fw.bin", img.clone(), &opts).unwrap();
        assert_eq!(b.info().format, Format::Raw);
        assert_eq!(b.info().arch, Arch::Thumb);
        assert_eq!(b.info().entry, base as u64 + 0x100);
        b.analyze();
        let names: BTreeMap<u64, String> = b.functions().into_iter().map(|f| (f.address, f.name)).collect();
        assert_eq!(names[&(base as u64 + 0x100)], "Reset_Handler");
        assert_eq!(names[&(base as u64 + 0x130)], "HardFault_Handler");
        assert_eq!(names[&(base as u64 + 0x150)], "Default_Handler");
        // The code is decoded as Thumb: push {r7, lr} at the reset handler.
        let first = b.disassemble(base as u64 + 0x100, 1).unwrap();
        assert!(first[0].mnemonic.to_lowercase().contains("push"), "{:?}", first[0]);

        // The same program as Intel HEX, with and without a start address, gives the same functions.
        for start in [None, Some(base + 0x100 + 1)] {
            let hex = as_intel_hex(&img, base, start);
            assert!(matches!(crate::Binary::load("fw.hex", hex.clone().into_bytes()), Err(crate::Error::NeedsRawOptions("Intel HEX"))));
            let mut h = crate::Binary::load_raw("fw.hex", hex.into_bytes(), &RawOptions { base: 0, ..opts.clone() }).unwrap();
            h.analyze();
            let hn: BTreeMap<u64, String> = h.functions().into_iter().map(|f| (f.address, f.name)).collect();
            assert_eq!(hn, names, "start {start:?}");
            assert_eq!(h.info().kind, "Intel HEX (Cortex-M firmware)");
        }
    }

    /// Functions nothing calls are found in a raw image by their frame set-up after the previous
    /// function's end, on CPUs with no unwind table to say where they are.
    #[test]
    fn a_raw_image_gets_its_uncalled_functions_from_prologues() {
        let starts = |arch: &str, code: Vec<u8>, base: u64| {
            let mut b = crate::Binary::load_raw("raw.bin", code, &RawOptions::for_arch(arch, base).unwrap()).unwrap();
            b.analyze();
            b.functions().into_iter().map(|f| f.address).collect::<Vec<u64>>()
        };
        // x86-64: push rbp; mov rbp, rsp; sub rsp, 32; xor eax, eax; add rsp, 32; pop rbp; ret; int3 padding.
        let f64 = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3];
        let mut code = Vec::new();
        for _ in 0..4 {
            code.extend_from_slice(&f64);
            code.extend_from_slice(&[0xcc; 16]);
        }
        let found = starts("x86-64", code, 0x1000);
        for want in [0x1000u64, 0x1020, 0x1040, 0x1060] {
            assert!(found.contains(&want), "x86-64: {want:#x} missing from {found:x?}");
        }
        // AArch64: stp x29, x30, [sp, #-16]!; mov x29, sp; ldp x29, x30, [sp], #16; ret; zero padding.
        let words = [0xa9bf_7bfdu32, 0x9100_03fd, 0xa8c1_7bfd, 0xd65f_03c0, 0, 0, 0, 0];
        let code: Vec<u8> = (0..4).flat_map(|_| words.iter().flat_map(|w| w.to_le_bytes())).collect();
        let found = starts("arm64", code, 0x10000);
        for want in [0x10000u64, 0x10020, 0x10040, 0x10060] {
            assert!(found.contains(&want), "arm64: {want:#x} missing from {found:x?}");
        }
        // Thumb: push {r7, lr}; mov r7, sp; pop {r7, pc}; padding.
        let thumb: Vec<u8> = (0..4)
            .flat_map(|_| [0xb580u16, 0x466f, 0xbd80, 0, 0, 0, 0, 0].iter().flat_map(|h| h.to_le_bytes()).collect::<Vec<u8>>())
            .collect();
        let found = starts("thumb", thumb, 0x8000);
        for want in [0x8000u64, 0x8010, 0x8020, 0x8030] {
            assert!(found.contains(&want), "thumb: {want:#x} missing from {found:x?}");
        }
    }

    #[test]
    fn architecture_names() {
        assert_eq!(parse_arch("AArch64"), Some((Arch::Arm64, 64)));
        assert_eq!(parse_arch("cortex_m"), Some((Arch::Thumb, 32)));
        assert_eq!(parse_arch("rv64"), Some((Arch::RiscV, 64)));
        assert_eq!(parse_arch("z80"), None);
        assert!(RawOptions::for_arch("z80", 0).unwrap_err().contains("riscv32"));
        assert!(RawOptions::for_arch("ppc", 0).unwrap().big_endian);
    }
}
