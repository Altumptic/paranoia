//! Go's function table (`pclntab`).
//!
//! Every Go binary carries a table of its functions with their start addresses
//! and names, because the runtime needs it for stack traces and the garbage
//! collector. Stripping (`-ldflags=-s -w`) removes the symbol table and DWARF
//! but not this, so it gives function boundaries and names for stripped Go
//! programs, which is most Go malware.
//!
//! Layouts by Go version (magic number first):
//!
//! - 1.2–1.15 (`0xfffffffb`): header, `nfunc`, then `nfunc` pairs of
//!   (entry address, offset of the function record), then the end address.
//! - 1.16–1.17 (`0xfffffffa`): a header of offsets; the function table pairs
//!   are still (entry address, record offset), both pointer-sized.
//! - 1.18+ (`0xfffffff0`, 1.20+ `0xfffffff1`): the header adds `textStart`;
//!   pairs are 32-bit (entry offset from `textStart`, record offset).
//!
//! In each record, a 32-bit name offset follows the entry: into the whole
//! table before 1.16, into the function-name table from 1.16 on.

/// Hard limit; real binaries have tens of thousands.
const MAX_FUNCS: usize = 2_000_000;
/// Longest name accepted (generic instantiations get long).
const MAX_NAME: usize = 4096;

/// One function from the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoFunc {
    pub entry: u64,
    pub end: u64,
    pub name: String,
}

struct Reader<'a> {
    d: &'a [u8],
    big: bool,
    ptr: usize,
}

impl Reader<'_> {
    fn u32(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.d.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }

    fn uptr(&self, at: usize) -> Option<u64> {
        if self.ptr == 4 {
            return self.u32(at).map(u64::from);
        }
        let b: [u8; 8] = self.d.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if self.big { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) })
    }

    fn usize_ptr(&self, at: usize) -> Option<usize> {
        usize::try_from(self.uptr(at)?).ok()
    }

    /// NUL-terminated name, printable ASCII or UTF-8 without control characters.
    fn name(&self, at: usize) -> Option<String> {
        let rest = self.d.get(at..)?;
        let len = rest.iter().take(MAX_NAME).position(|&b| b == 0)?;
        let s = std::str::from_utf8(&rest[..len]).ok()?;
        (!s.is_empty() && !s.chars().any(char::is_control)).then(|| s.to_string())
    }
}

/// Whether `d` starts with a plausible table header, and which version it is.
fn version(d: &[u8], big: bool) -> Option<(u32, usize)> {
    let magic: [u8; 4] = d.get(..4)?.try_into().ok()?;
    let magic = if big { u32::from_be_bytes(magic) } else { u32::from_le_bytes(magic) };
    if !matches!(magic, 0xffff_fffb | 0xffff_fffa | 0xffff_fff0 | 0xffff_fff1) {
        return None;
    }
    let (pad1, pad2, quantum, ptr) = (*d.get(4)?, *d.get(5)?, *d.get(6)?, *d.get(7)?);
    (pad1 == 0 && pad2 == 0 && matches!(quantum, 1 | 2 | 4) && matches!(ptr, 4 | 8)).then_some((magic, ptr as usize))
}

/// Parses a table starting at `d[0]`. `is_code` says whether an address is in executable memory;
/// the table is rejected unless every function starts in code and the starts are in order.
pub fn parse(d: &[u8], big: bool, is_code: &dyn Fn(u64) -> bool) -> Option<Vec<GoFunc>> {
    let (magic, ptr) = version(d, big)?;
    let r = Reader { d, big, ptr };
    let nfunc = r.usize_ptr(8)?;
    if nfunc == 0 || nfunc > MAX_FUNCS {
        return None;
    }
    // (entry, record offset from `base`) for nfunc + 1 entries; the last entry is the end.
    let mut entries: Vec<(u64, usize)> = Vec::with_capacity((nfunc + 1).min(d.len() / 8));
    let (base, names): (usize, usize);
    match magic {
        0xffff_fffb => {
            let tab = 8 + ptr;
            for i in 0..=nfunc {
                let at = tab + i * 2 * ptr;
                let entry = r.uptr(at)?;
                let off = if i < nfunc { r.usize_ptr(at + ptr)? } else { 0 };
                entries.push((entry, off));
            }
            base = 0;
            names = 0;
        }
        0xffff_fffa => {
            // nfunc, nfiles, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset.
            names = r.usize_ptr(8 + 2 * ptr)?;
            base = r.usize_ptr(8 + 6 * ptr)?;
            for i in 0..=nfunc {
                let at = base.checked_add(i * 2 * ptr)?;
                let entry = r.uptr(at)?;
                let off = if i < nfunc { r.usize_ptr(at + ptr)? } else { 0 };
                entries.push((entry, off));
            }
        }
        _ => {
            // nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset.
            let text = r.uptr(8 + 2 * ptr)?;
            names = r.usize_ptr(8 + 3 * ptr)?;
            base = r.usize_ptr(8 + 7 * ptr)?;
            for i in 0..=nfunc {
                let at = base.checked_add(i * 8)?;
                let entry = text.checked_add(u64::from(r.u32(at)?))?;
                let off = if i < nfunc { r.u32(at + 4)? as usize } else { 0 };
                entries.push((entry, off));
            }
        }
    }

    let mut out = Vec::with_capacity(entries.len());
    for i in 0..nfunc {
        let (entry, off) = entries[i];
        let end = entries[i + 1].0;
        if end < entry || !is_code(entry) {
            return None;
        }
        let rec = base.checked_add(off)?;
        // The record starts with the entry (pointer-sized before 1.18, a 32-bit offset after),
        // then the 32-bit name offset.
        let name_field = rec + if magic == 0xffff_fff0 || magic == 0xffff_fff1 { 4 } else { ptr };
        let name_off = r.u32(name_field)? as i32;
        let name = usize::try_from(name_off).ok().and_then(|n| r.name(names.checked_add(n)?));
        out.push(GoFunc { entry, end, name: name.unwrap_or_else(|| format!("go_func_{entry:x}")) });
    }
    // A real table names nearly every function; garbage that slipped past the checks doesn't.
    let named = out.iter().filter(|f| !f.name.starts_with("go_func_")).count();
    (named * 10 >= out.len() * 9).then_some(out)
}

/// Looks for the table in `data`: at the start of a section that should hold it, or
/// failing that (PE files have no such section) by its magic number in readable data.
pub fn find(
    data: &[u8],
    sections: &[(usize, usize)],
    named: Option<(usize, usize)>,
    big: bool,
    is_code: &dyn Fn(u64) -> bool,
) -> Option<Vec<GoFunc>> {
    if let Some((off, len)) = named {
        if let Some(found) = data.get(off..off.saturating_add(len).min(data.len())).and_then(|d| parse(d, big, is_code)) {
            return Some(found);
        }
    }
    for &(off, len) in sections {
        let Some(sec) = data.get(off..off.saturating_add(len).min(data.len())) else { continue };
        // The table is pointer-aligned inside its section.
        let mut at = 0;
        while at + 16 <= sec.len() {
            if sec[at + 4] == 0 && sec[at + 5] == 0 && sec[at] >= 0xf0 && version(&sec[at..], big).is_some() {
                if let Some(found) = parse(&sec[at..], big, is_code) {
                    return Some(found);
                }
            }
            at += 4;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Go 1.20-style table with two functions, little-endian, 64-bit.
    fn table() -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&0xffff_fff1u32.to_le_bytes());
        d.extend_from_slice(&[0, 0, 1, 8]);
        let header = 8 + 8 * 8;
        let names_at = header;
        let names = b"main.main\0main.helper\0";
        let pcln_at = names_at + names.len();
        // nfunc, nfiles, textStart, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset
        for v in [2u64, 0, 0x401000, names_at as u64, 0, 0, 0, pcln_at as u64] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(names);
        // functab: (entryoff, funcoff) x2, then the end
        let recs = 3 * 8;
        for (e, f) in [(0u32, recs), (0x40, recs + 8)] {
            d.extend_from_slice(&e.to_le_bytes());
            d.extend_from_slice(&(f as u32).to_le_bytes());
        }
        d.extend_from_slice(&0x90u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        // records: entryoff, nameoff
        for (e, n) in [(0u32, 0u32), (0x40, 10)] {
            d.extend_from_slice(&e.to_le_bytes());
            d.extend_from_slice(&n.to_le_bytes());
        }
        d
    }

    #[test]
    fn reads_a_go_120_table() {
        let code = |va: u64| (0x401000..0x402000).contains(&va);
        let f = parse(&table(), false, &code).unwrap();
        assert_eq!(f[0], GoFunc { entry: 0x401000, end: 0x401040, name: "main.main".into() });
        assert_eq!(f[1], GoFunc { entry: 0x401040, end: 0x401090, name: "main.helper".into() });
    }

    #[test]
    fn found_by_magic_inside_data() {
        let mut data = vec![0u8; 64];
        data.extend(table());
        let code = |va: u64| (0x401000..0x402000).contains(&va);
        let f = find(&data, &[(0, data.len())], None, false, &code).unwrap();
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn rejects_tables_pointing_outside_code() {
        let nowhere = |_: u64| false;
        assert!(parse(&table(), false, &nowhere).is_none());
    }

    #[test]
    fn hostile_tables_are_rejected_cleanly() {
        let code = |_: u64| true;
        let good = table();
        for cut in 0..good.len() {
            let _ = parse(&good[..cut], false, &code);
        }
        let mut huge = good.clone();
        huge[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse(&huge, false, &code).is_none());
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..2000 {
            let mut d = good.clone();
            for _ in 0..4 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                let i = (rng as usize) % d.len();
                d[i] = (rng >> 32) as u8;
            }
            let _ = parse(&d, false, &code);
        }
    }
}
