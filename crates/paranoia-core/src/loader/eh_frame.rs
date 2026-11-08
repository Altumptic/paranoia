//! Function starts from `.eh_frame_hdr` (`PT_GNU_EH_FRAME`): the sorted table the C++ /
//! Rust unwinder searches. Linkers emit it for almost every ELF, stripped or not, so it
//! finds functions where no symbol table is left.
//!
//! Layout: `version: u8 = 1`, three pointer encodings (`eh_frame_ptr`, `fde_count`,
//! `table`), the encoded `.eh_frame` pointer, the encoded FDE count, then `fde_count`
//! pairs `(initial_location, fde_address)` in `table` encoding. Every field is read with
//! bounds checks; anything unexpected ends the table instead of guessing.

/// Hard cap on table entries, far above real binaries (a large browser has ~200 k).
const MAX_ENTRIES: usize = 1_000_000;

const DW_EH_PE_OMIT: u8 = 0xff;

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.pos.checked_add(N)?;
        let s: [u8; N] = self.bytes.get(self.pos..end)?.try_into().ok()?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|b| b[0])
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// One `DW_EH_PE_*` encoded value. `field_va` is the address of the field (for
    /// pc-relative values), `data_va` the start of `.eh_frame_hdr` (for data-relative ones).
    fn encoded(&mut self, enc: u8, bits: u8, field_va: u64, data_va: u64) -> Option<u64> {
        if enc == DW_EH_PE_OMIT || enc & 0x80 != 0 {
            // Omitted, or indirect (a pointer to the value, which needs relocated memory).
            return None;
        }
        macro_rules! num {
            ($t:ty, $n:literal) => {{
                let b = self.take::<$n>()?;
                if self.big_endian {
                    <$t>::from_be_bytes(b)
                } else {
                    <$t>::from_le_bytes(b)
                }
            }};
        }
        let raw: i64 = match enc & 0x0f {
            0x00 if bits == 64 => num!(u64, 8) as i64,
            0x00 => i64::from(num!(u32, 4)),
            0x01 => self.uleb()? as i64,
            0x02 => i64::from(num!(u16, 2)),
            0x03 => i64::from(num!(u32, 4)),
            0x04 => num!(u64, 8) as i64,
            0x09 => self.sleb()?,
            0x0a => i64::from(num!(i16, 2)),
            0x0b => i64::from(num!(i32, 4)),
            0x0c => num!(i64, 8),
            _ => return None,
        };
        let base = match enc & 0x70 {
            0x00 => 0,
            0x10 => field_va,
            0x30 => data_va,
            _ => return None, // text- and function-relative bases are not used here
        };
        let v = base.wrapping_add(raw as u64);
        Some(if bits == 64 { v } else { v & 0xffff_ffff })
    }
}

/// Function start addresses listed in the `.eh_frame_hdr` at `hdr_va`, whose bytes are
/// `hdr`. Empty when the header is missing parts, uses an unsupported encoding, or has no
/// search table.
pub fn function_starts(hdr: &[u8], hdr_va: u64, big_endian: bool, bits: u8) -> Vec<u64> {
    let mut r = Reader { bytes: hdr, pos: 0, big_endian };
    let parse = |r: &mut Reader| -> Option<Vec<u64>> {
        if r.u8()? != 1 {
            return None;
        }
        let ptr_enc = r.u8()?;
        let count_enc = r.u8()?;
        let table_enc = r.u8()?;
        let at = |r: &Reader| hdr_va.wrapping_add(r.pos as u64);
        let field = at(r);
        if ptr_enc != DW_EH_PE_OMIT {
            r.encoded(ptr_enc, bits, field, hdr_va)?;
        }
        let field = at(r);
        let count = usize::try_from(r.encoded(count_enc, bits, field, hdr_va)?).ok()?;
        // Each entry takes at least two bytes; a count beyond what the bytes can hold is a lie.
        let count = count.min(hdr.len().saturating_sub(r.pos) / 2).min(MAX_ENTRIES);
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let field = at(r);
            let Some(start) = r.encoded(table_enc, bits, field, hdr_va) else { break };
            let field = at(r);
            if r.encoded(table_enc, bits, field, hdr_va).is_none() {
                break;
            }
            out.push(start);
        }
        Some(out)
    };
    parse(&mut r).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header as GNU ld writes it: pcrel|sdata4 pointer, udata4 count, datarel|sdata4 table.
    fn header(starts: &[i32], count: u32) -> Vec<u8> {
        let mut h = vec![1, 0x1b, 0x03, 0x3b];
        h.extend_from_slice(&0x40i32.to_le_bytes());
        h.extend_from_slice(&count.to_le_bytes());
        for (i, s) in starts.iter().enumerate() {
            h.extend_from_slice(&s.to_le_bytes());
            h.extend_from_slice(&(0x100 + i as i32 * 0x20).to_le_bytes());
        }
        h
    }

    #[test]
    fn reads_datarel_table() {
        let hdr_va = 0x2_24a8;
        // Function starts lie below the header in .text: negative data-relative offsets.
        let h = header(&[-0x1_0000, -0x0_f000, -0x0_8010], 3);
        let got = function_starts(&h, hdr_va, false, 64);
        assert_eq!(got, vec![hdr_va - 0x1_0000, hdr_va - 0xf000, hdr_va - 0x8010]);
        // 32-bit images wrap at 4 GiB.
        assert_eq!(function_starts(&header(&[-0x10], 1), 0x8, false, 32), vec![0xffff_fff8]);
    }

    #[test]
    fn hostile_headers_are_bounded() {
        // A count far larger than the bytes: only the entries that are present.
        let h = header(&[-0x100, -0x80], u32::MAX);
        assert_eq!(function_starts(&h, 0x1000, false, 64).len(), 2);
        // Truncated in the middle of an entry.
        let mut t = header(&[-0x100, -0x80], 2);
        t.truncate(t.len() - 3);
        assert_eq!(function_starts(&t, 0x1000, false, 64), vec![0x1000 - 0x100]);
        // Wrong version, omitted table, indirect and unknown encodings, empty input.
        assert!(function_starts(&[2, 0x1b, 0x03, 0x3b], 0, false, 64).is_empty());
        assert!(function_starts(&[1, 0x1b, 0xff, 0xff, 0, 0, 0, 0], 0, false, 64).is_empty());
        assert!(function_starts(&[1, 0x9b, 0x03, 0x3b, 0, 0, 0, 0], 0, false, 64).is_empty());
        assert!(function_starts(&[1, 0x1b, 0x03, 0x0d, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0], 0, false, 64).is_empty());
        assert!(function_starts(&[], 0, false, 64).is_empty());
        // Random bytes never panic.
        let mut seed = 0x1234_5678u32;
        for _ in 0..2000 {
            let n = (seed % 64) as usize;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (seed >> 16) as u8
                })
                .collect();
            let _ = function_starts(&bytes, u64::from(seed), seed & 1 == 0, if seed & 2 == 0 { 64 } else { 32 });
        }
    }

    #[test]
    fn leb128() {
        let mut r = Reader { bytes: &[0xe5, 0x8e, 0x26, 0x7f], pos: 0, big_endian: false };
        assert_eq!(r.uleb(), Some(624_485));
        assert_eq!(r.sleb(), Some(-1));
        let mut r = Reader { bytes: &[0x80; 20], pos: 0, big_endian: false };
        assert_eq!(r.uleb(), None, "an endless LEB128 must stop");
    }
}
