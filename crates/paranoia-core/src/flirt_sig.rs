//! IDA's binary FLIRT signature files (`.sig`, versions 5–10).
//!
//! A `.sig` is a compressed prefix tree of the same patterns a `.pat` file lists: each node holds a
//! run of pattern bytes (some of them wildcards), the leaves hold modules — CRC16 of the bytes
//! after the pattern, function length, public names, optional "tail" bytes and referenced names.
//! Flattening the tree gives exactly the [`PatSig`] list the `.pat` matcher already uses, so both
//! formats share one matcher. Referenced-function checks are not used (they need resolved call
//! targets); tail bytes are.
//!
//! The layout follows the open implementations in radare2 and angr; every read is bounds-checked
//! and the tree size is capped, so a hostile file fails cleanly.

use crate::sigs::PatSig;

const MAX_DEPTH: usize = 64;
const MAX_MODULES: usize = 2_000_000;
const MAX_NAME: usize = 4096;

/// Header fields of interest.
#[derive(Debug, Clone)]
pub struct SigHeader {
    /// FLIRT processor id: 0 = x86, 12 = MIPS, 13 = ARM, 15 = PowerPC, …
    pub arch: u8,
    pub library: String,
}

/// The processor a FLIRT arch id names, for messages.
pub fn arch_name(id: u8) -> &'static str {
    match id {
        0 => "x86",
        7 => "68k",
        12 => "MIPS",
        13 => "ARM",
        15 => "PowerPC",
        19 => ".NET",
        23 => "SPARC",
        _ => "another processor",
    }
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.p).ok_or("the .sig file ends unexpectedly")?;
        self.p += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.p.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("the .sig file ends unexpectedly")?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn le16(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn le32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn be16(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    /// One byte, or two when the top bit is set (15-bit value).
    fn max2(&mut self) -> Result<u32, String> {
        let b = self.u8()? as u32;
        if b & 0x80 == 0 {
            return Ok(b);
        }
        Ok(((b & 0x7f) << 8) | self.u8()? as u32)
    }
    /// 1, 2, 4 or 5 bytes, selected by the leading bits of the first one.
    fn multi(&mut self) -> Result<u32, String> {
        let b = self.u8()? as u32;
        if b & 0x80 == 0 {
            return Ok(b);
        }
        if b & 0xc0 != 0xc0 {
            return Ok(((b & 0x7f) << 8) | self.u8()? as u32);
        }
        if b & 0xe0 != 0xe0 {
            let hi = ((b & 0x3f) << 24) | ((self.u8()? as u32) << 16);
            return Ok(hi | self.be16()? as u32);
        }
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

struct Parser {
    version: u8,
    out: Vec<PatSig>,
    modules: usize,
}

impl Parser {
    fn offset(&self, r: &mut Reader) -> Result<u32, String> {
        if self.version >= 9 {
            r.multi()
        } else {
            r.max2()
        }
    }

    fn tree(&mut self, r: &mut Reader, prefix: &mut Vec<Option<u8>>, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("the .sig tree is nested too deeply".into());
        }
        let children = r.multi()?;
        if children == 0 {
            return self.leaf(r, prefix);
        }
        for _ in 0..children {
            let len = r.u8()? as usize;
            let mask: u64 = if len < 0x10 {
                r.max2()? as u64
            } else if len <= 0x20 {
                r.multi()? as u64
            } else if len <= 0x40 {
                ((r.multi()? as u64) << 32) | r.multi()? as u64
            } else {
                return Err(format!("bad node length {len} in the .sig tree"));
            };
            let keep = prefix.len();
            for i in 0..len {
                // The mask's most significant of `len` bits is the first byte; a set bit is a wildcard.
                let wild = mask >> (len - 1 - i) & 1 == 1;
                prefix.push(if wild { None } else { Some(r.u8()?) });
            }
            if prefix.len() > 0x400 {
                return Err("a .sig pattern is unreasonably long".into());
            }
            self.tree(r, prefix, depth + 1)?;
            prefix.truncate(keep);
        }
        Ok(())
    }

    fn leaf(&mut self, r: &mut Reader, pattern: &[Option<u8>]) -> Result<(), String> {
        loop {
            let crc_len = r.u8()? as usize;
            let crc = r.be16()?;
            loop {
                self.modules += 1;
                if self.modules > MAX_MODULES {
                    return Err("the .sig file has too many modules".into());
                }
                let len = self.offset(r)?;
                // Public names: the offsets accumulate; the byte after a name carries the flags.
                let mut off = 0u32;
                let mut first: Option<String> = None;
                let flags = loop {
                    off = off.wrapping_add(self.offset(r)?);
                    let mut b = r.u8()?;
                    let mut local = false;
                    if b < 0x20 {
                        local = b & 0x02 != 0;
                        b = r.u8()?;
                    }
                    let mut name = Vec::new();
                    while (0x20..0x80).contains(&b) {
                        if name.len() >= MAX_NAME {
                            return Err("a .sig function name is too long".into());
                        }
                        name.push(b);
                        b = r.u8()?;
                    }
                    if off == 0 && !local && first.is_none() && !name.is_empty() {
                        first = Some(String::from_utf8_lossy(&name).into_owned());
                    }
                    if b & 0x01 == 0 {
                        break b;
                    }
                };
                let mut tail = Vec::new();
                if flags & 0x02 != 0 {
                    let n = if self.version >= 8 { r.u8()? as usize } else { 1 };
                    for _ in 0..n {
                        let o = self.offset(r)?;
                        tail.push((o, r.u8()?));
                    }
                }
                if flags & 0x04 != 0 {
                    let n = if self.version >= 8 { r.u8()? as usize } else { 1 };
                    for _ in 0..n {
                        self.offset(r)?;
                        let mut nl = r.u8()? as usize;
                        if nl == 0 {
                            nl = r.multi()? as usize;
                        }
                        if nl > MAX_NAME {
                            return Err("a .sig referenced name is too long".into());
                        }
                        r.take(nl)?;
                    }
                }
                if let Some(name) = first {
                    self.out.push(PatSig { pattern: pattern.to_vec(), crc_len, crc, len, name, tail });
                }
                if flags & 0x08 == 0 {
                    if flags & 0x10 == 0 {
                        return Ok(());
                    }
                    break;
                }
            }
        }
    }
}

/// Parses a `.sig` file into its header and the flattened signatures.
pub fn parse_sig(data: &[u8]) -> Result<(SigHeader, Vec<PatSig>), String> {
    let mut r = Reader { b: data, p: 0 };
    if r.take(6).ok() != Some(b"IDASGN".as_slice()) {
        return Err("not an IDA signature file (no IDASGN header)".into());
    }
    let version = r.u8()?;
    if !(5..=10).contains(&version) {
        return Err(format!("unsupported .sig version {version} (5–10 are supported)"));
    }
    let arch = r.u8()?;
    let _file_types = r.le32()?;
    let _os_types = r.le16()?;
    let _app_types = r.le16()?;
    let features = r.le16()?;
    let _old_functions = r.le16()?;
    let _crc = r.le16()?;
    r.take(12)?; // ctype
    let name_len = r.u8()? as usize;
    let _ctypes_crc = r.le16()?;
    if version >= 6 {
        r.le32()?; // number of functions
    }
    if version >= 8 {
        r.le16()?; // pattern size
    }
    if version >= 10 {
        r.le16()?;
    }
    let library = String::from_utf8_lossy(r.take(name_len)?).trim_end_matches('\0').to_string();
    let header = SigHeader { arch, library };
    let rest = &data[r.p..];
    let body: Vec<u8>;
    let mut br = if features & 0x10 != 0 {
        // Compressed: a zlib stream (raw deflate in some older files).
        body = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(rest, 256 << 20)
            .or_else(|_| miniz_oxide::inflate::decompress_to_vec_with_limit(rest, 256 << 20))
            .map_err(|_| "the compressed part of the .sig file is damaged".to_string())?;
        Reader { b: &body, p: 0 }
    } else {
        Reader { b: rest, p: 0 }
    };
    let mut p = Parser { version, out: Vec::new(), modules: 0 };
    p.tree(&mut br, &mut Vec::new(), 0)?;
    Ok((header, p.out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)] // a test encoder: every field of the format is a knob
    /// Encodes a one-leaf tree: root with one child node holding `pattern`, one module.
    fn file(
        version: u8,
        compressed: bool,
        pattern: &[Option<u8>],
        crc_len: u8,
        crc: u16,
        len: u8,
        names: &[(u8, &str, bool)],
        tail: Option<(u8, u8)>,
    ) -> Vec<u8> {
        let mut body = vec![1u8, pattern.len() as u8];
        let mut mask = 0u32;
        for (i, b) in pattern.iter().enumerate() {
            if b.is_none() {
                mask |= 1 << (pattern.len() - 1 - i);
            }
        }
        assert!((0x10..=0x20).contains(&pattern.len()));
        body.extend(multi(mask));
        body.extend(pattern.iter().flatten());
        body.push(0); // no children: leaf
        body.push(crc_len);
        body.extend(crc.to_be_bytes());
        body.push(len);
        for (k, (off, name, local)) in names.iter().enumerate() {
            body.push(*off);
            if *local {
                body.push(0x02);
            }
            body.extend(name.as_bytes());
            let more = k + 1 < names.len();
            body.push(u8::from(more) | if !more && tail.is_some() { 0x02 } else { 0 });
        }
        if let Some((o, v)) = tail {
            if version >= 8 {
                body.push(1);
            }
            body.push(o);
            body.push(v);
        }
        let mut h = b"IDASGN".to_vec();
        h.push(version);
        h.push(0); // x86
        h.extend(0xffff_ffffu32.to_le_bytes());
        h.extend(0xffffu16.to_le_bytes());
        h.extend(0xffffu16.to_le_bytes());
        h.extend((if compressed { 0x10u16 } else { 0 }).to_le_bytes());
        h.extend(0u16.to_le_bytes());
        h.extend(0u16.to_le_bytes());
        h.extend([0u8; 12]);
        h.push(4);
        h.extend(0u16.to_le_bytes());
        if version >= 6 {
            h.extend(1u32.to_le_bytes());
        }
        if version >= 8 {
            h.extend(32u16.to_le_bytes());
        }
        if version >= 10 {
            h.extend(0u16.to_le_bytes());
        }
        h.extend(b"test");
        if compressed {
            h.extend(miniz_oxide::deflate::compress_to_vec_zlib(&body, 6));
        } else {
            h.extend(body);
        }
        h
    }

    /// The writer side of `Reader::multi`.
    fn multi(v: u32) -> Vec<u8> {
        if v < 0x80 {
            vec![v as u8]
        } else if v < 0x4000 {
            vec![0x80 | (v >> 8) as u8, v as u8]
        } else if v < 0x2000_0000 {
            vec![0xc0 | (v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8]
        } else {
            let mut o = vec![0xe0];
            o.extend(v.to_be_bytes());
            o
        }
    }

    #[test]
    fn variable_length_numbers_decode() {
        for v in [0u32, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fff_ffff, 0x2000_0000, u32::MAX] {
            let b = multi(v);
            assert_eq!(Reader { b: &b, p: 0 }.multi().unwrap(), v, "{v:#x}");
        }
        assert_eq!(Reader { b: &[0x85, 0x01], p: 0 }.max2().unwrap(), 0x501);
    }

    fn pat() -> Vec<Option<u8>> {
        let mut p: Vec<Option<u8>> = (0..32u8).map(Some).collect();
        p[3] = None;
        p[4] = None;
        p
    }

    #[test]
    fn synthetic_files_of_every_version_round_trip() {
        for v in [5u8, 6, 7, 8, 9, 10] {
            for compressed in [false, true] {
                let f = file(v, compressed, &pat(), 7, 0xbeef, 0x60, &[(0, "memcpy", false)], None);
                let (h, sigs) = parse_sig(&f).unwrap_or_else(|e| panic!("v{v} compressed={compressed}: {e}"));
                assert_eq!((h.arch, h.library.as_str()), (0, "test"));
                assert_eq!(sigs.len(), 1);
                let s = &sigs[0];
                assert_eq!((s.name.as_str(), s.crc_len, s.crc, s.len), ("memcpy", 7, 0xbeef, 0x60));
                assert_eq!(s.pattern, pat());
            }
        }
    }

    #[test]
    fn local_and_offset_names_are_not_the_function_name() {
        let f = file(9, false, &pat(), 0, 0, 0x40, &[(0, "_local", true), (0, "strlen", false), (0x10, "inner", false)], Some((2, 0xc3)));
        let (_, sigs) = parse_sig(&f).unwrap();
        assert_eq!(sigs[0].name, "strlen");
        assert_eq!(sigs[0].tail, vec![(2, 0xc3)]);
    }

    #[test]
    fn hostile_input_fails_cleanly() {
        assert!(parse_sig(b"").is_err());
        assert!(parse_sig(b"IDASGX\x0a").is_err());
        assert!(parse_sig(b"IDASGN\x04").unwrap_err().contains("version"));
        let good = file(10, false, &pat(), 7, 1, 0x60, &[(0, "f", false)], None);
        for cut in 0..good.len() {
            let _ = parse_sig(&good[..cut]); // never panics
        }
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let _ = parse_sig(&bad);
        let z = file(10, true, &pat(), 7, 1, 0x60, &[(0, "f", false)], None);
        let mut zb = z.clone();
        let m = zb.len() - 3;
        zb[m] ^= 0x55;
        let _ = parse_sig(&zb);
    }
}
