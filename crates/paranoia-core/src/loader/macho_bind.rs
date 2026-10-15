//! Mach-O import resolution, written from scratch with bounds checks on every
//! read: classic dyld bind opcode streams and modern `LC_DYLD_CHAINED_FIXUPS`.

/// Raw import: slot address, symbol, library ordinal.
#[derive(Debug, Clone)]
pub struct Bind {
    pub address: u64,
    pub name: String,
    pub ordinal: i64,
}

/// A segment as seen by the fixup walkers.
#[derive(Debug, Clone, Copy)]
pub struct Seg {
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

const MAX_BINDS: usize = 1_000_000;

fn uleb(d: &[u8], p: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *d.get(*p)?;
        *p += 1;
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

fn sleb(d: &[u8], p: &mut usize) -> Option<i64> {
    let mut v = 0i64;
    let mut shift = 0u32;
    loop {
        let b = *d.get(*p)?;
        *p += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as i64) << shift;
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

fn cstr(d: &[u8], p: usize) -> Option<&[u8]> {
    let rest = d.get(p..)?;
    rest.iter().position(|&b| b == 0).map(|n| &rest[..n])
}

fn u16_at(d: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(p..p + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?))
}

fn u64_at(d: &[u8], p: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(p..p + 8)?.try_into().ok()?))
}

/// Interprets a bind / weak-bind / lazy-bind opcode stream.
pub fn bind_opcodes(stream: &[u8], segs: &[Seg], ptr_size: u64, lazy: bool) -> Vec<Bind> {
    let mut out = Vec::new();
    let (mut p, mut ordinal, mut name, mut seg_addr): (usize, i64, &[u8], Option<u64>) = (0, 0, &[], None);
    let mut addr = 0u64;
    let emit = |out: &mut Vec<Bind>, addr: u64, name: &[u8], ordinal: i64| {
        if out.len() < MAX_BINDS && !name.is_empty() {
            out.push(Bind { address: addr, name: String::from_utf8_lossy(name).into_owned(), ordinal });
        }
    };
    while p < stream.len() {
        let byte = stream[p];
        p += 1;
        let (op, imm) = (byte & 0xf0, byte & 0x0f);
        match op {
            0x00 => {
                if !lazy {
                    break;
                }
            }
            0x10 => ordinal = imm as i64,
            0x20 => ordinal = uleb(stream, &mut p).unwrap_or(0) as i64,
            0x30 => ordinal = if imm == 0 { 0 } else { (imm | 0xf0) as i8 as i64 },
            0x40 => {
                let Some(s) = cstr(stream, p) else { break };
                p += s.len() + 1;
                name = s;
            }
            0x50 => {}
            0x60 => {
                if sleb(stream, &mut p).is_none() {
                    break;
                }
            }
            0x70 => {
                let Some(off) = uleb(stream, &mut p) else { break };
                seg_addr = segs.get(imm as usize).map(|s| s.vmaddr);
                addr = seg_addr.unwrap_or(0).wrapping_add(off);
            }
            0x80 => addr = addr.wrapping_add(uleb(stream, &mut p).unwrap_or(0)),
            0x90 => {
                if seg_addr.is_some() {
                    emit(&mut out, addr, name, ordinal);
                }
                addr = addr.wrapping_add(ptr_size);
            }
            0xa0 => {
                if seg_addr.is_some() {
                    emit(&mut out, addr, name, ordinal);
                }
                let Some(d) = uleb(stream, &mut p) else { break };
                addr = addr.wrapping_add(d).wrapping_add(ptr_size);
            }
            0xb0 => {
                if seg_addr.is_some() {
                    emit(&mut out, addr, name, ordinal);
                }
                addr = addr.wrapping_add(imm as u64 * ptr_size + ptr_size);
            }
            0xc0 => {
                let (Some(count), Some(skip)) = (uleb(stream, &mut p), uleb(stream, &mut p)) else { break };
                for _ in 0..count.min(MAX_BINDS as u64) {
                    if seg_addr.is_some() {
                        emit(&mut out, addr, name, ordinal);
                    }
                    addr = addr.wrapping_add(skip).wrapping_add(ptr_size);
                }
            }
            _ => break, // threaded binds and unknown opcodes: stop rather than guess
        }
        if out.len() >= MAX_BINDS {
            break;
        }
    }
    out
}

/// Walks `LC_DYLD_CHAINED_FIXUPS` and returns every bind location.
pub fn chained_fixups(file: &[u8], blob: &[u8], segs: &[Seg], image_base: u64) -> Vec<Bind> {
    let mut out = Vec::new();
    let Some(()) = (|| {
        let starts_offset = u32_at(blob, 4)? as usize;
        let imports_offset = u32_at(blob, 8)? as usize;
        let symbols_offset = u32_at(blob, 12)? as usize;
        let imports_count = u32_at(blob, 16)? as usize;
        let imports_format = u32_at(blob, 20)?;

        // Import table: (ordinal, name)
        let mut imports = Vec::with_capacity(imports_count.min(1 << 20));
        for i in 0..imports_count.min(1 << 20) {
            let (ordinal, name_off) = match imports_format {
                1 => {
                    let v = u32_at(blob, imports_offset + i * 4)?;
                    ((v & 0xff) as u8 as i8 as i64, (v >> 9) as usize)
                }
                2 => {
                    let v = u32_at(blob, imports_offset + i * 8)?;
                    ((v & 0xff) as u8 as i8 as i64, (v >> 9) as usize)
                }
                3 => {
                    let v = u64_at(blob, imports_offset + i * 16)?;
                    ((v & 0xffff) as u16 as i16 as i64, (v >> 32) as usize)
                }
                _ => return None,
            };
            let name = cstr(blob, symbols_offset + name_off).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
            imports.push((ordinal, name));
        }

        let seg_count = u32_at(blob, starts_offset)? as usize;
        for si in 0..seg_count.min(64) {
            let info_off = u32_at(blob, starts_offset + 4 + si * 4)? as usize;
            if info_off == 0 {
                continue;
            }
            let base = starts_offset + info_off;
            let page_size = u16_at(blob, base + 4)? as u64;
            let pointer_format = u16_at(blob, base + 6)?;
            let segment_offset = u64_at(blob, base + 8)?;
            let page_count = u16_at(blob, base + 20)? as u64;
            let (stride, ordinal_bits, next_shift, next_mask, bind_bit) = match pointer_format {
                1 | 7 | 9 => (8u64, 16u32, 51u32, 0x7ffu64, 62u32), // ARM64E variants
                12 => (8, 24, 51, 0x7ff, 62),                      // ARM64E_USERLAND24
                2 | 6 => (4, 24, 51, 0xfff, 63),                   // PTR_64 / PTR_64_OFFSET
                _ => continue,                                      // 32-bit and firmware formats
            };
            for page in 0..page_count {
                let start = u16_at(blob, base + 22 + page as usize * 2)?;
                if start == 0xffff || start & 0x8000 != 0 {
                    continue;
                }
                let mut vm = image_base.wrapping_add(segment_offset).wrapping_add(page * page_size).wrapping_add(start as u64);
                for _ in 0..(page_size.max(1) * 2) {
                    let Some(off) = va_to_off(segs, vm) else { break };
                    let Some(raw) = u64_at(file, off) else { break };
                    if (raw >> bind_bit) & 1 == 1 {
                        let idx = (raw & ((1u64 << ordinal_bits) - 1)) as usize;
                        if let Some((ordinal, name)) = imports.get(idx) {
                            out.push(Bind { address: vm, name: name.clone(), ordinal: *ordinal });
                        }
                    }
                    let next = (raw >> next_shift) & next_mask;
                    if next == 0 || out.len() >= MAX_BINDS {
                        break;
                    }
                    vm = vm.wrapping_add(next * stride);
                }
            }
        }
        Some(())
    })() else {
        return out;
    };
    out
}

fn va_to_off(segs: &[Seg], va: u64) -> Option<usize> {
    segs.iter()
        .find(|s| va >= s.vmaddr && va - s.vmaddr < s.filesize.min(s.vmsize))
        .map(|s| (s.fileoff + (va - s.vmaddr)) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_bind_stream() {
        let segs = [Seg { vmaddr: 0x1000, vmsize: 0x1000, fileoff: 0, filesize: 0x1000 }];
        // ordinal 1, symbol "_puts", segment 0 + 0x10, do bind, done
        let mut s = vec![0x11, 0x40];
        s.extend_from_slice(b"_puts\0");
        s.extend_from_slice(&[0x70, 0x10, 0x90, 0x00]);
        let b = bind_opcodes(&s, &segs, 8, false);
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].address, b[0].name.as_str(), b[0].ordinal), (0x1010, "_puts", 1));
        // Segment index out of range: no bind, no panic.
        let bad = [0x11, 0x40, b'x', 0, 0x7f, 0x10, 0x90, 0x00];
        assert!(bind_opcodes(&bad, &segs, 8, false).is_empty());
    }
}
