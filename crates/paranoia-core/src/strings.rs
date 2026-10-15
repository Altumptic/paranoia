//! ASCII and UTF-16LE string extraction.

use crate::model::StringEncoding;

pub const MAX_STRINGS: usize = 250_000;
const MAX_LEN: usize = 1024;

#[derive(Debug, Clone)]
pub struct RawString {
    pub offset: u64,
    pub encoding: StringEncoding,
    pub value: String,
}

#[inline]
fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Scans `data` for printable runs of at least `min_len` characters.
pub fn extract(data: &[u8], min_len: usize) -> Vec<RawString> {
    let mut out = Vec::new();
    let min_len = min_len.max(2);

    // ASCII / UTF-8-compatible 7-bit runs.
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            start.get_or_insert(i);
            continue;
        }
        if let Some(s) = start.take() {
            push_ascii(&mut out, data, s, i, min_len);
        }
        if out.len() >= MAX_STRINGS {
            return out;
        }
    }
    if let Some(s) = start {
        push_ascii(&mut out, data, s, data.len(), min_len);
    }

    // UTF-16LE runs of Latin-1-ish characters (the overwhelmingly common case for Windows binaries).
    for align in 0..2 {
        let mut i = align;
        let mut run_start = None;
        let mut units: Vec<u16> = Vec::new();
        while i + 1 < data.len() {
            let u = u16::from_le_bytes([data[i], data[i + 1]]);
            let ok = (u < 0x100 && printable(u as u8)) || (0x00a0..0x0100).contains(&u) || (0x0400..0x0500).contains(&u);
            if ok {
                run_start.get_or_insert(i);
                units.push(u);
            } else if let Some(s) = run_start.take() {
                if units.len() >= min_len {
                    let mut v = String::from_utf16_lossy(&units[..units.len().min(MAX_LEN)]);
                    if units.len() > MAX_LEN {
                        v.push('…');
                    }
                    out.push(RawString { offset: s as u64, encoding: StringEncoding::Utf16, value: v });
                    if out.len() >= MAX_STRINGS {
                        return out;
                    }
                }
                units.clear();
            }
            i += 2;
        }
    }
    out.sort_by_key(|s| s.offset);
    out
}

fn push_ascii(out: &mut Vec<RawString>, data: &[u8], s: usize, e: usize, min_len: usize) {
    let len = e - s;
    if len < min_len {
        return;
    }
    // Reject runs that are really UTF-16 seen byte-wise (handled by the UTF-16 pass) and pure filler.
    let slice = &data[s..e];
    if slice.iter().all(|&b| b == slice[0]) && len < 64 {
        return;
    }
    let mut v = String::from_utf8_lossy(&slice[..len.min(MAX_LEN)]).into_owned();
    if len > MAX_LEN {
        v.push('…');
    }
    out.push(RawString { offset: s as u64, encoding: StringEncoding::Ascii, value: v });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_and_utf16() {
        let mut data = b"\x00\x01hello world\x00\x02".to_vec();
        for c in "Wide!".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0, 0xff]);
        let s = extract(&data, 4);
        assert!(s.iter().any(|s| s.value == "hello world" && s.encoding == StringEncoding::Ascii));
        assert!(s.iter().any(|s| s.value == "Wide!" && s.encoding == StringEncoding::Utf16));
    }
}
