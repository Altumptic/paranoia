//! IDA-style items: the listing covers the whole address space, mixing code
//! with data items (`db`/`dw`/`dd`/`dq`, strings, pointers, `extrn` slots).
//! Users can redefine items (U, C, D, A) and get IDA-like automatic names
//! (`aHelloWorld`, `qword_140034400`, `off_1400290F8`).

use serde::{Deserialize, Serialize};

use crate::model::{Flow, Instruction, StringEncoding, Token, TokenKind, XrefKind};
use crate::Binary;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Byte,
    Word,
    Dword,
    Qword,
    /// Zero-terminated 8-bit string; `count` = characters without the terminator.
    Ascii,
    /// Zero-terminated UTF-16LE string; `count` = code units without the terminator.
    Utf16,
    /// Force instructions here (e.g. shellcode in a data section).
    Code,
}

impl ItemKind {
    fn unit(self) -> u64 {
        match self {
            ItemKind::Byte | ItemKind::Ascii | ItemKind::Code => 1,
            ItemKind::Word | ItemKind::Utf16 => 2,
            ItemKind::Dword => 4,
            ItemKind::Qword => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataItem {
    pub kind: ItemKind,
    #[serde(default = "one")]
    pub count: u32,
}

fn one() -> u32 {
    1
}

impl DataItem {
    pub fn size(&self) -> u64 {
        match self.kind {
            ItemKind::Ascii => self.count as u64 + 1,
            ItemKind::Utf16 => (self.count as u64 + 1) * 2,
            ItemKind::Code => 1,
            k => k.unit() * self.count.max(1) as u64,
        }
    }
}

const MAX_DATA_RUN: u64 = 16;

fn data_line(address: u64, size: u64, bytes: &[u8], mnemonic: &str, operands: Vec<Token>) -> Instruction {
    Instruction {
        address,
        size: size.min(u32::MAX as u64) as u32,
        bytes: hex::encode(&bytes[..bytes.len().min(16)]),
        mnemonic: mnemonic.into(),
        operands,
        flow: Flow::None,
        target: None,
        comment: None,
        label: None,
        user_comment: None,
    }
}

fn tok(t: impl Into<String>, k: TokenKind) -> Token {
    Token { t: t.into(), k }
}

/// `Hello, world!\n` → `aHelloWorld` (IDA's naming for string literals).
pub fn string_name(s: &str) -> String {
    let mut out = String::from("a");
    let mut upper = true;
    for c in s.chars() {
        if out.len() >= 26 {
            break;
        }
        if c.is_ascii_alphanumeric() {
            if upper {
                out.extend(c.to_uppercase());
            } else {
                out.push(c);
            }
            upper = false;
        } else {
            upper = true;
        }
    }
    if out.len() == 1 {
        out.push_str("Str");
    }
    out
}

fn quote(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars().take(200) {
        match c {
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    if s.chars().count() > 200 {
        out.push('…');
    }
    out.push('\'');
    out
}

impl Binary {
    fn ptr_size(&self) -> u64 {
        if self.info.bits == 64 {
            8
        } else {
            4
        }
    }

    fn read_uint(&self, va: u64, size: u64) -> Option<u64> {
        let b = self.bytes_at(va)?;
        let b = b.get(..size as usize)?;
        let mut v = 0u64;
        for (i, x) in b.iter().enumerate() {
            v |= (*x as u64) << (8 * i);
        }
        Some(v)
    }

    /// A pointer-sized, aligned value at `va` that points into the image.
    fn pointer_at(&self, va: u64) -> Option<u64> {
        let p = self.ptr_size();
        if va % p != 0 {
            return None;
        }
        let v = self.read_uint(va, p)?;
        (v > 0x10000 && v != va && self.range_of(v).is_some()).then_some(v)
    }

    /// Automatic name for data (IDA conventions); `None` for plain bytes nobody references.
    pub(crate) fn auto_data_name(&self, va: u64) -> Option<String> {
        if let Some(it) = self.annotations.items.get(&va) {
            let p = match it.kind {
                ItemKind::Ascii | ItemKind::Utf16 => {
                    return Some(self.string_value(va).map(|s| string_name(&s)).unwrap_or_else(|| format!("aStr_{va:X}")))
                }
                ItemKind::Code => return None,
                ItemKind::Byte => "byte_",
                ItemKind::Word => "word_",
                ItemKind::Dword => "dword_",
                ItemKind::Qword => {
                    if self.pointer_at(va).is_some() {
                        "off_"
                    } else {
                        "qword_"
                    }
                }
            };
            return Some(format!("{p}{va:X}"));
        }
        // Constants that merely look like addresses (GENERIC_READ = 0x80000000) stay numbers.
        self.range_of(va)?;
        let a = self.analysis.as_ref()?;
        let refs = a.xrefs.get(&va)?;
        let data: Vec<_> = refs.iter().filter(|r| r.kind == XrefKind::Data).collect();
        if data.is_empty() || (self.is_executable(va) && a.block_index.contains_key(&va)) {
            return None;
        }
        if let Some(&si) = self.string_by_va.get(&va) {
            return Some(string_name(&self.strings[si].value));
        }
        if self.pointer_at(va).is_some() {
            return Some(format!("off_{va:X}"));
        }
        let size = data.iter().map(|r| r.size).max().unwrap_or(0);
        let p = match size {
            1 => "byte_",
            2 => "word_",
            4 => "dword_",
            8 => "qword_",
            16 => "xmmword_",
            32 => "ymmword_",
            _ => "unk_",
        };
        Some(format!("{p}{va:X}"))
    }

    fn string_value(&self, va: u64) -> Option<String> {
        if let Some(&si) = self.string_by_va.get(&va) {
            return Some(self.strings[si].value.clone());
        }
        let it = self.annotations.items.get(&va)?;
        let b = self.bytes_at(va)?;
        match it.kind {
            ItemKind::Ascii => Some(String::from_utf8_lossy(&b[..(it.count as usize).min(b.len())]).into_owned()),
            ItemKind::Utf16 => {
                let units: Vec<u16> = b.chunks_exact(2).take(it.count as usize).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                Some(String::from_utf16_lossy(&units))
            }
            _ => None,
        }
    }

    /// Next address after `va` that must start its own line (named, referenced or defined).
    fn next_mark(&self, va: u64, limit: u64) -> u64 {
        let mut next = limit;
        if let Some((&k, _)) = self.annotations.items.range(va + 1..).next() {
            next = next.min(k);
        }
        if let Some(&k) = self.marks.range(va + 1..).next() {
            next = next.min(k);
        }
        next
    }

    /// One data line at `va` (never empty; always advances by at least one byte).
    fn data_line_at(&self, va: u64, range_end: u64) -> Instruction {
        let p = self.ptr_size();
        let avail = self.bytes_at(va).map(|b| b.len() as u64).unwrap_or(0);

        // Uninitialized memory (.bss / zero-fill): a single `dup(?)` line.
        if avail == 0 {
            let end = self.next_mark(va, range_end).max(va + 1);
            return data_line(
                va,
                end - va,
                &[],
                "db",
                vec![tok(format!("{}", end - va), TokenKind::Number), tok(" dup(?)", TokenKind::Punct)],
            );
        }
        let bytes = self.bytes_at(va).unwrap_or(&[]);

        // Import slots.
        if let Some(&i) = self.import_slots.get(&va) {
            let name = self.name_at(va).unwrap_or_else(|| self.info.imports[i].name.clone());
            let size = p.min(avail);
            return data_line(
                va,
                size,
                &bytes[..size as usize],
                "extrn",
                vec![tok(name, TokenKind::Symbol), tok(if p == 8 { ":qword" } else { ":dword" }, TokenKind::Punct)],
            );
        }

        // User-defined items.
        if let Some(it) = self.annotations.items.get(&va).copied() {
            return self.item_line(va, it, bytes);
        }

        // Strings.
        if let Some(&si) = self.string_by_va.get(&va) {
            let s = &self.strings[si];
            let (n, mnem, ops) = match s.encoding {
                StringEncoding::Ascii => {
                    let n = s.value.len() as u64 + u64::from(bytes.get(s.value.len()) == Some(&0));
                    (n, "db", vec![tok(quote(&s.value), TokenKind::Address), tok(",0", TokenKind::Punct)])
                }
                StringEncoding::Utf16 => {
                    let n = s.value.encode_utf16().count() as u64 * 2 + 2;
                    (
                        n,
                        "text",
                        vec![
                            tok("\"UTF-16LE\", ", TokenKind::Keyword),
                            tok(quote(&s.value), TokenKind::Address),
                            tok(",0", TokenKind::Punct),
                        ],
                    )
                }
            };
            let n = n.min(avail).max(1);
            return data_line(va, n, &bytes[..n as usize], mnem, ops);
        }

        // Pointers into the image.
        if let Some(t) = self.pointer_at(va) {
            let name = self.name_at(t).or_else(|| self.auto_data_name(t)).unwrap_or_else(|| format!("unk_{t:X}"));
            let mut l = data_line(
                va,
                p,
                &bytes[..p as usize],
                if p == 8 { "dq" } else { "dd" },
                vec![tok("offset ", TokenKind::Keyword), tok(name, TokenKind::Symbol)],
            );
            l.target = Some(t);
            return l;
        }

        let limit = self.next_mark(va, range_end).min(va + avail);
        // Runs of zeros fold into one line.
        if bytes[0] == 0 {
            let mut n = 1u64;
            while va + n < limit && bytes[n as usize] == 0 {
                n += 1;
            }
            if n >= 4 {
                return data_line(
                    va,
                    n,
                    &bytes[..n as usize],
                    "db",
                    vec![tok(n.to_string(), TokenKind::Number), tok(" dup(0)", TokenKind::Punct)],
                );
            }
        }
        let mut n = 1u64;
        while n < MAX_DATA_RUN && va + n < limit && !self.string_by_va.contains_key(&(va + n)) && self.pointer_at(va + n).is_none() {
            n += 1;
        }
        let mut ops = Vec::new();
        for (k, b) in bytes[..n as usize].iter().enumerate() {
            if k > 0 {
                ops.push(tok(", ", TokenKind::Punct));
            }
            ops.push(tok(format!("{b:#04x}"), TokenKind::Number));
        }
        data_line(va, n, &bytes[..n as usize], "db", ops)
    }

    fn item_line(&self, va: u64, it: DataItem, bytes: &[u8]) -> Instruction {
        match it.kind {
            ItemKind::Ascii | ItemKind::Utf16 => {
                let s = self.string_value(va).unwrap_or_default();
                let size = it.size().min(bytes.len() as u64).max(1);
                let ops = if it.kind == ItemKind::Ascii {
                    vec![tok(quote(&s), TokenKind::Address), tok(",0", TokenKind::Punct)]
                } else {
                    vec![tok("\"UTF-16LE\", ", TokenKind::Keyword), tok(quote(&s), TokenKind::Address), tok(",0", TokenKind::Punct)]
                };
                data_line(va, size, &bytes[..size as usize], if it.kind == ItemKind::Ascii { "db" } else { "text" }, ops)
            }
            kind => {
                let unit = kind.unit();
                let count = it.count.max(1) as u64;
                let size = (unit * count).min(bytes.len() as u64 / unit * unit).max(unit.min(bytes.len() as u64)).max(1);
                let mnem = match kind {
                    ItemKind::Byte => "db",
                    ItemKind::Word => "dw",
                    ItemKind::Dword => "dd",
                    _ => "dq",
                };
                let mut ops = Vec::new();
                let mut target = None;
                for i in 0..(size / unit).min(16) {
                    if i > 0 {
                        ops.push(tok(", ", TokenKind::Punct));
                    }
                    let v = self.read_uint(va + i * unit, unit).unwrap_or(0);
                    if unit == self.ptr_size() && v > 0x10000 && self.range_of(v).is_some() {
                        let name = self.name_at(v).or_else(|| self.auto_data_name(v)).unwrap_or_else(|| format!("unk_{v:X}"));
                        ops.push(tok("offset ", TokenKind::Keyword));
                        ops.push(tok(name, TokenKind::Symbol));
                        target.get_or_insert(v);
                    } else {
                        ops.push(tok(format!("{v:#x}"), TokenKind::Number));
                    }
                }
                if size / unit > 16 {
                    ops.push(tok(format!(", … ({} items)", size / unit), TokenKind::Punct));
                }
                let mut l = data_line(va, size, &bytes[..size as usize], mnem, ops);
                l.target = target;
                l
            }
        }
    }

    /// Whether `va` should be shown as instructions.
    fn is_code_at(&self, va: u64) -> bool {
        match self.annotations.items.get(&va) {
            Some(it) => it.kind == ItemKind::Code,
            None => {
                if !self.is_executable(va) {
                    return false;
                }
                // Data referenced from code inside .text (jump tables, literal pools) that no
                // function claims is shown as data.
                let a = self.analysis.as_ref();
                let claimed = a.is_some_and(|a| a.function_containing(va).is_some());
                let data_ref = a.and_then(|a| a.xrefs.get(&va)).is_some_and(|r| r.iter().any(|x| x.kind == XrefKind::Data));
                claimed || !data_ref
            }
        }
    }

    /// Code-or-data listing of up to `count` lines from `va` (IDA's disassembly view).
    pub fn listing(&self, va: u64, count: usize) -> Result<Vec<Instruction>, crate::Error> {
        let mut cur = va;
        let mut out: Vec<Instruction> = Vec::new();
        let names = crate::Names(self);
        let first = self.range_of(va).ok_or(crate::Error::Unmapped(va))?;
        let mut range_end = first.vaddr + first.vsize.max(first.file_size);
        while out.len() < count {
            if cur >= range_end {
                // Continue into the next mapping, like IDA's linear view across segments.
                match self.ranges.iter().filter(|r| r.vaddr >= range_end && r.vsize.max(r.file_size) > 0).min_by_key(|r| r.vaddr) {
                    Some(r) if r.vaddr - range_end < 0x1000_0000 => {
                        cur = r.vaddr;
                        range_end = r.vaddr + r.vsize.max(r.file_size);
                    }
                    _ => break,
                }
            }
            if self.is_code_at(cur) && self.bytes_at(cur).is_some() {
                // Decode until the next defined item (or the end of the mapping).
                let stop = self.annotations.items.range(cur + 1..).next().map(|(k, _)| *k).unwrap_or(u64::MAX).min(range_end);
                let bytes = self.bytes_at(cur).unwrap();
                let len = ((stop - cur) as usize).min(bytes.len());
                let want = (count - out.len()).min(256);
                let chunk = crate::disasm::render(self.info.arch, &bytes[..len], cur, want, &names);
                if chunk.is_empty() {
                    out.push(self.data_line_at(cur, range_end));
                } else {
                    // Stop before instructions that run into data the analysis identified.
                    for ins in chunk {
                        if ins.address != cur && !self.is_code_at(ins.address) {
                            break;
                        }
                        cur = ins.address + ins.size as u64;
                        out.push(ins);
                        if out.len() >= count {
                            break;
                        }
                    }
                    continue;
                }
            } else {
                out.push(self.data_line_at(cur, range_end));
            }
            cur = out.last().map(|l| l.address + (l.size as u64).max(1)).unwrap_or(cur + 1);
        }
        self.annotate(&mut out);
        Ok(crate::collapse_padding(out))
    }

    // --------------------------------------------------------------------------------------------
    // Item commands
    // --------------------------------------------------------------------------------------------

    fn clear_items(&mut self, from: u64, to: u64) {
        let keys: Vec<u64> = self.annotations.items.range(from..to).map(|(k, _)| *k).collect();
        for k in keys {
            self.annotations.items.remove(&k);
        }
    }

    /// Defines a data item (IDA's `D` / `*`).
    pub fn set_item(&mut self, va: u64, kind: ItemKind, count: u32) -> Result<(), String> {
        if self.range_of(va).is_none() {
            return Err(format!("{va:#x} is not mapped"));
        }
        let it = DataItem { kind, count: count.max(1) };
        self.clear_items(va, va + it.size());
        self.annotations.items.insert(va, it);
        Ok(())
    }

    /// Cycles byte → word → dword → qword → byte, like pressing `D` repeatedly.
    pub fn cycle_data(&mut self, va: u64) -> Result<ItemKind, String> {
        let next = match self.annotations.items.get(&va).map(|i| i.kind) {
            None | Some(ItemKind::Code) | Some(ItemKind::Ascii) | Some(ItemKind::Utf16) => ItemKind::Byte,
            Some(ItemKind::Byte) => ItemKind::Word,
            Some(ItemKind::Word) => ItemKind::Dword,
            Some(ItemKind::Dword) => ItemKind::Qword,
            Some(ItemKind::Qword) => ItemKind::Byte,
        };
        self.set_item(va, next, 1)?;
        Ok(next)
    }

    /// Defines a string at `va` (IDA's `A`), detecting 8-bit vs UTF-16.
    pub fn make_string(&mut self, va: u64) -> Result<(), String> {
        let b = self.bytes_at(va).ok_or("no file bytes at this address")?;
        let ascii = b.iter().take_while(|&&c| c != 0 && (c >= 0x20 || c == b'\t' || c == b'\n' || c == b'\r')).count();
        let wide = b.chunks_exact(2).take_while(|c| c[1] == 0 && c[0] >= 0x20).count();
        let (kind, n) = if wide >= 2 && wide >= ascii { (ItemKind::Utf16, wide) } else { (ItemKind::Ascii, ascii) };
        if n == 0 {
            return Err("no printable characters here".into());
        }
        self.set_item(va, kind, n.min(1 << 20) as u32)
    }

    /// Forces code at `va` (IDA's `C`).
    pub fn make_code(&mut self, va: u64) -> Result<(), String> {
        self.clear_items(va, va + 16);
        if !self.is_executable(va) {
            self.annotations.items.insert(va, DataItem { kind: ItemKind::Code, count: 1 });
        }
        Ok(())
    }

    /// Undefines the item or function at `va` (IDA's `U`). Returns true if analysis re-ran.
    pub fn undefine(&mut self, va: u64) -> bool {
        if self.annotations.items.remove(&va).is_some() {
            return false;
        }
        let is_func = self.analysis.as_ref().is_some_and(|a| a.by_start.contains_key(&va));
        if is_func {
            if !self.annotations.functions.remove(&va) {
                self.annotations.undefined.insert(va);
            }
            self.reanalyze();
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(string_name("Hello, world!\n"), "aHelloWorld");
        assert_eq!(string_name("%s"), "aS");
        assert_eq!(string_name("!!!"), "aStr");
        assert_eq!(DataItem { kind: ItemKind::Dword, count: 3 }.size(), 12);
        assert_eq!(DataItem { kind: ItemKind::Utf16, count: 3 }.size(), 8);
    }
}
