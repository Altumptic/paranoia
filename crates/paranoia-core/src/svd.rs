//! CMSIS-SVD files: the names of a microcontroller's peripherals and registers.
//!
//! A firmware image talks to hardware through memory-mapped registers (`*(volatile uint32_t *)0x40020014 = x`).
//! The chip vendor publishes the map as an SVD file (XML): every peripheral with its base address and every
//! register with its offset. Loading one lets the listing say `GPIOA_ODR` where the code uses `0x40020014`.
//!
//! This reads the part of the format that carries names and addresses: peripherals (with `derivedFrom`),
//! registers, clusters and `dim` arrays. Fields, enumerated values and interrupts are skipped. The XML reader is
//! small and deliberately strict about size and nesting, since SVD files come from vendors' web pages.

use std::collections::BTreeMap;

/// Largest file read (real SVD files are a few MiB).
pub const MAX_SVD: usize = 32 << 20;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 2_000_000;
const MAX_REGISTERS: usize = 500_000;

/// A memory-mapped register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    /// `GPIOA_ODR`: the peripheral's name and the register's.
    pub name: String,
    pub address: u64,
    /// Width in bits (32 when the file does not say).
    pub bits: u32,
    pub description: String,
}

/// A peripheral and where it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peripheral {
    pub name: String,
    pub base: u64,
    /// Bytes the peripheral occupies (its address block, or just past its last register).
    pub size: u64,
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Svd {
    pub device: String,
    pub peripherals: Vec<Peripheral>,
    pub registers: Vec<Register>,
}

// ------------------------------------------------------------------------------------------------
// A small XML reader
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Node {
    tag: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn child(&self, tag: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.tag == tag)
    }
    fn text_of(&self, tag: &str) -> Option<&str> {
        self.child(tag).map(|c| c.text.trim()).filter(|t| !t.is_empty())
    }
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// Parses `text` into a tree. Comments, the XML declaration, doctype and CDATA are handled; namespaces are ignored.
fn parse_xml(text: &str) -> Result<Node, String> {
    let b = text.as_bytes();
    let mut i = 0usize;
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    let mut nodes = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            // Character data.
            let end = text[i..].find('<').map_or(b.len(), |e| i + e);
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&unescape(&text[i..end]));
            }
            i = end;
            continue;
        }
        let rest = &text[i..];
        if rest.starts_with("<!--") {
            i += rest.find("-->").ok_or("an unterminated comment")? + 3;
        } else if rest.starts_with("<![CDATA[") {
            let e = rest.find("]]>").ok_or("an unterminated CDATA section")?;
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&rest[9..e]);
            }
            i += e + 3;
        } else if rest.starts_with("<?") {
            i += rest.find("?>").ok_or("an unterminated declaration")? + 2;
        } else if rest.starts_with("<!") {
            // A doctype: skip to the matching '>' (no internal subset is read, which also rules out entity tricks).
            i += rest.find('>').ok_or("an unterminated doctype")? + 1;
        } else if rest.starts_with("</") {
            let e = rest.find('>').ok_or("an unterminated closing tag")?;
            let name = rest[2..e].trim();
            let node = stack.pop().ok_or_else(|| format!("a closing </{name}> with nothing open"))?;
            if node.tag != name {
                return Err(format!("<{}> is closed by </{name}>", node.tag));
            }
            match stack.last_mut() {
                Some(parent) => parent.children.push(node),
                None => root = Some(node),
            }
            i += e + 1;
        } else {
            let e = tag_end(rest).ok_or("an unterminated tag")?;
            let inner = &rest[1..e];
            let (inner, empty) = match inner.strip_suffix('/') {
                Some(s) => (s, true),
                None => (inner, false),
            };
            let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
            let mut node = Node { tag: inner[..name_end].to_string(), ..Default::default() };
            node.attrs = attributes(&inner[name_end..]);
            nodes += 1;
            if nodes > MAX_NODES {
                return Err("too many elements".into());
            }
            if stack.len() >= MAX_DEPTH {
                return Err("elements nested too deeply".into());
            }
            if empty {
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            } else {
                stack.push(node);
            }
            i += e + 1;
        }
    }
    if let Some(open) = stack.last() {
        return Err(format!("<{}> is never closed", open.tag));
    }
    root.ok_or_else(|| "no elements".into())
}

/// Index of the `>` that ends the tag at the start of `s`, skipping quoted attribute values.
fn tag_end(s: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn attributes(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
        let Some(end) = after[1..].find(q) else { break };
        out.push((key, unescape(&after[1..1 + end])));
        rest = after[end + 2..].trim_start();
    }
    out
}

// ------------------------------------------------------------------------------------------------
// SVD
// ------------------------------------------------------------------------------------------------

/// `0x40020000`, `1073872896`, `#1010` (binary), with an optional sign.
fn number(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(b) = t.strip_prefix('#') {
        u64::from_str_radix(b, 2).ok()
    } else {
        t.parse().ok()
    }
}

/// The names a `dim` array expands to: `dimIndex` is a list (`A,B,C`) or a range (`0-3`); without it, `0..dim`.
fn dim_names(node: &Node, name: &str) -> Result<Vec<(String, u64)>, String> {
    let Some(dim) = node.text_of("dim").and_then(number) else { return Ok(vec![(name.to_string(), 0)]) };
    if dim == 0 || dim > 4096 {
        return Err(format!("{name}: a dim of {dim}"));
    }
    let inc = node.text_of("dimIncrement").and_then(number).unwrap_or(0);
    let labels: Vec<String> = match node.text_of("dimIndex") {
        Some(l) if l.contains(',') => l.split(',').map(|x| x.trim().to_string()).collect(),
        Some(l) if l.contains('-') && l.split('-').all(|p| p.trim().parse::<u32>().is_ok()) => {
            let (a, b) = l.split_once('-').unwrap();
            let (a, b) = (a.trim().parse::<u32>().unwrap(), b.trim().parse::<u32>().unwrap());
            if b.saturating_sub(a) >= 4096 {
                return Err(format!("{name}: a dimIndex range of more than 4096"));
            }
            (a..=b).map(|n| n.to_string()).collect()
        }
        _ => (0..dim).map(|n| n.to_string()).collect(),
    };
    Ok(labels
        .iter()
        .take(dim as usize)
        .enumerate()
        .map(|(k, l)| (if name.contains("%s") { name.replace("[%s]", l).replace("%s", l) } else { format!("{name}{l}") }, k as u64 * inc))
        .collect())
}

/// A register relative to its peripheral: name without the peripheral prefix, offset, width, description.
type RelRegister = (String, u64, u32, String);

struct Ctx {
    registers: Vec<Register>,
}

/// Collects the registers of `node` (a `registers` or `cluster` element) under `prefix` at `base`.
fn walk(node: &Node, prefix: &str, base: u64, default_bits: u32, ctx: &mut Ctx) -> Result<(), String> {
    for c in &node.children {
        let is_reg = c.tag == "register";
        if !is_reg && c.tag != "cluster" {
            continue;
        }
        let Some(name) = c.text_of("name") else { continue };
        let Some(offset) = c.text_of("addressOffset").and_then(number) else { continue };
        let bits = c.text_of("size").and_then(number).map_or(default_bits, |b| b as u32);
        for (n, step) in dim_names(c, name)? {
            let at = base.wrapping_add(offset).wrapping_add(step);
            if is_reg {
                if ctx.registers.len() >= MAX_REGISTERS {
                    return Err("too many registers".into());
                }
                ctx.registers.push(Register {
                    name: format!("{prefix}_{n}"),
                    address: at,
                    bits,
                    description: c.text_of("description").unwrap_or("").to_string(),
                });
            } else {
                walk(c, &format!("{prefix}_{n}"), at, bits, ctx)?;
            }
        }
    }
    Ok(())
}

/// Reads an SVD file's peripherals and registers.
pub fn parse(bytes: &[u8]) -> Result<Svd, String> {
    if bytes.len() > MAX_SVD {
        return Err(format!("larger than {} MiB", MAX_SVD >> 20));
    }
    let text = String::from_utf8_lossy(bytes);
    let root = parse_xml(text.trim_start_matches('\u{feff}')).map_err(|e| format!("not a readable XML file: {e}"))?;
    if root.tag != "device" {
        return Err(format!("this is not an SVD file (its root element is <{}>, not <device>)", root.tag));
    }
    let default_bits = root.text_of("size").and_then(number).map_or(32, |b| b as u32);
    let list = root.child("peripherals").ok_or("the device has no <peripherals>")?;
    let mut svd = Svd { device: root.text_of("name").unwrap_or("").to_string(), ..Default::default() };

    // Pass 1: peripherals with their own registers, by name. Pass 2 gives `derivedFrom` ones the same registers.
    let mut own: BTreeMap<String, (u64, Vec<RelRegister>)> = BTreeMap::new();
    for p in list.children.iter().filter(|c| c.tag == "peripheral") {
        let Some(name) = p.text_of("name") else { continue };
        let Some(base) = p.text_of("baseAddress").and_then(number) else { continue };
        let bits = p.text_of("size").and_then(number).map_or(default_bits, |b| b as u32);
        for (n, step) in dim_names(p, name)? {
            let at = base.wrapping_add(step);
            let mut ctx = Ctx { registers: Vec::new() };
            if let Some(regs) = p.child("registers") {
                walk(regs, &n, at, bits, &mut ctx)?;
            }
            let block = p.child("addressBlock").and_then(|a| a.text_of("size")).and_then(number);
            let end = ctx.registers.iter().map(|r| r.address + (r.bits as u64).div_ceil(8)).max().unwrap_or(at + 4);
            let size = block.unwrap_or_else(|| end.saturating_sub(at)).max(end.saturating_sub(at));
            svd.peripherals.push(Peripheral {
                name: n.clone(),
                base: at,
                size,
                description: p.text_of("description").unwrap_or("").to_string(),
            });
            if p.attr("derivedFrom").is_none() {
                let rel = ctx
                    .registers
                    .iter()
                    .map(|r| (r.name[n.len() + 1..].to_string(), r.address - at, r.bits, r.description.clone()))
                    .collect();
                own.insert(n.clone(), (at, rel));
            }
            svd.registers.extend(ctx.registers);
        }
    }
    for p in list.children.iter().filter(|c| c.tag == "peripheral") {
        let (Some(from), Some(name), Some(base)) = (p.attr("derivedFrom"), p.text_of("name"), p.text_of("baseAddress").and_then(number))
        else {
            continue;
        };
        if p.child("registers").is_some() {
            continue;
        }
        let Some((_, regs)) = own.get(from) else { continue };
        for (rname, rel, bits, desc) in regs {
            svd.registers.push(Register { name: format!("{name}_{rname}"), address: base + rel, bits: *bits, description: desc.clone() });
        }
        // A derived peripheral is as big as the one it copies.
        if let Some(per) = svd.peripherals.iter_mut().find(|q| q.name == name) {
            per.size = per.size.max(regs.iter().map(|(_, rel, bits, _)| rel + (*bits as u64).div_ceil(8)).max().unwrap_or(0));
        }
    }
    if svd.peripherals.is_empty() {
        return Err("the file lists no peripherals".into());
    }
    svd.registers.sort_by_key(|r| (r.address, r.name.clone()));
    svd.registers.dedup_by(|a, b| a.address == b.address && a.name == b.name);
    Ok(svd)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<!-- A made-up part -->
<device schemaVersion="1.3">
  <name>DEMO32</name>
  <size>32</size>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <description>General-purpose I/O &amp; alternate functions</description>
      <baseAddress>0x40020000</baseAddress>
      <addressBlock><offset>0</offset><size>0x400</size><usage>registers</usage></addressBlock>
      <registers>
        <register><name>MODER</name><addressOffset>0x0</addressOffset><description>mode</description></register>
        <register><name>ODR</name><addressOffset>0x14</addressOffset></register>
        <register><name>AFR[%s]</name><dim>2</dim><dimIncrement>4</dimIncrement><dimIndex>L,H</dimIndex><addressOffset>0x20</addressOffset></register>
      </registers>
    </peripheral>
    <peripheral derivedFrom="GPIOA">
      <name>GPIOB</name>
      <baseAddress>0x40020400</baseAddress>
    </peripheral>
    <peripheral>
      <name>TIM%s</name><dim>2</dim><dimIncrement>0x400</dimIncrement><dimIndex>2-3</dimIndex>
      <baseAddress>0x40000000</baseAddress>
      <registers>
        <cluster><name>CH%s</name><dim>2</dim><dimIncrement>0x10</dimIncrement><addressOffset>0x100</addressOffset>
          <register><name>CCR</name><addressOffset>0x4</addressOffset><size>16</size></register>
        </cluster>
        <register><name>CR1</name><addressOffset>0</addressOffset></register>
      </registers>
    </peripheral>
  </peripherals>
</device>"#;

    fn at(s: &Svd, addr: u64) -> Vec<&str> {
        s.registers.iter().filter(|r| r.address == addr).map(|r| r.name.as_str()).collect()
    }

    #[test]
    fn peripherals_registers_derived_clusters_and_arrays() {
        let s = parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(s.device, "DEMO32");
        assert_eq!(
            s.peripherals.iter().map(|p| (p.name.as_str(), p.base)).collect::<Vec<_>>(),
            vec![("GPIOA", 0x4002_0000), ("GPIOB", 0x4002_0400), ("TIM2", 0x4000_0000), ("TIM3", 0x4000_0400)]
        );
        assert_eq!(s.peripherals[0].description, "General-purpose I/O & alternate functions");
        assert_eq!(s.peripherals[0].size, 0x400);
        assert_eq!(at(&s, 0x4002_0014), vec!["GPIOA_ODR"]);
        // dimIndex list.
        assert_eq!(at(&s, 0x4002_0020), vec!["GPIOA_AFRL"]);
        assert_eq!(at(&s, 0x4002_0024), vec!["GPIOA_AFRH"]);
        // derivedFrom: the same registers at the new base.
        assert_eq!(at(&s, 0x4002_0414), vec!["GPIOB_ODR"]);
        assert_eq!(at(&s, 0x4002_0400), vec!["GPIOB_MODER"]);
        // dim with a range index, a cluster that repeats, and a register width.
        assert_eq!(at(&s, 0x4000_0000), vec!["TIM2_CR1"]);
        assert_eq!(at(&s, 0x4000_0504), vec!["TIM3_CH0_CCR"]);
        assert_eq!(at(&s, 0x4000_0104), vec!["TIM2_CH0_CCR"]);
        assert_eq!(at(&s, 0x4000_0114), vec!["TIM2_CH1_CCR"]);
        assert_eq!(s.registers.iter().find(|r| r.name == "TIM2_CH0_CCR").unwrap().bits, 16);
    }

    #[test]
    fn hostile_and_wrong_files_are_refused() {
        for (text, want) in [
            ("", "no elements"),
            ("<html><body/></html>", "not an SVD file"),
            ("<device><name>x</name></device>", "no <peripherals>"),
            ("<device><peripherals></peripherals></device>", "no peripherals"),
            ("<device><peripherals>", "never closed"),
            ("<a></b>", "closed by"),
            ("<a><!-- never ends</a>", "comment"),
        ] {
            let e = parse(text.as_bytes()).unwrap_err();
            assert!(e.contains(want), "{text}: {e}");
        }
        // Nesting and size limits.
        let deep = format!("{}{}", "<a>".repeat(100), "</a>".repeat(100));
        assert!(parse(deep.as_bytes()).unwrap_err().contains("nested"));
        assert!(parse(&vec![b' '; MAX_SVD + 1]).unwrap_err().contains("larger"));
        // A huge `dim` does not allocate.
        let big = SAMPLE.replace("<dim>2</dim><dimIncrement>4</dimIncrement>", "<dim>999999999</dim><dimIncrement>4</dimIncrement>");
        assert!(parse(big.as_bytes()).unwrap_err().contains("dim"));
        // Garbage bytes do not panic.
        let _ = parse(&[0xff, 0xfe, b'<', 0x80, b'>', 0, 1, 2]);
    }

    #[test]
    fn numbers_entities_and_attributes() {
        assert_eq!(number("0x10"), Some(16));
        assert_eq!(number(" 42 "), Some(42));
        assert_eq!(number("#101"), Some(5));
        assert_eq!(number("zz"), None);
        assert_eq!(unescape("a &lt; b &amp;&amp; c"), "a < b && c");
        assert_eq!(attributes(r#" a="1" b='x y'"#), vec![("a".into(), "1".into()), ("b".into(), "x y".into())]);
    }
}
