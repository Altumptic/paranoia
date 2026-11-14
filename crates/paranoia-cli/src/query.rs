//! `paranoia query`: stable, machine-readable answers for other tools (the REA
//! provider uses it). Every answer is one JSON object:
//!
//! ```json
//! {"format":"paranoia-query/1","file":{"sha256":"…","name":"…","format":"pe","arch":"x86_64","bits":64,"entry":"0x401000"},"result":…}
//! ```
//!
//! `file.sha256` lets the caller check that the bytes it asked about are the
//! bytes that were analysed. Addresses are strings, `0x` and lowercase hex with
//! no leading zeros, so they survive JSON parsers that turn numbers into doubles.
//! A selector that names nothing gives `"result": null`, not an error.
//!
//! Changing a field's meaning or removing one needs a new `format` version.

use anyhow::Result;
use paranoia_core::{Binary, XrefKind};
use serde_json::{json, Value};

pub const FORMAT: &str = "paranoia-query/1";

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

/// `0x…` is an address; anything else is a function, export or import name.
/// (Unlike the other commands, a bare word is never read as hex: `add` is a name.)
fn resolve(b: &Binary, sel: &str) -> Option<u64> {
    if let Some(h) = sel.strip_prefix("0x").or_else(|| sel.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    b.functions()
        .into_iter()
        .find(|f| f.name == sel)
        .map(|f| f.address)
        .or_else(|| b.info().exports.iter().find(|e| e.name == sel).map(|e| e.address))
        .or_else(|| b.info().imports.iter().find(|i| i.name == sel && i.address != 0).map(|i| i.address))
}

fn inventory(b: &Binary) -> Value {
    let functions: Vec<Value> = b
        .functions()
        .iter()
        .map(|f| {
            json!({
                "address": hex(f.address),
                "name": f.name,
                "size": f.size,
                "instructions": f.instructions,
                "thunk": f.is_import_thunk,
                "library": f.library,
            })
        })
        .collect();
    let imports: Vec<Value> = b
        .info()
        .imports
        .iter()
        .filter(|i| i.address != 0)
        .map(|i| json!({ "address": hex(i.address), "name": i.name, "library": i.library }))
        .collect();
    let strings: Vec<Value> = b
        .strings()
        .iter()
        .map(|s| {
            json!({
                "address": s.address.map(hex),
                "offset": hex(s.offset),
                "value": s.value,
                "encoding": s.encoding,
                "xrefs": s.xrefs,
            })
        })
        .collect();
    let pairs = |edges: Vec<(u64, u64)>| -> Vec<Value> { edges.into_iter().map(|(from, to)| json!([hex(from), hex(to)])).collect() };
    json!({
        "functions": functions,
        "imports": imports,
        "strings": strings,
        "calls": pairs(b.call_edges()),
        "tail_calls": pairs(b.tail_call_edges()),
    })
}

fn function(b: &mut Binary, sel: &str) -> Value {
    let Some(va) = resolve(b, sel) else { return Value::Null };
    let Some(f) = b.function_at(va) else { return Value::Null };
    let pseudocode = b.pseudocode(f.address).map(|p| {
        let mut out = String::new();
        for l in &p.lines {
            out.push_str(&"    ".repeat(l.indent as usize));
            out.extend(l.tokens.iter().map(|t| t.t.as_str()));
            out.push('\n');
        }
        out
    });
    let assembly = b.function_graph(f.address).map(|g| {
        let mut blocks = g.blocks;
        blocks.sort_by_key(|blk| blk.start);
        let mut out = String::new();
        for blk in &blocks {
            for i in &blk.instructions {
                if let Some(l) = &i.label {
                    out.push_str(l);
                    out.push_str(":\n");
                }
                let ops: String = i.operands.iter().map(|t| t.t.as_str()).collect();
                let comment = i.user_comment.as_ref().or(i.comment.as_ref()).map(|c| format!("  ; {c}")).unwrap_or_default();
                out.push_str(&format!("{:#x}  {:<8} {}{}\n", i.address, i.mnemonic, ops, comment).replace("  \n", "\n"));
            }
        }
        out
    });
    json!({
        "address": hex(f.address),
        "name": f.name,
        "size": f.size,
        "pseudocode": pseudocode,
        "assembly": assembly,
    })
}

fn xrefs(b: &Binary, sel: &str) -> Value {
    let Some(va) = resolve(b, sel) else { return Value::Null };
    let refs: Vec<Value> = b
        .xrefs_to(va)
        .iter()
        .map(|x| {
            json!({
                "from": hex(x.from),
                "kind": match x.kind { XrefKind::Call => "call", XrefKind::Jump => "jump", XrefKind::Data => "data" },
                "function": x.function.map(hex),
            })
        })
        .collect();
    json!({ "address": hex(va), "references": refs })
}

pub enum What {
    Inventory,
    Function(String),
    Xrefs(String),
}

/// Runs one query and prints its answer as one line of JSON.
pub fn run(file: &std::path::PathBuf, what: What) -> Result<()> {
    let mut b = super::open(file)?;
    b.analyze();
    let i = b.info();
    let header = json!({
        "sha256": i.hashes.sha256,
        "name": i.file_name,
        "format": i.format,
        "arch": i.arch,
        "bits": i.bits,
        "entry": hex(i.entry),
    });
    let result = match what {
        What::Inventory => inventory(&b),
        What::Function(sel) => function(&mut b, &sel),
        What::Xrefs(sel) => xrefs(&b, &sel),
    };
    println!("{}", serde_json::to_string(&json!({ "format": FORMAT, "file": header, "result": result }))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Binary {
        let exe = ["C:/Windows/System32/notepad.exe", "/bin/ls", "/usr/bin/true"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.is_file())
            .unwrap_or_else(|| std::env::current_exe().unwrap());
        let mut b = Binary::load("sample", std::fs::read(exe).unwrap()).unwrap();
        b.analyze();
        b
    }

    fn is_addr(v: &Value) -> bool {
        v.as_str().is_some_and(|s| {
            s.starts_with("0x")
                && s.len() > 2
                && s[2..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                && (s == "0x0" || !s[2..].starts_with('0'))
        })
    }

    #[test]
    fn inventory_function_and_xrefs_keep_the_contract() {
        let mut b = sample();
        let inv = inventory(&b);
        let funcs = inv["functions"].as_array().unwrap();
        assert!(!funcs.is_empty());
        assert!(funcs.iter().all(|f| is_addr(&f["address"]) && f["name"].is_string()));
        let starts: std::collections::HashSet<&str> = funcs.iter().filter_map(|f| f["address"].as_str()).collect();
        for c in inv["calls"].as_array().unwrap().iter().chain(inv["tail_calls"].as_array().unwrap()) {
            assert!(is_addr(&c[0]) && is_addr(&c[1]));
            assert!(starts.contains(c[0].as_str().unwrap()), "a call edge starts at a function: {c}");
        }
        // The first function by address answers by address and by name, with the same entry.
        let first = funcs.iter().find(|f| f["thunk"] == false).unwrap();
        let (addr, name) = (first["address"].as_str().unwrap().to_string(), first["name"].as_str().unwrap().to_string());
        let by_addr = function(&mut b, &addr);
        assert_eq!(by_addr["address"], addr.as_str());
        assert!(by_addr["assembly"].as_str().is_some_and(|a| a.contains(&addr)));
        assert_eq!(function(&mut b, &name)["address"], addr.as_str());
        // Nothing there: null, not an error. A bare word is a name, never hex.
        assert!(function(&mut b, "0x1").is_null());
        assert!(function(&mut b, "add").is_null() || function(&mut b, "add")["name"] == "add");
        let x = xrefs(&b, &addr);
        assert!(x["references"].as_array().unwrap().iter().all(|r| is_addr(&r["from"])));
    }
}
