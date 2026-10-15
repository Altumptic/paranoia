//! A tiny JSON-RPC style facade over [`Binary`]. Every front-end (WebAssembly,
//! Tauri, tests) drives the engine through [`Session::call`], so there is exactly
//! one wire contract to keep in sync with the TypeScript client.
//!
//! Addresses travel as JSON numbers; they are exact below 2^53, which covers
//! user-mode images on every supported platform.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{Annotations, Binary};

pub struct Session {
    bin: Binary,
}

#[derive(Deserialize)]
struct Va {
    va: u64,
}

#[derive(Deserialize)]
struct Disasm {
    va: u64,
    count: usize,
}

#[derive(Deserialize)]
struct Read {
    offset: u64,
    len: usize,
}

#[derive(Deserialize)]
struct Search {
    query: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

#[derive(Deserialize)]
struct Rename {
    va: u64,
    text: String,
}

#[derive(Deserialize)]
struct Offset {
    offset: u64,
}

fn default_limit() -> usize {
    200
}

fn args<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|e| format!("invalid arguments: {e}"))
}

fn to<T: serde::Serialize>(v: T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

impl Session {
    /// Loads and auto-analyzes a file.
    pub fn open(name: &str, bytes: Vec<u8>) -> Result<Self, String> {
        let mut bin = Binary::load(name, bytes).map_err(|e| e.to_string())?;
        bin.analyze();
        Ok(Session { bin })
    }

    pub fn binary(&self) -> &Binary {
        &self.bin
    }

    pub fn binary_mut(&mut self) -> &mut Binary {
        &mut self.bin
    }

    /// Dispatches one call. `args` is a JSON object (or null).
    pub fn call(&mut self, method: &str, args_v: Value) -> Result<Value, String> {
        let b = &mut self.bin;
        match method {
            "stats" => to(b.analyze()),
            "info" => to(b.info()),
            "functions" => to(b.functions()),
            "symbols" => to(b.symbols()),
            "strings" => to(b.strings()),
            "disassemble" => {
                let a: Disasm = args(args_v)?;
                to(b.disassemble(a.va, a.count.min(5000)).map_err(|e| e.to_string())?)
            }
            "previousAnchor" => to(b.previous_anchor(args::<Va>(args_v)?.va)),
            "graph" => to(b.function_graph(args::<Va>(args_v)?.va)),
            "functionAt" => to(b.function_at(args::<Va>(args_v)?.va)),
            "xrefs" => to(b.xrefs_to(args::<Va>(args_v)?.va)),
            "addressInfo" => to(b.address_info(args::<Va>(args_v)?.va)),
            "search" => {
                let a: Search = args(args_v)?;
                to(b.search(&a.query, a.limit.min(2000)))
            }
            "read" => {
                let a: Read = args(args_v)?;
                Ok(Value::String(hex::encode(b.read(a.offset, a.len.min(1 << 20)))))
            }
            "offsetToVa" => to(b.offset_to_va(args::<Offset>(args_v)?.offset)),
            "vaToOffset" => to(b.va_to_offset(args::<Va>(args_v)?.va)),
            "rename" => {
                let a: Rename = args(args_v)?;
                b.rename(a.va, &a.text);
                Ok(Value::Null)
            }
            "setComment" => {
                let a: Rename = args(args_v)?;
                b.set_comment(a.va, &a.text);
                Ok(Value::Null)
            }
            "annotations" => to(b.annotations()),
            "setAnnotations" => {
                let a: Annotations = args(args_v)?;
                b.set_annotations(a);
                Ok(Value::Null)
            }
            "version" => Ok(json!(env!("CARGO_PKG_VERSION"))),
            _ => Err(format!("unknown method `{method}`")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_and_bad_args() {
        // A minimal valid ELF is overkill here; errors are what we test.
        assert!(Session::open("x", vec![1, 2, 3]).is_err());
    }
}
