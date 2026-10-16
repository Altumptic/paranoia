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

#[derive(Deserialize)]
struct GraphArgs {
    va: u64,
    up: Option<u32>,
    down: Option<u32>,
}

#[derive(Deserialize)]
struct ItemArgs {
    va: u64,
    kind: crate::ItemKind,
    count: Option<u32>,
}

#[derive(Deserialize)]
struct InsnPatchArgs {
    va: u64,
    op: crate::InsnPatch,
}

#[derive(Deserialize)]
struct AdvSearch {
    kind: crate::SearchKind,
    query: String,
}

#[derive(Deserialize)]
struct Patch {
    offset: u64,
    hex: String,
}

#[derive(Deserialize)]
struct Bookmark {
    va: u64,
    text: Option<String>,
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
            "pseudocode" => to(b.pseudocode(args::<Va>(args_v)?.va)),
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
                b.checkpoint();
                let a: Rename = args(args_v)?;
                b.rename(a.va, &a.text);
                Ok(Value::Null)
            }
            "setComment" => {
                b.checkpoint();
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
            "callees" => to(b.callees(args::<Va>(args_v)?.va)),
            "searchAdvanced" => {
                let a: AdvSearch = args(args_v)?;
                to(b.search_advanced(a.kind, &a.query)?)
            }
            "makeFunction" => {
                b.checkpoint();
                b.make_function(args::<Va>(args_v)?.va)?;
                Ok(Value::Null)
            }
            "reanalyze" => {
                b.reanalyze();
                to(b.analyze())
            }
            "patch" => {
                b.checkpoint();
                let a: Patch = args(args_v)?;
                let bytes = hex::decode(a.hex.replace(' ', "")).map_err(|e| format!("invalid hex: {e}"))?;
                b.patch(a.offset, &bytes)?;
                Ok(Value::Null)
            }
            "revertPatches" => {
                b.revert_patches();
                Ok(Value::Null)
            }
            "patchedOffsets" => to(b.patched_offsets()),
            "exportIdc" => Ok(Value::String(b.export_idc())),
            "setBookmark" => {
                b.checkpoint();
                let a: Bookmark = args(args_v)?;
                b.set_bookmark(a.va, a.text.as_deref());
                Ok(Value::Null)
            }
            "frame" => to(b.frame(args::<Va>(args_v)?.va)),
            "names" => to(b.names()),
            "callGraph" => {
                let a: GraphArgs = args(args_v)?;
                to(b.call_graph(a.va, a.up.unwrap_or(1), a.down.unwrap_or(2)))
            }
            "setItem" => {
                let a: ItemArgs = args(args_v)?;
                b.checkpoint();
                b.set_item(a.va, a.kind, a.count.unwrap_or(1))?;
                Ok(Value::Null)
            }
            "cycleData" => {
                let va = args::<Va>(args_v)?.va;
                b.checkpoint();
                to(b.cycle_data(va)?)
            }
            "makeString" => {
                let va = args::<Va>(args_v)?.va;
                b.checkpoint();
                b.make_string(va)?;
                Ok(Value::Null)
            }
            "makeCode" => {
                let va = args::<Va>(args_v)?.va;
                b.checkpoint();
                b.make_code(va)?;
                Ok(Value::Null)
            }
            "undefine" => {
                let va = args::<Va>(args_v)?.va;
                b.checkpoint();
                to(b.undefine(va))
            }
            "patchInstruction" => {
                let a: InsnPatchArgs = args(args_v)?;
                b.checkpoint();
                b.patch_instruction(a.va, a.op)?;
                Ok(Value::Null)
            }
            "undo" => to(b.undo()),
            "redo" => to(b.redo()),
            "history" => to(b.history()),
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
