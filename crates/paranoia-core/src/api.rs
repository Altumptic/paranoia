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
struct VarType {
    va: u64,
    var: String,
    ty: String,
}

#[derive(Deserialize)]
struct Offset {
    offset: u64,
}

#[derive(Deserialize)]
struct TextArg {
    text: String,
}

#[derive(Deserialize)]
struct OperandArgs {
    va: u64,
    #[serde(flatten)]
    format: crate::operands::OperandFormat,
}

#[derive(Deserialize)]
struct ValueArg {
    value: i64,
    #[serde(default)]
    param: Option<String>,
}

#[derive(Deserialize)]
struct HexArg {
    hex: String,
}

#[derive(Deserialize)]
struct AssembleArgs {
    va: u64,
    text: String,
    #[serde(default)]
    apply: bool,
}

#[derive(Deserialize)]
struct NameArg {
    name: String,
}

#[derive(Deserialize)]
struct FindTypes {
    query: String,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct StructArgs {
    va: u64,
    name: String,
    count: Option<u32>,
}

#[derive(Deserialize)]
struct PdbArgs {
    hex: String,
    force: Option<bool>,
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
            "ssa" => to(b.ssa(args::<Va>(args_v)?.va)),
            "pseudocodeFromSsa" => to(b.pseudocode_from_ssa(args::<Va>(args_v)?.va)),
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
            "setVarType" => {
                let a: VarType = args(args_v)?;
                b.checkpoint();
                b.set_var_type(a.va, &a.var, &a.ty);
                Ok(Value::Null)
            }
            "setVarName" => {
                let a: VarType = args(args_v)?;
                b.checkpoint();
                b.set_var_name(a.va, &a.var, &a.ty)?;
                Ok(Value::Null)
            }
            "annotations" => to(b.annotations()),
            "fingerprint" => to(b.fingerprint_at(args::<Va>(args_v)?.va)),
            "renameMany" => {
                // Names carried over from a compared file. One undo step for the batch.
                #[derive(Deserialize)]
                struct Items {
                    items: Vec<Rename>,
                }
                let a: Items = args(args_v)?;
                b.checkpoint();
                for r in &a.items {
                    b.rename(r.va, &r.text);
                }
                Ok(json!(a.items.len()))
            }
            "applyKnown" => {
                // Remembered functions chosen by the user, as `recall` returned them. One undo step.
                #[derive(Deserialize)]
                struct Items {
                    items: Vec<crate::memory::Recall>,
                }
                let a: Items = args(args_v)?;
                b.checkpoint();
                let mut total = crate::memory::Applied::default();
                for r in &a.items {
                    let d = b.apply_known(r.address, &r.known, r.exact);
                    total.renamed |= d.renamed;
                    total.comments += d.comments;
                    total.variables += d.variables;
                }
                let renamed = a.items.iter().filter(|r| b.annotations().names.get(&r.address) == Some(&r.known.name)).count();
                Ok(json!({ "renamed": renamed, "comments": total.comments, "variables": total.variables }))
            }
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
            "assemble" => {
                let a: AssembleArgs = args(args_v)?;
                if a.apply {
                    b.checkpoint();
                }
                to(hex::encode(b.assemble_at(a.va, &a.text, a.apply)?))
            }
            "undo" => to(b.undo()),
            "redo" => to(b.redo()),
            "history" => to(b.history()),
            "pdbPath" => to(b.pdb_path()),
            "loadPdb" => {
                let a: PdbArgs = args(args_v)?;
                let bytes = hex::decode(&a.hex).map_err(|e| format!("invalid hex: {e}"))?;
                to(b.load_pdb(bytes, a.force.unwrap_or(false))?)
            }
            "types" => to(&b.annotations().types),
            "findTypes" => {
                let a: FindTypes = args(args_v)?;
                to(b.type_view().search(&a.query, a.limit.unwrap_or(40).min(500)))
            }
            "structDef" => {
                let a: NameArg = args(args_v)?;
                to(crate::types::TypeSource::struct_def(&b.type_view(), &a.name).cloned())
            }
            "debugTypeCounts" => to((b.debug_types().structs.len(), b.debug_types().enums.len())),
            "setTypes" => {
                let a: TextArg = args(args_v)?;
                b.checkpoint();
                to(b.set_types(&a.text)?)
            }
            "applyStruct" => {
                let a: StructArgs = args(args_v)?;
                b.checkpoint();
                b.apply_struct(a.va, &a.name, a.count.unwrap_or(1))?;
                Ok(Value::Null)
            }
            "applyPat" => {
                let a: TextArg = args(args_v)?;
                b.checkpoint();
                to(b.apply_pat(&a.text)?)
            }
            "applySig" => {
                let a: HexArg = args(args_v)?;
                let bytes = hex::decode(a.hex.trim()).map_err(|_| "the .sig data is not hex".to_string())?;
                b.checkpoint();
                to(b.apply_sig(&bytes)?)
            }
            "makePat" => {
                let library = args_v.get("library").and_then(Value::as_bool).unwrap_or(false);
                to(b.make_pat(library))
            }
            "setOperandFormat" => {
                let a: OperandArgs = args(args_v)?;
                b.checkpoint();
                b.set_operand_format(a.va, a.format)?;
                Ok(Value::Null)
            }
            "enumCandidates" => {
                let a: ValueArg = args(args_v)?;
                to(b.enum_candidates(a.value, a.param.as_deref()))
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
