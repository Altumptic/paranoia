//! Navigation helpers: the names window, call graphs, instruction-level patches
//! and annotation undo / redo.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::model::{Arch, XrefKind};
use crate::{Annotations, Binary};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameEntry {
    pub address: u64,
    pub name: String,
    /// function, import, export, label, data, string, user
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallNode {
    pub address: u64,
    pub name: String,
    /// root, caller, callee, import
    pub kind: String,
    pub depth: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub root: u64,
    pub nodes: Vec<CallNode>,
    pub edges: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InsnPatch {
    /// Replace the instruction with NOPs.
    Nop,
    /// Flip a conditional branch (jz ↔ jnz, b.eq ↔ b.ne, cbz ↔ cbnz).
    Invert,
    /// Make a conditional branch unconditional.
    Jmp,
}

const MAX_UNDO: usize = 200;

impl Binary {
    /// Every named address: functions, imports, exports, user names and auto-named data.
    pub fn names(&self) -> Vec<NameEntry> {
        let mut out: BTreeMap<u64, NameEntry> = BTreeMap::new();
        let mut put = |address: u64, name: String, kind: &str| {
            out.entry(address).or_insert(NameEntry { address, name, kind: kind.into() });
        };
        for (va, n) in &self.annotations.names {
            put(*va, n.clone(), "user");
        }
        for f in self.functions() {
            put(f.address, f.name, "function");
        }
        for i in &self.info.imports {
            if i.address != 0 {
                put(i.address, self.name_at(i.address).unwrap_or_else(|| i.name.clone()), "import");
            }
        }
        for e in &self.info.exports {
            if e.address != 0 {
                put(e.address, self.name_at(e.address).unwrap_or_else(|| e.name.clone()), "export");
            }
        }
        for (va, n) in &self.static_names {
            put(*va, n.clone(), "label");
        }
        if let Some(a) = &self.analysis {
            for (va, refs) in &a.xrefs {
                if refs.iter().any(|r| r.kind == XrefKind::Data) && !out.contains_key(va) {
                    if let Some(n) = self.auto_data_name(*va) {
                        let kind = if self.string_by_va.contains_key(va) { "string" } else { "data" };
                        out.insert(*va, NameEntry { address: *va, name: n, kind: kind.into() });
                    }
                }
            }
        }
        for va in self.annotations.items.keys() {
            if !out.contains_key(va) {
                if let Some(n) = self.auto_data_name(*va) {
                    out.insert(*va, NameEntry { address: *va, name: n, kind: "data".into() });
                }
            }
        }
        out.into_values().collect()
    }

    /// Callers (up to `up` levels) and callees (up to `down` levels) around a function.
    pub fn call_graph(&self, va: u64, up: u32, down: u32) -> Option<CallGraph> {
        const MAX_NODES: usize = 80;
        let a = self.analysis.as_ref()?;
        let root = a.functions[self.function_index_containing(va)?].address;
        let mut nodes: BTreeMap<u64, CallNode> = BTreeMap::new();
        let mut edges: BTreeSet<(u64, u64)> = BTreeSet::new();
        nodes.insert(root, CallNode { address: root, name: self.name_at(root).unwrap_or_default(), kind: "root".into(), depth: 0 });

        // Callees.
        let mut q = VecDeque::from([(root, 0u32)]);
        while let Some((f, d)) = q.pop_front() {
            if d >= down || nodes.len() >= MAX_NODES {
                continue;
            }
            for c in self.callees(f) {
                edges.insert((f, c.address));
                if !nodes.contains_key(&c.address) && nodes.len() < MAX_NODES {
                    let kind = if c.is_import { "import" } else { "callee" };
                    nodes.insert(c.address, CallNode { address: c.address, name: c.name, kind: kind.into(), depth: d as i32 + 1 });
                    if !c.is_import {
                        q.push_back((c.address, d + 1));
                    }
                }
            }
        }
        // Callers.
        let mut q = VecDeque::from([(root, 0u32)]);
        while let Some((f, d)) = q.pop_front() {
            if d >= up || nodes.len() >= MAX_NODES {
                continue;
            }
            let callers: BTreeSet<u64> = a
                .xrefs
                .get(&f)
                .map(|r| {
                    r.iter().filter(|x| x.kind == XrefKind::Call).filter_map(|x| a.function_containing(x.from).map(|g| g.address)).collect()
                })
                .unwrap_or_default();
            for c in callers {
                edges.insert((c, f));
                if !nodes.contains_key(&c) && nodes.len() < MAX_NODES {
                    nodes.insert(
                        c,
                        CallNode { address: c, name: self.name_at(c).unwrap_or_default(), kind: "caller".into(), depth: -(d as i32) - 1 },
                    );
                    q.push_back((c, d + 1));
                }
            }
        }
        let edges = edges.into_iter().filter(|(x, y)| nodes.contains_key(x) && nodes.contains_key(y)).collect();
        Some(CallGraph { root, nodes: nodes.into_values().collect(), edges })
    }

    /// Patches the instruction at `va` (x86/x64 and AArch64).
    pub fn patch_instruction(&mut self, va: u64, op: InsnPatch) -> Result<(), String> {
        let off = self.va_to_offset(va).ok_or("address has no file bytes")?;
        let ins = self.listing(va, 1).map_err(|e| e.to_string())?.into_iter().next().ok_or("no instruction here")?;
        let bytes = hex::decode(&ins.bytes).map_err(|e| e.to_string())?;
        let len = ins.size as usize;
        if bytes.len() < len || len == 0 {
            return Err("cannot patch a data item".into());
        }
        let new: Vec<u8> = match self.info.arch {
            Arch::X86 | Arch::X86_64 => match op {
                InsnPatch::Nop => vec![0x90; len],
                InsnPatch::Invert => match bytes.as_slice() {
                    [b, rest @ ..] if (0x70..=0x7f).contains(b) => [&[b ^ 1], rest].concat(),
                    [0x0f, b, rest @ ..] if (0x80..=0x8f).contains(b) => [&[0x0f, b ^ 1], rest].concat(),
                    _ => return Err("not a conditional jump".into()),
                },
                InsnPatch::Jmp => match bytes.as_slice() {
                    [b, rel] if (0x70..=0x7f).contains(b) => vec![0xeb, *rel],
                    [0x0f, b, r0, r1, r2, r3] if (0x80..=0x8f).contains(b) => {
                        // jcc rel32 (6 bytes) → jmp rel32 (5 bytes) + nop; the displacement grows by one.
                        let rel = i32::from_le_bytes([*r0, *r1, *r2, *r3]).wrapping_add(1);
                        let mut v = vec![0xe9];
                        v.extend_from_slice(&rel.to_le_bytes());
                        v.push(0x90);
                        v
                    }
                    _ => return Err("not a conditional jump".into()),
                },
            },
            Arch::Arm64 if len == 4 => {
                let w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let is_bcond = w & 0xff00_0010 == 0x5400_0000;
                let is_cb = w & 0x7e00_0000 == 0x3400_0000; // cbz / cbnz
                let is_tb = w & 0x7e00_0000 == 0x3600_0000; // tbz / tbnz
                let out = match op {
                    InsnPatch::Nop => 0xd503_201f,
                    InsnPatch::Invert if is_bcond => w ^ 1,
                    InsnPatch::Invert if is_cb || is_tb => w ^ (1 << 24),
                    InsnPatch::Jmp if is_bcond => {
                        let imm19 = ((w >> 5) & 0x7ffff) as i32;
                        let off = (imm19 << 13) >> 13; // sign-extend
                        0x1400_0000 | ((off as u32) & 0x03ff_ffff)
                    }
                    _ => return Err("not a conditional branch".into()),
                };
                out.to_le_bytes().to_vec()
            }
            _ => return Err("patching is not supported for this architecture".into()),
        };
        self.patch(off, &new)
    }

    // --------------------------------------------------------------------------------------------
    // Undo / redo
    // --------------------------------------------------------------------------------------------

    /// Records the current annotations before a change.
    pub fn checkpoint(&mut self) {
        self.undo_stack.push(self.annotations.clone());
        if self.undo_stack.len() > MAX_UNDO {
            self.undo_stack.remove(0);
        }
        self.redo_stack.clear();
    }

    /// Returns `Some(reanalyzed)` when there was something to undo.
    pub fn undo(&mut self) -> Option<bool> {
        let prev = self.undo_stack.pop()?;
        let cur = self.annotations.clone();
        self.redo_stack.push(cur);
        Some(self.restore(prev))
    }

    pub fn redo(&mut self) -> Option<bool> {
        let next = self.redo_stack.pop()?;
        self.undo_stack.push(self.annotations.clone());
        Some(self.restore(next))
    }

    pub fn history(&self) -> (usize, usize) {
        (self.undo_stack.len(), self.redo_stack.len())
    }

    /// Applies a snapshot, re-running analysis only when function definitions changed.
    fn restore(&mut self, a: Annotations) -> bool {
        let reanalyze = a.functions != self.annotations.functions || a.undefined != self.annotations.undefined;
        self.revert_patches();
        self.annotations = a;
        self.apply_saved_patches();
        if reanalyze {
            self.reanalyze();
        }
        reanalyze
    }
}
