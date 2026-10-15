//! Auto-analysis: recursive-descent function discovery, basic blocks and
//! cross references.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::disasm::{Decoded, Disassembler};
use crate::loader::Seed;
use crate::model::{BasicBlock, Edge, EdgeKind, Flow, FunctionSource, XrefKind};

/// Hard limits keep analysis responsive on huge or hostile inputs.
const MAX_FUNCTIONS: usize = 200_000;
const MAX_INSNS_PER_FUNCTION: usize = 60_000;
const MAX_TOTAL_INSNS: usize = 6_000_000;

/// Imports that never return; code after a call to them is not followed.
const NORETURN: &[&str] = &[
    "ExitProcess", "ExitThread", "FreeLibraryAndExitThread", "RaiseException", "RtlExitUserProcess", "RtlExitUserThread",
    "TerminateProcess", "_exit", "_Exit", "exit", "abort", "__assert_fail", "__stack_chk_fail", "__cxa_throw",
    "_CxxThrowException", "__fortify_fail", "err", "errx", "longjmp", "_longjmp", "siglongjmp", "pthread_exit",
    "__security_check_cookie_fail", "__report_gsfailure", "_invalid_parameter_noinfo_noreturn", "std::terminate",
    "objc_terminate", "__libc_start_main",
];

#[derive(Debug, Clone)]
pub struct Function {
    pub address: u64,
    pub source: FunctionSource,
    pub blocks: Vec<BasicBlock>,
    pub instructions: usize,
    pub calls: Vec<u64>,
    /// For `jmp [import]` thunks: the import slot being forwarded to.
    pub thunk_slot: Option<u64>,
    pub end: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct XrefRec {
    pub from: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Default)]
pub struct Analysis {
    pub functions: Vec<Function>,
    /// Function start -> index into `functions`.
    pub by_start: HashMap<u64, usize>,
    /// Block start -> (block end, function index), for "which function contains X".
    pub block_index: BTreeMap<u64, (u64, usize)>,
    /// Target -> references to it.
    pub xrefs: HashMap<u64, Vec<XrefRec>>,
    pub instruction_count: usize,
    pub block_count: usize,
}

impl Analysis {
    pub fn function_containing(&self, va: u64) -> Option<&Function> {
        let (_, &(end, idx)) = self.block_index.range(..=va).next_back()?;
        (va < end).then(|| &self.functions[idx])
    }
}

/// Memory access needed by the analyzer.
pub trait CodeSource {
    /// Bytes readable at `va` (up to the end of its mapping), only for executable memory.
    fn code_at(&self, va: u64) -> Option<&[u8]>;
    /// Import name if `va` is an import slot.
    fn import_at(&self, va: u64) -> Option<&str>;
}

pub fn run(src: &dyn CodeSource, dis: &mut Disassembler, seeds: &[Seed], arm: bool) -> Analysis {
    let mut a = Analysis::default();
    let noreturn: BTreeSet<&str> = NORETURN.iter().copied().collect();

    // Seed queue, deduplicated, preferring the most informative source per address.
    let mut known: HashMap<u64, Seed> = HashMap::new();
    for s in seeds {
        if src.code_at(s.address).is_none() {
            continue;
        }
        let entry = known.entry(s.address).or_insert(*s);
        if entry.end.is_none() {
            entry.end = s.end;
        }
        if priority(s.source) < priority(entry.source) {
            entry.source = s.source;
        }
    }
    let mut queue: VecDeque<Seed> = {
        let mut v: Vec<Seed> = known.values().copied().collect();
        v.sort_by_key(|s| (priority(s.source), s.address));
        v.into()
    };
    let mut queued: BTreeSet<u64> = known.keys().copied().collect();
    let mut noreturn_funcs: BTreeSet<u64> = BTreeSet::new();

    while let Some(seed) = queue.pop_front() {
        if a.functions.len() >= MAX_FUNCTIONS || a.instruction_count >= MAX_TOTAL_INSNS {
            break;
        }
        if a.by_start.contains_key(&seed.address) {
            continue;
        }
        let Some(f) = explore(src, dis, seed, &queued, &noreturn, &noreturn_funcs, arm, &mut a.xrefs) else { continue };

        // Single-instruction jump through an import slot = thunk to a no-return import?
        if let Some(slot) = f.thunk_slot {
            if src.import_at(slot).is_some_and(|n| noreturn.contains(strip_decoration(n))) {
                noreturn_funcs.insert(f.address);
            }
        }
        for &c in &f.calls {
            if queued.insert(c) && src.code_at(c).is_some() {
                queue.push_back(Seed { address: c, source: FunctionSource::Call, end: None });
            }
        }
        let idx = a.functions.len();
        for b in &f.blocks {
            a.block_index.entry(b.start).or_insert((b.end, idx));
        }
        a.instruction_count += f.instructions;
        a.block_count += f.blocks.len();
        a.by_start.insert(f.address, idx);
        a.functions.push(f);
    }
    a.functions.iter_mut().for_each(|f| f.calls.sort_unstable());
    a
}

fn priority(s: FunctionSource) -> u8 {
    match s {
        FunctionSource::User => 0,
        FunctionSource::Entry => 1,
        FunctionSource::Export => 2,
        FunctionSource::Symbol => 3,
        FunctionSource::ExceptionTable => 4,
        FunctionSource::Call => 5,
    }
}

/// Removes leading underscores / `__imp_` so `_exit` and `exit` compare loosely.
fn strip_decoration(n: &str) -> &str {
    let n = n.strip_prefix("__imp_").unwrap_or(n);
    n.split('@').next().unwrap_or(n)
}

struct Insn {
    len: u8,
    d: Decoded,
}

#[allow(clippy::too_many_arguments)]
fn explore(
    src: &dyn CodeSource,
    dis: &mut Disassembler,
    seed: Seed,
    other_functions: &BTreeSet<u64>,
    noreturn: &BTreeSet<&str>,
    noreturn_funcs: &BTreeSet<u64>,
    arm: bool,
    xrefs: &mut HashMap<u64, Vec<XrefRec>>,
) -> Option<Function> {
    let start = seed.address;
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::from([start]);
    let mut edges: HashMap<u64, Vec<Edge>> = HashMap::new(); // keyed by the terminating instruction
    let mut calls: BTreeSet<u64> = BTreeSet::new();
    let mut work = vec![start];
    let in_bounds = |va: u64| seed.end.is_none_or(|end| va >= start && va < end);

    while let Some(block_start) = work.pop() {
        let mut va = block_start;
        dis.reset();
        loop {
            if insns.contains_key(&va) {
                leaders.insert(va);
                break;
            }
            if insns.len() >= MAX_INSNS_PER_FUNCTION {
                break;
            }
            let Some(bytes) = src.code_at(va) else { break };
            let d = dis.decode(bytes, va);
            if !d.valid {
                if va == start {
                    return None;
                }
                break;
            }
            insns.insert(va, Insn { len: d.len, d });
            let next = va + d.len as u64;

            if let Some(r) = d.data_ref {
                xrefs.entry(r).or_default().push(XrefRec { from: va, kind: XrefKind::Data });
            }
            if let Some(slot) = d.indirect_slot {
                let kind = if d.flow == Flow::Call { XrefKind::Call } else { XrefKind::Jump };
                xrefs.entry(slot).or_default().push(XrefRec { from: va, kind });
            }

            match d.flow {
                Flow::None => {}
                Flow::Call => {
                    let mut returns = true;
                    if let Some(t) = d.target {
                        xrefs.entry(t).or_default().push(XrefRec { from: va, kind: XrefKind::Call });
                        if src.code_at(t).is_some() {
                            calls.insert(t);
                        }
                        returns &= !noreturn_funcs.contains(&t);
                    }
                    if let Some(slot) = d.indirect_slot {
                        if let Some(name) = src.import_at(slot) {
                            returns &= !noreturn.contains(strip_decoration(name));
                        }
                    }
                    if !returns {
                        break;
                    }
                }
                Flow::Jump => {
                    if let Some(t) = d.target {
                        xrefs.entry(t).or_default().push(XrefRec { from: va, kind: XrefKind::Jump });
                        // Jumping to another function's start (or outside known bounds) is a tail call.
                        let tail = (t != start && other_functions.contains(&t)) || !in_bounds(t) || src.code_at(t).is_none();
                        if tail {
                            if src.code_at(t).is_some() && t != start {
                                calls.insert(t);
                            }
                        } else {
                            edges.entry(va).or_default().push(Edge { to: t, kind: EdgeKind::Uncond });
                            leaders.insert(t);
                            work.push(t);
                        }
                    }
                    break;
                }
                Flow::CondJump => {
                    if let Some(t) = d.target {
                        xrefs.entry(t).or_default().push(XrefRec { from: va, kind: XrefKind::Jump });
                        if src.code_at(t).is_some() {
                            edges.entry(va).or_default().push(Edge { to: t, kind: EdgeKind::True });
                            leaders.insert(t);
                            work.push(t);
                        }
                    }
                    edges.entry(va).or_default().push(Edge { to: next, kind: EdgeKind::False });
                    leaders.insert(next);
                    work.push(next);
                    break;
                }
                Flow::Ret | Flow::Interrupt => break,
            }
            // On ARM, a known function start right after us means we ran into the next function.
            if arm && next != start && other_functions.contains(&next) {
                break;
            }
            va = next;
        }
    }
    if insns.is_empty() {
        return None;
    }

    // Split into basic blocks.
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut cur: Option<BasicBlock> = None;
    let mut prev_end = 0u64;
    for (&va, ins) in &insns {
        let starts_new = leaders.contains(&va) || va != prev_end || cur.is_none();
        if starts_new {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            cur = Some(BasicBlock { start: va, end: va, succs: Vec::new() });
        }
        let b = cur.as_mut().unwrap();
        b.end = va + ins.len as u64;
        if let Some(e) = edges.get(&va) {
            b.succs.extend(e.iter().cloned());
        }
        prev_end = b.end;
        // A block also ends after any control transfer even if the next address isn't a leader.
        if ins.d.ends_block() {
            blocks.push(cur.take().unwrap());
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    // Fallthrough edges into a following leader.
    let starts: BTreeSet<u64> = blocks.iter().map(|b| b.start).collect();
    for b in &mut blocks {
        if b.succs.is_empty() {
            let last = insns.range(..b.end).next_back().map(|(_, i)| i.d);
            if last.is_some_and(|d| !d.ends_block() && d.flow != Flow::Interrupt) && starts.contains(&b.end) {
                b.succs.push(Edge { to: b.end, kind: EdgeKind::Fall });
            }
        }
    }

    // `jmp [slot]` as the very first instruction marks an import thunk.
    let first = insns.get(&start).map(|i| i.d);
    let thunk_slot = first.filter(|d| d.flow == Flow::Jump).and_then(|d| d.indirect_slot).filter(|s| src.import_at(*s).is_some());

    let end = insns.iter().next_back().map(|(va, i)| va + i.len as u64).unwrap_or(start);
    Some(Function {
        address: start,
        source: seed.source,
        instructions: insns.len(),
        blocks,
        calls: calls.into_iter().collect(),
        thunk_slot,
        end,
    })
}
