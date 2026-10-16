//! Jump-table (`switch`) recovery for x86 / x86-64.
//!
//! Recognized shapes, ending in an indirect `jmp`:
//!
//! * absolute table: `jmp [table + idx*4|8]`
//! * MSVC x64: `lea rB, __ImageBase` … `mov eT, [rB + idx*4 + tableRVA]` … `add rT, rB` … `jmp rT`
//! * GCC/Clang PIC: `lea rB, [rip+table]` … `movsxd rT, [rB + idx*4]` … `add rT, rB` … `jmp rT`
//!
//! The case count comes from a dominating `cmp idx, N` + `ja` when it is in the
//! same block, otherwise entries are read until one stops looking like code.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::analysis::CodeSource;

const MAX_CASES: usize = 1024;

pub struct Switch {
    pub table: u64,
    pub targets: Vec<u64>,
}

fn decode_block(src: &dyn CodeSource, bits: u32, start: u64, end: u64) -> Vec<Instruction> {
    let Some(bytes) = src.code_at(start) else { return Vec::new() };
    let len = ((end - start) as usize).min(bytes.len());
    let mut d = Decoder::with_ip(bits, &bytes[..len], start, DecoderOptions::NONE);
    let mut v = Vec::new();
    while d.can_decode() {
        let i = d.decode();
        if i.is_invalid() {
            break;
        }
        v.push(i);
    }
    v
}

fn read_u32(src: &dyn CodeSource, va: u64) -> Option<u32> {
    let b = src.read_at(va)?;
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

fn read_u64(src: &dyn CodeSource, va: u64) -> Option<u64> {
    let b = src.read_at(va)?;
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

/// `cmp idx, N` followed by `ja`/`jae` in the block gives the number of cases.
fn case_limit(insns: &[Instruction]) -> Option<usize> {
    for w in insns.windows(2) {
        let (c, j) = (&w[0], &w[1]);
        if c.mnemonic() == Mnemonic::Cmp
            && c.op_kind(0) == OpKind::Register
            && matches!(
                c.op_kind(1),
                OpKind::Immediate8to32 | OpKind::Immediate32 | OpKind::Immediate8 | OpKind::Immediate8to64 | OpKind::Immediate32to64
            )
        {
            let n = c.immediate(1) as usize;
            match j.mnemonic() {
                Mnemonic::Ja => return Some(n + 1),
                Mnemonic::Jae => return Some(n),
                _ => {}
            }
        }
    }
    None
}

pub fn recover(src: &dyn CodeSource, bits: u32, block_start: u64, jmp_va: u64, jmp_len: u64) -> Option<Switch> {
    let insns = decode_block(src, bits, block_start, jmp_va + jmp_len);
    let jmp = insns.last()?;
    if jmp.mnemonic() != Mnemonic::Jmp {
        return None;
    }
    let limit = case_limit(&insns).unwrap_or(MAX_CASES).min(MAX_CASES);
    let valid = |t: u64| src.code_at(t).is_some() && t.abs_diff(jmp_va) < 0x10_0000;

    // Absolute table: jmp [table + idx*scale]
    if jmp.op_kind(0) == OpKind::Memory && jmp.memory_base() == Register::None && jmp.memory_index() != Register::None {
        let table = jmp.memory_displacement64() & if bits == 32 { 0xffff_ffff } else { u64::MAX };
        let scale = jmp.memory_index_scale() as u64;
        let mut targets = Vec::new();
        for i in 0..limit as u64 {
            let t = if scale == 8 { read_u64(src, table + i * 8) } else { read_u32(src, table + i * 4).map(u64::from) };
            match t {
                Some(t) if valid(t) => targets.push(t),
                _ => break,
            }
        }
        return (!targets.is_empty()).then_some(Switch { table, targets });
    }

    // Register jump: find `add rT, rB` and the load feeding rT.
    if jmp.op_kind(0) != OpKind::Register {
        return None;
    }
    let rt = jmp.op_register(0).full_register();
    let n = insns.len();
    let add = insns[..n - 1].iter().rposition(|i| {
        i.mnemonic() == Mnemonic::Add
            && i.op_kind(0) == OpKind::Register
            && i.op_register(0).full_register() == rt
            && i.op_kind(1) == OpKind::Register
    })?;
    let rb = insns[add].op_register(1).full_register();
    // The base register's value: a RIP-relative lea.
    let base = insns[..add]
        .iter()
        .rev()
        .find(|i| i.mnemonic() == Mnemonic::Lea && i.op_register(0).full_register() == rb && i.is_ip_rel_memory_operand())?
        .ip_rel_memory_address();
    // The load into rT: [rB + idx*4 + disp]
    let load = insns[..add].iter().rev().find(|i| {
        matches!(i.mnemonic(), Mnemonic::Mov | Mnemonic::Movsxd)
            && i.op_kind(0) == OpKind::Register
            && i.op_register(0).full_register() == rt
            && i.op_kind(1) == OpKind::Memory
    })?;
    if load.memory_base().full_register() != rb || load.memory_index() == Register::None || load.memory_index_scale() != 4 {
        return None;
    }
    let table = base.wrapping_add(load.memory_displacement64());
    let signed = load.mnemonic() == Mnemonic::Movsxd;
    let mut targets = Vec::new();
    for i in 0..limit as u64 {
        let Some(e) = read_u32(src, table + i * 4) else { break };
        // MSVC stores RVAs (unsigned, added to __ImageBase); PIC tables store signed offsets.
        let t = if signed { base.wrapping_add(e as i32 as i64 as u64) } else { base.wrapping_add(e as u64) };
        if !valid(t) {
            break;
        }
        targets.push(t);
    }
    (!targets.is_empty()).then_some(Switch { table, targets })
}
