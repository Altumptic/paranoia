//! Stack frame recovery (IDA's frame view): local variables and arguments
//! addressed through the stack or frame pointer.

use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::model::Arch;
use crate::Binary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameVar {
    /// Offset from the base register (negative below a frame pointer).
    pub offset: i64,
    pub name: String,
    /// Largest access size seen, in bytes.
    pub size: u32,
    pub reads: u32,
    pub writes: u32,
    /// First instruction that touches the slot.
    pub first_use: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub address: u64,
    /// `rsp`, `rbp`, `esp` or `ebp`.
    pub base: String,
    /// Bytes reserved by `sub rsp, N` (0 when unknown).
    pub local_size: u64,
    /// Callee-saved registers pushed in the prologue.
    pub saved: Vec<String>,
    pub vars: Vec<FrameVar>,
}

fn is_write(m: Mnemonic) -> bool {
    !matches!(m, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push | Mnemonic::Bt)
}

impl Binary {
    pub fn frame(&self, va: u64) -> Option<Frame> {
        if !matches!(self.info.arch, Arch::X86 | Arch::X86_64) {
            return None;
        }
        let bits = if self.info.arch == Arch::X86 { 32 } else { 64 };
        let a = self.analysis.as_ref()?;
        let f = &a.functions[self.function_index_containing(va)?];

        let mut frame_reg = None;
        let mut local_size = 0u64;
        let mut saved = Vec::new();
        let mut slots: BTreeMap<(Register, i64), FrameVar> = BTreeMap::new();

        let mut blocks: Vec<_> = f.blocks.iter().collect();
        blocks.sort_by_key(|b| b.start);
        for (bi, b) in blocks.iter().enumerate() {
            let bytes = self.bytes_at(b.start)?;
            let len = ((b.end - b.start) as usize).min(bytes.len());
            let mut d = Decoder::with_ip(bits, &bytes[..len], b.start, DecoderOptions::NONE);
            let mut idx = 0;
            while d.can_decode() {
                let ins = d.decode();
                if ins.is_invalid() {
                    break;
                }
                // Prologue facts come from the entry block.
                if bi == 0 || b.start == f.address {
                    match ins.mnemonic() {
                        Mnemonic::Push if idx < 12 && ins.op_kind(0) == OpKind::Register => {
                            saved.push(format!("{:?}", ins.op_register(0)).to_lowercase())
                        }
                        Mnemonic::Sub
                            if ins.op_kind(0) == OpKind::Register
                                && matches!(ins.op_register(0), Register::RSP | Register::ESP)
                                && ins.op_kind(1) != OpKind::Register =>
                        {
                            local_size = local_size.max(ins.immediate(1));
                        }
                        Mnemonic::Mov
                            if ins.op_kind(0) == OpKind::Register
                                && ins.op_kind(1) == OpKind::Register
                                && matches!(ins.op_register(1), Register::RSP | Register::ESP)
                                && matches!(ins.op_register(0), Register::RBP | Register::EBP) =>
                        {
                            frame_reg = Some(ins.op_register(0));
                        }
                        _ => {}
                    }
                }
                idx += 1;
                for op in 0..ins.op_count() {
                    if ins.op_kind(op) != OpKind::Memory || ins.memory_index() != Register::None {
                        continue;
                    }
                    let base = ins.memory_base();
                    if !matches!(base, Register::RSP | Register::ESP | Register::RBP | Register::EBP) {
                        continue;
                    }
                    let off = if bits == 64 { ins.memory_displacement64() as i64 } else { ins.memory_displacement32() as i32 as i64 };
                    let size = ins.memory_size().size() as u32;
                    let e = slots.entry((base, off)).or_insert_with(|| FrameVar {
                        offset: off,
                        name: String::new(),
                        size: 0,
                        reads: 0,
                        writes: 0,
                        first_use: ins.ip(),
                    });
                    e.size = e.size.max(size);
                    e.first_use = e.first_use.min(ins.ip());
                    if op == 0 && is_write(ins.mnemonic()) && ins.mnemonic() != Mnemonic::Lea {
                        e.writes += 1;
                    } else {
                        e.reads += 1;
                    }
                }
            }
        }

        let base = frame_reg.unwrap_or(if bits == 64 { Register::RSP } else { Register::ESP });
        let mut vars: Vec<FrameVar> = slots
            .into_iter()
            .filter(|((r, _), _)| frame_reg.is_none() || *r == base || matches!(*r, Register::RSP | Register::ESP))
            .map(|((r, off), mut v)| {
                // Same naming as the pseudocode view.
                v.name = if matches!(r, Register::RSP | Register::ESP) {
                    format!("var_{off:X}")
                } else if off < 0 {
                    format!("var_{:X}", -off)
                } else {
                    format!("arg_{off:X}")
                };
                v
            })
            .collect();
        vars.sort_by_key(|v| v.offset);
        Some(Frame { address: f.address, base: format!("{base:?}").to_lowercase(), local_size, saved, vars })
    }
}
