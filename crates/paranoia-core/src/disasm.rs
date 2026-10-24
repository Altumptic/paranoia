//! Instruction decoding. Two layers:
//!
//! * [`decode`] — fast, allocation-free decoding used by the analysis passes
//!   (length, control flow, branch target, referenced memory).
//! * [`render`] — full formatting into highlighted tokens for the UI, with
//!   addresses resolved to names.

use std::collections::HashMap;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind, IntelFormatter, OpKind, Register, SymbolResolver,
    SymbolResult,
};
use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_arm::armv7 as a32;
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand, SizeCode};

use crate::model::{Arch, Flow, Instruction, Token, TokenKind};

/// Result of a fast decode.
#[derive(Debug, Clone, Copy)]
pub struct Decoded {
    pub len: u8,
    pub flow: Flow,
    /// Direct branch / call target.
    pub target: Option<u64>,
    /// Address of a memory operand or address-like immediate (data reference).
    pub data_ref: Option<u64>,
    /// Access size in bytes of the memory operand behind `data_ref` (0 = unknown).
    pub mem_size: u8,
    /// Indirect jump/call through a fixed memory slot (`jmp [rip+X]`, `call [X]`).
    pub indirect_slot: Option<u64>,
    pub valid: bool,
}

impl Decoded {
    fn invalid() -> Self {
        Decoded { len: 1, flow: Flow::None, target: None, data_ref: None, mem_size: 0, indirect_slot: None, valid: false }
    }

    /// Execution cannot continue to the next instruction.
    pub fn ends_block(&self) -> bool {
        matches!(self.flow, Flow::Jump | Flow::CondJump | Flow::Ret) || !self.valid
    }
}

/// Resolves addresses to display names for the renderer.
pub trait NameLookup {
    fn name_at(&self, va: u64) -> Option<String>;
}

// ------------------------------------------------------------------------------------------------
// Fast decode
// ------------------------------------------------------------------------------------------------

/// Stateful decoder. ARM64 tracks `adrp` page bases so `adrp + add/ldr` pairs
/// produce a data reference like on x86's RIP-relative operands.
pub struct Disassembler {
    arch: Arch,
    bits: u32,
    big: bool,
    /// Known register values: ARM64 `adrp` pages, RISC-V `auipc`/`lui`, MIPS `lui`.
    adrp: [Option<u64>; 32],
    /// MIPS: a branch waiting for its delay slot.
    pending: Option<(Flow, Option<u64>)>,
}

impl Disassembler {
    pub fn new(arch: Arch) -> Self {
        let bits = match arch {
            Arch::X86 => 32,
            _ => 64,
        };
        Disassembler { arch, bits, big: false, adrp: [None; 32], pending: None }
    }

    /// For architectures whose decoding depends on the image: RISC-V XLEN, MIPS width and byte order.
    pub fn with_mode(arch: Arch, bits: u8, big_endian: bool) -> Self {
        let mut d = Self::new(arch);
        if matches!(arch, Arch::RiscV | Arch::Mips) {
            d.bits = if bits == 64 { 64 } else { 32 };
        }
        d.big = big_endian;
        d
    }

    /// Forget register state (call at basic-block boundaries).
    pub fn reset(&mut self) {
        self.adrp = [None; 32];
        self.pending = None;
    }

    pub fn decode(&mut self, bytes: &[u8], va: u64) -> Decoded {
        match self.arch {
            Arch::X86 | Arch::X86_64 => decode_x86(self.bits, bytes, va),
            Arch::Arm64 => self.decode_arm64(bytes, va),
            Arch::Arm | Arch::Thumb => decode_arm32(self.arch == Arch::Thumb, bytes, va).1,
            Arch::RiscV => self.decode_riscv(bytes, va),
            Arch::Mips => self.decode_mips(bytes, va),
            _ => Decoded::invalid(),
        }
    }

    fn decode_arm64(&mut self, bytes: &[u8], va: u64) -> Decoded {
        if bytes.len() < 4 {
            return Decoded::invalid();
        }
        let mut reader = U8Reader::new(&bytes[..4]);
        let Ok(inst) = InstDecoder::default().decode(&mut reader) else {
            return Decoded { len: 4, ..Decoded::invalid() };
        };
        let pc_target = inst.operands.iter().find_map(|op| match op {
            Operand::PCOffset(o) => Some(va.wrapping_add(*o as u64)),
            _ => None,
        });
        let mut d = Decoded { len: 4, flow: Flow::None, target: None, data_ref: None, mem_size: 0, indirect_slot: None, valid: true };
        match inst.opcode {
            Opcode::B => {
                d.flow = Flow::Jump;
                d.target = pc_target;
            }
            Opcode::BL => {
                d.flow = Flow::Call;
                d.target = pc_target;
            }
            Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
                d.flow = Flow::CondJump;
                d.target = pc_target;
            }
            Opcode::BR | Opcode::BRAA | Opcode::BRAAZ | Opcode::BRAB | Opcode::BRABZ => d.flow = Flow::Jump,
            Opcode::BLR | Opcode::BLRAA | Opcode::BLRAAZ | Opcode::BLRAB | Opcode::BLRABZ => d.flow = Flow::Call,
            Opcode::RET | Opcode::RETAA | Opcode::RETAB | Opcode::ERET => d.flow = Flow::Ret,
            Opcode::BRK | Opcode::HLT | Opcode::UDF => d.flow = Flow::Interrupt,
            Opcode::ADR => d.data_ref = pc_target,
            Opcode::ADRP => {
                if let (Operand::Register(_, rd), Operand::PCOffset(o)) = (inst.operands[0], inst.operands[1]) {
                    let page = (va & !0xfff).wrapping_add(o as u64);
                    if (rd as usize) < 31 {
                        self.adrp[rd as usize] = Some(page);
                    }
                    d.data_ref = None;
                    return d;
                }
            }
            Opcode::ADD => {
                let reg = |op: Operand| match op {
                    Operand::Register(_, r) | Operand::RegisterOrSP(_, r) => Some(r as usize),
                    _ => None,
                };
                let imm = match inst.operands[2] {
                    Operand::Immediate(i) => Some(i as u64),
                    Operand::ImmShift(i, s) => Some((i as u64) << s),
                    _ => None,
                };
                if let (Some(rd), Some(rn), Some(imm)) = (reg(inst.operands[0]), reg(inst.operands[1]), imm) {
                    if let Some(page) = self.adrp.get(rn).copied().flatten() {
                        d.data_ref = Some(page + imm);
                    }
                    if rd < 31 {
                        self.adrp[rd] = None;
                    }
                }
            }
            Opcode::LDR | Opcode::STR | Opcode::LDRB | Opcode::LDRH | Opcode::LDRSW => {
                if let Operand::RegPreIndex(rn, off, false) = inst.operands[1] {
                    if let Some(page) = self.adrp.get(rn as usize).copied().flatten() {
                        d.data_ref = Some(page.wrapping_add(off as i64 as u64));
                    }
                }
                if let Some(t) = pc_target {
                    d.data_ref = Some(t); // literal load
                }
            }
            _ => {}
        }
        // Writes to a register clobber any tracked page base.
        if let Operand::Register(SizeCode::X | SizeCode::W, rd) = inst.operands[0] {
            if !matches!(inst.opcode, Opcode::ADRP) && (rd as usize) < 31 && inst.opcode != Opcode::STR {
                self.adrp[rd as usize] = None;
            }
        }
        d
    }
}

fn decode_x86(bits: u32, bytes: &[u8], va: u64) -> Decoded {
    let mut dec = Decoder::with_ip(bits, bytes, va, DecoderOptions::NONE);
    let ins = dec.decode();
    if ins.is_invalid() {
        return Decoded::invalid();
    }
    x86_summary(&ins)
}

fn x86_summary(ins: &iced_x86::Instruction) -> Decoded {
    let flow = match ins.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => Flow::None,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::CondJump,
        FlowControl::Return => Flow::Ret,
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call,
        FlowControl::Interrupt | FlowControl::Exception => Flow::Interrupt,
    };
    let target = match ins.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => Some(ins.near_branch_target()),
        _ => None,
    };
    let mem = x86_mem_address(ins);
    let indirect_slot = match ins.flow_control() {
        FlowControl::IndirectBranch | FlowControl::IndirectCall => mem,
        _ => None,
    };
    let mut data_ref = if indirect_slot.is_some() { None } else { mem };
    if data_ref.is_none() && target.is_none() {
        // `push offset aString` / `mov eax, offset x` in 32-bit code.
        for i in 0..ins.op_count() {
            if matches!(ins.op_kind(i), OpKind::Immediate32 | OpKind::Immediate32to64) {
                let v = ins.immediate(i);
                if v >= 0x1000 {
                    data_ref = Some(v);
                }
            }
        }
    }
    // `int3` padding and `ud2` end a block like an interrupt.
    let flow = if ins.mnemonic() == iced_x86::Mnemonic::Ud2 || ins.mnemonic() == iced_x86::Mnemonic::Hlt { Flow::Interrupt } else { flow };
    let mem_size = if data_ref.is_some() && mem.is_some() { ins.memory_size().size().min(255) as u8 } else { 0 };
    Decoded { len: ins.len() as u8, flow, target, data_ref, mem_size, indirect_slot, valid: true }
}

fn x86_mem_address(ins: &iced_x86::Instruction) -> Option<u64> {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) == OpKind::Memory {
            if ins.is_ip_rel_memory_operand() {
                return Some(ins.ip_rel_memory_address());
            }
            if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
                let d = ins.memory_displacement64();
                return (d >= 0x1000).then_some(d);
            }
        }
    }
    None
}

// ------------------------------------------------------------------------------------------------
// Rendering
// ------------------------------------------------------------------------------------------------

/// Decodes and formats up to `max` instructions from `bytes` (located at `va`).
/// Undecodable bytes become a `db` pseudo-instruction so the listing never stalls.
pub fn render(arch: Arch, bytes: &[u8], va: u64, max: usize, names: &dyn NameLookup) -> Vec<Instruction> {
    render_mode(arch, 64, false, bytes, va, max, names)
}

/// Like [`render`], with the image's word size and byte order (RISC-V, MIPS).
pub fn render_mode(arch: Arch, bits: u8, big: bool, bytes: &[u8], va: u64, max: usize, names: &dyn NameLookup) -> Vec<Instruction> {
    match arch {
        Arch::RiscV | Arch::Mips => render_rv_mips(arch, bits, big, bytes, va, max, names),
        Arch::X86 | Arch::X86_64 => render_x86(if arch == Arch::X86 { 32 } else { 64 }, bytes, va, max, names),
        Arch::Arm64 => render_arm64(bytes, va, max, names),
        Arch::Arm | Arch::Thumb => render_arm32(arch == Arch::Thumb, bytes, va, max, names),
        _ => Vec::new(),
    }
}

fn data_byte(va: u64, b: u8) -> Instruction {
    Instruction {
        address: va,
        size: 1,
        bytes: format!("{b:02x}"),
        mnemonic: "db".into(),
        operands: vec![Token { t: format!("0x{b:02x}"), k: TokenKind::Number }],
        flow: Flow::None,
        target: None,
        comment: None,
        label: None,
        user_comment: None,
    }
}

struct MapResolver(HashMap<u64, String>);

impl SymbolResolver for MapResolver {
    fn symbol(&mut self, _i: &iced_x86::Instruction, _o: u32, _io: Option<u32>, address: u64, _s: u32) -> Option<SymbolResult<'_>> {
        self.0.get(&address).map(|n| SymbolResult::with_str_kind(address, n.as_str(), FormatterTextKind::Function))
    }
}

struct TokenSink(Vec<Token>);

impl FormatterOutput for TokenSink {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let k = match kind {
            FormatterTextKind::Register => TokenKind::Register,
            FormatterTextKind::Number => TokenKind::Number,
            FormatterTextKind::Keyword | FormatterTextKind::Decorator => TokenKind::Keyword,
            FormatterTextKind::Prefix | FormatterTextKind::Mnemonic => TokenKind::Prefix,
            FormatterTextKind::Function | FormatterTextKind::Label | FormatterTextKind::Data => TokenKind::Symbol,
            FormatterTextKind::LabelAddress | FormatterTextKind::FunctionAddress => TokenKind::Address,
            FormatterTextKind::Operator | FormatterTextKind::Punctuation => TokenKind::Punct,
            _ => TokenKind::Text,
        };
        // Merge adjacent tokens of the same kind to keep payloads small.
        if let Some(last) = self.0.last_mut() {
            if last.k == k {
                last.t.push_str(text);
                return;
            }
        }
        self.0.push(Token { t: text.to_string(), k });
    }
}

fn render_x86(bits: u32, bytes: &[u8], va: u64, max: usize, names: &dyn NameLookup) -> Vec<Instruction> {
    let mut decoded = Vec::with_capacity(max.min(4096));
    let mut pos = 0usize;
    while decoded.len() < max && pos < bytes.len() {
        let ip = va + pos as u64;
        let mut dec = Decoder::with_ip(bits, &bytes[pos..], ip, DecoderOptions::NONE);
        let ins = dec.decode();
        if ins.is_invalid() {
            decoded.push(Err(bytes[pos]));
            pos += 1;
        } else {
            pos += ins.len();
            decoded.push(Ok(ins));
        }
    }

    // Resolve every address that could appear in an operand once, up front.
    let mut map = HashMap::new();
    for ins in decoded.iter().flatten() {
        let s = x86_summary(ins);
        for a in [s.target, s.data_ref, s.indirect_slot].into_iter().flatten() {
            if let std::collections::hash_map::Entry::Vacant(e) = map.entry(a) {
                if let Some(n) = names.name_at(a) {
                    e.insert(n);
                }
            }
        }
    }

    let mut fmt = IntelFormatter::with_options(Some(Box::new(MapResolver(map))), None);
    let o = fmt.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_space_after_operand_separator(true);
    o.set_show_branch_size(false);
    o.set_branch_leading_zeros(false);
    o.set_leading_zeros(false);
    o.set_rip_relative_addresses(false);
    o.set_memory_size_options(iced_x86::MemorySizeOptions::Minimal);

    let mut out = Vec::with_capacity(decoded.len());
    let mut offset = 0usize;
    for item in decoded {
        match item {
            Err(b) => {
                out.push(data_byte(va + offset as u64, b));
                offset += 1;
            }
            Ok(ins) => {
                let len = ins.len();
                let mut mnem = TokenSink(Vec::new());
                fmt.format_mnemonic(&ins, &mut mnem);
                let mnemonic = mnem.0.iter().map(|t| t.t.as_str()).collect::<String>();
                let mut ops = TokenSink(Vec::new());
                fmt.format_all_operands(&ins, &mut ops);
                let s = x86_summary(&ins);
                out.push(Instruction {
                    address: ins.ip(),
                    size: len as u32,
                    bytes: hex::encode(&bytes[offset..offset + len]),
                    mnemonic,
                    operands: ops.0,
                    flow: s.flow,
                    target: s.target.or(s.data_ref).or(s.indirect_slot),
                    comment: None,
                    label: None,
                    user_comment: None,
                });
                offset += len;
            }
        }
    }
    out
}

fn render_arm64(bytes: &[u8], va: u64, max: usize, names: &dyn NameLookup) -> Vec<Instruction> {
    let mut dis = Disassembler::new(Arch::Arm64);
    let mut out = Vec::new();
    let mut pos = 0usize;
    while out.len() < max && pos + 4 <= bytes.len() {
        let ip = va + pos as u64;
        let word = &bytes[pos..pos + 4];
        let mut reader = U8Reader::new(word);
        let decoded = InstDecoder::default().decode(&mut reader);
        let summary = dis.decode(word, ip);
        let Ok(inst) = decoded else {
            out.push(Instruction {
                address: ip,
                size: 4,
                bytes: hex::encode(word),
                mnemonic: ".word".into(),
                operands: vec![Token { t: format!("{:#010x}", u32::from_le_bytes(word.try_into().unwrap())), k: TokenKind::Number }],
                flow: Flow::None,
                target: None,
                comment: None,
                label: None,
                user_comment: None,
            });
            pos += 4;
            continue;
        };
        let text = inst.to_string();
        let (mnemonic, ops) = text.split_once(' ').unwrap_or((text.as_str(), ""));
        let target = summary.target.or(summary.data_ref);
        let mut operands = tokenize_arm(ops);
        // Replace `$+0x40` style PC offsets with the resolved address / name.
        if let Some(t) =
            summary.target.or(if inst.opcode == Opcode::ADR || inst.opcode == Opcode::ADRP { pc_value(&inst, ip) } else { None })
        {
            for tok in operands.iter_mut() {
                if tok.t.starts_with('$') {
                    match names.name_at(t) {
                        Some(n) => *tok = Token { t: n, k: TokenKind::Symbol },
                        None => *tok = Token { t: format!("{t:#x}"), k: TokenKind::Address },
                    }
                }
            }
        }
        out.push(Instruction {
            address: ip,
            size: 4,
            bytes: hex::encode(word),
            mnemonic: mnemonic.to_string(),
            operands,
            flow: summary.flow,
            target,
            comment: None,
            label: None,
            user_comment: None,
        });
        if summary.ends_block() {
            dis.reset();
        }
        pos += 4;
    }
    out
}

fn pc_value(inst: &yaxpeax_arm::armv8::a64::Instruction, ip: u64) -> Option<u64> {
    inst.operands.iter().find_map(|op| match op {
        Operand::PCOffset(o) if inst.opcode == Opcode::ADRP => Some((ip & !0xfff).wrapping_add(*o as u64)),
        Operand::PCOffset(o) => Some(ip.wrapping_add(*o as u64)),
        _ => None,
    })
}

/// Light lexer for yaxpeax's textual operand output.
fn tokenize_arm(s: &str) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let push = |out: &mut Vec<Token>, t: String, k: TokenKind| {
        if let Some(last) = out.last_mut() {
            if last.k == k && k == TokenKind::Punct {
                last.t.push_str(&t);
                return;
            }
        }
        out.push(Token { t, k });
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_alphanumeric() || c == '$' || c == '#' || c == '_' || c == '.' || c == '-' || c == '+' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '$' | '#' | '_' | '.' | '-' | '+')) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let k =
                if word.starts_with('#') || word.starts_with("0x") || word.chars().next().is_some_and(|c| c.is_ascii_digit() || c == '-') {
                    TokenKind::Number
                } else if word.starts_with('$') {
                    TokenKind::Address
                } else if is_arm_register(&word) {
                    TokenKind::Register
                } else {
                    TokenKind::Keyword
                };
            push(&mut out, word, k);
        } else {
            push(&mut out, c.to_string(), TokenKind::Punct);
            i += 1;
        }
    }
    out
}

fn is_arm_register(w: &str) -> bool {
    let w = w.split('.').next().unwrap_or(w).trim_end_matches('!');
    matches!(
        w,
        "sp" | "wsp" | "xzr" | "wzr" | "lr" | "fp" | "pc" | "ip" | "sb" | "sl" | "nzcv" | "fpcr" | "fpsr" | "apsr" | "cpsr" | "spsr"
    ) || (w.len() >= 2
        && matches!(w.as_bytes()[0], b'x' | b'w' | b'v' | b'q' | b'd' | b's' | b'h' | b'b' | b'z' | b'p' | b'r')
        && w[1..].bytes().all(|b| b.is_ascii_digit()))
}

// ------------------------------------------------------------------------------------------------
// ARM32 / Thumb-2
// ------------------------------------------------------------------------------------------------

/// Length of the Thumb instruction starting with halfword `h` (2 or 4 bytes).
fn thumb_len(h: u16) -> usize {
    if matches!(h >> 11, 0b11101..=0b11111) {
        4
    } else {
        2
    }
}

fn sext(v: u32, bits: u32) -> i64 {
    ((v << (32 - bits)) as i32 >> (32 - bits)) as i64
}

/// Decodes one ARM or Thumb instruction. Branch targets are computed from the raw
/// encoding (the decoder's offset conventions differ between encodings).
fn decode_arm32(thumb: bool, bytes: &[u8], va: u64) -> (Option<a32::Instruction>, Decoded) {
    let len = if thumb {
        if bytes.len() < 2 {
            return (None, Decoded::invalid());
        }
        thumb_len(u16::from_le_bytes([bytes[0], bytes[1]]))
    } else {
        4
    };
    if bytes.len() < len {
        return (None, Decoded::invalid());
    }
    let mut d = Decoded { len: len as u8, flow: Flow::None, target: None, data_ref: None, mem_size: 0, indirect_slot: None, valid: true };
    let mut reader = U8Reader::new(&bytes[..len]);
    let mut dec = if thumb { a32::InstDecoder::default_thumb() } else { a32::InstDecoder::default() };
    // Reject UNPREDICTABLE encodings (e.g. ldrd with an odd/pc register pair) instead
    // of decoding them; the decoder panics on some of those.
    dec.set_allow_nonconforming(false);
    let Ok(inst) = dec.decode(&mut reader) else {
        return (None, Decoded { len: len as u8, ..Decoded::invalid() });
    };
    let conditional = inst.condition != a32::ConditionCode::AL;
    let reg = |op: a32::Operand| match op {
        a32::Operand::Reg(r) | a32::Operand::RegWBack(r, _) => Some(r.number()),
        _ => None,
    };
    let writes_pc = reg(inst.operands[0]) == Some(15);
    let list_has_pc = inst.operands.iter().any(|o| matches!(o, a32::Operand::RegList(l) if l & 0x8000 != 0));
    // PC reads as the address of the instruction plus 8 (ARM) or 4 (Thumb).
    let pc = va + if thumb { 4 } else { 8 };
    let pc_aligned = pc & !3;

    if thumb {
        let h1 = u16::from_le_bytes([bytes[0], bytes[1]]) as u32;
        if len == 2 {
            if h1 >> 12 == 0b1101 && (h1 >> 8) & 0xf < 0b1110 {
                d.flow = Flow::CondJump;
                d.target = Some(pc.wrapping_add((sext(h1 & 0xff, 8) << 1) as u64));
            } else if h1 >> 11 == 0b11100 {
                d.flow = Flow::Jump;
                d.target = Some(pc.wrapping_add((sext(h1 & 0x7ff, 11) << 1) as u64));
            } else if h1 & 0xf500 == 0xb100 {
                // cbz / cbnz
                let off = (((h1 >> 9) & 1) << 6) | (((h1 >> 3) & 0x1f) << 1);
                d.flow = Flow::CondJump;
                d.target = Some(pc + off as u64);
            } else if h1 & 0xff00 == 0x4700 {
                let rm = (h1 >> 3) & 0xf;
                d.flow = if h1 & 0x80 != 0 {
                    Flow::Call
                } else if rm == 14 {
                    Flow::Ret
                } else {
                    Flow::Jump
                };
            } else if h1 & 0xff00 == 0xbd00 {
                d.flow = Flow::Ret; // pop {..., pc}
            } else if h1 & 0xf800 == 0xa000 {
                d.data_ref = Some(pc_aligned + ((h1 & 0xff) << 2) as u64); // adr
            } else if h1 & 0xf800 == 0x4800 {
                d.data_ref = Some(pc_aligned + ((h1 & 0xff) << 2) as u64); // ldr rt, [pc, #imm]
                d.mem_size = 4;
            } else if h1 == 0xdefe || h1 >> 8 == 0xbe {
                d.flow = Flow::Interrupt; // udf / bkpt
            }
        } else {
            let h2 = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
            if h1 >> 11 == 0b11110 && h2 & 0x8000 != 0 {
                let s = (h1 >> 10) & 1;
                let j1 = (h2 >> 13) & 1;
                let j2 = (h2 >> 11) & 1;
                let op = ((h2 >> 14) & 1, (h2 >> 12) & 1);
                if op == (0, 0) {
                    // b<cond>.w
                    if (h1 >> 6) & 0xf < 0b1110 {
                        let imm = (s << 20) | (j2 << 19) | (j1 << 18) | ((h1 & 0x3f) << 12) | ((h2 & 0x7ff) << 1);
                        d.flow = Flow::CondJump;
                        d.target = Some(pc.wrapping_add(sext(imm, 21) as u64));
                    }
                } else {
                    let i1 = 1 ^ (j1 ^ s);
                    let i2 = 1 ^ (j2 ^ s);
                    let imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3ff) << 12) | ((h2 & 0x7ff) << 1);
                    let off = sext(imm, 25) as u64;
                    match op {
                        (0, _) => {
                            d.flow = Flow::Jump;
                            d.target = Some(pc.wrapping_add(off));
                        }
                        (_, 1) => {
                            d.flow = Flow::Call;
                            d.target = Some(pc.wrapping_add(off));
                        }
                        _ => {
                            d.flow = Flow::Call; // blx into ARM code
                            d.target = Some(pc_aligned.wrapping_add(off));
                        }
                    }
                }
            } else if h1 == 0xe8bd && h2 & 0x8000 != 0 {
                d.flow = Flow::Ret; // pop.w {..., pc}
            } else if h1 == 0xf85d && h2 == 0xfb04 {
                d.flow = Flow::Ret; // ldr pc, [sp], #4
            } else if h1 & 0xff7f == 0xf85f {
                // ldr.w rt, [pc, #±imm12]
                let imm = (h2 & 0xfff) as u64;
                let a = if h1 & 0x80 != 0 { pc_aligned + imm } else { pc_aligned.wrapping_sub(imm) };
                if h2 >> 12 == 15 {
                    d.flow = Flow::Jump;
                    d.indirect_slot = Some(a);
                } else {
                    d.data_ref = Some(a);
                    d.mem_size = 4;
                }
            } else if h1 & 0xfff0 == 0xe8d0 && h2 & 0xffe0 == 0xf000 {
                d.flow = Flow::Jump; // tbb / tbh
            }
        }
        if conditional && d.flow == Flow::Ret {
            d.flow = Flow::None;
        }
        return (Some(inst), d);
    }

    // ARM state.
    let word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    match inst.opcode {
        a32::Opcode::B | a32::Opcode::BL if (word >> 25) & 0b111 == 0b101 => {
            let off = (sext(word & 0x00ff_ffff, 24) << 2) as u64;
            d.flow = if inst.opcode == a32::Opcode::BL {
                Flow::Call
            } else if conditional {
                Flow::CondJump
            } else {
                Flow::Jump
            };
            d.target = Some(pc.wrapping_add(off));
        }
        a32::Opcode::BLX if word >> 28 == 0b1111 => {
            // blx imm: switches to Thumb, H supplies bit 1.
            let off = ((sext(word & 0x00ff_ffff, 24) << 2) | (((word >> 24) & 1) << 1) as i64) as u64;
            d.flow = Flow::Call;
            d.target = Some(pc.wrapping_add(off));
        }
        a32::Opcode::BLX => d.flow = Flow::Call,
        a32::Opcode::BX => {
            d.flow = if reg(inst.operands[0]) == Some(14) { Flow::Ret } else { Flow::Jump };
        }
        a32::Opcode::POP | a32::Opcode::LDM(..) if list_has_pc => d.flow = Flow::Ret,
        a32::Opcode::LDR if writes_pc => {
            d.flow = if matches!(inst.operands[1], a32::Operand::RegDerefPostindexOffset(r, 4, true, _) if r.number() == 13) {
                Flow::Ret
            } else {
                Flow::Jump
            };
        }
        a32::Opcode::MOV if writes_pc => {
            d.flow = if reg(inst.operands[1]) == Some(14) { Flow::Ret } else { Flow::Jump };
        }
        a32::Opcode::ADD if writes_pc => d.flow = Flow::Jump,
        a32::Opcode::ADR => {
            let rot = ((word >> 8) & 0xf) * 2;
            let imm = (word & 0xff).rotate_right(rot) as u64;
            d.data_ref = Some(if (word >> 21) & 0xf == 0b0100 { pc + imm } else { pc.wrapping_sub(imm) });
        }
        a32::Opcode::UDF | a32::Opcode::BKPT => d.flow = Flow::Interrupt,
        _ => {}
    }
    if matches!(inst.opcode, a32::Opcode::LDR | a32::Opcode::LDRB | a32::Opcode::LDRH | a32::Opcode::LDRD) {
        if let a32::Operand::RegDerefPreindexOffset(r, imm, add, false) = inst.operands[1] {
            if r.number() == 15 {
                let a = if add { pc + imm as u64 } else { pc.wrapping_sub(imm as u64) };
                if d.flow == Flow::Jump {
                    d.indirect_slot = Some(a);
                } else {
                    d.data_ref = Some(a);
                    d.mem_size = 4;
                }
            }
        }
    }
    if conditional && matches!(d.flow, Flow::Ret | Flow::Jump) && d.target.is_none() {
        d.flow = Flow::None;
    }
    (Some(inst), d)
}

fn render_arm32(thumb: bool, bytes: &[u8], va: u64, max: usize, names: &dyn NameLookup) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let step = if thumb { 2 } else { 4 };
    while out.len() < max && pos + step <= bytes.len() {
        let ip = va + pos as u64;
        let (inst, s) = decode_arm32(thumb, &bytes[pos..], ip);
        let Some(inst) = inst.filter(|_| s.valid) else {
            let raw = &bytes[pos..pos + step];
            let value = if thumb {
                format!("{:#06x}", u16::from_le_bytes([raw[0], raw[1]]))
            } else {
                format!("{:#010x}", u32::from_le_bytes(raw.try_into().unwrap()))
            };
            out.push(Instruction {
                address: ip,
                size: step as u32,
                bytes: hex::encode(raw),
                mnemonic: if thumb { ".short" } else { ".word" }.into(),
                operands: vec![Token { t: value, k: TokenKind::Number }],
                flow: Flow::None,
                target: None,
                comment: None,
                label: None,
                user_comment: None,
            });
            pos += step;
            continue;
        };
        let len = s.len as usize;
        let text = inst.to_string();
        let (mnemonic, ops) = text.split_once(' ').unwrap_or((text.as_str(), ""));
        let mut operands = tokenize_arm(ops);
        let target = s.target.or(s.data_ref).or(s.indirect_slot);
        if let Some(t) = s.target.or(s.data_ref).or(s.indirect_slot) {
            // Show pc-relative operands as the resolved address / name.
            let named = names.name_at(t).map(|n| Token { t: n, k: TokenKind::Symbol });
            let tok = named.unwrap_or(Token { t: format!("{t:#x}"), k: TokenKind::Address });
            if s.target.is_some() {
                let branch = operands.iter().rposition(|t| t.k == TokenKind::Address || t.k == TokenKind::Number);
                match branch {
                    Some(i) => operands[i] = tok,
                    None => operands.push(tok),
                }
            } else {
                operands.push(Token { t: " ; ".into(), k: TokenKind::Punct });
                operands.push(tok);
            }
        }
        out.push(Instruction {
            address: ip,
            size: len as u32,
            bytes: hex::encode(&bytes[pos..pos + len]),
            mnemonic: mnemonic.to_string(),
            operands,
            flow: s.flow,
            target,
            comment: None,
            label: None,
            user_comment: None,
        });
        pos += len;
    }
    out
}

// ------------------------------------------------------------------------------------------------
// RISC-V and MIPS
// ------------------------------------------------------------------------------------------------

impl Disassembler {
    fn track(&mut self, rd: u8, v: Option<u64>) {
        if rd != 0 && (rd as usize) < 32 {
            self.adrp[rd as usize] = v;
        }
    }

    fn decode_riscv(&mut self, bytes: &[u8], va: u64) -> Decoded {
        let Some(i) = crate::riscv::decode(bytes, va, self.bits) else {
            let len = if bytes.first().is_some_and(|b| b & 3 == 3) { 4 } else { 2 };
            return Decoded { len, ..Decoded::invalid() };
        };
        let mut d = Decoded { len: i.len, flow: i.flow, target: i.target, data_ref: None, mem_size: 0, indirect_slot: None, valid: true };
        use crate::riscv::Effect;
        match i.effect {
            Effect::SetAddr(rd, v) => self.track(rd, Some(v)),
            Effect::AddImm(rd, rs1, imm) => {
                let v = self.adrp.get(rs1 as usize).copied().flatten().map(|b| b.wrapping_add(imm as u64));
                d.data_ref = v.filter(|_| rs1 != 0);
                self.track(rd, v.filter(|_| rs1 != 0));
            }
            Effect::Mem(rd, rs1, imm, size) => {
                if let Some(b) = self.adrp.get(rs1 as usize).copied().flatten().filter(|_| rs1 != 0) {
                    d.data_ref = Some(b.wrapping_add(imm as u64));
                    d.mem_size = size;
                }
                self.track(rd, None);
            }
            Effect::Jalr(rd, rs1, imm) => {
                if let Some(b) = self.adrp.get(rs1 as usize).copied().flatten().filter(|_| rs1 != 0) {
                    d.target = Some(b.wrapping_add(imm as u64));
                }
                self.track(rd, None);
            }
            Effect::Write(rd) => self.track(rd, None),
            Effect::None => {}
        }
        d
    }

    fn decode_mips(&mut self, bytes: &[u8], va: u64) -> Decoded {
        let pending = self.pending.take();
        let Some(i) = crate::mips::decode(bytes, va, self.big, self.bits == 64) else {
            return Decoded { len: 4, ..Decoded::invalid() };
        };
        let mut d = Decoded { len: 4, flow: Flow::None, target: None, data_ref: None, mem_size: 0, indirect_slot: None, valid: true };
        use crate::mips::Effect;
        match i.effect {
            Effect::SetAddr(rt, v) => self.track(rt, Some(v)),
            Effect::AddImm(rt, rs, imm) => {
                let v = self.adrp.get(rs as usize).copied().flatten().filter(|_| rs != 0).map(|b| b.wrapping_add(imm as u64));
                d.data_ref = v;
                self.track(rt, v);
            }
            Effect::Mem(rt, rs, imm, size) => {
                if let Some(b) = self.adrp.get(rs as usize).copied().flatten().filter(|_| rs != 0) {
                    d.data_ref = Some(b.wrapping_add(imm as u64));
                    d.mem_size = size;
                }
                self.track(rt, None);
            }
            Effect::Write(rd) => self.track(rd, None),
            Effect::None => {}
        }
        // `jalr t9` / `jr t9` through a register built from `lui` + `addiu`.
        let mut target = i.target;
        if target.is_none() && matches!(i.mnemonic.as_str(), "jalr" | "jr") {
            if let Some(crate::mips::Op::Reg(r)) = i.ops.last() {
                target = self.adrp.get(*r as usize).copied().flatten();
            }
        }
        if i.delay_slot {
            // The branch takes effect after its delay slot: report it on the next instruction.
            self.pending = Some((i.flow, target));
        } else if i.flow != Flow::None {
            d.flow = i.flow;
            d.target = target;
        }
        if let Some((flow, t)) = pending {
            d.flow = flow;
            d.target = t;
        }
        d
    }
}

fn rv_mips_tokens(arch: Arch, ops_rv: &[crate::riscv::Op], ops_mips: &[crate::mips::Op], names: &dyn NameLookup) -> Vec<Token> {
    let num = |v: i64| Token {
        t: if (-9..=9).contains(&v) {
            v.to_string()
        } else if v < 0 {
            format!("-{:#x}", v.unsigned_abs())
        } else {
            format!("{v:#x}")
        },
        k: TokenKind::Number,
    };
    let addr = |t: u64| match names.name_at(t) {
        Some(n) => Token { t: n, k: TokenKind::Symbol },
        None => Token { t: format!("{t:#x}"), k: TokenKind::Address },
    };
    let reg = |s: &str| Token { t: s.to_string(), k: TokenKind::Register };
    let mut out: Vec<Token> = Vec::new();
    let sep = |out: &mut Vec<Token>| {
        if !out.is_empty() {
            out.push(Token { t: ", ".into(), k: TokenKind::Punct });
        }
    };
    let mem = |out: &mut Vec<Token>, off: i64, base: &str| {
        out.push(num(off));
        out.push(Token { t: "(".into(), k: TokenKind::Punct });
        out.push(reg(base));
        out.push(Token { t: ")".into(), k: TokenKind::Punct });
    };
    if arch == Arch::RiscV {
        use crate::riscv::{Op, FREGS, REGS};
        for op in ops_rv {
            sep(&mut out);
            match op {
                Op::Reg(r) => out.push(reg(REGS[*r as usize])),
                Op::FReg(r) => out.push(reg(FREGS[*r as usize])),
                Op::Imm(v) => out.push(num(*v)),
                Op::Mem(off, b) => mem(&mut out, *off, REGS[*b as usize]),
                Op::Addr(t) => out.push(addr(*t)),
                Op::Csr(c) => match crate::riscv::csr_name(*c) {
                    Some(n) => out.push(reg(n)),
                    None => out.push(num(*c as i64)),
                },
            }
        }
    } else {
        use crate::mips::{Op, REGS};
        for op in ops_mips {
            sep(&mut out);
            match op {
                Op::Reg(r) => out.push(reg(&format!("${}", REGS[*r as usize]))),
                Op::FReg(r) => out.push(reg(&format!("$f{r}"))),
                Op::Imm(v) => out.push(num(*v)),
                Op::Mem(off, b) => mem(&mut out, *off, &format!("${}", REGS[*b as usize])),
                Op::Addr(t) => out.push(addr(*t)),
                Op::Cop0(r) => out.push(reg(&format!("$cp0_{r}"))),
            }
        }
    }
    out
}

fn render_rv_mips(arch: Arch, bits: u8, big: bool, bytes: &[u8], va: u64, max: usize, names: &dyn NameLookup) -> Vec<Instruction> {
    let mut dis = Disassembler::with_mode(arch, bits, big);
    let mut out = Vec::new();
    let mut pos = 0usize;
    while out.len() < max && pos + 2 <= bytes.len() {
        let ip = va + pos as u64;
        let rest = &bytes[pos..];
        let summary = dis.decode(rest, ip);
        let decoded = if arch == Arch::RiscV {
            crate::riscv::decode(rest, ip, dis.bits)
                .map(|i| (i.len as usize, i.mnemonic, i.flow, i.target, rv_mips_tokens(arch, &i.ops, &[], names)))
        } else {
            crate::mips::decode(rest, ip, big, bits == 64)
                .map(|i| (4, i.mnemonic, i.flow, i.target, rv_mips_tokens(arch, &[], &i.ops, names)))
        };
        let Some((len, mnemonic, flow, target, mut operands)) = decoded.filter(|d| d.0 <= rest.len()) else {
            let step = if arch == Arch::RiscV && rest[0] & 3 != 3 { 2 } else { 4 }.min(rest.len());
            if step < 2 {
                break;
            }
            let raw = &rest[..step];
            let value = if step == 2 {
                format!("{:#06x}", u16::from_le_bytes([raw[0], raw[1]]))
            } else if big {
                format!("{:#010x}", u32::from_be_bytes(raw.try_into().unwrap()))
            } else {
                format!("{:#010x}", u32::from_le_bytes(raw.try_into().unwrap()))
            };
            out.push(Instruction {
                address: ip,
                size: step as u32,
                bytes: hex::encode(raw),
                mnemonic: if step == 2 { ".short" } else { ".word" }.into(),
                operands: vec![Token { t: value, k: TokenKind::Number }],
                flow: Flow::None,
                target: None,
                comment: None,
                label: None,
                user_comment: None,
            });
            pos += step;
            continue;
        };
        // Addresses formed by `auipc`/`lui` pairs: show the resolved name after the operands.
        let data = summary.data_ref.filter(|_| target.is_none());
        let call_target = target.or(if matches!(flow, Flow::Call | Flow::Jump) { summary.target } else { None });
        if let Some(t) = data.or(if target.is_none() { call_target } else { None }) {
            operands.push(Token { t: " ; ".into(), k: TokenKind::Punct });
            operands.push(match names.name_at(t) {
                Some(n) => Token { t: n, k: TokenKind::Symbol },
                None => Token { t: format!("{t:#x}"), k: TokenKind::Address },
            });
        }
        out.push(Instruction {
            address: ip,
            size: len as u32,
            bytes: hex::encode(&rest[..len]),
            mnemonic,
            operands,
            flow,
            target: call_target.or(data),
            comment: None,
            label: None,
            user_comment: None,
        });
        if matches!(flow, Flow::Ret | Flow::Jump) && arch == Arch::RiscV {
            dis.reset();
        }
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoNames;
    impl NameLookup for NoNames {
        fn name_at(&self, _: u64) -> Option<String> {
            None
        }
    }

    #[test]
    fn x86_call_and_ret() {
        // call +5 ; ret
        let code = [0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let mut d = Disassembler::new(Arch::X86_64);
        let a = d.decode(&code, 0x1000);
        assert_eq!(a.flow, Flow::Call);
        assert_eq!(a.target, Some(0x1005));
        let b = d.decode(&code[5..], 0x1005);
        assert_eq!(b.flow, Flow::Ret);
        let r = render(Arch::X86_64, &code, 0x1000, 10, &NoNames);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].mnemonic, "call");
        assert_eq!(r[1].mnemonic, "ret");
    }

    #[test]
    fn x86_rip_relative_data_ref() {
        // lea rcx, [rip+0x10]
        let code = [0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00];
        let a = Disassembler::new(Arch::X86_64).decode(&code, 0x2000);
        assert_eq!(a.data_ref, Some(0x2000 + 7 + 0x10));
    }

    #[test]
    fn arm64_branches_and_adrp() {
        // bl #+8 ; adrp x0, #page+1 ; add x0, x0, #0x10 ; ret
        let code: Vec<u8> = [0x9400_0002u32, 0xb000_0000, 0x9100_4000, 0xd65f_03c0].iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut d = Disassembler::new(Arch::Arm64);
        let bl = d.decode(&code[0..4], 0x4000);
        assert_eq!(bl.flow, Flow::Call);
        assert_eq!(bl.target, Some(0x4008));
        d.decode(&code[4..8], 0x4004);
        let add = d.decode(&code[8..12], 0x4008);
        assert_eq!(add.data_ref, Some(0x5000 + 0x10));
        assert_eq!(d.decode(&code[12..16], 0x400c).flow, Flow::Ret);
        let r = render(Arch::Arm64, &code, 0x4000, 10, &NoNames);
        assert_eq!(r[0].mnemonic, "bl");
        assert_eq!(r[0].operands[0].t, "0x4008");
    }

    #[test]
    fn arm32_branches() {
        // bl +8 ; bx lr ; ldr r0, [pc, #4]
        let code: Vec<u8> = [0xeb00_0000u32, 0xe12f_ff1e, 0xe59f_0004].iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut d = Disassembler::new(Arch::Arm);
        let bl = d.decode(&code, 0x8000);
        assert_eq!((bl.flow, bl.target), (Flow::Call, Some(0x8008)));
        assert_eq!(d.decode(&code[4..], 0x8004).flow, Flow::Ret);
        assert_eq!(d.decode(&code[8..], 0x8008).data_ref, Some(0x8008 + 8 + 4));
        let r = render(Arch::Arm, &code, 0x8000, 10, &NoNames);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].mnemonic, "bl");
        assert_eq!(r[0].operands.last().unwrap().t, "0x8008");
    }

    #[test]
    fn arm32_never_panics_on_noise() {
        for seed in [0x2545_f491_4f6c_dd1du64, 0x9e37_79b9_7f4a_7c15, 0xdead_beef_cafe_f00d, 7] {
            let mut x = seed;
            let noise: Vec<u8> = (0..128 * 1024)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            for arch in [Arch::Arm, Arch::Thumb] {
                let mut d = Disassembler::new(arch);
                for off in (0..noise.len()).step_by(2) {
                    d.decode(&noise[off..], 0x10000 + off as u64);
                }
                let r = render(arch, &noise, 0x10000, usize::MAX, &NoNames);
                assert!(r.len() >= noise.len() / 4);
            }
        }
    }

    #[test]
    fn thumb_branches() {
        // push {r4, lr} ; bl.w +0x100 ; cbz r0, +4 ; beq -4 ; pop {r4, pc}
        let code: [u8; 12] = [0x10, 0xb5, 0x00, 0xf0, 0x7e, 0xf8, 0x10, 0xb1, 0xfc, 0xd0, 0x10, 0xbd];
        let mut d = Disassembler::new(Arch::Thumb);
        assert_eq!(d.decode(&code, 0x1000).len, 2);
        let bl = d.decode(&code[2..], 0x1002);
        assert_eq!((bl.len, bl.flow, bl.target), (4, Flow::Call, Some(0x1002 + 4 + 0xfc)));
        let cbz = d.decode(&code[6..], 0x1006);
        assert_eq!((cbz.flow, cbz.target), (Flow::CondJump, Some(0x1006 + 4 + 4)));
        let beq = d.decode(&code[8..], 0x1008);
        assert_eq!((beq.flow, beq.target), (Flow::CondJump, Some(0x1008 + 4 - 8)));
        assert_eq!(d.decode(&code[10..], 0x100a).flow, Flow::Ret);
        let r = render(Arch::Thumb, &code, 0x1000, 10, &NoNames);
        assert_eq!(r.iter().map(|i| i.size).collect::<Vec<_>>(), vec![2, 4, 2, 2, 2]);
    }
}
