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
    /// Indirect jump/call through a fixed memory slot (`jmp [rip+X]`, `call [X]`).
    pub indirect_slot: Option<u64>,
    pub valid: bool,
}

impl Decoded {
    fn invalid() -> Self {
        Decoded { len: 1, flow: Flow::None, target: None, data_ref: None, indirect_slot: None, valid: false }
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
    adrp: [Option<u64>; 32],
}

impl Disassembler {
    pub fn new(arch: Arch) -> Self {
        let bits = match arch {
            Arch::X86 => 32,
            _ => 64,
        };
        Disassembler { arch, bits, adrp: [None; 32] }
    }

    /// Forget register state (call at basic-block boundaries).
    pub fn reset(&mut self) {
        self.adrp = [None; 32];
    }

    pub fn decode(&mut self, bytes: &[u8], va: u64) -> Decoded {
        match self.arch {
            Arch::X86 | Arch::X86_64 => decode_x86(self.bits, bytes, va),
            Arch::Arm64 => self.decode_arm64(bytes, va),
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
        let mut d = Decoded { len: 4, flow: Flow::None, target: None, data_ref: None, indirect_slot: None, valid: true };
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
    Decoded { len: ins.len() as u8, flow, target, data_ref, indirect_slot, valid: true }
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
    match arch {
        Arch::X86 | Arch::X86_64 => render_x86(if arch == Arch::X86 { 32 } else { 64 }, bytes, va, max, names),
        Arch::Arm64 => render_arm64(bytes, va, max, names),
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
                    size: len as u8,
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
    let w = w.split('.').next().unwrap_or(w);
    matches!(w, "sp" | "wsp" | "xzr" | "wzr" | "lr" | "fp" | "pc" | "nzcv" | "fpcr" | "fpsr")
        || (w.len() >= 2
            && matches!(w.as_bytes()[0], b'x' | b'w' | b'v' | b'q' | b'd' | b's' | b'h' | b'b' | b'z' | b'p')
            && w[1..].bytes().all(|b| b.is_ascii_digit()))
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
}
