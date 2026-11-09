//! A text assembler for x86 / x64 (Intel syntax), built on iced's encoder.
//!
//! `mov eax, [ebx+ecx*4+8]`, `jz 0x401020`, `ret 8`, `lock xadd [rdi], eax`, `db 0x90, 0xcc`.
//! The mnemonic selects every encoding of that mnemonic, the operands are fitted to each one, and the
//! shortest one wins, which is what you want when patching.
//!
//! Branch targets are absolute addresses. RIP-relative memory is written with the absolute target
//! (`[rip+0x140002000]`, the address the instruction reads), not the displacement.

use std::collections::HashMap;
use std::sync::OnceLock;

use iced_x86::{Code, Encoder, FlowControl, Instruction, MemoryOperand, Mnemonic, OpCodeOperandKind, Register};

struct Tables {
    mnemonics: HashMap<String, Mnemonic>,
    registers: HashMap<String, Register>,
    by_mnemonic: HashMap<Mnemonic, Vec<Code>>,
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut mnemonics = HashMap::new();
        for m in Mnemonic::values() {
            mnemonics.insert(format!("{m:?}").to_ascii_lowercase(), m);
        }
        // Intel / MASM spellings iced does not use as primary names.
        for (alias, real) in [
            ("jz", "je"),
            ("jnz", "jne"),
            ("jc", "jb"),
            ("jnae", "jb"),
            ("jnc", "jae"),
            ("jnb", "jae"),
            ("jna", "jbe"),
            ("jnbe", "ja"),
            ("jnge", "jl"),
            ("jnl", "jge"),
            ("jng", "jle"),
            ("jnle", "jg"),
            ("jpe", "jp"),
            ("jpo", "jnp"),
            ("retn", "ret"),
            ("setz", "sete"),
            ("setnz", "setne"),
            ("cmovz", "cmove"),
            ("cmovnz", "cmovne"),
            ("sal", "shl"),
        ] {
            if let Some(m) = mnemonics.get(real).copied() {
                mnemonics.entry(alias.to_string()).or_insert(m);
            }
        }
        let mut registers = HashMap::new();
        for r in Register::values() {
            if r != Register::None {
                registers.insert(format!("{r:?}").to_ascii_lowercase(), r);
            }
        }
        let mut by_mnemonic: HashMap<Mnemonic, Vec<Code>> = HashMap::new();
        for c in Code::values() {
            by_mnemonic.entry(c.mnemonic()).or_default().push(c);
        }
        Tables { mnemonics, registers, by_mnemonic }
    })
}

#[derive(Debug, Clone)]
enum Operand {
    Reg(Register),
    Mem { mem: MemoryOperand, size: Option<u32> },
    Num(i128),
}

fn parse_num(s: &str) -> Option<i128> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r.trim()),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i128::from_str_radix(h, 16).ok()?
    } else if let Some(h) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        if !h.chars().next()?.is_ascii_digit() {
            return None;
        }
        i128::from_str_radix(h, 16).ok()?
    } else if let Some(b) = s.strip_prefix("0b") {
        i128::from_str_radix(b, 2).ok()?
    } else {
        s.parse::<i128>().ok()?
    };
    Some(if neg { -v } else { v })
}

fn split_operands(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out.into_iter().map(|s| s.trim().to_string()).collect()
}

fn parse_memory(text: &str, bitness: u32) -> Result<Operand, String> {
    let t = tables();
    let mut rest = text.trim().to_ascii_lowercase();
    // Size prefix.
    let mut size = None;
    for (word, bytes) in [
        ("byte", 1),
        ("word", 2),
        ("dword", 4),
        ("qword", 8),
        ("tbyte", 10),
        ("xmmword", 16),
        ("oword", 16),
        ("ymmword", 32),
        ("zmmword", 64),
    ] {
        if let Some(r) = rest.strip_prefix(word) {
            if r.starts_with(|c: char| c.is_whitespace() || c == '[') {
                size = Some(bytes);
                rest = r.trim_start().to_string();
                break;
            }
        }
    }
    if let Some(r) = rest.strip_prefix("ptr") {
        rest = r.trim_start().to_string();
    }
    // Segment override: `fs:[0x30]`.
    let mut segment = Register::None;
    if let Some((seg, r)) = rest.split_once(':') {
        let reg = t
            .registers
            .get(seg.trim())
            .copied()
            .filter(|r| matches!(r, Register::ES | Register::CS | Register::SS | Register::DS | Register::FS | Register::GS));
        segment = reg.ok_or_else(|| format!("unknown segment `{seg}`"))?;
        rest = r.trim().to_string();
    }
    let inner = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')).ok_or("memory operands are written [base+index*scale+disp]")?;
    let (mut base, mut index, mut scale, mut disp) = (Register::None, Register::None, 1u32, 0i128);
    // Split into signed terms.
    let mut terms: Vec<(i128, String)> = Vec::new();
    let mut sign = 1;
    let mut cur = String::new();
    for c in inner.chars().chain(std::iter::once('+')) {
        match c {
            '+' | '-' => {
                if !cur.trim().is_empty() {
                    terms.push((sign, std::mem::take(&mut cur).trim().to_string()));
                } else {
                    cur.clear();
                }
                sign = if c == '-' { -1 } else { 1 };
            }
            _ => cur.push(c),
        }
    }
    for (sg, term) in terms {
        if let Some((r, s)) = term.split_once('*') {
            let (r, s) = if t.registers.contains_key(r.trim()) { (r.trim(), s.trim()) } else { (s.trim(), r.trim()) };
            let reg = t.registers.get(r).copied().ok_or_else(|| format!("`{r}` is not a register"))?;
            let sc = parse_num(s).ok_or_else(|| format!("bad scale `{s}`"))?;
            if sg < 0 || !matches!(sc, 1 | 2 | 4 | 8) || index != Register::None {
                return Err("bad index / scale".into());
            }
            index = reg;
            scale = sc as u32;
        } else if let Some(reg) = t.registers.get(term.as_str()).copied() {
            if sg < 0 {
                return Err("a register cannot be subtracted".into());
            }
            if base == Register::None {
                base = reg;
            } else if index == Register::None {
                index = reg;
            } else {
                return Err("too many registers in the address".into());
            }
        } else if let Some(n) = parse_num(&term) {
            disp += sg * n;
        } else {
            return Err(format!("cannot read `{term}` in the address"));
        }
    }
    let disp = i64::try_from(disp).map_err(|_| "displacement out of range")?;
    let displ_size = if base == Register::RIP || base == Register::EIP {
        // iced takes the absolute target for RIP-relative operands.
        8
    } else if base == Register::None && index == Register::None {
        if bitness == 64 && i32::try_from(disp).is_err() {
            8
        } else {
            4
        }
    } else if disp == 0 {
        u32::from(matches!(base, Register::EBP | Register::RBP | Register::R13 | Register::R13D))
    } else if i8::try_from(disp).is_ok() {
        1
    } else {
        4
    };
    let displ_size = if base == Register::RIP || base == Register::EIP { 8 } else { displ_size };
    Ok(Operand::Mem { mem: MemoryOperand::new(base, index, scale, disp, displ_size, false, segment), size })
}

fn parse_operand(text: &str, bitness: u32) -> Result<Operand, String> {
    let t = tables();
    let low = text.trim().to_ascii_lowercase();
    if low.contains('[') {
        return parse_memory(&low, bitness);
    }
    if let Some(r) = t.registers.get(low.as_str()) {
        return Ok(Operand::Reg(*r));
    }
    parse_num(&low).map(Operand::Num).ok_or_else(|| format!("cannot read operand `{text}`"))
}

fn is_near_branch(code: Code) -> bool {
    if code.op_code().op_count() != 1 {
        return false;
    }
    matches!(
        code.flow_control(),
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::XbeginXabortXend
    ) && matches!(
        code.op_code().op0_kind(),
        OpCodeOperandKind::br32_1 | OpCodeOperandKind::br32_4 | OpCodeOperandKind::br64_1 | OpCodeOperandKind::br64_4
    )
}

/// Builds `code` with the given operands; every operand-kind combination iced has a constructor for.
fn build(code: Code, ops: &[Operand]) -> Option<Instruction> {
    use Operand::{Mem, Num, Reg};
    let imm_i = |n: i128| i32::try_from(n).ok();
    let imm_u = |n: i128| u32::try_from(n).ok();
    let imm_i64 = |n: i128| i64::try_from(n).ok();
    let imm_u64 = |n: i128| u64::try_from(n).ok();
    match ops {
        [] => Some(Instruction::with(code)),
        [Reg(a)] => Instruction::with1(code, *a).ok(),
        [Mem { mem, .. }] => Instruction::with1(code, *mem).ok(),
        [Num(n)] => {
            imm_i(*n).and_then(|v| Instruction::with1(code, v).ok()).or_else(|| imm_u(*n).and_then(|v| Instruction::with1(code, v).ok()))
        }
        [Reg(a), Reg(b)] => Instruction::with2(code, *a, *b).ok(),
        [Reg(a), Mem { mem, .. }] => Instruction::with2(code, *a, *mem).ok(),
        [Mem { mem, .. }, Reg(b)] => Instruction::with2(code, *mem, *b).ok(),
        [Reg(a), Num(n)] => imm_i(*n)
            .and_then(|v| Instruction::with2(code, *a, v).ok())
            .or_else(|| imm_u(*n).and_then(|v| Instruction::with2(code, *a, v).ok()))
            .or_else(|| imm_i64(*n).and_then(|v| Instruction::with2(code, *a, v).ok()))
            .or_else(|| imm_u64(*n).and_then(|v| Instruction::with2(code, *a, v).ok())),
        [Mem { mem, .. }, Num(n)] => imm_i(*n)
            .and_then(|v| Instruction::with2(code, *mem, v).ok())
            .or_else(|| imm_u(*n).and_then(|v| Instruction::with2(code, *mem, v).ok())),
        [Num(n), Reg(b)] => imm_u(*n).and_then(|v| Instruction::with2(code, v, *b).ok()),
        [Num(a), Num(b)] => Instruction::with2(code, u32::try_from(*a).ok()?, u32::try_from(*b).ok()?).ok(),
        [Reg(a), Reg(b), Reg(c)] => Instruction::with3(code, *a, *b, *c).ok(),
        [Reg(a), Reg(b), Mem { mem, .. }] => Instruction::with3(code, *a, *b, *mem).ok(),
        [Reg(a), Reg(b), Num(n)] => imm_i(*n)
            .and_then(|v| Instruction::with3(code, *a, *b, v).ok())
            .or_else(|| imm_u(*n).and_then(|v| Instruction::with3(code, *a, *b, v).ok())),
        [Reg(a), Mem { mem, .. }, Num(n)] => imm_i(*n)
            .and_then(|v| Instruction::with3(code, *a, *mem, v).ok())
            .or_else(|| imm_u(*n).and_then(|v| Instruction::with3(code, *a, *mem, v).ok())),
        [Mem { mem, .. }, Reg(b), Reg(c)] => Instruction::with3(code, *mem, *b, *c).ok(),
        [Mem { mem, .. }, Reg(b), Num(n)] => imm_u(*n).and_then(|v| Instruction::with3(code, *mem, *b, v).ok()),
        _ => None,
    }
}

struct Candidate {
    bytes: Vec<u8>,
    mem_size: Option<u32>,
}

fn encode_one(inst: &Instruction, ip: u64, bitness: u32) -> Option<Vec<u8>> {
    let mut enc = Encoder::new(bitness);
    enc.encode(inst, ip).ok()?;
    Some(enc.take_buffer())
}

/// Assembles one instruction (or a `db` directive) at `ip`.
pub fn assemble(text: &str, ip: u64, bitness: u32) -> Result<Vec<u8>, String> {
    if bitness != 32 && bitness != 64 {
        return Err("the assembler supports 32-bit and 64-bit x86".into());
    }
    if text.len() > 1024 {
        return Err("one instruction per line, please (the text is too long)".into());
    }
    let text = text.split(';').next().unwrap_or("").trim();
    if text.is_empty() {
        return Err("nothing to assemble".into());
    }
    let (word, rest) = text.split_once(char::is_whitespace).map_or((text, ""), |(a, b)| (a, b.trim()));
    if word.eq_ignore_ascii_case("db") {
        let mut out = Vec::new();
        for item in split_operands(rest) {
            if let Some(s) = item.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                out.extend(s.bytes());
            } else {
                let n = parse_num(&item).ok_or_else(|| format!("bad byte `{item}`"))?;
                out.push(
                    u8::try_from(n).or_else(|_| i8::try_from(n).map(|v| v as u8)).map_err(|_| format!("`{item}` does not fit a byte"))?,
                );
            }
        }
        return if out.is_empty() { Err("db needs at least one byte".into()) } else { Ok(out) };
    }
    // Prefixes.
    let (mut lock, mut rep, mut repne) = (false, false, false);
    let (mut mnem, mut rest) = (word.to_ascii_lowercase(), rest.to_string());
    loop {
        match mnem.as_str() {
            "lock" => lock = true,
            "rep" | "repe" | "repz" => rep = true,
            "repne" | "repnz" => repne = true,
            _ => break,
        }
        let (w, r) = rest.split_once(char::is_whitespace).map_or((rest.as_str(), ""), |(a, b)| (a, b.trim()));
        mnem = w.to_ascii_lowercase();
        rest = r.to_string();
    }
    let t = tables();
    let m = *t.mnemonics.get(&mnem).ok_or_else(|| format!("unknown mnemonic `{mnem}`"))?;
    let ops: Vec<Operand> = split_operands(&rest).iter().map(|o| parse_operand(o, bitness)).collect::<Result<_, _>>()?;
    let wanted_size = ops.iter().find_map(|o| if let Operand::Mem { size, .. } = o { *size } else { None });
    let has_reg = ops.iter().any(|o| matches!(o, Operand::Reg(_)));
    let has_mem = ops.iter().any(|o| matches!(o, Operand::Mem { .. }));

    let mut found: Vec<Candidate> = Vec::new();
    for &code in t.by_mnemonic.get(&m).map(Vec::as_slice).unwrap_or(&[]) {
        if code.op_code().op_count() as usize != ops.len() {
            continue;
        }
        // 16-bit-offset branches (operand-size prefix) are never what a 32/64-bit patch wants.
        if matches!(code.op_code().op0_kind(), OpCodeOperandKind::br16_1 | OpCodeOperandKind::br16_2) {
            continue;
        }
        let built = if let ([Operand::Num(target)], true) = (ops.as_slice(), is_near_branch(code)) {
            u64::try_from(*target).ok().and_then(|t| Instruction::with_branch(code, t).ok())
        } else {
            build(code, &ops)
        };
        let Some(mut inst) = built else { continue };
        inst.set_has_lock_prefix(lock);
        inst.set_has_rep_prefix(rep);
        inst.set_has_repne_prefix(repne);
        let mem_size = if has_mem { inst.memory_size().size().try_into().ok().filter(|s: &u32| *s > 0) } else { None };
        if let (Some(w), Some(have)) = (wanted_size, mem_size) {
            if w != have {
                continue;
            }
        }
        if let Some(bytes) = encode_one(&inst, ip, bitness) {
            found.push(Candidate { bytes, mem_size });
        }
    }
    if found.is_empty() {
        return Err(format!("cannot encode `{text}` for {bitness}-bit x86 (check the operand sizes and the mnemonic)"));
    }
    // Memory with no register to give the size and no `dword ptr`: ambiguous unless every encoding agrees.
    if has_mem && !has_reg && wanted_size.is_none() {
        let first = found[0].mem_size;
        if found.iter().any(|c| c.mem_size != first) {
            return Err("operand size not specified — write byte / word / dword / qword ptr".into());
        }
    }
    found.sort_by_key(|c| c.bytes.len());
    Ok(found.swap_remove(0).bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

    /// Assembles, decodes the result and compares the disassembly text.
    fn rt(text: &str, ip: u64, bits: u32) -> String {
        let bytes = assemble(text, ip, bits).unwrap_or_else(|e| panic!("{text}: {e}"));
        let mut d = Decoder::with_ip(bits, &bytes, ip, DecoderOptions::NONE);
        let i = d.decode();
        assert_eq!(i.len(), bytes.len(), "{text}: decoded length");
        let mut f = IntelFormatter::new();
        f.options_mut().set_space_after_operand_separator(true);
        f.options_mut().set_hex_prefix("0x");
        f.options_mut().set_hex_suffix("");
        f.options_mut().set_uppercase_hex(false);
        f.options_mut().set_branch_leading_zeros(false);
        let mut s = String::new();
        f.format(&i, &mut s);
        s
    }

    #[test]
    fn common_instructions_round_trip() {
        assert_eq!(assemble("nop", 0, 32).unwrap(), [0x90]);
        assert_eq!(assemble("ret", 0, 32).unwrap(), [0xc3]);
        assert_eq!(assemble("ret 8", 0, 32).unwrap(), [0xc2, 8, 0]);
        assert_eq!(assemble("int3", 0, 64).unwrap(), [0xcc]);
        assert_eq!(assemble("push ebp", 0, 32).unwrap(), [0x55]);
        assert_eq!(assemble("mov ebp, esp", 0, 32).unwrap().len(), 2);
        assert_eq!(assemble("xor eax, eax", 0, 32).unwrap(), [0x31, 0xc0]);
        assert_eq!(assemble("mov eax, 5", 0, 32).unwrap(), [0xb8, 5, 0, 0, 0]);
        assert_eq!(assemble("add esp, 0x10", 0, 32).unwrap(), [0x83, 0xc4, 0x10]);
        assert_eq!(assemble("push 1", 0, 32).unwrap(), [0x6a, 1]);
        assert_eq!(rt("mov eax, [ebx+ecx*4+8]", 0, 32), "mov eax, [ebx+ecx*4+8]");
        assert_eq!(rt("mov dword ptr [ebp-4], 0x1f", 0, 32), "mov dword ptr [ebp-4], 0x1f");
        assert_eq!(rt("lea rax, [rsp+0x20]", 0, 64), "lea rax, [rsp+0x20]");
        assert_eq!(rt("mov rax, 0x1122334455667788", 0, 64), "mov rax, 0x1122334455667788");
        assert_eq!(rt("movzx eax, byte ptr [esi]", 0, 32), "movzx eax, byte ptr [esi]");
        assert_eq!(rt("imul eax, ecx, 10", 0, 32), "imul eax, ecx, 0xa");
        assert_eq!(rt("test al, 1", 0, 32), "test al, 1");
        assert_eq!(rt("sub rsp, 0x28", 0, 64), "sub rsp, 0x28");
        assert_eq!(rt("mov eax, fs:[0x30]", 0, 32), "mov eax, fs:[0x30]");
        assert_eq!(rt("call dword ptr [0x402000]", 0, 32), "call dword ptr [0x402000]");
        assert_eq!(rt("lock xadd [rdi], eax", 0, 64), "lock xadd [rdi], eax");
    }

    #[test]
    fn branches_use_absolute_targets() {
        // Short form when the target is near, near form otherwise.
        assert_eq!(assemble("jmp 0x401010", 0x401000, 32).unwrap(), [0xeb, 0x0e]);
        assert_eq!(assemble("jz 0x401010", 0x401000, 32).unwrap(), [0x74, 0x0e]);
        assert_eq!(assemble("jne 0x402000", 0x401000, 32).unwrap().len(), 6);
        assert_eq!(assemble("call 0x401100", 0x401000, 32).unwrap(), [0xe8, 0xfb, 0x00, 0x00, 0x00]);
        assert_eq!(rt("call 0x140001230", 0x140001000, 64), "call 0x140001230");
        assert_eq!(rt("jmp 0x7ff600001000", 0x7ff600000000, 64), "jmp 0x7ff600001000");
    }

    #[test]
    fn data_prefix_and_errors() {
        assert_eq!(assemble("db 0x90, 0xcc, \"hi\"", 0, 32).unwrap(), [0x90, 0xcc, b'h', b'i']);
        assert_eq!(assemble("MOV EAX, 1Fh", 0, 32).unwrap(), [0xb8, 0x1f, 0, 0, 0]);
        // A comment after `;` is ignored.
        assert_eq!(assemble("nop ; does nothing", 0, 32).unwrap(), [0x90]);
        assert!(assemble("frobnicate eax", 0, 32).unwrap_err().contains("unknown mnemonic"));
        assert!(assemble("mov rax, 1", 0, 32).is_err(), "rax does not exist in 32-bit mode");
        assert!(assemble("mov [eax], 5", 0, 32).unwrap_err().contains("operand size"));
        assert!(assemble("mov eax, [", 0, 32).is_err());
        assert!(assemble("", 0, 32).is_err());
        assert!(assemble(&"nop ".repeat(400), 0, 32).unwrap_err().contains("too long"));
    }
}
