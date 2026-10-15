//! Serializable data model shared by every Paranoia front-end
//! (desktop app, CLI, WebAssembly build).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Pe,
    Elf,
    MachO,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::MachO => "Mach-O",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    PowerPc,
    RiscV,
    Unknown,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86-64",
            Arch::Arm => "ARM",
            Arch::Arm64 => "AArch64",
            Arch::Mips => "MIPS",
            Arch::PowerPc => "PowerPC",
            Arch::RiscV => "RISC-V",
            Arch::Unknown => "unknown",
        }
    }

    /// Whether the disassembler can decode this architecture.
    pub fn disassembly_supported(self) -> bool {
        matches!(self, Arch::X86 | Arch::X86_64 | Arch::Arm64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl std::fmt::Display for Perms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}{}", if self.r { 'r' } else { '-' }, if self.w { 'w' } else { '-' }, if self.x { 'x' } else { '-' })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    /// Owning segment (Mach-O) when applicable.
    pub segment: Option<String>,
    pub vaddr: u64,
    pub vsize: u64,
    pub offset: u64,
    pub raw_size: u64,
    pub perms: Perms,
    /// Shannon entropy of the raw bytes, 0.0 ..= 8.0.
    pub entropy: f64,
    pub flags: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub library: String,
    /// Address of the slot (IAT entry / GOT / lazy pointer) the code references.
    pub address: u64,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
    pub ordinal: Option<u32>,
    /// `lib!symbol` when the export is forwarded elsewhere.
    pub forward: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    File,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// PE import hash (Mandiant imphash) when applicable.
    pub imphash: Option<String>,
}

/// Exploit mitigations detected in the image, in `checksec` style.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mitigation {
    pub name: String,
    pub enabled: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub file_name: String,
    pub file_size: u64,
    pub format: Format,
    pub arch: Arch,
    pub bits: u8,
    pub endian: Endian,
    pub kind: String,
    pub entry: u64,
    pub image_base: u64,
    pub entropy: f64,
    /// Entropy of consecutive fixed-size chunks across the whole file (for the overview map).
    pub entropy_map: Vec<f32>,
    pub hashes: Hashes,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub libraries: Vec<String>,
    pub symbol_count: usize,
    pub mitigations: Vec<Mitigation>,
    /// Format-specific header fields rendered as key/value pairs.
    pub headers: Vec<KeyValue>,
    pub warnings: Vec<String>,
    pub disassembly_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    None,
    Call,
    Jump,
    CondJump,
    Ret,
    Interrupt,
}

/// Token classes used by the UI for syntax highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Text,
    Register,
    Number,
    Keyword,
    Symbol,
    Address,
    Punct,
    Prefix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub t: String,
    pub k: TokenKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub size: u8,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: Vec<Token>,
    pub flow: Flow,
    /// Direct branch / call target, or the address of a referenced memory operand.
    pub target: Option<u64>,
    /// Auto-generated annotation (string literal, import name, ...).
    pub comment: Option<String>,
    /// Function name or `loc_` label when this address starts a function / block.
    pub label: Option<String>,
    pub user_comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeKind {
    Uncond,
    True,
    False,
    Fall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub to: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,
    pub succs: Vec<Edge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FunctionSource {
    Entry,
    Export,
    Symbol,
    ExceptionTable,
    Call,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub blocks: usize,
    pub instructions: usize,
    pub calls: usize,
    pub xrefs: usize,
    pub source: FunctionSource,
    pub is_import_thunk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphBlock {
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<Instruction>,
    pub succs: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionGraph {
    pub address: u64,
    pub name: String,
    pub blocks: Vec<GraphBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringEncoding {
    Ascii,
    Utf16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub offset: u64,
    pub address: Option<u64>,
    pub section: Option<String>,
    pub encoding: StringEncoding,
    pub value: String,
    pub xrefs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefKind {
    Call,
    Jump,
    Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
    /// Function containing `from`, if known.
    pub function: Option<u64>,
    pub function_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub functions: usize,
    pub instructions: usize,
    pub blocks: usize,
    pub strings: usize,
    pub xrefs: usize,
    pub millis: u64,
}

/// What lives at an address, used by "Go to" and hover tooltips.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub address: u64,
    pub offset: Option<u64>,
    pub section: Option<String>,
    pub name: Option<String>,
    pub function: Option<u64>,
    pub function_name: Option<String>,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub kind: String,
    pub label: String,
    pub detail: String,
    pub address: u64,
}
