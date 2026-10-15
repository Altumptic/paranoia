// Mirror of crates/paranoia-core/src/model.rs. Keep in sync with the Rust side.

export type Format = "pe" | "elf" | "macho";
export type Arch = "x86" | "x86_64" | "arm" | "arm64" | "mips" | "powerpc" | "riscv" | "unknown";

export interface Perms {
  r: boolean;
  w: boolean;
  x: boolean;
}

export interface Section {
  name: string;
  segment: string | null;
  vaddr: number;
  vsize: number;
  offset: number;
  raw_size: number;
  perms: Perms;
  entropy: number;
  flags: number;
}

export interface Import {
  name: string;
  library: string;
  address: number;
  ordinal: number | null;
}

export interface Export {
  name: string;
  address: number;
  ordinal: number | null;
  forward: string | null;
}

export type SymbolKind = "function" | "object" | "section" | "file" | "other";

export interface Symbol {
  name: string;
  address: number;
  size: number;
  kind: SymbolKind;
  global: boolean;
}

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
  imphash: string | null;
}

export interface Mitigation {
  name: string;
  enabled: boolean;
  detail: string;
}

export interface KeyValue {
  key: string;
  value: string;
}

export interface BinaryInfo {
  file_name: string;
  file_size: number;
  format: Format;
  arch: Arch;
  bits: number;
  endian: "little" | "big";
  kind: string;
  entry: number;
  image_base: number;
  entropy: number;
  entropy_map: number[];
  hashes: Hashes;
  sections: Section[];
  imports: Import[];
  exports: Export[];
  libraries: string[];
  symbol_count: number;
  mitigations: Mitigation[];
  headers: KeyValue[];
  warnings: string[];
  disassembly_supported: boolean;
}

export type Flow = "none" | "call" | "jump" | "condjump" | "ret" | "interrupt";
export type TokenKind = "text" | "register" | "number" | "keyword" | "symbol" | "address" | "punct" | "prefix";

export interface Token {
  t: string;
  k: TokenKind;
}

export interface Instruction {
  address: number;
  size: number;
  bytes: string;
  mnemonic: string;
  operands: Token[];
  flow: Flow;
  target: number | null;
  comment: string | null;
  label: string | null;
  user_comment: string | null;
}

export type EdgeKind = "uncond" | "true" | "false" | "fall";

export interface Edge {
  to: number;
  kind: EdgeKind;
}

export type FunctionSource = "entry" | "export" | "symbol" | "exceptiontable" | "call" | "user";

export interface FunctionSummary {
  address: number;
  name: string;
  size: number;
  blocks: number;
  instructions: number;
  calls: number;
  xrefs: number;
  source: FunctionSource;
  is_import_thunk: boolean;
}

export interface GraphBlock {
  start: number;
  end: number;
  instructions: Instruction[];
  succs: Edge[];
}

export interface FunctionGraph {
  address: number;
  name: string;
  blocks: GraphBlock[];
}

export interface StringEntry {
  offset: number;
  address: number | null;
  section: string | null;
  encoding: "ascii" | "utf16";
  value: string;
  xrefs: number;
}

export interface Xref {
  from: number;
  to: number;
  kind: "call" | "jump" | "data";
  function: number | null;
  function_name: string | null;
}

export interface AnalysisStats {
  functions: number;
  instructions: number;
  blocks: number;
  strings: number;
  xrefs: number;
  millis: number;
}

export interface AddressInfo {
  address: number;
  offset: number | null;
  section: string | null;
  name: string | null;
  function: number | null;
  function_name: string | null;
  executable: boolean;
}

export interface SearchHit {
  kind: "address" | "function" | "import" | "export" | "string";
  label: string;
  detail: string;
  address: number;
}

export interface Annotations {
  names: Record<string, string>;
  comments: Record<string, string>;
}
