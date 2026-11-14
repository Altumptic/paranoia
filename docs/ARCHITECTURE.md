# Architecture

Paranoia is one analysis engine written in Rust, plus a few programs that drive it.

```
apps/desktop (React UI, Electron)
   │                        │
   │ JSON over stdio         │ Web Worker
   ▼                        ▼
paranoia-engine          paranoia-wasm
(+ paranoia-db, debugger)   │
   │                        │
   └──────► paranoia-core ◄─┘ ◄── paranoia-cli (CLI, scripts, MCP server)
            Session::call(method, args)
```

Every front end talks to the engine through one function, `Session::call(method, args)` in `crates/paranoia-core/src/api.rs`, with JSON arguments and results. Addresses are JSON numbers, which is exact below 2^53 and covers user-mode images. The native engine and the WebAssembly build expose exactly the same methods.

## paranoia-core

The engine. No I/O, threads or C dependencies, so the same code builds natively and for WebAssembly.

| Files | What they do |
| --- | --- |
| `loader/` | PE, ELF and Mach-O loaders that produce a common `Loaded` image: sections, address map, imports, exports, symbols, function seeds, mitigations. The PE `.pdata` table, Mach-O bind opcodes, chained fixups, the export trie and the ELF `.eh_frame_hdr` table and Go's function table (`gopclntab.rs`) are parsed by our own bounds-checked code. |
| `disasm.rs`, `riscv.rs`, `mips.rs`, `ppc.rs` | Decoding for analysis (length, flow, targets, data references) and token rendering for the UI. x86 uses iced-x86, ARM uses yaxpeax-arm, RISC-V, MIPS and PowerPC have their own decoders. |
| `analysis.rs`, `switch.rs` | Recursive-descent function discovery, basic blocks, jump tables, the cross-reference index. |
| `pseudo.rs`, `pseudo_opt.rs`, `pseudo_types.rs`, `pseudo_ssa.rs` | The x86/x64 decompiler: lifting to C-like lines, expression propagation, loops and `switch`, variables and their types. |
| `pseudo_structs.rs` | Struct member access for variables typed with `Y`, and types passed along calls. |
| `ssa.rs`, `ssa/a64.rs`, `ssa/c.rs` | An SSA form (phi nodes, constant and copy propagation, dead code) for x86/x64 and AArch64, and C generated from it. AArch64 pseudocode comes from here. |
| `items.rs`, `types.rs`, `operands.rs`, `protos.rs` | Data items and auto names, local C types, operand display, about 250 API prototypes. |
| `pdbsym.rs`, `pdbtypes.rs`, `dwarf.rs` | PDB and DWARF symbols, source lines and types. |
| `sigs.rs`, `flirt_sig.rs` | FLIRT signatures: `.pat` files, IDA `.sig` files, a built-in MSVC x64 library. |
| `memory/` | Function memory: per-function fingerprints (`print.rs`), matching two binaries (`diff.rs`), and what the knowledge base stores and how recalled functions are chosen and applied (`knowledge.rs`). Storage is in `paranoia-db`. |
| `asm_x86.rs` | A small x86 assembler for patching. |
| `tools.rs`, `nav.rs`, `frame.rs` | Search, patching, call graph, undo, stack frames, IDC export. |
| `strings.rs`, `metrics.rs`, `demangle.rs` | Strings, hashes and entropy, MSVC/Itanium/Rust demangling. |
| `api.rs` | `Session::call`, the only way in. |

### Hostile input

Files are treated as hostile. Loaders don't trust any size or offset, analysis has hard limits (`MAX_FUNCTIONS`, `MAX_INSNS_PER_FUNCTION`, `MAX_TOTAL_INSNS`), and `tests/real_binaries.rs` feeds corrupted copies of real binaries to the engine to check that nothing panics. Where a third-party parser turned out to panic on bad input, we replaced it with our own. In the desktop app the engine also runs in a separate process, so a crash doesn't take the UI down.

## The other crates

- **paranoia-engine** is the process the desktop app starts. It reads JSON requests on stdin, keeps the workspace store (`paranoia-db`, a redb file keyed by each file's SHA-256), and contains the debuggers: `debugger.rs` for Windows (x64 and WOW64) and `debugger_linux.rs` for Linux x86-64 and ARM64 (ptrace; a small `arch` module holds the register file, the breakpoint instruction and call detection).
- **paranoia-cli** is the `paranoia` command. `script.rs` runs Python scripts without the app, `mcp.rs` is the MCP server and `disclosure.rs` has its string redaction and disclosure log.
- **paranoia-wasm** exports `pn_alloc`, `pn_open`, `pn_call` and a few more as a plain C ABI. No wasm-bindgen.

## The desktop app

- `apps/desktop/src` is the React UI. `engine/client.ts` wraps the engine API with types and works with both backends.
- `apps/desktop/electron` is the Electron main process, which is the security boundary: it checks the sender of every IPC message, only lets the engine open files the user picked, and asks before starting the debugger or a Python script. `ai.cjs` makes the AI assistant's requests and `plugins.cjs` validates plugins. See [SECURITY-DESIGN.md](SECURITY-DESIGN.md).
- The JavaScript console runs scripts in a Web Worker that can only reach the engine through `pn` calls. Python scripts run in the user's own interpreter.

## Adding an engine method

1. Implement it on `Binary`, with a test.
2. Add it to `Session::call` in `api.rs`.
3. Add a typed wrapper to `apps/desktop/src/engine/client.ts` and any new types to `types.ts`.
