# Roadmap

Paranoia aims to cover the day-to-day workflow of IDA Pro in an open, local-first package. This page is an honest comparison of where it stands today.

Legend: ✅ available · 🟡 partial · ⏳ planned

## Parity with IDA Pro

| Capability | Status | Notes |
| --- | --- | --- |
| PE / ELF / Mach-O loading | ✅ | Universal binaries, chained fixups, forwarders, TLS callbacks |
| Raw binaries, firmware, COFF/OMF objects, DEX, NE/LE | ⏳ | Manual load address and processor selection |
| x86 / x86-64 disassembly | ✅ | |
| AArch64 disassembly | ✅ | ADRP-based data references |
| ARM32 / Thumb-2 disassembly | ✅ | Thumb chosen from the entry point's mode bit (Windows on ARM is always Thumb); literal pools and `adr` as data references |
| RISC-V disassembly | ✅ | RV32 / RV64 IMAFDC + Zicsr, compressed instructions, `auipc`/`lui` pairs resolved to data and call targets |
| MIPS disassembly | ✅ | MIPS32 / MIPS64, both byte orders, branch delay slots, `lui` + `addiu`/`lw` pairs |
| PowerPC disassembly | ⏳ | Headers and strings already work |
| Auto-analysis, functions, basic blocks | ✅ | Recursive descent seeded by entry, exports, symbols, `.pdata` |
| Switch/jump-table recovery | ✅ | Absolute tables, MSVC `__ImageBase` RVA tables, PIC relative tables |
| Listing with labels, jump arrows, comments | ✅ | |
| Graph view | ✅ | |
| Cross references (to / from) | ✅ | Code and data |
| Rename, comments, bookmarks | ✅ | Persisted per SHA-256 |
| Create function (`P`) / reanalyze | ✅ | |
| Undefine / define code, data & strings (`U`, `C`, `D`, `A`) | ✅ | Listing covers data: `db/dw/dd/dq`, strings, `offset`, `extrn`, `dup` |
| Auto names (`aString`, `qword_…`, `off_…`, `loc_…`) | ✅ | From access sizes and references, like IDA |
| Name demangling | ✅ | MSVC, Itanium, Rust |
| Search: bytes, text, immediates | ✅ | |
| Hex view & patching, save patched file | ✅ | |
| Instruction patches (NOP, invert, force jump) | ✅ | x86/x64 and AArch64 |
| Assemble arbitrary instructions | ⏳ | |
| Pseudocode | 🟡 | x86/x64: typed variables (`a1…`, `v1…` split at independent overwrites, types from API prototypes), expression propagation, `switch`, `while`/`for`/`do-while` with `break`/`continue`, symbolic API constants. Not yet: SSA-based variable recovery, struct member access, other architectures |
| Operand representation (`H`, `R`, `B`, `M`) | ✅ | Hex / decimal, character, binary, symbolic constant; built-in Windows / POSIX enums applied to API arguments automatically |
| Types, structures, enums, local types | ✅ | C declarations (struct / union / enum / typedef, arrays, pointers, natural alignment); apply a struct to data (`Alt+Q`) |
| Stack frame / local variable view | ✅ | Offsets, sizes, read/write counts; same names as pseudocode |
| Argument labels from API prototypes | ✅ | ~250 WinAPI / libc prototypes (`; lpFileName`) |
| FLIRT-style library signatures | ✅ | Reads IDA FLAIR `.pat` files, writes them from any binary with symbols (`sigmake`), built-in MSVC x64 runtime library; IDA's binary `.sig` format is not read yet |
| PDB debug info | ✅ | Publics, procedures and globals; GUID check; the PDB next to the binary is picked up automatically |
| DWARF debug info | ✅ | Function names and bounds, globals and source lines (ELF, Mach-O, MinGW / Rust-gnu PE) |
| Call graph / proximity view | ✅ | Callers / callees to configurable depth |
| Navigation band | ✅ | |
| Xrefs dialog (`X`), token highlight, context menu | ✅ | |
| Scripting | ✅ | Python (your CPython, IDAPython-style `idc` / `idautils` names) and JavaScript consoles; headless `paranoia script` batch mode. Plugins planned |
| Debugger | 🟡 | Local Windows x64: breakpoints (`F2`), run / step into / step over / run to cursor (`F9`/`F7`/`F8`/`F4`), registers, stack. x86, Linux and remote planned |
| Export: IDC script | ✅ | Names, comments, user functions |
| Project files, undo/redo | ✅ | Annotations auto-save per file hash; undo / redo (200 steps) |
| Collaboration / shared projects | ⏳ | Pro edition |

## Next milestones

1. **Decompiler v2** — SSA-based expression propagation, variable recovery, `for`/`switch`/`break` structuring, type propagation from imports.
2. **Signatures & types** — IDA `.sig` reading, more built-in libraries; DWARF types into Local Types.
3. **Plugins** — a plugin manifest on top of the Python and JavaScript APIs.
4. **AI assistant** — optional, local-first (Ollama / LM Studio) or user-supplied API keys: explain function, suggest names, flag suspicious patterns. Nothing leaves the machine unless the user opts in.
5. **More architectures** — PowerPC; mixed ARM/Thumb images; pseudocode beyond x86.
6. **Debugger** — 32-bit Windows targets, Linux (ptrace / gdbserver) and remote backends.

## Editions

The engine, CLI and desktop app described above are and will stay open source (Apache-2.0). A paid Pro edition with collaboration and team features may follow; it will build on, not take away from, the open core.
