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
| ARM32/Thumb, MIPS, PowerPC, RISC-V | ⏳ | Headers and strings already work for these |
| Auto-analysis, functions, basic blocks | ✅ | Recursive descent seeded by entry, exports, symbols, `.pdata` |
| Switch/jump-table recovery | ⏳ | Indirect jumps currently end a block |
| Listing with labels, jump arrows, comments | ✅ | |
| Graph view | ✅ | |
| Cross references (to / from) | ✅ | Code and data |
| Rename, comments, bookmarks | ✅ | Persisted per SHA-256 |
| Create function (`P`) / reanalyze | ✅ | |
| Undefine / define data & strings (`U`, `D`, `A`) | ⏳ | |
| Name demangling | ✅ | MSVC, Itanium, Rust |
| Search: bytes, text, immediates | ✅ | |
| Hex view & patching, save patched file | ✅ | |
| Assemble (`Alt+F2`-style patching from mnemonics) | ⏳ | |
| Pseudocode | 🟡 | x86/x64 lifter with `if`/`do-while`; a full decompiler (types, SSA, expression propagation, `for`/`switch`) is the largest planned item |
| Types, structures, enums, local types | ⏳ | |
| Stack frame / local variable view | 🟡 | Stack slots are named in pseudocode |
| FLIRT-like library signatures | ⏳ | |
| PDB / DWARF debug info | 🟡 | PDB path and GUID shown; symbol loading planned |
| Call graph / proximity view | 🟡 | Callees and callers in the inspector |
| Scripting (Python / JS) and plugins | ⏳ | Stable plugin API over the JSON engine contract |
| Debugger (local / remote) | ⏳ | |
| Export: IDC script | ✅ | Names, comments, user functions |
| Project files, undo/redo | 🟡 | Annotations auto-save; undo planned |
| Collaboration / shared projects | ⏳ | Pro edition |

## Next milestones

1. **Data definitions** — undefine / make data / make string, switch tables, typed globals.
2. **Decompiler v2** — SSA-based expression propagation, variable recovery, `for`/`switch`/`break` structuring, type propagation from imports.
3. **Signatures & debug info** — FLIRT-style library matching, PDB and DWARF symbol loading.
4. **Scripting** — embedded Python and JS against the engine API; plugin manifest.
5. **AI assistant** — optional, local-first (Ollama / LM Studio) or user-supplied API keys: explain function, suggest names, flag suspicious patterns. Nothing leaves the machine unless the user opts in.
6. **More architectures** — ARM32/Thumb, MIPS, RISC-V, PowerPC.
7. **Debugger** — Windows (DbgEng/WinAPI) and Linux (ptrace/gdbserver) backends.

## Editions

The engine, CLI and desktop app described above are and will stay open source (Apache-2.0). A paid Pro edition with collaboration and team features may follow; it will build on, not take away from, the open core.
