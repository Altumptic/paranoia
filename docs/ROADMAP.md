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
| ARM32 / Thumb-2 disassembly | ✅ | Mixed ARM / Thumb images: the instruction set is tracked per address from ELF mapping symbols (`$a` / `$t`), the mode bit of function symbols, exports and the entry point, and `blx` targets found during analysis; the image default comes from the entry point (Windows on ARM is always Thumb). Literal pools and `adr` as data references. Limit: in a stripped image, code that follows a `blx` target with no symbol of its own is read in the target's mode |
| RISC-V disassembly | ✅ | RV32 / RV64 IMAFDC + Zicsr, compressed instructions, `auipc`/`lui` pairs resolved to data and call targets |
| MIPS disassembly | ✅ | MIPS32 / MIPS64, both byte orders, branch delay slots, `lui` + `addiu`/`lw` pairs |
| PowerPC disassembly | ✅ | 32- and 64-bit, both byte orders (ELF, Mach-O): integer, branches with simplified mnemonics (`beq`, `bdnz`, `blr`, `bctrl`), loads / stores, rotates, SPR moves, floating point, common AltiVec / VSX; `lis` + `addi`/`ori`/loads resolve addresses. Checked on Go-built ppc64 / ppc64le binaries: under 0.01 % of non-zero words undecoded. Not yet: pseudocode, PPC64 TOC-relative references |
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
| Assemble arbitrary instructions | ✅ | x86 / x64, Intel syntax (`Edit → Assemble…`): `mov eax, [ebx+ecx*4+8]`, `jz 0x401020`, `lock xadd [rdi], eax`, `db 0x90, 0xcc`; the shortest encoding wins, longer code takes over the following instructions and the rest is NOP-padded. Branch targets and RIP-relative operands are absolute addresses |
| Pseudocode | 🟡 | x86/x64: typed variables (`a1…`, `v1…` split at independent overwrites, types from API prototypes), expression propagation, `switch`, `while`/`for`/`do-while` with `break`/`continue`, symbolic API constants, struct member access (`Y` types a variable; fields, nesting, arrays render as `ctx->name`), argument/return types that flow across internal calls, and pointer fields that chain (`p = ctx->next` is typed `PKT *`, so lists and trees keep rendering as `p->…`). Pointer arithmetic on typed pointers follows C (`p += 0x60` on a 48-byte `T *` prints `p += 2`; other byte counts keep an explicit `(uint8_t *)` cast). Variables come from reaching definitions over the structured code (an SSA-style web per value, inside branches and loops too), so a register reused for unrelated values becomes separate variables. Not yet: a real SSA IR with phi-based expression propagation, other architectures |
| Operand representation (`H`, `R`, `B`, `M`) | ✅ | Hex / decimal, character, binary, symbolic constant; built-in Windows / POSIX enums applied to API arguments automatically |
| Types, structures, enums, local types | ✅ | C declarations (struct / union / enum / typedef, arrays, pointers, natural alignment); apply a struct to data (`Alt+Q`) |
| Stack frame / local variable view | ✅ | Offsets, sizes, read/write counts; same names as pseudocode |
| Argument labels from API prototypes | ✅ | ~250 WinAPI / libc prototypes (`; lpFileName`) |
| FLIRT-style library signatures | ✅ | Reads IDA's binary `.sig` files (versions 5–10, compressed or not, tail bytes checked) and FLAIR `.pat` files, writes `.pat` from any binary with symbols (`sigmake`), built-in MSVC x64 runtime library. Referenced-function checks in `.sig` modules are not used yet |
| PDB debug info | ✅ | Publics, procedures and globals; GUID check; the PDB next to the binary is picked up automatically |
| DWARF debug info | ✅ | Function names and bounds, globals and source lines (ELF, Mach-O, MinGW / Rust-gnu PE); struct, union and enum definitions kept as debug-info types (a runtime layer under Local Types, never saved) for `Y` and the decompiler |
| PDB types | ✅ | Struct, union and enum definitions from the PDB type stream (C-like names only; templates and namespaced C++ types are skipped) join the same debug-info layer; searchable in the Types panel and offered by `Y` |
| Call graph / proximity view | ✅ | Callers / callees to configurable depth |
| Navigation band | ✅ | |
| Xrefs dialog (`X`), token highlight, context menu | ✅ | |
| Scripting | ✅ | Python (your CPython, IDAPython-style `idc` / `idautils` names) and JavaScript consoles; headless `paranoia script` batch mode |
| AI assistant | ✅ | Optional; off until you choose a model server: local (Ollama, LM Studio) or cloud (Claude through Anthropic's API; OpenAI / Codex, DeepSeek, Kimi, Gemini, Mistral, OpenRouter through the OpenAI chat API). **Assistant** menu: explain the function under the cursor, suggest a name (applied only on click), flag suspicious behaviour. Requests come from the main process, carry one function's decompiled text, and a non-loopback host needs native consent. Not yet: streaming, chat, batch renaming |
| Plugins | ✅ | Folder + `plugin.json` manifest + one `.js` / `.py` script; commands in the **Plugins** menu; native confirmation per version (SHA-256 of manifest + script). See [PLUGINS.md](PLUGINS.md). Not yet: plugin panels, hotkeys, event hooks |
| Debugger | 🟡 | Local Windows x64 and 32-bit (WOW64) programs: breakpoints (`F2`), run / step into / step over / run to cursor (`F9`/`F7`/`F8`/`F4`), registers, stack. Linux and remote planned |
| Export: IDC script | ✅ | Names, comments, user functions |
| Project files, undo/redo | ✅ | Annotations auto-save per file hash; undo / redo (200 steps) |
| Collaboration / shared projects | ⏳ | Pro edition |

## Next milestones

1. **Decompiler v3** — ~~SSA-style variable recovery~~ (reaching definitions, done); next: a real SSA IR (phi nodes, cross-block expression propagation), type propagation through arithmetic and arrays of structures.
2. **Signatures & types** — ~~IDA `.sig` reading~~ and ~~PDB types~~ (done); next: referenced-function checks, more built-in libraries.
3. ~~**Plugins**~~ — done (commands); next: panels, hotkeys and event hooks.
4. ~~**AI assistant**~~ — done (explain, suggest a name, flag suspicious behaviour); next: batch naming of `sub_` functions, chat about a selection, streaming.
5. **More architectures** — ~~PowerPC~~, ~~mixed ARM/Thumb~~ (done); pseudocode beyond x86.
6. **Debugger** — ~~32-bit Windows targets~~ (done), Linux (ptrace / gdbserver) and remote backends.

## Editions

The engine, CLI and desktop app described above are and will stay open source (Apache-2.0). A paid Pro edition with collaboration and team features may follow; it will build on, not take away from, the open core.
