# Roadmap

Paranoia aims to cover the day-to-day workflow of IDA Pro in an open, local-first package. This page is an honest comparison of where it stands today and the order in which the gaps get closed. Why this order: [STRATEGY.md](STRATEGY.md).

Legend: ✅ available · 🟡 partial · ⏳ planned

## Parity with IDA Pro

| Capability | Status | Notes |
| --- | --- | --- |
| PE / ELF / Mach-O loading | ✅ | Universal binaries, chained fixups, forwarders, TLS callbacks |
| Raw binaries, firmware, COFF/OMF objects, DEX, NE/LE | ⏳ | Raw images and firmware first (phase 4 below); COFF/OMF, DEX, NE/LE later |
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
| Rename, comments, bookmarks | ✅ | Persisted per SHA-256. Pseudocode variables too: click a variable, press `N` (C identifier; keywords, generated names and names already used in the function are refused) — in the C view; the SSA views and the stack-frame panel keep the generated names |
| Create function (`P`) / reanalyze | ✅ | |
| Undefine / define code, data & strings (`U`, `C`, `D`, `A`) | ✅ | Listing covers data: `db/dw/dd/dq`, strings, `offset`, `extrn`, `dup` |
| Auto names (`aString`, `qword_…`, `off_…`, `loc_…`) | ✅ | From access sizes and references, like IDA |
| Name demangling | ✅ | MSVC, Itanium, Rust |
| Search: bytes, text, immediates | ✅ | |
| Hex view & patching, save patched file | ✅ | |
| Instruction patches (NOP, invert, force jump) | ✅ | x86/x64 and AArch64 |
| Assemble arbitrary instructions | ✅ | x86 / x64, Intel syntax (`Edit → Assemble…`): `mov eax, [ebx+ecx*4+8]`, `jz 0x401020`, `lock xadd [rdi], eax`, `db 0x90, 0xcc`; the shortest encoding wins, longer code takes over the following instructions and the rest is NOP-padded. Branch targets and RIP-relative operands are absolute addresses |
| Pseudocode | 🟡 | x86/x64: typed variables (`a1…`, `v1…` split at independent overwrites, types from API prototypes), expression propagation, `switch`, `while`/`for`/`do-while` with `break`/`continue`, symbolic API constants, struct member access (`Y` types a variable; fields, nesting, arrays render as `ctx->name`), argument/return types that flow across internal calls, and pointer fields that chain (`p = ctx->next` is typed `PKT *`, so lists and trees keep rendering as `p->…`). Pointer arithmetic on typed pointers follows C (`p += 0x60` on a 48-byte `T *` prints `p += 2`; other byte counts keep an explicit `(uint8_t *)` cast). Variables come from reaching definitions over the structured code (an SSA-style web per value, inside branches and loops too), so a register reused for unrelated values becomes separate variables. An **SSA view** (Pseudocode → SSA) shows the same function as an SSA IR: phi nodes placed with dominance frontiers, one definition per value, constant and copy propagation (also through phi nodes), dead definitions marked, calls clobbering the ABI's volatile registers. The C view uses the SSA IR's facts: register assignments SSA proves are never read are left out (liveness is decided before constants are folded; calls read the ABI's argument registers, and in 32-bit code ecx / edx for `thiscall` / `fastcall`; jumps out of the function count as tail calls), and values SSA proves constant through joins are noted (`// = 0x10`). A second C view, **C·SSA**, is generated from the SSA IR itself: phi classes become variables, stack slots are named from the tracked stack pointer (frame pointers and stdcall cleanup included), conditions come from the flags, call arguments from the ABI registers or the pushes, tail jumps become calls, single-use values are written in place, and forward branches / back edges become `if` and `do … while`. On 600 real functions it calls the same functions as the C view in all but two. Not yet: `else` / `while` / `switch` in C·SSA, types, memory SSA, other architectures |
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
| AI assistant | ✅ | Optional; off until you choose a model server: local (Ollama, LM Studio) or cloud (Claude through Anthropic's API; OpenAI / Codex, DeepSeek, Kimi, Gemini, Mistral, OpenRouter through the OpenAI chat API). **Assistant** menu: explain the function under the cursor, suggest a name (applied only on click), flag suspicious behaviour. Requests come from the main process, carry one function's decompiled text, and a non-loopback host needs native consent. Tested against a stub server only; runs against real Ollama / LM Studio models are pending. Not yet: streaming, chat, batch renaming |
| MCP server for AI agents | ✅ | `paranoia mcp`: stdio only, files confined to `--root` folders, read-only unless `--allow-writes`; 14 read tools (open, info, functions, pseudocode, disassembly, graph, xrefs, callees, strings, imports, exports, search, IDC export) and 3 write tools that stay in the session. See [MCP.md](MCP.md). Not yet: shared names with the desktop app, resources, batch tools |
| Plugins | ✅ | Folder + `plugin.json` manifest + one `.js` / `.py` script; commands in the **Plugins** menu; native confirmation per version (SHA-256 of manifest + script). See [PLUGINS.md](PLUGINS.md). Not yet: plugin panels, hotkeys, event hooks |
| Debugger | 🟡 | Local programs of the OS the app runs on: Windows x64 and 32-bit (WOW64) PE, Linux x86-64 ELF (ptrace; PIE base from `/proc/<pid>/maps`, program output in the debugger log). Breakpoints (`F2`), run / step into / step over / run to cursor (`F9`/`F7`/`F8`/`F4`), registers, stack. Not yet: remote targets (gdbserver), Linux 32-bit / ARM, macOS |
| Export: IDC script | ✅ | Names, comments, user functions |
| Project files, undo/redo | ✅ | Annotations auto-save per file hash; undo / redo (200 steps) |
| Collaboration / shared projects | ⏳ | Pro edition |

## Plan

Phases run in this order; a phase is done when its exit criteria hold on CI, not when the code is merged. Version numbers are targets, not promises. Work inside a phase can run in parallel.

### Phase 1 — Agent-ready (v0.8)

The [key feature](STRATEGY.md#the-key-feature-private-agent-ready-analysis) made usable by people who do not build from source.

| Item | Status | Exit criterion |
| --- | --- | --- |
| MCP server `paranoia mcp` | ✅ done | Tests in `crates/paranoia-cli/src/mcp.rs`; stdio session against system binaries |
| CLI in Windows releases | ✅ workflow changed | `paranoia-cli-vX.Y.Z-windows-x64.exe` present, in `SHA256SUMS` and attested on the next release |
| Pseudocode variable rename (`N` on a variable) | ✅ done | `var_names_in_pseudocode` test |
| AI assistant against real local models | ⏳ | Explain / name / flag run against Ollama and LM Studio with two open models each; results and failures written down here |
| MCP names shared with the desktop app | ⏳ | Opt-in `--workspace`: a name set by an agent appears in the app after reopening the file, and the other way round; the app and the server never write the store at the same time |
| MCP batch tools for triage | ⏳ | One call returns, per function, its callees, imports and referenced strings, paged; a 2 600-function DLL in under 2 s |

### Phase 2 — AArch64 decompiler (v0.9, top priority for the decompiler)

AArch64 covers Apple silicon, Android and Linux servers. The SSA IR (`ssa.rs`) and the C generator built on it (`ssa/c.rs`) are architecture-neutral by design; the work is a lifter and the ABI.

| Step | Exit criterion |
| --- | --- |
| Lift AArch64 into the SSA IR: data processing, loads / stores (pre / post index, pairs), `b.cond` / `cbz` / `tbz`, `bl` / `blr`, `ret`; NZCV flags into conditions | Unit tests per instruction class, assembled from known encodings |
| AAPCS64: arguments `x0`–`x7`, result `x0`, callee-saved `x19`–`x28`, stack slots from `sp` / `x29` | Signatures on Go, Rust and clang arm64 binaries match their symbols' argument counts in ≥ 90 % of functions |
| C output (C·SSA) for AArch64 in the app, CLI and MCP | No panic across the mutation suite; on the corpus, the callees in the C text match the disassembly in ≥ 95 % of functions |
| Types: API prototypes for libc and common Apple / Android imports | Calls to known APIs render with typed arguments, as on x86 |
| Corpus | arm64 ELF and Mach-O built from published sources, in `PARANOIA_ARM64_DIR`, run on CI |

Afterwards: make C·SSA the default view on x86 / x64 once it matches the C view's types and structuring (`else` / `while` / `switch` still missing there), memory SSA for stack slots.

### Phase 3 — Linux and macOS builds (v0.10)

| Item | Exit criterion | Note |
| --- | --- | --- |
| Linux AppImage and `.deb` | Built by CI on `ubuntu-latest` on every tag, checksummed, signed and attested like the Windows files; starts on a clean Ubuntu LTS and opens a file | `electron-builder` targets are already configured but have never been built |
| Flatpak | Manifest on `org.electronjs.Electron2.BaseApp`, builds in CI; submitted to Flathub | Free; Flathub reviews the submission |
| macOS `.dmg` (arm64 and x64), unsigned | Built by CI on macOS runners; opens a file on both architectures | Without notarisation Gatekeeper blocks the first launch; the README will say how to allow it |
| macOS notarisation | Notarised builds | **Needs an Apple Developer ID (paid yearly, held by the maintainer). Deferred until the account exists** |
| CLI (and MCP) for Linux and macOS | `paranoia-cli-*` for linux-x64, linux-arm64, macos-arm64, macos-x64 in each release | |

### Phase 4 — Firmware and raw images (v0.11)

| Item | Exit criterion |
| --- | --- |
| Raw loader: the user picks architecture, endianness and base address | A raw `.bin` opens with functions found from user-given entry points |
| Intel HEX and Motorola S-record | Loaded at the addresses they declare; mutation tests like the other loaders |
| Cortex-M vector table | Initial SP and handler addresses recognised (Thumb bit), handlers seeded as functions without the user typing anything |
| Base-address recovery for raw images | On a test set of firmware with known bases, the right base ranks first in ≥ 80 % of cases |
| Memory map | Named regions (flash, RAM, peripherals); SVD files later |

### Phase 5 — Remote debugging (v0.12)

| Item | Exit criterion |
| --- | --- |
| GDB remote serial protocol client in the engine | Registers, memory, breakpoints, step and continue against `gdbserver` and QEMU's gdbstub |
| Targets | Linux x86-64 and AArch64 through `gdbserver`; QEMU user and system mode; OpenOCD later |
| Security first | The engine's first network socket: started only by the user, loopback by default, any other host confirmed natively; [SECURITY-DESIGN.md](SECURITY-DESIGN.md) and [PSB.md](PSB.md) updated **before** it ships |

### Ongoing

- **Signatures & types:** `.sig` referenced-function checks, more built-in libraries.
- **Plugins:** panels, hotkeys and event hooks.
- **AI assistant:** batch naming of `sub_` functions, chat about a selection, streaming.
- **Debugger:** Linux 32-bit and ARM, macOS.
- **Security baseline:** reviewed before every release ([PSB.md](PSB.md)); an independent audit when funding allows.

## Editions

The engine, CLI and desktop app described above are and will stay open source (Apache-2.0). A paid Pro edition with collaboration and team features may follow; it will build on, not take away from, the open core.
