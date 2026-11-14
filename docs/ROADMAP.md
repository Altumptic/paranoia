# Roadmap

The goal is to cover the everyday IDA Pro workflow in an open tool that runs entirely on your machine. This page lists what works today and what comes next.

## Direction

Paranoia is aimed at people who analyse files they're not allowed to upload anywhere: incident responders, malware analysts, security engineers. That means it has to work offline, be quick, and be safe to point at hostile files. Work done on one sample should not be lost on the next: function memory carries names, comments and now the struct types their variables need to new versions and related samples, from a database that stays on the analyst's machine. It also means that when an AI agent helps with the analysis, the analyst decides what the agent sees and can show afterwards what it saw. That's what `--redact-strings`, `--redact-ips` and `--ledger` in [MCP.md](MCP.md) are for, and the in-app assistant follows the same rule: it can hide the file's strings and IP-like numbers from the model and records what it sent in a local disclosure ledger ([ASSISTANT.md](ASSISTANT.md)).

We don't try to match IDA or Ghidra on the number of architectures or on C++ decompilation. The decompiler work concentrates on x86/x64 and AArch64, which cover Windows, Linux servers, Android and Apple silicon.

Claims on this page are measured, not asserted: a reproducible benchmark compares the decompiler, symbol recovery and call-name agreement with Ghidra on real binaries, and commits the raw results and the failures ([BENCHMARK.md](BENCHMARK.md)).

When two things compete, they're done in this order:

1. crashes or hangs on bad input
2. readable pseudocode on x86/x64 and AArch64
3. the agent interface and scripting
4. Linux and macOS packages
5. firmware, remote debugging, more architectures

## What works today

✅ done · 🟡 partly · ⏳ not yet

| Feature | | Notes |
| --- | --- | --- |
| PE, ELF, Mach-O | ✅ | Universal binaries, chained fixups, forwarders, TLS callbacks |
| Raw images, firmware, COFF/OMF, DEX, NE/LE | ⏳ | Raw images and firmware first |
| x86, x86-64 | ✅ | |
| AArch64 | ✅ | `adrp`-based references; calls through `adrp` + `add` + `blr` are followed |
| ARM32, Thumb-2 | ✅ | Mixed ARM/Thumb images, tracked per address |
| RISC-V | ✅ | RV32/RV64 IMAFDC, compressed instructions |
| MIPS | ✅ | 32/64-bit, both byte orders, delay slots. Not tested on a full binary yet |
| PowerPC | ✅ | 32/64-bit, both byte orders, common AltiVec/VSX. No pseudocode |
| Function discovery | ✅ | Entry, exports, symbols, `.pdata`, ELF `.eh_frame_hdr`, Mach-O `LC_FUNCTION_STARTS`, Go's function table. A stripped GNU `ls` goes from 18 functions to 446 with the unwind table; a stripped Go program keeps all its functions and names |
| Function memory | ✅ | Binary diff and a local knowledge base of named functions, with measured accuracy. Remembers the struct types its typed variables need. See [FUNCTION-MEMORY.md](FUNCTION-MEMORY.md) |
| Switch tables | ✅ | Absolute, MSVC RVA and PIC relative tables |
| Listing, graph, cross references | ✅ | |
| Rename, comments, bookmarks | ✅ | Also pseudocode variables (`N` on a selected variable) |
| Define code, data, strings; create functions | ✅ | |
| Auto names, demangling | ✅ | IDA-style names; MSVC, Itanium and Rust demangling |
| Search | ✅ | Bytes, text, immediates |
| Hex view, patching, assembler | ✅ | NOP/invert/force-jump on x86 and AArch64; an x86 assembler for anything else |
| Pseudocode, x86/x64 | 🟡 | Typed variables, API constants, loops and `switch`, struct member access, types across calls. An SSA view and a second C view built from it (C·SSA) |
| Pseudocode, AArch64 | 🟡 | Experimental, built from the SSA form. Types come from the prototypes of called libc and WinAPI functions and from the types you set (`Y`: signature, declaration, `->field`); they do not follow calls yet |
| Operand display (`H` `R` `B` `M`) | ✅ | Windows and POSIX enums applied to API arguments |
| Local types, structs, enums | ✅ | C declarations; apply a struct to data |
| Stack frames | ✅ | Same names as the pseudocode |
| API prototypes | ✅ | About 250 WinAPI and libc functions |
| FLIRT signatures | ✅ | IDA `.sig` (v5–10) and `.pat`; writes `.pat`. Referenced-function checks not used yet |
| Ready-made signatures | ✅ | MSVC x64 static CRT (4 664), Rust std (580) and musl libc (1 023) packs built in, ≥99 % precision when measured on independent builds; Go names come from the pclntab. See [SIGNATURES.md](SIGNATURES.md) |
| Benchmark | ✅ | Reproducible comparison with Ghidra on real binaries: coverage, naming, call-name agreement, time. Raw JSON and the failures are included. See [BENCHMARK.md](BENCHMARK.md) |
| Case studies | ✅ | Three worked walk-throughs with commands and hashes: a stripped Go binary, an MSVC `/MT` binary and a real version diff. See [CASE-STUDIES.md](CASE-STUDIES.md) |
| PDB, DWARF | ✅ | Names, globals, source lines, struct/union/enum types |
| Call graph | ✅ | |
| Scripting | ✅ | Python (`idc`/`idautils` names), JavaScript, headless batch mode |
| Plugins | ✅ | Commands only. See [PLUGINS.md](PLUGINS.md) |
| AI assistant | ✅ | Local or hosted models, with a model list and a connection test. Opt-in string and IP-like number redaction, and a local hash-chained disclosure ledger. Tested live with llama.cpp and a small local model; see [ASSISTANT.md](ASSISTANT.md) |
| MCP server | ✅ | Read-only by default, string and IP-like number redaction (`--redact-ips`), disclosure log, names shared with the app. See [MCP.md](MCP.md) |
| Debugger | 🟡 | Local Windows (x64, 32-bit), Linux x86-64 and Linux ARM64 programs. The ARM64 one is new and tested on CI's ARM runner only. No remote targets, no macOS |
| IDC export, undo/redo | ✅ | |
| Collaboration | ⏳ | |

## Next

Version numbers are targets. A step counts as done when its check passes on CI.

### 0.8: agent interface and function memory (released)

- [x] `paranoia mcp` with redaction, disclosure log, `triage` and `--workspace`
- [x] `paranoia ledger` checks a disclosure log
- [x] The CLI is part of the release, for Windows, Linux and macOS
- [x] Try the AI assistant against a real local model server and write down what works ([ASSISTANT.md](ASSISTANT.md))
- [x] Function memory: binary diff and a local knowledge base ([FUNCTION-MEMORY.md](FUNCTION-MEMORY.md))
- [x] Go's function table; `paranoia query` for other tools ([QUERY.md](QUERY.md)), used by the REA provider

Moved to the next releases: redaction of symbol and function names on request. Strings and numbers that look like IP addresses are redacted now, in both the MCP server and the in-app assistant, with a disclosure log for each.

### 0.9: every platform, benchmark, 32-bit PE (released)

- [x] Desktop app for Windows, Linux (x64, ARM64) and macOS (ARM64, x64), built and smoke-tested by CI ([SIGNING.md](SIGNING.md) for what is not signed)
- [x] Reproducible benchmark against Ghidra, and the gaps it found closed: PE COFF symbols, 32-bit PE function discovery ([BENCHMARK.md](BENCHMARK.md))
- [x] Built-in signature packs, privacy for agents and the assistant, function memory with struct types

### 0.10: AArch64 decompiler

- [x] Lift AArch64 into the SSA form (arithmetic, moves, shifts, loads/stores, branches, calls)
- [x] C, C·SSA and SSA views for AArch64. On two Go binaries, 5 700 of 5 720 functions call the same functions as the listing
- [ ] Check signatures against symbols on Go, Rust and clang binaries (target: 90 % right)
- [x] Types from the prototypes of called functions: argument counts, `void` results, parameter and variable types (C·SSA on x64 and AArch64)
- [x] Variable types you set (`Y`) apply to AArch64 pseudocode and travel with function memory; not yet across calls
- [ ] More prototypes: Apple and Android APIs
- [ ] A corpus of clang and Rust arm64 binaries on CI
- [ ] Make C·SSA the default on x86/x64 once it has `else`, `while` and `switch`

### 0.11: Linux and macOS packaging

- [x] AppImage and `.deb` built by CI for x64 and ARM64 (since 0.9.0); Sigstore-signed checksums and attestations cover them
- [ ] Flatpak, submitted to Flathub
- [x] macOS `.dmg` and `.zip` for arm64 and x64, ad-hoc signed (since 0.9.0)
- [ ] macOS notarisation. This needs a paid Apple Developer ID, so it waits until there is one. Signing and notarisation are already wired behind the secrets in [SIGNING.md](SIGNING.md)
- [x] CLI builds for Linux and macOS (since 0.8.0)

### 0.12: firmware and raw images

- [ ] Raw loader: pick the architecture, byte order and base address
- [ ] Intel HEX and Motorola S-record
- [ ] Cortex-M vector table: handlers become functions automatically
- [ ] Guess the base address of a raw image
- [ ] Named memory regions, later SVD files

### 0.13: remote debugging

- [ ] GDB remote protocol: `gdbserver` and QEMU's gdbstub, Linux x86-64 and AArch64
- [ ] This is the first time the engine opens a socket. It will only connect when the user asks, to loopback by default, and the security docs get updated before it ships

### Function memory, next steps

- [x] Recognise C runtime and standard library functions from a database built from debug builds — built in: MSVC x64 static CRT, Rust std and musl libc packs, 828 KiB in total, recorded with measured recognition in `sigs/manifest.json` and rebuilt by CI ([SIGNATURES.md](SIGNATURES.md))
- [ ] Measure on more pairs: real version updates of open-source programs, clang and MSVC builds
- [x] Carry struct types along with names: a remembered function brings the Local Types declarations its typed variables need, merged on recall without overwriting a type the file already defines
- [ ] Function prototypes: needs a user-set signature in the model (an `Annotations` field, pseudocode honouring it, API/UI), then memory can carry it

### Benchmark follow-ups

The first published run names its own weaknesses ([BENCHMARK.md](BENCHMARK.md)); these are the concrete follow-ups, in order:

- [x] Import the COFF symbol table that GNU ld leaves in PE images: GNU-linked Rust PE naming went from 5.6 % to 84.2 % (Ghidra 83.7 % on the same files)
- [x] 32-bit PE function discovery: a scan for prologues and relocation targets takes `comctl32` from 380 to 1 913 functions (Ghidra 1 883) and agrees with Ghidra on five system DLLs at about 98 % both ways
- [ ] A correctness metric for decompiled C (differential execution or round-trip recompilation), not just coverage
- [ ] A larger, less PE-heavy corpus, later including a malware corpus published as hashes

### Later

- Signature checks for referenced functions, more built-in libraries
- Plugin panels, hotkeys and event hooks
- Batch naming and chat in the AI assistant
- Debugger for Linux 32-bit and ARM32, and macOS
- An independent security audit

## Editions

The engine, the CLI and the desktop app are open source under Apache-2.0 and will stay that way. A paid edition with team features may come later. It would be built on top of the open version without removing anything from it.
