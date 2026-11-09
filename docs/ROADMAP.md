# Roadmap

The goal is to cover the everyday IDA Pro workflow in an open tool that runs entirely on your machine. This page lists what works today and what comes next.

## Direction

Paranoia is aimed at people who analyse files they're not allowed to upload anywhere: incident responders, malware analysts, security engineers. That means it has to work offline, be quick, and be safe to point at hostile files. It also means that when an AI agent helps with the analysis, the analyst decides what the agent sees and can show afterwards what it saw. That's what `--redact-strings` and `--ledger` in [MCP.md](MCP.md) are for.

We don't try to match IDA or Ghidra on the number of architectures or on C++ decompilation. The decompiler work concentrates on x86/x64 and AArch64, which cover Windows, Linux servers, Android and Apple silicon.

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
| Function discovery | ✅ | Entry, exports, symbols, `.pdata`, ELF `.eh_frame_hdr`, Mach-O `LC_FUNCTION_STARTS`. A stripped GNU `ls` goes from 18 functions to 446 with the unwind table |
| Switch tables | ✅ | Absolute, MSVC RVA and PIC relative tables |
| Listing, graph, cross references | ✅ | |
| Rename, comments, bookmarks | ✅ | Also pseudocode variables (`N` on a selected variable) |
| Define code, data, strings; create functions | ✅ | |
| Auto names, demangling | ✅ | IDA-style names; MSVC, Itanium and Rust demangling |
| Search | ✅ | Bytes, text, immediates |
| Hex view, patching, assembler | ✅ | NOP/invert/force-jump on x86 and AArch64; an x86 assembler for anything else |
| Pseudocode, x86/x64 | 🟡 | Typed variables, API constants, loops and `switch`, struct member access, types across calls. An SSA view and a second C view built from it (C·SSA) |
| Pseudocode, AArch64 | 🟡 | Experimental, built from the SSA form. No types yet |
| Operand display (`H` `R` `B` `M`) | ✅ | Windows and POSIX enums applied to API arguments |
| Local types, structs, enums | ✅ | C declarations; apply a struct to data |
| Stack frames | ✅ | Same names as the pseudocode |
| API prototypes | ✅ | About 250 WinAPI and libc functions |
| FLIRT signatures | ✅ | IDA `.sig` (v5–10) and `.pat`; writes `.pat`. Referenced-function checks not used yet |
| PDB, DWARF | ✅ | Names, globals, source lines, struct/union/enum types |
| Call graph | ✅ | |
| Scripting | ✅ | Python (`idc`/`idautils` names), JavaScript, headless batch mode |
| Plugins | ✅ | Commands only. See [PLUGINS.md](PLUGINS.md) |
| AI assistant | ✅ | Local or hosted models. Only tested against a stub server so far |
| MCP server | ✅ | Read-only by default, string redaction, disclosure log, names shared with the app. See [MCP.md](MCP.md) |
| Debugger | 🟡 | Local Windows (x64, 32-bit) and Linux x86-64 programs. No remote targets, no macOS |
| IDC export, undo/redo | ✅ | |
| Collaboration | ⏳ | |

## Next

Version numbers are targets. A step counts as done when its check passes on CI.

### 0.8: agent interface

- [x] `paranoia mcp` with redaction, disclosure log, `triage` and `--workspace`
- [x] `paranoia ledger` checks a disclosure log
- [x] The CLI is part of the Windows release
- [ ] Try the AI assistant with real Ollama and LM Studio models and write down what works
- [ ] Redaction beyond strings: numbers that look like IP addresses, symbol names on request
- [ ] The same redaction and log for the AI assistant in the app

### 0.9: AArch64 decompiler

- [x] Lift AArch64 into the SSA form (arithmetic, moves, shifts, loads/stores, branches, calls)
- [x] C, C·SSA and SSA views for AArch64. On two Go binaries, 5 700 of 5 720 functions call the same functions as the listing
- [ ] Check signatures against symbols on Go, Rust and clang binaries (target: 90 % right)
- [ ] Types for common libc, Apple and Android APIs
- [ ] A corpus of clang and Rust arm64 binaries on CI
- [ ] Make C·SSA the default on x86/x64 once it has `else`, `while` and `switch`

### 0.10: Linux and macOS builds

- [ ] AppImage and `.deb` built and signed by CI (the electron-builder targets exist but were never built)
- [ ] Flatpak, submitted to Flathub
- [ ] Unsigned macOS `.dmg` for arm64 and x64
- [ ] macOS notarisation. This needs a paid Apple Developer ID, so it waits until there is one
- [ ] CLI builds for Linux and macOS

### 0.11: firmware and raw images

- [ ] Raw loader: pick the architecture, byte order and base address
- [ ] Intel HEX and Motorola S-record
- [ ] Cortex-M vector table: handlers become functions automatically
- [ ] Guess the base address of a raw image
- [ ] Named memory regions, later SVD files

### 0.12: remote debugging

- [ ] GDB remote protocol: `gdbserver` and QEMU's gdbstub, Linux x86-64 and AArch64
- [ ] This is the first time the engine opens a socket. It will only connect when the user asks, to loopback by default, and the security docs get updated before it ships

### Later

- Signature checks for referenced functions, more built-in libraries
- Plugin panels, hotkeys and event hooks
- Batch naming and chat in the AI assistant
- Debugger for Linux 32-bit, ARM and macOS
- An independent security audit

## Editions

The engine, the CLI and the desktop app are open source under Apache-2.0 and will stay that way. A paid edition with team features may come later. It would be built on top of the open version without removing anything from it.
