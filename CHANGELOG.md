# Changelog

Notable changes in each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [SemVer](https://semver.org/) (0.x: minor versions may change behaviour). Release notes on GitHub have the download links and how to verify them.

## Unreleased

### Added
- Function memory. `paranoia diff A B` matches the functions of two binaries (identical bytes, same instructions, same imports/strings/constants, call graph, then fuzzy MinHash matching) and lists what changed, was added or removed. `paranoia memory learn/recall` keeps a local knowledge base of named functions and recognises them in other files, using the call graph as context; nothing leaves the machine. In the app: Analysis → Function memory and Analysis → Compare with another file, with the two versions of a function side by side. Measured on `gofmt` builds with names hidden: GOAMD64 v1 vs v3, 100 % of functions with 16+ instructions matched right by `diff`, 88.7 % recalled with no wrong names.
- `paranoia mcp`: an MCP server so AI agents can open binaries and read listings, pseudocode, graphs and cross references. It only reads files under `--root`, never opens a socket, and is read-only unless `--allow-writes` is given. Includes a `triage` tool (per function: calls and strings) that handles a 2 600-function DLL in about a second.
- `--redact-strings` hides the file's strings from the agent (numbered placeholders instead). `--ledger FILE` writes every answer to a hash-chained log before it's sent, and `paranoia ledger FILE` checks that log.
- `--workspace` shares names, comments and types between the MCP server and the desktop app.
- AArch64 pseudocode (experimental), built from the shared SSA form. On two Go binaries, 99.7 % of 5 720 functions call what the listing calls.
- Rename pseudocode variables: select one and press `N`.
- Function discovery from `.eh_frame_hdr` (ELF) and `LC_FUNCTION_STARTS` (Mach-O). A stripped GNU `ls` goes from 18 functions to 446.
- AArch64 calls and jumps through a register built with `adrp` + `add` are followed. A stripped Go darwin/arm64 binary goes from 1 function to 723.
- The release workflow also builds the command-line tool for Windows.

### Changed
- AI assistant: presets for llama.cpp, Jan, vLLM, OpenCode, Grok, Groq and Together; **Load models** reads the model list from the server; **Test** checks endpoint, key and model with a one-line prompt. Tested live against llama.cpp ([docs/ASSISTANT.md](docs/ASSISTANT.md)).
- The AI assistant no longer treats `*.localhost` names as local.
- Docs, README and code comments rewritten; the roadmap now has the direction and priorities.

### Security
- Only the app's own `index.html` gets the desktop bridge; before, any `file://` page did.
- The page can no longer add arbitrary paths to the recent-files list (which doubles as the file allow-list). It gets a fixed set of store methods.
- A save dialog allows one write; "show in folder" only works for files the user opened or saved.
- The debugger confirmation shows the program and its command-line arguments.
- External links only open for a short list of https hosts.
- `#![forbid(unsafe_code)]` in `paranoia-core`, `paranoia-cli` and `paranoia-db`. The remaining `unsafe` (debuggers, wasm ABI) has a `SAFETY` comment on every block, enforced by clippy. Address arithmetic in the debuggers no longer overflows.

### Fixed
- Declaration comments in 32-bit pseudocode named 64-bit registers (`rdx` instead of `edx`).

## 0.7.0 — 2026-11-06

### Added
- Reading IDA `.sig` signature files (versions 5–10).
- PowerPC disassembly, 32- and 64-bit, both byte orders.
- Mixed ARM/Thumb images, with the instruction set tracked per address.
- A Linux x86-64 debugger on `ptrace`.
- Cloud models for the AI assistant: Claude, OpenAI, DeepSeek, Kimi, Gemini, Mistral, OpenRouter.
- An SSA form for x86/x64 functions, used by the C view, plus an experimental C·SSA view that generates C from it.

### Fixed
- Decoding no longer panics in debug builds when code crosses a 4 GiB address boundary.
- Changing the AI model server always asks first; assembler input is size-limited.

## 0.6.0 — 2026-11-04

### Added
- An x86/x64 assembler (`Edit → Assemble…`).
- 32-bit Windows debugging (WOW64).
- Plugins: a folder with `plugin.json` and one script adds commands to the Plugins menu.
- An optional AI assistant: explain a function, suggest a name, flag suspicious behaviour.
- PDB struct, union and enum types.
- New look: grey whale mark, menu bar with command centre, About dialog.

### Changed
- Pseudocode variables come from reaching definitions, so a register reused for unrelated values becomes separate variables.
- Pointer arithmetic on typed pointers follows C.
- DWARF and PDB types are kept out of the saved annotations (they had added 11 MB on one test file).

## 0.5.1 — 2026-10-29

A security release.

### Security
- Electron 38 → 44.9.3, which fixes more than 30 advisories, among them a context-isolation bypass.
- IPC requests must come from the app's own page; the engine only opens files the user chose; starting the debugger or a Python script needs a native confirmation.
- No `'unsafe-eval'` in the CSP; console scripts run in an isolated worker.
- Electron fuses: no `RunAsNode`, `NODE_OPTIONS` or `--inspect`; asar integrity enforced; DevTools off in packaged builds.
- Python scripts run from a fresh private folder with `-E`.
- Fuzzing found and fixed a crash on a truncated instruction at the end of RISC-V and MIPS code.
- CI actions pinned to commit hashes; dependency audits block releases.
- Releases now ship signed checksums, build provenance attestations and an SBOM.

### Fixed
- Arguments of calls using MSVC's `mov rax, rsp` prologue were shifted by one slot in pseudocode.
- Imports by ordinal are named `Ordinal_N`.

### Changed
- Local data moved to `%APPDATA%\Paranoia` (the old folder is moved automatically).

## 0.5.0 — 2026-10-25

### Added
- Decompiler v2 for x86/x64: variables with types, `switch` from jump tables, `while`/`for` loops.
- Better function boundaries from chained `.pdata` entries (about 90 % fewer false tail calls in kernel32).
- RISC-V and MIPS disassembly.
- FLIRT-style `.pat` signatures: read, write, and a built-in MSVC x64 library.
- Python scripting in your own interpreter, with common IDAPython calls.

## 0.4.0 — 2026-10-24

### Added
- Operand display as in IDA (`H`, `R`, `B`, `M`) and about 25 built-in Windows and POSIX enums applied to API arguments.
- Pseudocode substitutes values into expressions (`HeapFree(GetProcessHeap(), 0, p)`).
- DWARF names, globals and source lines.

## 0.3.0 — 2026-10-24

### Added
- A Windows x64 debugger.
- PDB symbols.
- Local C types, applicable to data.
- ARM32 and Thumb-2 disassembly.

## 0.2.0 — 2026-10-16

### Added
- Code and data in one listing, with auto names and item commands (`C` `D` `A` `U` `P`).
- Switch tables, an API prototype library, stack frames, the xrefs dialog, names window, call graph and navigation band.
- Instruction patches, undo/redo, a JavaScript script console.

## 0.1.1 — 2026-10-15

### Changed
- New app icon and wordmark.

## 0.1.0 — 2026-10-15

First release: PE, ELF and Mach-O loading; x86, x86-64 and AArch64 disassembly; graphs, pseudocode for x86/x64, cross references, patching, triage, light and dark themes.
