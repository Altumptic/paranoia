# Changelog

Notable changes in each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [SemVer](https://semver.org/) (0.x: minor versions may change behaviour). Release notes on GitHub have the download links and how to verify them.

## Unreleased

## 0.10.0 — 2026-11-14

A release process with release candidates, an opt-in update check, the debugger on Linux ARM64, user types in AArch64 pseudocode, and CI that starts every packaged desktop app for real.

### Added
- Help → Check for updates (desktop app): after you press the button, one request to GitHub's public release list tells you whether a newer release exists and opens its page. Nothing is sent but the request, nothing is downloaded or installed, and there is no background check; see [SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md#update-check).
- `bench/pdb-truth.mjs` scores the 32-bit PE function list against the functions Microsoft's public PDBs name: 99.3 % of 8,191 on four system DLLs, 81.7 % on `ole32` (a table of a thousand 10-byte stubs). Results in [docs/BENCHMARK.md](docs/BENCHMARK.md).
- A release process: `scripts/release.mjs` checks that every version number agrees with the tag and the CHANGELOG, generates the release notes, and tags with a suffix (`v0.10.0-rc.1`) publish a pre-release. [docs/RELEASING.md](docs/RELEASING.md) has the versioning rules, the channels and the support policy.
- CI runs the engine tests on Linux ARM64 as well, and starts every packaged desktop app (Windows, Linux, macOS Apple silicon) for real: it opens a file and checks the window over the DevTools protocol.
- The Linux debugger runs ARM64 programs as well as x86-64 ones (`ptrace` with `brk #0` breakpoints), so the ARM64 desktop package can debug what it analyses. Its tests run on CI's ARM runner; there is no macOS or remote debugger yet.
- AArch64 pseudocode now applies the variable types you set with `Y`: the signature and declaration carry the type and loads through the pointer become `->field`, as on x86. Function memory therefore restores typed variables on AArch64 too.

### Changed
- `windows-sys` 0.61 for the Windows debugger. With the `x86_64-pc-windows-gnu` toolchain this needs MinGW-w64 binutils and `-C dlltool` (README); the MSVC toolchain and CI are unaffected.
- UI dependencies: Electron 45, TypeScript 7, dagre 3, react-resizable-panels 4, React 19, Vite 8.
- `redb` 4.5, `miniz_oxide` 0.9, `zustand` 5.1.

## 0.9.0 — 2026-11-14

The desktop app for Linux and macOS, 32-bit PE function discovery, PE symbol names, and a measured benchmark against Ghidra.

### Added
- Desktop builds for Linux and macOS in the tag workflow, next to Windows: AppImage and `.deb` for x64 and ARM64, `.dmg` and `.zip` for Apple silicon and Intel. One publish job now collects every platform and hashes, signs and attests the whole release. CI builds every package and smoke-tests it (the packaged engine runs, the deb carries it, the macOS app verifies as signed); macOS stays ad-hoc signed until a Developer ID exists (PSB-EX-5).
- Ready-made signatures built into the engine: the MSVC x64 static CRT (4 664 signatures), the Rust standard library (580) and musl libc (1 023), generated from public toolchains by `scripts/build-sigpack.mjs` and re-measured by CI. On programs they were not built from they name 53 %, 85 % and 91 % of the relevant library functions at ≥99 % precision. Go needs no pack: its function table already names stripped Go binaries. See [docs/SIGNATURES.md](docs/SIGNATURES.md).
- `bench/`: a reproducible decompiler benchmark against Ghidra on real binaries (Go, Rust and Windows PE; ground truth from the Go pclntab, COFF symbols and PE exports), with the raw JSON committed. The first published run covers 13 binaries, 23 085 functions and 3 393 sampled decompilations; [docs/BENCHMARK.md](docs/BENCHMARK.md) has the numbers, the failures and the gaps it found.
- `paranoia mcp --redact-ips`: tool answers replace IPv4/IPv6 literals with `<ip#N>` and count them with string redactions in the disclosure ledger. `paranoia ledger` reports the combined count.
- AI assistant privacy: opt-in hiding of the file's strings (`<str#N len=L>`, `aRedactedN`) and IP-like numbers (`<ip#N>`), applied in the main process before the prompt leaves; every request and answer is recorded in a hash-chained `assistant-ledger.jsonl` in the app's data folder, and the request is withheld if it cannot be recorded.
- Function memory now carries the local struct and enum declarations a remembered function's typed variables need: recalling a known function restores `MY_STRUCT *` variables and their `->field` accesses instead of plain integers. A type the file already defines wins and old knowledge bases load unchanged. Function prototypes are not carried yet (the model has no user-set signature).
- [docs/CASE-STUDIES.md](docs/CASE-STUDIES.md): three reproducible walk-throughs — a stripped Go binary, an MSVC `/MT` binary and a real fzf version diff — with commands and SHA-256 hashes.

- PE images: the COFF symbol table GNU ld leaves in the file is read (bounds-checked), so GNU-linked Rust and MinGW programs get their function names: 84.2 % named on the Rust test binaries, from 5.6 %.
- 32-bit x86: functions that no call, export or symbol reaches are found by scanning uncovered code for prologues after padding and for addresses the base relocations point at, each candidate checked by decoding. `comctl32` (x86) goes from 380 to 1 913 functions; on five system DLLs the list agrees with Ghidra's at 97.8 % / 98.0 %. These functions are marked as found by a scan.
- `paranoia query FILE inventory` also lists tail calls (`tail_calls`).

### Changed
- Minimum Rust version 1.82 → 1.88 (gimli 0.32 → 0.34, required by the DWARF reader).
- Linux and macOS data folders documented; release, verification and signing docs updated for the new packages.

### Security
- macOS builds are ad-hoc signed and not notarised while there is no Developer ID; recorded as PSB-EX-5, with the Gatekeeper limitation stated in the README.

### Fixed
- The benchmark's Rust name matching scored correct names as wrong (escaped characters in mangled names); both tools' naming figures were understated. Go function names now follow the Go function table, so a function has one name stripped or not (a PE symbol table spelled them with `.abi0`).
- macOS showed "A JavaScript error occurred in the main process" (`TypeError: win.setTitleBarOverlay is not a function`) at start-up and on every theme change: the method is documented for Windows and Linux only, and the IPC handler called it unconditionally. `policy.titleBarOverlaySupported` now gates it.
- The title bar no longer covers the macOS traffic lights, and the command centre stays in the flow there so a narrow window cannot overlap the menus.

## 0.8.0 — 2026-11-12

### Added
- Command-line builds for Linux (x64 and ARM64, static, any distribution) and macOS (Apple Silicon and Intel), in every release next to the Windows files, covered by the same signed checksums and attestations.
- C·SSA (and so AArch64 pseudocode) uses the prototypes of called functions: the right number of arguments, no result for `void` functions, and parameter and variable types (`HANDLE v1`, `const char *a2`). A parameter a function passes on in another argument register is now recognised as a parameter.
- Go's function table is read, so stripped Go programs keep all their functions and names (ELF, PE and Mach-O; Go 1.2 to current). A stripped `gofmt` goes from 721 functions to 3 078.
- `paranoia query FILE inventory|function|xrefs`: one JSON answer per run, with the file's SHA-256, for other tools. See docs/QUERY.md.
- `paranoia mcp`: `compare_binaries`, and `recognize_functions` with `--memory`.
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
- Creating a `.pat` signature file could panic on x86 instructions whose first operand isn't an immediate.

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
