<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/lockup-dark.png" />
  <img src="assets/brand/lockup-light.png" width="420" alt="Paranoia" />
</picture>

A local-first reverse-engineering tool for PE, ELF and Mach-O.

[![CI](https://github.com/Altumptic/paranoia/actions/workflows/ci.yml/badge.svg)](https://github.com/Altumptic/paranoia/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Altumptic/paranoia?label=release)](https://github.com/Altumptic/paranoia/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

`PSB-C` · `SIGNED` · `ATTESTED` · `SBOM` · `NO-TELEMETRY` · `LOCAL-FIRST` · `AUDIT:NONE` · `DISCLOSURE:OK` ([what these mean](docs/PSB.md))

</div>

<p align="center">
  <img src="docs/screenshots/pseudocode-dark.png" alt="Pseudocode view" width="49%" />
  <img src="docs/screenshots/graph-dark.png" alt="Graph view" width="49%" />
</p>
<p align="center">
  <img src="docs/screenshots/listing-light.png" alt="Listing" width="49%" />
  <img src="docs/screenshots/overview-dark.png" alt="File overview" width="49%" />
</p>

Paranoia does disassembly, control-flow graphs, decompilation, debugging and scripting, with keys and scripting names that IDA users will recognise. It runs entirely on your machine: no account, no telemetry, no update checks. The engine is written in Rust and the same engine is used by the desktop app, the command-line tool, a browser build (WebAssembly) and an MCP server for AI agents.

## Features

- **Formats:** PE/PE32+ (forwarders, TLS callbacks, `.pdata`, .NET detection), ELF (PIE, PLT/GOT, symbol versions), Mach-O (universal binaries, bind opcodes, chained fixups, export trie).
- **Architectures:** x86, x86-64, AArch64, ARM32/Thumb-2, RISC-V, MIPS, PowerPC.
- **Analysis:** functions from entry points, exports, symbols and unwind tables (so stripped ELF and Mach-O files keep their functions), switch tables, cross references, auto names in the IDA style.
- **Decompiler:** x86 and x64, with typed variables, API constants, loops and `switch`, struct member access (`Y` on a variable) and types that follow calls. AArch64 is experimental.
- **Editing:** rename, comments, bookmarks, define code/data/strings, create functions, local C types, undo and redo. Everything is saved per file hash.
- **Patching:** hex view, byte patches, NOP/invert/force-jump, an x86 assembler, save the patched file.
- **Debug info:** PDB and DWARF names and types, FLIRT signatures (`.sig` and `.pat`).
- **Debugger:** local Windows (x64 and 32-bit) and Linux x86-64 programs.
- **Scripting:** Python in your own interpreter (`idc` and `idautils` work for common calls), JavaScript, plugins, and a headless batch mode.
- **AI:** an optional assistant in the app (local or hosted model), and `paranoia mcp` for agents such as Claude Code, which can hide the sample's strings from the model and keep a log of everything the agent was shown. See [docs/MCP.md](docs/MCP.md).

Speed, measured on a Core i5-12450H with a release build: `notepad.exe` is analysed in 45 ms, `shell32.dll` (7.7 MB, 24 449 functions) in about a second.

## Limits

- Pseudocode exists for x86 and x64. AArch64 pseudocode is experimental (no types, tested on Go binaries only). Other architectures have disassembly and graphs only.
- MIPS has only been tested on known instruction encodings, not on a full binary.
- The debugger runs local programs only. Remote debugging is planned.
- Release builds are Windows only. On Linux, run the app from source. macOS and Linux packages are planned.
- Raw firmware images without a PE/ELF/Mach-O header can't be loaded yet.
- The Windows executables aren't Authenticode-signed yet.

The [roadmap](docs/ROADMAP.md) has the full list.

## Install

Download the installer or the portable build from [Releases](https://github.com/Altumptic/paranoia/releases/latest). Since the executables aren't signed, SmartScreen may warn on first start. You can check the download against the signed checksums:

```powershell
Get-FileHash .\Paranoia-<version>-portable.exe -Algorithm SHA256   # compare with SHA256SUMS
```

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Altumptic/paranoia/\.github/workflows/ci\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify Paranoia-<version>-portable.exe --repo Altumptic/paranoia
```

More in [docs/VERIFY.md](docs/VERIFY.md).

## Privacy and security

The app makes no network connections. The only exception is the AI assistant, and only after you point it at a server. Your names, comments and recent files are stored in `%APPDATA%\Paranoia` and nowhere else.

The renderer is sandboxed, the engine runs in its own process and only opens files you chose, and starting the debugger or a Python script asks for confirmation first. The debugger runs the program you're analysing, so use a VM for malware. There has been no independent audit.

Details: [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Keys

| Key | Action | Key | Action |
| --- | --- | --- | --- |
| `Ctrl O` | Open file | `Space` | Listing / graph |
| `Ctrl K`, `G` | Go to address or name | `Tab`, `F5` | Pseudocode |
| `Esc`, `Alt ←` | Back | `Alt →` | Forward |
| `Enter` | Follow operand | `X` | Cross references |
| `N` | Rename | `;` | Comment |
| `Y` | Type a variable | `Alt M`, `Ctrl M` | Bookmark, list bookmarks |
| `P` | Create function | `Ctrl Z`, `Ctrl Y` | Undo, redo |
| `C` `D` `A` `U` | Code, data, string, undefine | ``Ctrl ` `` | Script console |
| `H` `R` `B` `M` | Hex/decimal, char, binary, enum | `1`–`6` | Switch view |
| `Alt B` `Alt T` `Alt I` | Search bytes, text, immediate | `Ctrl B`, `Ctrl J` | Sidebar, inspector |
| `F2` `F9` `F7` `F8` `F4` | Breakpoint, run, step into, step over, run to cursor | | |

## Command line

```bash
paranoia info sample.exe
paranoia functions sample.exe
paranoia disasm sample.exe --at main -n 40
paranoia pseudo sample.exe main
paranoia xrefs sample.exe CreateFileW
paranoia strings --referenced sample.exe --json
paranoia script sample.exe analyse.py      # run a Python script without the app
paranoia sigapply app.exe libc.sig         # IDA .sig or .pat signatures
paranoia mcp --root ./samples              # MCP server for AI agents
```

## Building

You need Rust 1.82+ and Node.js 20+.

```bash
cargo build --release -p paranoia-engine -p paranoia-cli
cargo test --workspace

cd apps/desktop
npm ci
npm run app:dev     # app with hot reload
npm run dist        # Windows installer and portable exe in apps/desktop/out/
```

On Windows everything builds with the `x86_64-pc-windows-gnu` toolchain, no C compiler needed. If the checkout path has spaces in it and you get `dlltool` errors, set `CARGO_TARGET_DIR` to a path without spaces.

```
crates/paranoia-core     the engine: loaders, disassemblers, analysis, decompiler
crates/paranoia-engine   engine process for the desktop app, workspace store, debugger
crates/paranoia-cli      the `paranoia` command
crates/paranoia-db       workspace store (redb)
crates/paranoia-wasm     the engine as WebAssembly
apps/desktop             React UI and Electron shell
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit.

## License

[Apache-2.0](LICENSE)
