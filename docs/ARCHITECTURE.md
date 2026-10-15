# Architecture

Paranoia is split into a pure-Rust analysis engine and thin front-ends that drive it.

```
                    ┌─────────────────────────────── apps/desktop ───────────────────────────────┐
                    │  React UI (renderer, sandboxed)                                            │
                    │    engine/client.ts ── Backend interface ──┬── DesktopBackend ─┐           │
                    │                                            └── WasmBackend ──┐ │           │
                    │  Electron main (electron/main.cjs)                            │ │           │
                    │    IPC bridge (preload.cjs) ◄────────────────────────────────┼─┘           │
                    └───────────────┬──────────────────────────────────────────────┼─────────────┘
                                    │ stdio, line-delimited JSON                    │ Web Worker
                         ┌──────────▼───────────┐                       ┌───────────▼────────────┐
                         │ paranoia-engine.exe  │                       │ paranoia.wasm (C ABI)  │
                         │  + paranoia-db       │                       │                        │
                         └──────────┬───────────┘                       └───────────┬────────────┘
                                    └────────────────► paranoia-core::api ◄─────────┘
                                                       (one JSON method contract)
```

## paranoia-core

No I/O, no threads, no C dependencies — the same code runs natively and in WebAssembly.

| Module | Responsibility |
| --- | --- |
| `loader/` | PE, ELF and Mach-O loaders producing a normalized `Loaded` image: sections, address map, imports, exports, symbols, function seeds, mitigations, headers. Mach-O imports (bind opcodes, chained fixups) and the export trie are parsed by our own bounds-checked code. |
| `disasm.rs` | Fast decode for analysis (length, flow, targets, data refs) and token rendering for the UI (iced-x86 for x86/x64, yaxpeax-arm for AArch64). |
| `analysis.rs` | Recursive-descent function discovery with tail-call and no-return handling, basic blocks and the cross-reference index. |
| `pseudo.rs` | x86/x64 → C-like lifter with condition folding and `if`/`do-while` structuring. |
| `tools.rs` | Byte/text/immediate search, callees, user functions, patching, bookmarks, IDC export. |
| `demangle.rs` | MSVC, Itanium and Rust demangling. |
| `api.rs` | `Session::call(method, args)` — the JSON contract every front-end uses. |

### Robustness

Input files are hostile by default. The loaders never trust sizes or offsets, analysis has hard limits (`MAX_FUNCTIONS`, `MAX_INSNS_PER_FUNCTION`, `MAX_TOTAL_INSNS`), and `tests/real_binaries.rs` mutates real samples (`PARANOIA_FUZZ_ITERS`, `PARANOIA_FUZZ_SEED`, `PARANOIA_FUZZ_FILE`) to make sure nothing panics. Where third-party parsers proved fragile (goblin's `.pdata` iterator, Mach-O bind interpreter and export trie) Paranoia uses its own implementations. As a final layer, the desktop engine runs out of process and the UI recovers if it ever dies.

## Front-ends

- **Desktop** — Electron shell with a sandboxed renderer (`contextIsolation`, no Node integration, strict CSP, no navigation). File writes are only allowed to paths the user just chose in a save dialog. The native engine is bundled under `resources/engine/`.
- **Browser** — `paranoia-wasm` exposes `pn_alloc` / `pn_open` / `pn_call` and friends; `wasm.worker.ts` runs it off the UI thread. No wasm-bindgen or extra tooling is needed.
- **CLI** — `paranoia` for scripting and CI.

## Workspace storage

Annotations (names, comments, user functions, bookmarks, patches) and the recent-files list are keyed by the file's SHA-256 and stored in a redb database in the user's app-data folder (desktop) or `localStorage` (browser).

## Adding an engine method

1. Implement it on `Binary` in `paranoia-core`.
2. Expose it in `api.rs` (`Session::call`).
3. Add a typed wrapper to `Session` in `apps/desktop/src/engine/client.ts` and any new types to `types.ts`.

Both backends pick it up automatically.
