# AGENTS.md

Single entry point for AI assistants (and humans in a hurry). Everything you need to work productively in this repo — layout, commands, invariants, pitfalls — is on this page, so you don't have to rediscover it. Follow the pointers for depth instead of re-reading the codebase.

## What this is

**Paranoia** — an open (Apache-2.0), local-first reverse-engineering platform: a free alternative to IDA Pro. Disassembly, CFG, an x86/x64 decompiler, a Windows x64 debugger, IDA-style scripting (Python `idc`/`idautils`, JavaScript) for PE / ELF / Mach-O on x86/x64, AArch64, ARM32/Thumb-2, RISC-V and MIPS. No network, no telemetry, ever.

## The 30-second mental model

```
paranoia-core (pure Rust: no I/O, no threads, no C deps)
      │  one JSON-RPC-style contract: Session::call(method, args) in api.rs
      ├── paranoia-engine.exe   ← desktop app talks over line-delimited JSON on stdio (+ debugger, workspace store via paranoia-db/redb)
      ├── paranoia.wasm         ← browser build (plain C ABI: pn_alloc/pn_open/pn_call), runs in a Web Worker
      └── paranoia-cli          ← `paranoia` CLI drives core directly (also headless `paranoia script`)
```

Addresses travel as JSON numbers; exact below 2^53 (covers user-mode images). Both backends (native + wasm) expose the *same* contract — nothing may exist in one and not the other.

## Repo map

| Path | What lives there |
| --- | --- |
| `Cargo.toml` | Workspace; **the** version source (`[workspace.package] version`, inherited by every crate) |
| `crates/paranoia-core/` | The whole analysis engine (~13k lines, the heart of the project) |
| `crates/paranoia-engine/src/` | `main.rs` — engine process (JSON over stdio, workspace store); `debugger.rs` — Windows x64 + 32-bit (WOW64) debugger; `debugger_linux.rs` — Linux x86-64 ptrace debugger with the same interface (tests run on CI's ubuntu job; locally: build with `--target x86_64-unknown-linux-musl`, linker `rust-lld` + `-C linker-flavor=ld.lld -C link-self-contained=yes`, run the test binary in WSL) |
| `crates/paranoia-cli/src/` | `main.rs` — `paranoia <subcommand>`; `script.rs` — headless Python batch mode |
| `crates/paranoia-db/src/` | redb store: annotations + recent files, keyed by file SHA-256 |
| `crates/paranoia-wasm/src/` | The engine for the browser, plain C ABI (no wasm-bindgen) |
| `apps/desktop/src/` | React + TS UI. Key files: `engine/client.ts` (typed `Session` mirror), `engine/types.ts`, `store.ts` (app state), `components/views/` (Overview, DisassemblyView, Graph, Pseudocode, Hex, Calls), `components/` (dialogs: Xrefs, Search, Edit, CommandPalette, Console) |
| `apps/desktop/electron/` | `main.cjs` (IPC, security boundary), `preload.cjs` (bridge), `engine.cjs` (engine process), `python.cjs` + `paranoia.py` (Python scripts in the user's CPython), `ai.cjs` (optional AI assistant: endpoint rules, prompts, chat call, name parser; network only from the main process, tests in `ai.test.cjs`), `plugins.cjs` (plugin manifests: read + validate + fingerprint, never runs code; tests in `plugins.test.cjs`, run with `npm test`) |
| `scripts/` | `build-wasm.mjs`, `dev-desktop.mjs` (Vite + Electron dev loop), `brand.mjs` |
| `docs/` | All product/security/process docs — see index below |
| `assets/brand/` | Logo and app icon sources |

### paranoia-core module guide

| Module | Responsibility |
| --- | --- |
| `loader/` (`pe.rs`, `elf.rs`, `macho.rs`, `macho_bind.rs`) | Loaders producing a normalized `Loaded` image; our own bounds-checked parsers for Mach-O bind/fixups/export trie and PE `.pdata` |
| `model.rs` | Serializable data model shared by all front-ends |
| `disasm.rs`, `riscv.rs`, `mips.rs`, `ppc.rs` | Decode (fast, for analysis) + render (tokens, for UI); iced-x86, yaxpeax-arm, own RISC-V/MIPS/PowerPC decoders. PowerPC real-binary test: `PARANOIA_PPC_DIR` with Go-built `hello-ppc64`/`hello-ppc64le` |
| `analysis.rs`, `switch.rs` | Recursive-descent function discovery, basic blocks, jump-table recovery, xref index |
| `pseudo.rs`, `pseudo_opt.rs`, `pseudo_types.rs` | x86/x64 decompiler: lifting, expression propagation, loops/switch, typed variables |
| `pseudo_structs.rs` | Struct member access in pseudocode (types set with `Y`); argument/return types flow across internal calls, pointer fields chain |
| `items.rs`, `types.rs`, `operands.rs`, `protos.rs` | Listing items + auto names, local C types, operand display/constants, ~250 API prototypes |
| `pseudo_ssa.rs` | Variable recovery: flow graph from the structured pseudocode lines (over-approximated on purpose — an extra edge only merges variables), reaching definitions, webs. `type_variables_with` falls back to the old splitting if the structure cannot be read; `Binary::set_ssa_variables(false)` switches it off for comparison |
| `flirt_sig.rs` | IDA binary `.sig` reader → the same `PatSig` list the `.pat` matcher uses (`Binary::apply_sig`, API `applySig`). Real-file test: set `PARANOIA_FLIRT_DIR` to angr's `libc_ubuntu_2004.sig` + static-libc ELF |
| `asm_x86.rs` | Text assembler (Intel syntax) on iced's encoder; `Binary::assemble_at` (API `assemble`) patches code with it |
| `pdbsym.rs`, `pdbtypes.rs`, `dwarf.rs`, `sigs.rs` | PDB (symbols; types in `pdbtypes.rs`), DWARF (names, lines, struct/enum types). Types from debug info live in `Binary::debug_types` (runtime, NOT in annotations); read types only via `Binary::type_view()` (user Local Types win), FLIRT-style `.pat` signatures (+ `sigs/msvc_x64.pat` built-in) |
| `tools.rs`, `nav.rs`, `frame.rs` | Search/patching/user functions/export, call graph + undo, stack frames |
| `strings.rs`, `metrics.rs`, `demangle.rs` | String extraction, entropy/hashes, MSVC/Itanium/Rust demangling |
| `api.rs` | **The contract**: `Session::call(method, args)` — the only way in |

## Commands

Engine (run from repo root):

```bash
cargo test --workspace                                   # all engine tests (unit + mutation suite)
cargo test --release -p paranoia-core --test real_binaries corrupted   # hostile-input suite (CI: PARANOIA_FUZZ_ITERS=500)
cargo fmt                                                # required before commit (CI checks)
cargo clippy --workspace --all-targets -- -D warnings    # required before commit (CI: -D warnings)
cargo build --release -p paranoia-engine                 # build the native engine for the desktop app
```

Desktop app (from `apps/desktop/`):

```bash
npm ci                # once
npm run wasm          # browser engine; needs `rustup target add wasm32-unknown-unknown`
npm run engine        # = cargo build --release -p paranoia-engine
npm run app:dev       # Vite + Electron with hot reload (needs the engine built first)
npm run dev           # browser-only build at http://localhost:1420
npm run typecheck     # tsc -b --noEmit
npm run dist          # installer + portable .exe into apps/desktop/out/
```

CI (`.github/workflows/ci.yml`) enforces: fmt, clippy `-D warnings`, tests, mutation tests on 3 OSes, frontend typecheck + build, `cargo audit` + `npm audit` via `scripts/npm-audit-gate.mjs` (known advisories **block** the build; the few accepted ones are listed with an expiry date in that script and in `docs/PSB.md`).

## Invariants — breaking any of these is a bug

1. **Never panic on input.** Every offset/size in a file is attacker-controlled: checked arithmetic, `.get(..)` over indexing, hard limits (`MAX_FUNCTIONS`, `MAX_INSNS_PER_FUNCTION`, `MAX_TOTAL_INSNS`). If you fix a crash, add a case to `crates/paranoia-core/tests/real_binaries.rs`.
2. **`paranoia-core` stays pure**: no I/O, no threads, no C dependencies — it must keep compiling to `wasm32-unknown-unknown`.
3. **One contract.** New engine features: implement on `Binary` → expose in `api.rs` → mirror the typed wrapper in `apps/desktop/src/engine/client.ts` + types in `engine/types.ts`. Both backends then work automatically.
4. **Privacy is a feature.** No telemetry, no network calls, no remote resources (fonts, CDNs, update checks). Updates are manual.
5. **Electron is the security boundary.** Read `docs/SECURITY-DESIGN.md` *before* touching `apps/desktop/electron/`. IPC handlers go through `handle()` (sender check), never widen file access beyond what the user picked, keep the CSP free of `'unsafe-eval'` and inline script.
6. **Own parsers over fragile third-party ones** where robustness was proven necessary (Mach-O bind/trie, PE `.pdata`). New parser code must be bounds-checked.
7. **CI actions** are pinned to full commit SHAs; permissions stay least-privilege. New dependencies must pass `cargo audit` / `npm audit`.
8. **Style.** rustfmt: `max_width = 140`, `use_small_heuristics = "Max"`. Indent: Rust 4, TS/CSS/JSON 2. LF everywhere (`text=auto eol=lf`). Module files start with a `//!` doc comment.

## Pitfalls

- **Checkout path contains spaces** (`D:\WorkSpace - IT\Paranoia` does): if `dlltool` errors appear during Windows builds, set `CARGO_TARGET_DIR` to a space-free path. Windows builds use the `x86_64-pc-windows-gnu` toolchain — no MSVC/C compiler needed.
- `npm run app:dev` fails without a previously built engine (`cargo build --release -p paranoia-engine` or `npm run engine`).
- Wasm build requires the target: `rustup target add wasm32-unknown-unknown`.
- The mutation suite (`real_binaries.rs`) corrupts **host binaries in memory** (`notepad.exe`, `/bin/ls`, or `$PARANOIA_FUZZ_FILE`) and never executes them; every test is a no-op when its sample is missing.
- IDA's compressed binary `.sig` files are **not** read (`.pat` only) — don't "fix" this silently in unrelated PRs, it's a roadmap item.
- `docs/screenshots/` and release artifacts are regenerated by CI/scripts — don't hand-edit.

## Recipes

**Add an engine method** (e.g. a new query the UI needs):
1. Implement on `Binary` in `paranoia-core` (+ unit test).
2. Match it in `api.rs` (`Session::call`).
3. Add the typed wrapper in `engine/client.ts` + types in `engine/types.ts`, then call it from the view.

**Fix a crash on a sample**: reproduce via `cargo test -p paranoia-core --test real_binaries`, fix with bounds-checked code, add the regression case, run the full `cargo test --workspace`.

**Release a version**: bump `version` in root `Cargo.toml` **and** `apps/desktop/package.json` → tag `vX.Y.Z` → CI builds installer/portable, signs checksums (sigstore), attests provenance, produces Rust+npm SBOMs → write release notes (artifact layout documented in `docs/VERIFY.md`).

## Doc index

| Doc | Read it when… |
| --- | --- |
| `docs/ARCHITECTURE.md` | You need engine internals or the data flow diagram |
| `docs/SECURITY-DESIGN.md` | Touching Electron, IPC, scripting, or anything attack-surface related (threat model + data inventory) |
| `docs/ROADMAP.md` | Planning work — the IDA-parity table and the next-milestone list |
| `docs/PSB.md` | Release/security-baseline labels (`PSB-C`, `SIGNED`, …) and their exceptions |
| `docs/VERIFY.md`, `docs/SIGNING.md` | Release artifacts, checksums, attestations, the signing pipeline |
| `docs/BRAND.md` | Logo/brand usage |
| `CONTRIBUTING.md` | Ground rules (short — AGENTS.md already summarizes them) |
| `SECURITY.md` | Reporting a vulnerability (privately, never a public issue) |

## Where the work is

Check `docs/ROADMAP.md` → "Next milestones" for the current priorities: a real SSA IR in the decompiler, `.sig` referenced-function checks, pseudocode beyond x86, remote debugging. Mixed ARM/Thumb: per-address mode in `Binary::arm_modes` (`loader::fix_arm_thumb` + `blx` targets); render code with `Binary::render_code`, never `render_mode` directly. Verify your work with the Commands section before handing it over — CI is the same on your machine as on GitHub.
