# Contributing

## Setup

```bash
cargo build --release -p paranoia-engine    # the desktop app needs this first
cargo test --workspace

cd apps/desktop
npm ci
npm run wasm        # browser build of the engine (rustup target add wasm32-unknown-unknown)
npm run app:dev     # Vite + Electron with hot reload
npm run dev         # browser only, http://localhost:1420
```

Before opening a pull request, run:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd apps/desktop && npm run typecheck && npm test
```

CI runs the same checks on Windows, Linux and macOS, plus `cargo audit` and `npm audit`.

## Rules

- **Don't panic on input.** Every size and offset in a file can be hostile. Use checked arithmetic and `.get()` instead of indexing. When you fix a crash, add the case to `crates/paranoia-core/tests/real_binaries.rs`.
- **Keep `paranoia-core` pure.** No I/O, threads or C dependencies, so it still builds for `wasm32-unknown-unknown`.
- **One API.** A new engine feature is a method on `Binary`, exposed in `api.rs`, with a typed wrapper in `apps/desktop/src/engine/client.ts` and its types in `types.ts`. The native and the WebAssembly backends then both get it.
- **No network.** No telemetry, no update checks, no fonts or scripts from CDNs.
- **Security.** Read [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) before changing anything in `apps/desktop/electron/`. IPC handlers go through `handle()`, never give the page access to files the user didn't pick, and keep `'unsafe-eval'` and inline scripts out of the CSP.
- **Dependencies** have to pass `cargo audit` and `npm audit`. CI actions are pinned to commit hashes.
- **Style:** rustfmt with `max_width = 140`; 4 spaces in Rust, 2 in TS/CSS/JSON; LF line endings. Each Rust module starts with a short `//!` comment.

## Things that trip people up

- If the checkout path has spaces and you get `dlltool` errors on Windows, set `CARGO_TARGET_DIR` to a path without spaces.
- `npm run app:dev` fails until the engine has been built once.
- The crash tests in `real_binaries.rs` mutate system binaries in memory (`notepad.exe`, `/bin/ls`, or `PARANOIA_FUZZ_FILE`) and never run them. Tests whose sample is missing just pass.
- Optional sample directories for slower tests: `PARANOIA_FLIRT_DIR` (IDA `.sig` files), `PARANOIA_PPC_DIR` (PowerPC), `PARANOIA_ARM64_DIR` (AArch64 pseudocode).
- In `paranoia mcp`, stdout is the protocol. Log to stderr only.
- The Linux debugger tests run on CI's Ubuntu job. Locally, build with `--target x86_64-unknown-linux-musl` (linker `rust-lld`) and run the test binary in WSL.

## Releases

Bump `version` in the root `Cargo.toml` and in `apps/desktop/package.json`, then push a `vX.Y.Z` tag. CI builds the installer, the portable exe and the CLI, signs the checksums and attaches the SBOMs. [docs/VERIFY.md](docs/VERIFY.md) describes what a release contains.

## Bugs and security issues

For a bug, include the file's SHA-256, its format and architecture, and what you expected to see. Please don't attach live malware to public issues.

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the Apache-2.0 license.
