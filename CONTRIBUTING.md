# Contributing to Paranoia

Thanks for helping! A few guidelines keep things smooth.

## Getting set up

```bash
cargo test --workspace                 # engine tests (includes mutation tests on host binaries)
cargo build --release -p paranoia-engine
cd apps/desktop && npm install && npm run app:dev
```

Run `cargo fmt`, `cargo clippy --workspace` and `npm run typecheck` before opening a pull request.

## Ground rules

- **Never panic on input.** Every offset and size in a file is attacker-controlled. Use checked arithmetic and `get(..)` instead of indexing, and add a case to `crates/paranoia-core/tests/real_binaries.rs` when you fix a crash.
- **Keep the core pure.** `paranoia-core` has no I/O, threads or C dependencies so it can run in WebAssembly.
- **One contract.** New engine features go through `api.rs` and are mirrored in `apps/desktop/src/engine/{client,types}.ts`.
- **Privacy.** No telemetry, no network calls, no remote resources in the UI.
- **Security.** Read [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) before touching the Electron shell (`electron/`), the IPC bridge or the script runners. New IPC handlers go through `handle()` (sender check) and must not widen file access beyond what the user chose. Keep the page CSP free of `'unsafe-eval'` and inline script. New dependencies must pass `cargo audit` / `npm audit` in CI.

## Security issues

Do not open public issues for vulnerabilities — follow [SECURITY.md](SECURITY.md).

## Reporting bugs

Include the file's SHA-256, format and architecture, and what you expected. Please do not attach live malware to public issues.

## License

By contributing you agree that your contributions are licensed under the Apache-2.0 license.
