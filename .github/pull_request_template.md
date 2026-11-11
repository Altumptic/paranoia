## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checks

- [ ] `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass
- [ ] `npm run typecheck` and `npm test` pass in `apps/desktop` (if the UI or Electron code changed)
- [ ] A crash fix comes with a case in `crates/paranoia-core/tests/real_binaries.rs`
- [ ] No new network access, telemetry or `unsafe` without a `SAFETY` comment
- [ ] Docs and `CHANGELOG.md` updated if behaviour changed
