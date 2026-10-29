# Altumptic Product Security Baseline — Paranoia

Paranoia is assigned **class C — local-first tooling** (reverse-engineering tool, offline, no account). Class C requires **PSB-Core + supply chain**. This page records how each requirement is met, with evidence, and lists every exception with an expiry date.

Status key: ✅ met · ⚠️ met with an exception · ➖ not applicable to class C · ❌ not met

Last reviewed: 2026-10-28 · Applies from release v0.5.1.

## Labels

`PSB-C` · `SIGNED` · `ATTESTED` · `SBOM` · `NO-TELEMETRY` · `LOCAL-FIRST` · `AUDIT:NONE` · `DISCLOSURE:OK`

`SIGNED` means signed checksums: `SHA256SUMS` carries a Sigstore keyless signature whose identity is this repository's release workflow (see [VERIFY.md](VERIFY.md)). The Windows executables themselves are **not** Authenticode-signed yet (exception PSB-EX-1).

## 0. Principles

| | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| P1 | Open by default | ✅ | All code Apache-2.0 in this repository; no closed components |
| P2 | Least data | ✅ | No telemetry, no accounts, no network ([SECURITY-DESIGN.md § Network](SECURITY-DESIGN.md#network)) |
| P3 | Prove, don't claim | ✅ | Signed checksums, attestations, SBOM, tests named in [SECURITY-DESIGN.md](SECURITY-DESIGN.md) |
| P4 | Fail closed | ✅ | Untrusted IPC senders, unchosen file paths and declined confirmations are refused, never bypassed |
| P5 | Authorized scope only | ✅ | A tool for analysing software you are allowed to analyse; the debugger only starts programs the user chooses and warns before every start |
| P6 | Name the limits | ✅ | Known limits and non-goals in [SECURITY-DESIGN.md](SECURITY-DESIGN.md); roadmap lists what is missing |

## 2. Cryptography and data protection

| Requirement | Status | Notes |
| --- | --- | --- |
| Allowed algorithms only | ✅ | SHA-256 for identity and integrity; Sigstore (ECDSA P-256 with Fulcio, justified by the Sigstore ecosystem) for signatures. MD5 / SHA-1 are displayed for file identification only, never for a security decision |
| Keys and secrets | ➖ | The product holds no keys or secrets. CI uses OIDC tokens for signing; the optional Authenticode certificate would live in GitHub encrypted secrets |
| Data at rest | ➖ | Only the user's own annotations and recent-file list, stored locally ([data inventory](SECURITY-DESIGN.md#data-inventory)) |
| Data in transit | ➖ | No network traffic |

## 3. Release authenticity

| Requirement | Status | Evidence |
| --- | --- | --- |
| `SHA256SUMS` | ✅ | Release job, `.github/workflows/ci.yml` |
| Signed checksums, published identity | ✅ | `SHA256SUMS.sigstore.json` (cosign keyless, Rekor log); identity documented in [VERIFY.md](VERIFY.md) |
| Provenance | ✅ | `actions/attest-build-provenance` for every executable and `SHA256SUMS` |
| SBOM | ✅ | CycloneDX JSON attached to the release and attested |
| Security changes in release notes | ✅ | Release checklist below |
| Windows Authenticode | ⚠️ | PSB-EX-1 |

## 5. Hardened surfaces (desktop)

| Requirement | Status | Evidence |
| --- | --- | --- |
| Minimal OS permissions, explained | ✅ | No admin rights, all permission requests denied ([SECURITY-DESIGN.md § Operating-system permissions](SECURITY-DESIGN.md#operating-system-permissions)) |
| Auto-update only from a signed channel | ➖ | No auto-update; manual download + verification |
| No debug builds on stable | ✅ | DevTools disabled in packaged builds; Electron fuses disable `RunAsNode`, `NODE_OPTIONS`, `--inspect`; asar integrity enforced |
| CSP without eval | ⚠️ | `script-src 'self' 'wasm-unsafe-eval'` — no `'unsafe-eval'`, no inline script (PSB-EX-2 for `'wasm-unsafe-eval'`) |
| Renderer isolation | ⚠️ | Sandbox, `contextIsolation`, no Node integration, sender checks on every IPC handler, file allow-list, native confirmations; Electron's extra `file://` privileges kept (PSB-EX-3) |

## 6. Privacy

| Requirement | Status | Notes |
| --- | --- | --- |
| Data inventory | ✅ | [SECURITY-DESIGN.md § Data inventory](SECURITY-DESIGN.md#data-inventory) |
| No silent PII | ✅ | The recent-files list stores full paths locally; this is stated in the inventory |
| No analytics SDKs | ✅ | None in the dependency tree (see SBOM) |
| Export / delete | ✅ | Delete `%APPDATA%\Paranoia` |

## 7. Secure development lifecycle

| Requirement | Status | Evidence |
| --- | --- | --- |
| Threat model | ✅ | [SECURITY-DESIGN.md](SECURITY-DESIGN.md) (not required for class C, provided anyway) |
| Pinned dependencies | ✅ | `Cargo.lock`, `package-lock.json`; GitHub Actions pinned to commit SHAs |
| Audit in CI, critical CVEs block release | ✅ | `audit` job (`cargo audit`, `npm audit --audit-level=moderate`); the release job depends on it |
| CI secrets short-lived | ✅ | Signing and attestations use OIDC; release job has the only write permissions |
| Second pair of eyes on security diffs | ⚠️ | Single-maintainer project: security-relevant changes are recorded in commit messages and release notes (founder sign-off) |
| Negative tests for untrusted input | ✅ | Noise and mutation tests in `paranoia-core` (decoders, loaders, type and `.pat` parsers) |

## 8. Vulnerability disclosure

| Requirement | Status | Evidence |
| --- | --- | --- |
| Policy and `security.txt` | ✅ | <https://altumptic.com/security>, <https://altumptic.com/.well-known/security.txt> (Paranoia is in scope) |
| Contact with current PGP key | ✅ | [SECURITY.md](../SECURITY.md) |
| GitHub Security Advisories for OSS | ⚠️ | Private vulnerability reporting is not enabled on the repository yet; reports go to the email in SECURITY.md |

## Exceptions

| ID | Deviation | Why | Compensating control | Expires |
| --- | --- | --- | --- | --- |
| PSB-EX-1 | Windows executables are not Authenticode-signed | No code-signing certificate yet ([SIGNING.md](SIGNING.md)) | `SHA256SUMS` + Sigstore signature + GitHub attestations; stated on the README and in every release | 2027-04-30 |
| PSB-EX-2 | CSP allows `'wasm-unsafe-eval'` | The browser build runs the engine as WebAssembly; the directive allows compiling WebAssembly only, not JavaScript `eval` | No `'unsafe-eval'`, no inline script; the desktop app uses the native engine | 2027-04-30 (review: split desktop and web CSP) |
| PSB-EX-3 | Electron fuse `grantFileProtocolExtraPrivileges` left on | The app is loaded from `file://` and starts workers from it | Navigation blocked, no remote content, CSP; plan: move to a custom `app://` protocol | 2027-04-30 |

An exception without an expiry date is a violation of the baseline; these are reviewed before every release.

## Release checklist

- [ ] PSB class and labels current on README
- [ ] No deprecated crypto on new paths
- [ ] `SHA256SUMS`, signature, attestations and SBOM present on the release (CI)
- [ ] Verify guide run on a clean machine
- [ ] Fail-closed behaviour covered (IPC checks, confirmations)
- [ ] No new telemetry or network access
- [ ] Limits, exceptions and audit status updated
- [ ] SECURITY.md contacts valid; `security.txt` not expired (expires 2027-10-23)
- [ ] README and release notes match the shipped version and capabilities
