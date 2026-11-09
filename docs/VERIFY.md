# Verifying a download

Every release since v0.5.1 has these files next to the executables:

| File | What it proves |
| --- | --- |
| `SHA256SUMS` | the SHA-256 of each executable |
| `SHA256SUMS.sigstore.json` | a [Sigstore](https://www.sigstore.dev/) signature over `SHA256SUMS`, made by this repository's release workflow (keyless, so there is no long-lived private key) |
| GitHub attestations | build provenance (which workflow run, commit and tag built the file) and the SBOM, both signed through GitHub |
| `paranoia-vX.Y.Z-rust.cdx.json`, `paranoia-vX.Y.Z-npm.cdx.json` | the SBOMs (CycloneDX): every Rust crate in `Cargo.lock` and every npm package in `package-lock.json`, including development dependencies, because Electron and the UI libraries end up inside the app |

Releases after v0.7.0 also contain `paranoia-cli-vX.Y.Z-windows-x64.exe`, the command-line tool (which is also the [MCP server](MCP.md)). It's in `SHA256SUMS` and attested like the other executables.

Releases up to v0.5.0 predate this and have none of these files. v0.5.1 has a single SBOM, `paranoia-v0.5.1.cdx.json`, which lists the Rust crates but not the npm packages (the scanner skipped development dependencies). From v0.5.2 there are two complete SBOMs.

The Windows executables aren't Authenticode-signed yet, so SmartScreen may warn on first launch. Use the steps below to check a download instead.

## 1. Check the hashes

Download the executable and `SHA256SUMS` into the same folder.

PowerShell:

```powershell
Get-FileHash .\Paranoia-0.5.1-portable.exe -Algorithm SHA256
Get-Content .\SHA256SUMS
```

The two hashes must match.

Linux / macOS / Git Bash:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

## 2. Check the signature on SHA256SUMS

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) (v3 or newer), download `SHA256SUMS.sigstore.json`, then:

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Altumptic/paranoia/\.github/workflows/ci\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`Verified OK` means the checksums were signed by this repository's CI workflow running for a release tag, and the signature is recorded in the public Rekor transparency log.

## 3. Check the build provenance (optional)

With the [GitHub CLI](https://cli.github.com/):

```bash
gh attestation verify Paranoia-0.5.1-portable.exe --repo Altumptic/paranoia
```

This shows the workflow, commit and tag that produced the file.

To check the SBOM attestation as well:

```bash
gh attestation verify Paranoia-0.5.1-portable.exe --repo Altumptic/paranoia \
  --predicate-type https://cyclonedx.org/bom
```

## 4. Look at the SBOM (optional)

The SBOMs are plain JSON. Any CycloneDX tool can read them, for example:

```bash
grype sbom:paranoia-v0.5.2-npm.cdx.json   # known vulnerabilities in the listed components
```

## If something does not match

Do not run the file. Report it as described in [SECURITY.md](../SECURITY.md).
