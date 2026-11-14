# Verifying a download

Every release since v0.5.1 has these files next to the downloads:

| File | What it proves |
| --- | --- |
| `SHA256SUMS` | the SHA-256 of every package, executable and archive in the release |
| `SHA256SUMS.sigstore.json` | a [Sigstore](https://www.sigstore.dev/) signature over `SHA256SUMS`, made by this repository's release workflow (keyless, so there is no long-lived private key) |
| GitHub attestations | build provenance (which workflow run, commit and tag built the file) and the SBOM, both signed through GitHub |
| `paranoia-vX.Y.Z-rust.cdx.json`, `paranoia-vX.Y.Z-npm.cdx.json` | the SBOMs (CycloneDX): every Rust crate in `Cargo.lock` and every npm package in `package-lock.json`, including development dependencies, because Electron and the UI libraries end up inside the app |

From v0.8.0, releases also contain the command-line tool (which is also the [MCP server](MCP.md)): `paranoia-cli-vX.Y.Z-windows-x64.exe`, and `paranoia-cli-vX.Y.Z-<os>-<arch>.tar.gz` for Linux (x64, ARM64) and macOS (ARM64, x64). They're in `SHA256SUMS` and attested like the other files; check a `.tar.gz` before unpacking it.

Releases up to v0.5.0 predate this and have none of these files. v0.5.1 has a single SBOM, `paranoia-v0.5.1.cdx.json`, which lists the Rust crates but not the npm packages (the scanner skipped development dependencies). From v0.6.0 there are two complete SBOMs.

The release workflow also builds the desktop app for Linux and macOS. Those packages are new in this pipeline: no tagged release had been built with them when the jobs were added, so the first tagged release after that change is the first one to contain them. The same checksums, Sigstore signature and attestations apply to them as to the Windows builds.

## What is in a release

| File | Platform |
| --- | --- |
| `Paranoia-Setup-<version>.exe` | Windows installer (x64) |
| `Paranoia-<version>-portable.exe` | Windows portable executable (x64) |
| `Paranoia-<version>-linux-x86_64.AppImage`, `Paranoia-<version>-linux-amd64.deb` | Linux x64 (AppImage, Debian package) |
| `Paranoia-<version>-linux-arm64.AppImage`, `Paranoia-<version>-linux-arm64.deb` | Linux ARM64 (AppImage, Debian package) |
| `Paranoia-<version>-mac-arm64.dmg`, `Paranoia-<version>-mac-arm64.zip` | macOS, Apple Silicon |
| `Paranoia-<version>-mac-x64.dmg`, `Paranoia-<version>-mac-x64.zip` | macOS, Intel |
| `paranoia-cli-v<version>-windows-x64.exe` | command-line tool, Windows x64 |
| `paranoia-cli-v<version>-<os>-<arch>.tar.gz` | command-line tool, Linux (x64, ARM64) and macOS (ARM64, x64) |
| `paranoia-v<version>-rust.cdx.json`, `paranoia-v<version>-npm.cdx.json` | the two SBOMs |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | hashes and their signature |

The desktop artifacts use the bare version (`0.9.0`) and the CLI and SBOM files keep the `v` from the tag (`v0.9.0`); this follows the naming that releases already use.

The Windows executables aren't Authenticode-signed yet, and the macOS app is only ad-hoc signed rather than signed with a Developer ID, so it isn't notarised. SmartScreen and Gatekeeper may warn on first launch. Use the steps below to check a download instead of trusting the file.

## 1. Check the hashes

Download the file and `SHA256SUMS` into the same folder.

PowerShell:

```powershell
Get-FileHash .\Paranoia-0.5.1-portable.exe -Algorithm SHA256
Get-Content .\SHA256SUMS
```

Linux / Git Bash:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

macOS ships `shasum` instead of `sha256sum`; check one downloaded file with:

```bash
grep 'Paranoia-<version>-mac-arm64.dmg' SHA256SUMS | shasum -a 256 -c -
```

The hashes must match. `--check` also fails if a listed file is modified, and `--ignore-missing` (GNU) skips files you didn't download.

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
gh attestation verify Paranoia-<version>-linux-x86_64.AppImage --repo Altumptic/paranoia
```

This shows the workflow, commit and tag that produced the file. The release job also attests every package to both SBOMs:

```bash
gh attestation verify Paranoia-<version>-linux-x86_64.AppImage --repo Altumptic/paranoia \
  --predicate-type https://cyclonedx.org/bom
```

## 4. Look at the SBOM (optional)

The SBOMs are plain JSON. Any CycloneDX tool can read them, for example:

```bash
grype sbom:paranoia-v0.6.0-npm.cdx.json   # known vulnerabilities in the listed components
```

## On macOS: expected Gatekeeper behaviour

While there is no Developer ID certificate, the `.app` inside the `.dmg` and `.zip` is ad-hoc signed:

```bash
codesign -dv --verbose=4 /Applications/Paranoia.app   # "Signature=adhoc", no TeamIdentifier
spctl --assess --type execute /Applications/Paranoia.app
```

`spctl` fails on an ad-hoc signed app that isn't notarised; that is expected, not a sign of tampering. Verify the download with the checksums and the Sigstore signature above, then allow the app as described in the [README](../README.md#macos) (clear the quarantine flag). If a Developer ID is added later ([SIGNING.md](SIGNING.md)), future releases will pass `spctl` and `codesign` will show the Developer ID team.

## If something does not match

Do not run the file. Report it as described in [SECURITY.md](../SECURITY.md).
