Full list of changes: [CHANGELOG.md](https://github.com/Altumptic/paranoia/blob/{{tag}}/CHANGELOG.md). Known limits: [README](https://github.com/Altumptic/paranoia/blob/{{tag}}/README.md#limits).

## Downloads

| File | For |
| --- | --- |
| `Paranoia-Setup-{{version}}.exe`, `Paranoia-{{version}}-portable.exe` | Windows desktop app |
| `Paranoia-{{version}}-linux-x86_64.AppImage`, `Paranoia-{{version}}-linux-amd64.deb` | Linux x64 desktop app |
| `Paranoia-{{version}}-linux-arm64.AppImage`, `Paranoia-{{version}}-linux-arm64.deb` | Linux ARM64 desktop app |
| `Paranoia-{{version}}-mac-arm64.dmg` / `.zip` | macOS, Apple silicon |
| `Paranoia-{{version}}-mac-x64.dmg` / `.zip` | macOS, Intel |
| `paranoia-cli-{{tag}}-windows-x64.exe` | Command-line tool, Windows |
| `paranoia-cli-{{tag}}-linux-x64.tar.gz`, `…-linux-arm64.tar.gz` | Command-line tool, Linux (static) |
| `paranoia-cli-{{tag}}-macos-arm64.tar.gz`, `…-macos-x64.tar.gz` | Command-line tool, macOS |

## Not signed

- The Windows files aren't Authenticode-signed: SmartScreen may warn.
- The macOS apps are ad-hoc signed and not notarised: Gatekeeper blocks the first launch. After checking the checksum run `xattr -dr com.apple.quarantine /Applications/Paranoia.app`.

The checksums are signed and every file has a build provenance attestation, which is what to rely on until the files carry platform signatures.

## Verify

```bash
sha256sum -c SHA256SUMS --ignore-missing
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Altumptic/paranoia/\.github/workflows/ci\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify paranoia-cli-{{tag}}-linux-x64.tar.gz --repo Altumptic/paranoia
```

More in [VERIFY.md](https://github.com/Altumptic/paranoia/blob/{{tag}}/docs/VERIFY.md).
