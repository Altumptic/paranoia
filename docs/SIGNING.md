# Code signing

Every release is already verifiable without OS-vendor signatures: `SHA256SUMS` is signed with Sigstore by the release workflow and every package carries GitHub build-provenance and SBOM attestations ([VERIFY.md](VERIFY.md)). Vendor signing is the remaining step that removes the Windows SmartScreen warning and the macOS Gatekeeper warning. Until certificates are in place they are tracked as exceptions PSB-EX-1 (Windows Authenticode) and PSB-EX-5 (macOS notarisation) in [PSB.md](PSB.md).

Windows shows a SmartScreen warning for unsigned programs. To ship signed builds you need an **Authenticode code-signing certificate** issued to you or your organization. The project can't create one itself.

## Windows: Authenticode

### Options

| Option | Cost | Notes |
| --- | --- | --- |
| [SignPath Foundation](https://signpath.org) | Free for open source | Signs releases built by GitHub Actions; apply with the repository URL |
| [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/) | Low monthly fee | Identity validation by Microsoft; supported by electron-builder (`win.azureSignOptions`) |
| OV / EV certificate from a CA (DigiCert, Sectigo, SSL.com, …) | Paid yearly | EV certificates are stored on hardware tokens / cloud HSMs |

A self-signed certificate does **not** remove the SmartScreen warning.

### Using a .pfx certificate in CI

1. Export the certificate with its private key as `cert.pfx`.
2. Base64-encode it: `base64 -w0 cert.pfx > cert.txt` (PowerShell: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))`).
3. In the GitHub repository, add two **Actions secrets**:
   - `WINDOWS_CERTIFICATE`: the base64 text
   - `WINDOWS_CERTIFICATE_PASSWORD`: the .pfx password
4. Push a `v*` tag. The Windows desktop build signs the installer, the portable build and the bundled `paranoia-engine.exe` with SHA-256 and an RFC 3161 timestamp.

Without the secrets the build still runs and publishes unsigned executables.

## macOS: Developer ID and notarisation

A macOS app needs two things for a double-click launch without warnings: a **Developer ID Application** certificate (the signature) and **notarisation** by Apple's notary service. Both require a paid [Apple Developer Program](https://developer.apple.com/programs/) membership (99 USD/year). The project doesn't have one, so the release workflow currently ad-hoc signs the app and skips notarisation (PSB-EX-5).

The workflow is already wired for the real thing:

- With `CSC_LINK` and `CSC_KEY_PASSWORD` set, electron-builder signs the `.app` with the Developer ID certificate, using the hardened runtime. The bundled `paranoia-engine` is signed too (`mac.binaries` in `apps/desktop/package.json`); an unsigned executable inside the bundle would make notarisation fail.
- With the Apple notarisation credentials also set, electron-builder's [@electron/notarize](https://github.com/electron/notarize) integration submits the app to `notarytool`, waits for the result and staples the ticket. The `.dmg` and `.zip` then contain the notarised app.
- If the certificate is set but the Apple credentials are not, the build logs a warning and ships a signed but un-notarised app.
- If neither is set, the build also succeeds: it ad-hoc signs the app (required to run on Apple Silicon) and drops the hardened runtime, which an ad-hoc signature cannot satisfy. Gatekeeper still warns; users clear the quarantine flag after checking the checksum ([VERIFY.md](VERIFY.md)).

### Repository secrets

| Secret | Contents |
| --- | --- |
| `MACOS_CERTIFICATE` | base64 of the exported `.p12` (Developer ID Application certificate and its private key) |
| `MACOS_CERTIFICATE_PASSWORD` | the password set when exporting the `.p12` |
| `APPLE_ID` | the Apple ID email address of the developer account |
| `APPLE_APP_SPECIFIC_PASSWORD` | an app-specific password for that Apple ID, created at <https://appleid.apple.com> |
| `APPLE_TEAM_ID` | the 10-character team identifier from the developer account (Membership details) |

Export the `.p12` from Keychain Access (*My Certificates* → *Developer ID Application: …* → *Export*) and base64-encode it as a single line, so it can be stored in one secret:

```bash
base64 -i DeveloperID.p12 | tr -d '\n' > macos-cert.txt
```

The workflow passes the certificate password as `CSC_KEY_PASSWORD`; the Apple credentials are picked up by electron-builder from the `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD` and `APPLE_TEAM_ID` environment variables.

electron-builder also accepts App Store Connect API keys (`APPLE_API_KEY`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER`); the workflow currently wires the Apple ID pair only.

## Signing locally

Windows:

```powershell
$env:CSC_LINK = "C:\path\to\cert.pfx"
$env:CSC_KEY_PASSWORD = "…"
cd apps/desktop
npm run dist:win
```

macOS:

```bash
export CSC_LINK=/path/to/DeveloperID.p12
export CSC_KEY_PASSWORD=…
export APPLE_ID=…
export APPLE_APP_SPECIFIC_PASSWORD=…
export APPLE_TEAM_ID=…
cd apps/desktop
npm run dist:mac
```

To reproduce what CI produces without a certificate (ad-hoc signed, not notarised):

```bash
cd apps/desktop
npm run wasm && npm run engine && npm run build
npx electron-builder --mac --publish never --config.mac.identity=- --config.mac.hardenedRuntime=false
```
