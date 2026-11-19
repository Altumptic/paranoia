# Flatpak

`app.paranoia.Paranoia` repackages the `.deb` that CI builds, signs and attests for each release (x86-64 and ARM64) in a Flatpak sandbox, on `org.freedesktop.Platform` with the Electron base app. It does not build Paranoia from source in Flatpak: the engine is built by the release workflow, and the Flatpak uses exactly the file whose checksum is in the signed `SHA256SUMS`.

## Making the manifest for a release

After the release exists (a final one, not a candidate) and you have verified its `SHA256SUMS` ([VERIFY.md](../../docs/VERIFY.md)):

```bash
node scripts/flatpak-manifest.mjs --tag v0.10.0 --sums SHA256SUMS --date 2026-12-01 --out build/flatpak
flatpak-builder --user --install --force-clean build/flatpak-build build/flatpak/app.paranoia.Paranoia.yml
flatpak run app.paranoia.Paranoia
```

The script reads the two `.deb` checksums from `SHA256SUMS`, writes the URLs, sums, version and date into the manifest and the AppStream file, and refuses a tag, a file or a date that does not fit.

## Permissions

The manifest asks for the display (X11 and Wayland), the GPU and IPC, **nothing else**: no network, no home folder. Files are opened through the portal's file dialog, which is how a sandboxed app is meant to read a file the user picks. Three optional features need more, and you can grant them per user:

| Feature | Needs | Grant |
| --- | --- | --- |
| AI assistant, Check for updates | network | `flatpak override --user --share=network app.paranoia.Paranoia` |
| Debugging a GDB server on this computer | network (loopback) | the same |
| The local debugger (starting a program under ptrace) | `devel` | `flatpak override --user --allow=devel app.paranoia.Paranoia` |

The local debugger runs the program inside the sandbox, with the sandbox's files; to debug something from the host, use the GDB server route or the non-Flatpak package.

## Status

The files here have not been built with `flatpak-builder` or submitted to Flathub: that needs a Flatpak toolchain and a release to point at, neither of which this repository's CI has yet. What is tested is the generator (`scripts/flatpak-manifest.test.mjs`): it fills the placeholders correctly, keeps the sandbox defaults, and refuses candidates and missing checksums. Details that a first real build may correct: the path of the payload inside the `.deb` (`./opt/Paranoia`), the Electron base-app version, and AppStream validation (`flatpak run org.freedesktop.appstream-glib validate`).
