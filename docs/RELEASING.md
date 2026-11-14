# Releasing

How a Paranoia release is made, what the version numbers promise, and how long a version is supported.

## Versions

Paranoia uses [SemVer](https://semver.org/): `MAJOR.MINOR.PATCH`.

- Before 1.0, a **minor** version (`0.10`, `0.11`) may change behaviour, file formats and command-line flags; the CHANGELOG says what and how to migrate. Knowledge bases and workspaces from older versions are loaded by newer ones; if that ever has to break, the release says so first.
- A **patch** version (`0.10.1`) contains only fixes: crashes and hangs on input, wrong results, security problems, packaging bugs. No new features, no behaviour changes beyond the fix.
- `1.0` is declared when the file formats and the command-line, MCP and query interfaces are stable and we are ready to keep them compatible within a major version. Until then they are documented but may change between minors.

Release numbers are never reused or moved. A bad release is superseded by the next patch version, and the broken release is marked in the CHANGELOG and on its GitHub page; it is not deleted.

## Channels

| | Tag | Meant for |
| --- | --- | --- |
| Release | `v0.10.0` | Everyone. Marked "latest" on GitHub. |
| Release candidate | `v0.10.0-rc.1`, `-rc.2`… | People who want to test it first. Marked pre-release, never "latest". Built and checked exactly like a release. |
| `main` | none | Development. Builds are not published. CI keeps it green, but it has no release notes and no migration guarantees. |

A candidate carries the version it will become: the files say `0.10.0` and the release candidate is only a tag. So a candidate's installer is called `Paranoia-Setup-0.10.0.exe`, the same as the final release's, and the two are different downloads from different releases. Check the release page, not the file name.

## What is supported

Only the **latest release** (and, while one is open, its release candidates) gets fixes, including security fixes. There is one maintainer; supporting older minors as well would mean fixes that nobody has time to test. If you need to stay on an older version, read the CHANGELOG between yours and the current one before upgrading, and see [SECURITY.md](../SECURITY.md) for how vulnerabilities are handled.

Cadence: a minor release when a set of changes is ready and measured, not on a calendar. Patch releases as soon as a fix is verified. Dependency updates (Dependabot) land on `main` continuously and ship with the next release; a security advisory in a dependency we actually use triggers a patch release.

## Making a release

Everything below is checked by `node scripts/release.mjs check` (CI runs it on every push, and on a tag it also checks the tag against the files and the CHANGELOG).

1. **Decide the version.** Patch if the change list is only fixes, otherwise the next minor.
2. **Write the CHANGELOG.** Entries go under `## Unreleased` while you work, under *Added / Changed / Deprecated / Removed / Fixed / Security*. Say what the user sees, not what the code did. Put measured claims next to their measurement.
3. **Bump.** `node scripts/release.mjs bump 0.10.0` sets the version in `Cargo.toml`, `Cargo.lock`, `apps/desktop/package.json` and its lockfile, and turns `Unreleased` into `## 0.10.0 — <today>`. Review `git diff`, run `cargo test --workspace` and `npm test` in `apps/desktop`, commit as `Release 0.10.0`, and push to `main`.
4. **Check the release builds.** Run the *CI* workflow by hand on `main` (Actions → CI → Run workflow). It builds every CLI and desktop package, runs the launch and packaging smoke tests, and stops before publishing.
5. **Release candidate.** Tag the commit `v0.10.0-rc.1` and push the tag. The publish job builds, checksums, signs and attests the files and creates a **pre-release** with notes generated from the CHANGELOG. Install it on each platform you can. A minor release gets at least one candidate; a patch release may skip it when the fix is small and covered by a test.
6. **Fix and repeat** (`-rc.2`) if the candidate has problems. Fixes go to `main` first; the candidate tag is moved only by creating the next one.
7. **Release.** When the candidate holds up, tag **the same commit** `v0.10.0` and push the tag. Same workflow, same checks; the release is marked latest.
8. **Afterwards.** Download the release once and run the verification steps from the notes ([VERIFY.md](VERIFY.md)); update the *Unreleased* section so new work has a place; mention the release wherever it is announced.

If a published release turns out to be broken: do not delete or retag it. Mark it in the CHANGELOG and on its page ("Superseded by 0.10.1: …"), fix on `main`, and release the next patch.

## Why the files are checked

A release that says `0.10.0` in the installer but `0.9.0` in the engine, or that ships without a CHANGELOG entry, is worse than a late release. `scripts/release.mjs` refuses: a version that differs between files, a tag that does not match them, an empty or missing CHANGELOG section, or entries still sitting under *Unreleased* when a final release is tagged.

## Updates for users

The app does not update itself. It can check, when you ask it to, whether a newer release exists (Help → Check for updates); it only reads the public GitHub release list and never downloads or installs anything. Installing is a deliberate step: download the new package, verify it ([VERIFY.md](VERIFY.md)), run it. Silent auto-update stays off until the packages carry platform signatures, because an updater that installs unsigned code on its own would be the weakest link in an otherwise verifiable chain.
