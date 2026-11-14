# Ready-made signatures

Paranoia ships signature packs for the standard libraries that programs link into
every binary, so a fresh file gets `__scrt_common_main_seh`, `std::thread::spawn`
or `malloc` from the start instead of `sub_140001234`. The packs are FLIRT-style
`.pat` files (the same format `paranoia sigapply` and the built-in matcher use)
that are generated from public toolchains and embedded in the engine at compile
time.

| Pack | File | Size | Signatures | Built from | Applies to |
| --- | --- | --: | --: | --- | --- |
| Microsoft C/C++ runtime | `sigs/msvc_x64.pat` | 659 KB | 4 664 | MSVC 14.44.35207 (`libcmt`, `libvcruntime`, `libucrt`) | x86-64 PE images linked against the static CRT (`/MT`) |
| Rust standard library | `sigs/rust_std_x64.pat` | 75 KB | 580 | rustc 1.94.1, target `x86_64-unknown-linux-musl` | x86-64 ELF images built with that rustc |
| musl libc | `sigs/musl_x64.pat` | 95 KB | 1 023 | musl 1.2.5 in the musl.cc `x86_64-linux-musl` cross toolchain | x86-64 ELF images statically linked against that toolchain's `libc.a` |

Total: 848 257 bytes. `sigs/manifest.json` records the exact versions, sources,
SHA-256 sums, signature counts and the measurements below for every pack.

Go is deliberately absent: Go binaries carry the runtime's function table
(`pclntab`), which survives stripping, so Paranoia already names every Go function
without a pack (see [Go](#go-no-signature-pack-needed)).

## How the packs are used

`Binary::analyze` applies every embedded pack whose format and architecture match
the loaded image, after recursive-descent analysis:

* matching happens only for functions that have no user annotation, no symbol and
  no import thunk, exactly like a `.pat` file applied by hand;
* a recognised function is reported with `library: true` in `paranoia functions`,
  named in the disassembly/overview and shown as a library function in the UI;
* a user annotation always wins: the packs only fill in functions that have no
  annotation, no symbol and no import thunk, exactly like a `.pat` file applied by
  hand;
* when two packs match the same function the first one in pack order keeps the
  name, and ambiguous matches are dropped by the matcher as usual.

The packs are embedded in every backend, including `paranoia.wasm`, so the browser
build recognises the same libraries as the CLI and the desktop app.

For signatures that are not built in, `paranoia sigmake` writes a `.pat` from any
binary with symbols and `paranoia sigapply <binary> <file.pat>` matches one
against a file. The engine API exposes the same through `makePat` and `applyPat`.

## Measured recognition

The numbers come from `node scripts/build-sigpack.mjs`, which the
[sigpacks workflow](../.github/workflows/sigpacks.yml) re-runs on every change to
the packs, the generator or the matcher. Each pack is applied to programs that
were **not** used to build it, then the applied names are compared with the names
those programs carry themselves (PDB for MSVC, the ELF symbol table for Rust and
musl, read from an unstripped twin of the analysed binary).

Terms used in the table:

* **named**: functions that the test binary itself names and that analysis finds
  in the analysed (stripped or PDB-less) image.
* **relevant**: the subset of those that the pack is supposed to know — the
  functions the PDB marks as runtime-library functions (MSVC), or functions whose
  name occurs in the pack (Rust and musl). User code is not part of the
  denominator.
* **recall**: correctly named / relevant.
* **precision**: (correct + collisions) / matched. A *collision* is a function
  whose bytes are identical to another library function (linker ICF folding), so
  the applied name is one of several legitimate names; a *wrong* name is a match
  where no such twin exists.
* **coverage**: relevant / named — how much of the test binary's named code the
  pack even attempts to name.

| Pack | Test program | named | relevant | matched | correct | wrong | collisions | recall | precision |
| --- | --- | --: | --: | --: | --: | --: | --: | --: | --: |
| MSVC CRT | `verify1.exe` — C, `/O1 /MT` | 570 | 568 | 307 | 305 | 1 | 1 | 53.7 % | 99.7 % |
| MSVC CRT | `verify2.exe` — C++/STL, `/O2 /MT` | 911 | 790 | 412 | 411 | 0 | 1 | 52.0 % | 100 % |
| MSVC CRT | `verify3.exe` — minimal hello, `/O2 /MT` | 499 | 497 | 275 | 274 | 0 | 1 | 55.1 % | 100 % |
| Rust std | Rust program 1, stripped | 791 | 470 | 394 | 391 | 3 | 0 | 83.2 % | 99.2 % |
| Rust std | Rust program 2, stripped | 699 | 436 | 378 | 376 | 2 | 0 | 86.2 % | 99.5 % |
| musl libc | C program 1, static musl, stripped | 70 | 51 | 45 | 45 | 0 | 0 | 88.2 % | 100 % |
| musl libc | C program 2, static musl, stripped | 66 | 47 | 44 | 44 | 0 | 0 | 93.6 % | 100 % |

Aggregated by pack: MSVC CRT 53.4 % recall / 99.9 % precision, Rust std
84.7 % / 99.4 %, musl 90.8 % / 100 %. Coverage (relevant / named) is 87–99.6 % for
the MSVC programs, 59–62 % for the Rust programs and 71–73 % for the musl
programs; the missing part is the test program's own code plus, for the C++
program, the STL functions the pack does not cover. The MSVC number is lower than
the others because the static CRT is mostly made of tiny forwarder thunks and leaf
helpers that the `.pat` format cannot represent (see [Limits](#limits)).

### Microsoft C/C++ runtime (x86-64, static `/MT`)

Built by compiling a small C program with the MSVC static CRT and linking the
three runtime archives whole-archive (`/WHOLEARCHIVE:libcmt.lib`,
`libvcruntime.lib`, `libucrt.lib`) with `/DEBUG`, so the PDB names every function.
The pack also contains the UCRT header-inline wrappers (`printf`, `snprintf`,
`_vfprintf_l`, …) that the compiler emits into the *user's* translation unit rather
than the library; these are taken from a second, unfiltered `sigmake` pass.

* Tied to the MSVC version recorded in `sigs/manifest.json` (14.44 = VS 2022
  17.14). A different MSVC release compiles the same sources differently and
  lowers recall; regenerate with `node scripts/build-sigpack.mjs msvc`.
* `/MD` binaries import the CRT from `vcruntime140.dll`/`ucrtbase.dll` and do not
  contain the static code, so the pack does not apply.
* The C++ standard library (`libcpmt`) is not covered yet; a C++ program's STL
  functions stay numbered unless the C++ runtime objects happen to be matched.
* 32-bit x86 is not covered.
* The lowest recall of the three packs is structural: much of the static CRT is
  5-byte forwarders (`malloc` → `_malloc_base`), `__declspec(noinline)` inline
  helpers and dispatch thunks that are shorter than the 32-byte pattern or have
  too few fixed bytes to sign. They are left unnamed by design.

### Rust standard library (x86-64 ELF)

Built from an optimised Rust program that exercises `String`, `Vec`, `HashMap`,
`BTreeMap`, `VecDeque`, formatting, `fs`, `io`, threads and channels; every std
monomorphisation linked into it is captured. The sample is built for
`x86_64-unknown-linux-musl` so the pack is also usable on machines without a
glibc sysroot, and it includes the musl libc bundled with the Rust target.

* Tied to the rustc version in the manifest: Rust does not guarantee a stable
  internal ABI, so std machine code changes between releases. Regenerate with
  `node scripts/build-sigpack.mjs rust`.
* Generic monomorphisations that compile to identical bytes are ambiguous; the
  matcher drops ambiguous matches rather than guessing, which is why recall tops
  out in the mid-80s rather than 100 %.
* Windows and macOS Rust targets are not covered yet (the pack is ELF-only); the
  gate checks format *and* architecture, so a Mach-O binary is never renamed as if
  it were a Linux one.

### musl libc (x86-64, static)

Built from the `libc.a` that ships inside the pinned
[musl.cc](https://musl.cc) `x86_64-linux-musl` cross toolchain (musl 1.2.5,
gcc 11.2.1), linked whole-archive into a single ELF. The tarball is pinned by
SHA-256 in `scripts/build-sigpack.mjs`; a changed upstream tarball fails the build
with an explicit "re-pin" message instead of silently changing the signatures.

* Only binaries statically linked against that toolchain's `libc.a` match. Alpine,
  a distribution's `libc.so`, or a musl built with another compiler produce
  different machine code.
* Static musl binaries built by musl.cc toolchains are common for containers,
  recovery tools and cross-compiled utilities; those are the target audience.
* In a stripped musl binary the analysis can only discover functions reachable
  from the entry point plus the ones in the unwind tables — the `named` column
  (70 and 66 functions) is small for that reason, not because the pack is small.

### Go: no signature pack needed

Go embeds the runtime's function table (`.gopclntab`/`__gopclntab`) in every
binary, including stripped ones, and Paranoia's loader reads it directly
(`loader::gopclntab`, names and entry/end bounds). Measured with Go 1.23.4 on a
`-ldflags="-s -w"` build:

* 1 825 functions discovered, **1 806 named** (99.0 %) from the pclntab;
* `main.main`, `main.fib` and the `runtime.*`/`internal/*` functions all carry
  their Go names.

A `.pat` pack would be strictly worse: it could only name functions whose byte
patterns matched one sample build, whereas the pclntab names everything,
including the user's own functions. The only unmatched entries are synthetic
table entries (`go:buildid`) and Go's own generated code that has no pclntab
record. The check is part of `scripts/build-sigpack.mjs go` and runs in CI.

## Limits

* **The `.pat` format signs the first 32 bytes plus one CRC run.** Functions
  shorter than 16 bytes, or with fewer than 24 fixed bytes in that window
  (5-byte jump thunks, heavily relocatable dispatch stubs), cannot be represented.
  This is the main reason MSVC CRT recall is about half of the library functions
  present in a `/MT` binary.
* **Ambiguity is dropped, not guessed.** If two different names match the same
  bytes, Paranoia leaves the function unnamed. This keeps the wrong-name rate at
  0.1–0.8 % instead of trading it for a few more names.
* **Identical-code folding.** When the linker folds two functions with different
  names into one address, the surviving function can receive a twin's name; the
  measurement counts these separately as *collisions*, not as errors.
* **Toolchain-specific.** Each pack matches the exact compiler and library
  versions in `sigs/manifest.json`. That is inherent: two builds of the same
  source with different flags are different machine code.
* **Only functions the analysis finds can be named.** Stripped static binaries
  without unwind information hide unreferenced leaf functions; the pack is
  applied to what recursive descent discovered.

## Rebuilding

```bash
cargo build --release -p paranoia-cli
node scripts/build-sigpack.mjs              # everything this host can build
node scripts/build-sigpack.mjs msvc         # one pack: msvc, rust, musl or go
node scripts/build-sigpack.mjs --check      # measure the committed packs
```

The script compiles the sample and verification programs, runs
`paranoia sigmake`, merges the packs, writes `sigs/*.pat` plus
`sigs/manifest.json`, and measures the result. On Windows the musl pack is built
inside WSL; on Linux it uses `bash` directly. Requirements per pack are printed by
the script's header comment.

`.github/workflows/sigpacks.yml` re-runs the generator and `--check` on Windows
(MSVC pack) and Ubuntu (Rust and musl packs) whenever the packs, the generator,
the matcher or the manifest change, and fails when the committed packs no longer
meet the documented recall/precision thresholds. That is the signal to regenerate
the packs after a compiler update.
