# Case studies: three real binaries, taken apart with Paranoia

This page is three worked examples of the everyday reverse-engineering loop with
the command-line build of Paranoia: build or download a real sample, open it,
see what the analysis recovered on its own, read one function, and write down what
that does and does not prove. Every command and every output excerpt below comes
from a run recorded while this page was written; `…` marks lines that were cut,
and timings are from one run (they change between runs).

These are **demos, not audits**. They show a workflow and its rough edges; they do
not measure the tool. The measured baseline is [BENCHMARK.md](BENCHMARK.md)
(decompiler against Ghidra on 13 binaries, including the failures), the signature
numbers are in [SIGNATURES.md](SIGNATURES.md), the function-memory accuracy in
[FUNCTION-MEMORY.md](FUNCTION-MEMORY.md), and the agent interface in
[MCP.md](MCP.md). If you want to know whether the decompiler holds up on code it
was not written for, read the benchmark, not this page.

What the studies do establish, because you can re-run them:

1. a stripped Go program keeps all of its function names — the names are in the
   file, not in a symbol table;
2. a plain MSVC `/MT` program gets its static CRT named with no setup, while its
   own `main` stays `sub_…` (as it should);
3. a one-patch version diff of a real program narrows the change to four
   functions, and the pseudocode of those functions shows the shape of the fix.

All samples are open-source release artifacts or were built locally from a
toolchain on this machine. Nothing came from an untrusted source, nothing is
malware, and **no analysed program was executed** — Paranoia only parsed the
files.

## How this was run

| Item | Value |
| --- | --- |
| Paranoia | 0.8.0, release build of the working tree (includes the in-tree signature packs; it is not the tagged 0.8.0 binary) |
| CLI binary | `target/release/paranoia.exe`, SHA-256 `5a975e95627021684c549497889de9d67888755e9d87ed4736e2c519cadd82d1` |
| Host | Windows 11 (x64), PowerShell 7, `TEMP`/`TMP` redirected to `D:\temp` because the system drive was nearly full |
| Scratch directory | `D:\temp\cases` (outside the repository — no downloaded binary is committed) |
| Tools used to build samples | Go 1.23.4 (`D:\goland\bin\go.exe`), MSVC Build Tools 2022 (cl 19.44.35219, linker 14.44.35219.0) |

The release build was used as-is; no compiler or engine code was changed for
these runs. Where a number matters it is quoted from the tool output, not
recomputed.

---

## 1. A stripped Go binary: the names are in the file

### The sample

A locally built, stripped `gofmt` — the Go 1.23.4 source tree was already on the
machine. The benchmark corpus builds the same file; this build is byte-identical
to the corpus manifest entry `gofmt_go123_amd64v1_stripped.exe`, which is a useful
sanity check on the recipe:

```powershell
$env:TEMP='D:\temp'; $env:TMP='D:\temp'
Push-Location D:\goland\src
$env:GOAMD64='v1'
& D:\goland\bin\go.exe build -trimpath -ldflags "-s -w" -o D:\temp\cases\gofmt-stripped.exe cmd/gofmt
Pop-Location
Get-FileHash D:\temp\cases\gofmt-stripped.exe -Algorithm SHA256
```

- Provenance: `go1.23.4 windows/amd64`, `GOAMD64=v1`, `-trimpath -ldflags "-s -w"`,
  working directory `$GOROOT/src` (`D:\goland\src`).
- SHA-256: `e7019df5c7faf657e55dd82c3d5f44e34f5ac18ed26bae067ba7e3fc7e19ef72`,
  size 2 978 304 bytes — the same hash as the benchmark corpus file, so the
  published benchmark's stripped-Go numbers apply to this exact binary (its
  per-binary row lists the same 3 284 functions and 100 % decompilation coverage
  on the sampled functions).

`-s -w` removes the symbol table and DWARF. There is no PDB, and the PE
`.symtab` section is an empty 4-byte stub — `info` reports `symbols 0`:

```powershell
paranoia info D:\temp\cases\gofmt-stripped.exe
```

```
gofmt-stripped.exe  (2978304 bytes)
  format       PE 64-bit, Executable
  arch         x86-64 (Little-endian)
  entry        0x473c00
  image base   0x400000
  entropy      6.080
  sha256       e7019df5c7faf657e55dd82c3d5f44e34f5ac18ed26bae067ba7e3fc7e19ef72
  …
  sections 8 | imports 48 | exports 0 | libraries 1 | symbols 0
  …
  Go function table    3255 functions (466 new, 3255 names added)
```

Two lines matter. `symbols 0` says the file has no symbol table, and the last line
says the Go runtime's function table (`pclntab`) was found and used: 3 255
functions were named from it, and 466 of them were function starts the normal
entry-point/`.pdata` analysis had not discovered. The table is part of the Go
runtime and survives `-s -w`; that is why the names are free.

### What the tool recovered

```powershell
paranoia functions D:\temp\cases\gofmt-stripped.exe
```

```
0x0000000000401000       1 insn    1 blk    0 xref  go:buildid
0x0000000000401080      27 insn    5 blk    0 xref  internal/abi.Kind.String
0x00000000004010e0       3 insn    1 blk    1 xref  internal/abi.(*Type).Kind
  …
0x00000000005432c0      22 insn    3 blk    1 xref  main.usage
0x0000000000543320      49 insn   14 blk    2 xref  main.isGoFile
0x0000000000544840      70 insn    9 blk    1 xref  main.main
0x0000000000549a00      19 insn    3 blk    2 xref  main.simplify
  …
3284 functions, 53586 blocks, 287802 instructions, 9246 strings, 77798 xrefs in 126 ms
```

The last line is written to stderr, so it does not pollute piping or JSON output.
Counting the JSON form gives the breakdown: **3 284 functions; 3 255 carry a Go
name; 29 do not and are labelled `sub_…`.** Those 29 (0x472ba9–0x47301a) sit
inside the named `runtime.duffzero` (0x472b60) and `runtime.duffcopy` (0x472ce0)
helpers: they are the size-specific entry points the Go compiler calls *into the
middle* of those helpers, so the table has no separate name for them. They are
runtime code, not missed user functions — compare with the benchmark's Go row,
which recovers every ground-truth function in the pclntab.

### One real function, decompiled

`main.simplify` is 19 instructions and its source is known. Disassembly:

```powershell
paranoia disasm -a main.simplify -n 22 D:\temp\cases\gofmt-stripped.exe
```

```
main.simplify:
  0x000000549a00  493b6610                 cmp      rsp, [r14+0x10]
  0x000000549a04  7637                     jbe      loc_549A3D
loc_549A06:
  0x000000549a06  55                       push     rbp
  0x000000549a07  4889e5                   mov      rbp, rsp
  0x000000549a0a  4883ec20                 sub      rsp, 0x20
  0x000000549a0e  4889442430               mov      [rsp+0x30], rax
  0x000000549a13  e848000000               call     main.removeEmptyDeclGroups
  0x000000549a18  488d0579240800           lea      rax, [off_5CBE98]
  0x000000549a1f  488d1dba711c00           lea      rbx, [unk_710BE0]
  0x000000549a26  488d0d732a0800           lea      rcx, [off_5CC4A0]
  0x000000549a2d  488b7c2430               mov      rdi, [rsp+0x30]
  0x000000549a32  e8690df9ff               call     go/ast.Walk
  0x000000549a37  4883c420                 add      rsp, 0x20
  0x000000549a3b  5d                       pop      rbp
  0x000000549a3c  c3                       ret
```

Pseudocode:

```powershell
paranoia pseudo D:\temp\cases\gofmt-stripped.exe main.simplify
```

```c
__int64 __fastcall main.simplify()
{
    __int64 var_30;
    __int64 var_8;
    __int64 v1; // r14
    __int64 v2; // rax
    __int64 v3; // rdi
    __int64 v4; // rax

    if ((unsigned)rsp > *(uint64_t *)(v1 + 0x10)) {
        var_30 = v2;
        main.removeEmptyDeclGroups();
        v3 = var_30;
        v2 = go/ast.Walk(&off_5CC4A0);
        return v2;
    }
    var_8 = v2;
    runtime.morestack_noctxt();
    v4 = var_8;
    goto main.simplify;
}
```

The Go 1.23 source of the same function, from the local GOROOT:

```go
func simplify(f *ast.File) {
	// remove empty declarations such as "const ()", etc
	removeEmptyDeclGroups(f)

	var s simplifier
	ast.Walk(s, f)
}
```

The two calls are recovered with their real names and in the right order, and the
three `lea` loads before `go/ast.Walk` are what Go's register ABI passes for
`ast.Walk(s, f)`: the `simplifier` value (two words) and the node interface's type
word; `f` itself is the `mov rdi`. What the C view cannot give you is the Go
calling convention: `f` arrives in a register and is shown as `var_30`, not as a
parameter, so the signature `__int64 __fastcall main.simplify()` is a lie of
convenience. The stack-growth check at the top (`cmp rsp, [r14+0x10]`) is shown as
a conditional expression over `rsp`; a reader has to recognise it as Go's
`morestack` prologue. Neither the `simplifier` visitor interface nor the
`f *ast.File` type is reconstructed in the pseudocode.

The same function is also available as JSON for a script or an agent, one object
per run (`paranoia query` is documented in [QUERY.md](QUERY.md)):

```powershell
paranoia query D:\temp\cases\gofmt-stripped.exe function main.simplify
```

```
{"file":{"arch":"x86_64","bits":64,"entry":"0x473c00","format":"pe","name":"gofmt-stripped.exe","sha256":"e7019df5…"},"format":"paranoia-query/1","result":{"address":"0x549a00","assembly":"main.simplify:\n0x549a00  cmp      rsp, [r14+0x10]\n…","name":"main.simplify","pseudocode":"__int64 __fastcall main.simplify()\n…","size":78}}
```

### What this shows / what it does not

- **Shows:** function discovery and naming need nothing but the file. 3 255 of
  3 284 functions carry their real Go names, including `main.main`,
  `main.gofmtMain`, `internal/abi.Kind.String` and runtime helpers. No
  signatures, PDB or symbol server are involved.
- **Does not show:** Go source recovery. There is no Go ABI model, no slice/string
  or interface typing, no goroutine or channel semantics, and closures are
  separate `funcN` entries with no link back to the function that created them.
  Type and struct work, inlining decisions and any "is this actually what the
  source said" question still need the source, Ghidra/IDA, or a human who knows
  Go.
- It also does not prove that *every* Go binary works: this sample's `pclntab` is
  the format Go 1.23 emits and the loader is tested against it. A newer Go release
  that changes the table format, or a packer that strips/encrypts it, leaves the
  same functions unnamed. That is not hypothetical: during this work the same
  build was also pointed at fzf 0.75.0 (`fzf.exe` SHA-256 `5708f0b7…`, official
  GitHub release, compiled with Go 1.27.3). `paranoia info` printed **no** Go
  function-table line for it, and the listing was 4 802 functions, 4 801 of them
  `sub_…` — none carried a Go name. The older fzf releases in study 3 are Go
  1.20.4 and are named normally. Whatever Go 1.27.3 changed, the Go-table reader
  is format-specific and has to be maintained as Go changes.

### Reproduce it

```powershell
$env:TEMP='D:\temp'; $env:TMP='D:\temp'
# Go 1.23.4 is at D:\goland\bin\go.exe on this machine; use your own GOROOT.
Push-Location D:\goland\src; $env:GOAMD64='v1'
go build -trimpath -ldflags "-s -w" -o D:\temp\cases\gofmt-stripped.exe cmd/gofmt
Pop-Location
# expect SHA-256 e7019df5c7faf657e55dd82c3d5f44e34f5ac18ed26bae067ba7e3fc7e19ef72
paranoia info      D:\temp\cases\gofmt-stripped.exe
paranoia functions D:\temp\cases\gofmt-stripped.exe --json
paranoia disasm -a main.simplify -n 22 D:\temp\cases\gofmt-stripped.exe
paranoia pseudo D:\temp\cases\gofmt-stripped.exe main.simplify
paranoia query  D:\temp\cases\gofmt-stripped.exe function main.simplify
```

### Using an agent

The agent does not need the desktop app. With `--root D:\temp\cases`,
`paranoia mcp` exposes `triage`, `list_functions`, `decompile`, `callees` and
`xrefs_to` as MCP tools (read-only by default, [MCP.md](MCP.md)); with
`paranoia query` any script can ask one question per process and get one JSON
object, as above. For this sample that means an agent can pull the function list,
see that the binary is Go with names attached, ask for `main.simplify`, and read
the two named calls — without any of the engine being part of the model's
context. What it cannot do is know that `var_30` is `f *ast.File`; the agent will
guess, so its explanation needs checking.

---

## 2. MSVC static CRT: library names with no setup

### The sample

A program small enough to fit in one screen, compiled with the static CRT
(`/MT`) and optimised, so the runtime libraries are linked into the executable:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

int main(void)
{
    char *buf = malloc(64);
    if (!buf) {
        return 1;
    }
    strcpy(buf, "hello from the static CRT");
    printf("%s: fib(10) = %d, strlen = %zu\n", buf, fib(10), strlen(buf));
    free(buf);
    return 0;
}
```

Build (one `cmd` invocation, because `vcvars64.bat` has to run in the same shell
as `cl`):

```powershell
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul && cl /nologo /O2 /MT hello.c'
```

- Compiler: `Microsoft (R) C/C++ Optimizing Compiler Version 19.44.35219 for x64`
  (MSVC 14.44), linker `14.44.35219.0`; the built-in pack was generated from
  MSVC 14.44.35207, so this is the same toolset family, a slightly newer patch
  build.
- The executable analysed here: `hello.exe`, 140 800 bytes, SHA-256
  `8e23e449797dca4f4841261590f04fe5b6a8b693533d5c0d318448830de4bb5d`. MSVC output
  is not bit-reproducible without `/Brepro` (the PE timestamp moves), so the hash
  identifies this build; a rebuild is a different but equivalent sample.

There is no PDB, no COFF symbol table and no import of the CRT:

```powershell
paranoia info D:\temp\cases\msvc\hello.exe
```

```
hello.exe  (140800 bytes)
  format       PE 64-bit, Executable
  arch         x86-64 (Little-endian)
  entry        0x140001394
  image base   0x140000000
  entropy      6.168
  sha256       8e23e449797dca4f4841261590f04fe5b6a8b693533d5c0d318448830de4bb5d
  …
  sections 6 | imports 76 | exports 0 | libraries 1 | symbols 0
```

### What the tool recovered

```powershell
paranoia functions D:\temp\cases\msvc\hello.exe
```

```
0x0000000140001050      35 insn    3 blk    1 xref  sub_140001050
0x00000001400010e0      25 insn    1 blk    1 xref  printf
0x0000000140001218      98 insn   21 blk    2 xref  __scrt_common_main_seh
0x00000001400015e8      39 insn    3 blk    2 xref  __security_init_cookie
0x0000000140008290      19 insn    5 blk  151 xref  _free_base
0x0000000140008f50      29 insn    8 blk   15 xref  _malloc_base
0x00000001400157a0      57 insn   22 blk    2 xref  strlen
  …
500 functions, 5104 blocks, 22627 instructions, 748 strings, 5879 xrefs in 18 ms
```

The JSON form breaks the 500 functions down as: **275 carry a library name from
the built-in MSVC pack** (`"library": true`), 219 are `sub_…`, 1 is the entry
point `start`, 5 are import jump thunks (`j_FlsAlloc`, `j_InitializeCriticalSectionEx`, …).
That is 55 % of the listing named as runtime code with zero configuration. Compare
with [SIGNATURES.md](SIGNATURES.md): the pack's measured recall is about 53 % of
the runtime functions *relevant* to it, and the two numbers land in the same
place on different denominators.

The pack names the startup layer (`__scrt_common_main_seh`,
`__security_init_cookie`, …), the UCRT header wrappers the compiler emits into the
user's translation unit (`printf` at 0x1400010e0), and the internal
implementations (`_malloc_base`, `_free_base`, `strlen`). It does **not** name
the user's `main` — that is by design; the packs only fill functions without a
symbol, annotation or thunk, and the user's code has none.

### One function, decompiled

Cross-reference `printf` to find the caller (`main`, inlined `fib` and all):

```powershell
paranoia xrefs D:\temp\cases\msvc\hello.exe printf
```

```
0x00000001400010c4  Call sub_140001050
```

```powershell
paranoia pseudo D:\temp\cases\msvc\hello.exe sub_140001050
```

```c
__int64 __fastcall sub_140001050()
{
    __int64 v1; // rax
    __int64 v2; // rbx
    __int64 v3; // rcx
    int v4; // eax
    __int64 v5; // r8
    __int64 v6; // rdx
    __int64 v7; // rdx

    v1 = sub_140006750(0x40);
    v2 = v1;
    if (v1 == 0) {
        return 1;
    }
    __asm { movups xmm0, "hello from the static CRT" }
    v3 = v2;
    __asm { movups *(__m128 *)rax, xmm0 }
    __asm { movsd xmm0, qword_140016340 }
    __asm { movsd *(uint64_t *)(rax + 0x10), xmm0 }
    v4 = (uint32_t)word_140016348;
    *(uint16_t *)(v2 + 0x18) = LOWORD(v4);
    v5 = sub_140001010(9, v6, v5, strlen(v3));
    v5 += sub_140001010(8, v6, v5);
    v7 = v2;
    printf("%s: fib(10) = %d, strlen = %zu\n");
    sub_140006740(v2);
    return 0;
}
```

The call names are the win: `strlen` is called with the buffer, `printf` gets the
format string and the function ends with a matching free. The disassembly also
shows the API prototype database working (`; size_t strlen(const char *s)`,
`; int printf(const char *format, ...)`). Two honest gaps are visible at the same
time:

- `malloc` and `free` were not named: the compiler emitted 5-byte forwarders
  (`jmp _malloc_base`, `jmp _free_base`) and the `.pat` format cannot sign
  functions that short — exactly the limit documented in
  [SIGNATURES.md](SIGNATURES.md). The targets *are* named:

  ```
  sub_140006750:
    0x000140006750  e9fb270000               jmp      _malloc_base
  sub_140006740:
    0x000140006740  e94b1b0000               jmp      _free_base
  ```

- The compiler's SIMD copy of the string literal is presented as `__asm` blocks
  instead of a C string assignment. The format string in `printf` is recovered;
  the `movups` copy is not folded back into `strcpy`. A human reads it fine, but
  the C is not something you could recompile as-is.

**Before/after?** There is no CLI switch or environment variable that turns the
built-in packs off in this build: `Binary::analyze` calls `apply_builtin_signatures`
unconditionally (`crates/paranoia-core/src/lib.rs:456` → `crates/paranoia-core/src/sigs.rs:389`).
The closest observable "before" is the `"library": true` flag in the JSON
listing: those 275 functions would be `sub_…` without the pack. This study
therefore shows the named result, not a pack-on/pack-off comparison; the
measurements in [SIGNATURES.md](SIGNATURES.md) are the proper accuracy figures.

A useful applicability check: the same source built with `/MD` (dynamic CRT)
produces 69 functions, of which only 11 are pack-named — and those 11 are all
startup/security glue that is still linked statically (`__scrt_*`,
`__security_init_cookie`, `_onexit`, …). The bulk of the /MT pack has nothing to
name in a /MD binary, because the libc functions are imports there. The pack is
not "the CRT recogniser"; it recognises the static CRT specifically.

### What this shows / what it does not

- **Shows:** a plain MSVC `/MT` build arrives with most of its runtime named,
  calls resolve to import/prototype names, and cross-references work from the
  library function back to the user code. All of it offline, with no PDB.
- **Does not show:** user-code recovery. `main` remains `sub_140001050`; struct
  fields, types and the string-copy idiom are not reconstructed. The pack is
  tied to an MSVC release (14.44 here), does not cover 32-bit x86 or the C++
  standard library, and `/MD` binaries mostly bypass it. For a real audit you
  would load the PDB if you have it and still read the user functions in
  IDA/Ghidra alongside this listing.

### Reproduce it

```powershell
$env:TEMP='D:\temp'; $env:TMP='D:\temp'
New-Item -ItemType Directory -Force D:\temp\cases\msvc | Out-Null
# write hello.c (above) to D:\temp\cases\msvc\hello.c, then:
Set-Location D:\temp\cases\msvc
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul && cl /nologo /O2 /MT hello.c'
Set-Location -
paranoia info      D:\temp\cases\msvc\hello.exe
paranoia functions D:\temp\cases\msvc\hello.exe --json
paranoia xrefs     D:\temp\cases\msvc\hello.exe printf
paranoia pseudo    D:\temp\cases\msvc\hello.exe sub_140001050
```

### Using an agent

`paranoia mcp` gives an agent `list_functions` (with the library flag in the
JSON), `xrefs_to` and `decompile`; a useful agent prompt is "find the user
function that reaches printf, ignore library-marked functions, summarise what it
writes". `triage` is the one-line-per-function view that makes this cheap. The
agent can tell library from user code; it cannot check the C against a PDB it
does not have, so its summary is a lead, not a finding.

---

## 3. Version diff: what did fzf 0.44.1 actually change?

### The samples

Two official Windows builds of [fzf](https://github.com/junegunn/fzf), one patch
release apart, downloaded from the project's GitHub Releases through the local
proxy. They were built with the **same Go version** (1.20.4), which is what makes
this diff readable: most of the binary is identical and only the source change
shows up.

```powershell
$env:TEMP='D:\temp'; $env:TMP='D:\temp'
New-Item -ItemType Directory -Force D:\temp\cases\fzf | Out-Null
Set-Location D:\temp\cases\fzf
curl.exe -sS -L -o fzf-0.44.0-windows_amd64.zip https://github.com/junegunn/fzf/releases/download/0.44.0/fzf-0.44.0-windows_amd64.zip
curl.exe -sS -L -o fzf-0.44.1-windows_amd64.zip https://github.com/junegunn/fzf/releases/download/0.44.1/fzf-0.44.1-windows_amd64.zip
New-Item -ItemType Directory -Force v0.44.0, v0.44.1 | Out-Null
tar.exe -xf fzf-0.44.0-windows_amd64.zip -C v0.44.0   # each zip contains fzf.exe at the root
tar.exe -xf fzf-0.44.1-windows_amd64.zip -C v0.44.1
Set-Location -
```

| Version | Zip SHA-256 | `fzf.exe` SHA-256 | `fzf.exe` size |
| --- | --- | --- | ---: |
| 0.44.0 | `d1c3f874ac712e5ce274d72158ed77f35d957d8425e2c09df36bd10948e1446a` | `b2534a2d2c3651c3a0ce1c3d947dcecbbf836d0666cd6d03dfd3443fdccfe6c8` | 4 176 896 |
| 0.44.1 | `bb8f1d47d9aea2a40b5460ee0399f406ae9081ea4e1cb532593ce5b90b9b620f` | `496f31fe02437c39fc7cb161fd39220733c61fa34ccf50cb0bc46c015a2ba0d0` | 4 177 408 |

Both `.exe` files are stripped Go PE images: `symbols 0`, but each carries a Go
function table (3 564 functions named from it, 3 600 in the listing including
import thunks). The `info` output for both is otherwise almost identical — same
entry point `0x4669c0`, same imphash `f0ea7b7844bbc5bfa9bb32efdcea957c`, same
six sections and 40 imports.

```powershell
paranoia diff -n 4 D:\temp\cases\fzf\v0.44.0\fzf.exe D:\temp\cases\fzf\v0.44.1\fzf.exe
```

```
fzf.exe  3600 functions
fzf.exe  3600 functions

matched 3600 (3596 identical, 4 changed), removed 0, added 0, similarity 100.0%
by pass: name 3481, exact 93, callgraph 24, fuzzy 2

changed (least similar first)
   75.7%  0x00005c22e0 0x00005c2320  name       github.com/junegunn/fzf/src.(*Terminal).Loop.func7.1
   89.8%  0x00005c0740 0x00005c0780  name       github.com/junegunn/fzf/src.(*Terminal).Loop.func7
   95.4%  0x00005c0520 0x00005c0540  name       github.com/junegunn/fzf/src.(*Terminal).Loop.func8
   99.9%  0x00005ba020 0x00005ba020  name       github.com/junegunn/fzf/src.(*Terminal).Loop.func18
```

Read it as: 3 596 of 3 600 functions are byte-identical after masking addresses,
4 changed, none added or removed. The "similarity 100.0%" is the average
fingerprint score rounded to one decimal; it hides those four, which is why the
changed list matters more than the headline. The changed functions are all
closures defined inside `(*Terminal).Loop` — the event loop. No application
function *outside* the loop changed.

For comparison, the 0.44.0 section of the upstream changelog is a long list
(Sixel/iTerm2 preview, `--listen` hardening) while 0.44.1 says exactly one thing:
"Fixed crash when preview window is hidden on `focus` event." The diff is
consistent with a small fix in the event loop.

### The change, side by side

Decompile the least-similar function in both versions, and diff the two
pseudocode outputs (this is a text diff of Paranoia's own output, not a diff
feature of the tool):

```powershell
$old='D:\temp\cases\fzf\v0.44.0\fzf.exe'; $new='D:\temp\cases\fzf\v0.44.1\fzf.exe'
$f='github.com/junegunn/fzf/src.(*Terminal).Loop.func7.1'
paranoia pseudo $old $f > old.c
paranoia pseudo $new $f > new.c
git diff --no-index -- old.c new.c
```

The meaningful part, trimmed (the rest of the diff is register renaming, stack
offsets and label addresses):

```diff
-        var_20 = *(uint64_t *)(v5 + 0x18);
-        v6 = *(uint64_t *)(v5 + 0x20);
+        var_28 = *(uint64_t *)(v5 + 0x18);
+        v6 = *(uint64_t *)(v5 + 0x28);
         var_18 = v6;
-        v7 = *(uint64_t *)(v5 + 0x10);
-        var_28 = v7;
+        v7 = *(uint64_t *)(v5 + 0x20);
+        var_20 = v7;
+        var_30 = *(uint64_t *)(v5 + 0x10);
         v5 = *(uint64_t *)(v5 + 8);
-        var_30 = v5;
+        var_38 = v5;
```

and the function's stack frame grows from `rsp - 0xc0` in 0.44.0 to `rsp - 0xe8`
in 0.44.1, because the request values are copied into more locals.

That is what the tool can say on its own: *the structure read here got bigger —
one more word is read from it, the fields after that one moved, and the code
around it was rebuilt for the new layout.* It cannot label the new field. For the
label we went outside Paranoia: the project's own changelog and the tag-diff of
`src/terminal.go` between the two releases show the fix.

```diff
 type previewRequest struct {
 	template     string
+	pwindow      tui.Window
 	pwindowSize  tui.TermSize
 	scrollOffset int
 	list         []*Item
```

`previewRequest` is the structure the loop's preview closures copy around, and
the goroutine now uses a window captured when the request was enqueued
(`pwindow = request.pwindow`) instead of reading `t.pwindow` later — which is the
use-after-hide that crashed on `focus`. The new field is a two-word interface
value; the extra word the pseudocode reads from the structure and the larger
frame are that change in machine form, but only the source tells you which field
it is. This correlation is the honest workflow: Paranoia localised the change and
showed its shape; the meaning came from the release notes and the source.

### A "changed" entry is not automatically a behaviour change

The 99.9 %-similar `func18` is instructive. Its pseudocode diff is only this:

```diff
-    v1 = rsp - 0x728;
+    v1 = rsp - 0x738;
  …
-            return *(uint64_t *)(&off_66B2E0 + (v1 * 8))(v8, v5, v12, v13);
+            return *(uint64_t *)(&off_66C320 + (v1 * 8))(v8, v5, v12, v13);
```

The stack frame grew by 16 bytes (the pseudocode's `var_…` names shift with it)
and a jump-table base address moved; there is no change in the decompiled logic.
That is a layout change, not a logic change. Reading the changed list as "four
functions were modified" is correct at the byte level; reading it as "four
behaviour changes" is not. Always open the pair before writing a sentence about
what a patch fixed.

### When the diff is mostly the toolchain

The two releases above were built with the same Go version, which is why the
table is clean. That is not the normal case. On fzf **0.46.0 vs 0.46.1** (both
official releases, nine days apart — `fzf.exe` SHA-256 `dcb07f87…` and
`f2a5e000…`) the same command gives:

```
matched 3453 (328 identical, 3125 changed), removed 279, added 205, similarity 60.8%
```

Those two binaries were compiled with `go1.21.6` and `go1.20.13` respectively.
Most of the 3 125 "changed" functions are Go runtime and standard-library code
that differs between compilers, not fzf code. On a pair like that, the diff tells
you how the programs were *built* before it tells you what the source change was;
if the question is "what did this patch fix", pick versions with the same
toolchain (or diff the source). For binaries with no useful names at all (for
example two Rust/MSVC release builds whose PE images carry no COFF symbols), the
matcher falls back to code similarity and the changed table becomes much harder to
trust — the same command on ripgrep 15.1.0 vs 15.2.0 (official GitHub release
assets, `rg.exe` SHA-256 `decdd499…` and `14231169…`) reports 964 matched (195
identical, 769 changed), 406 removed, 271 added, 26.3 % similarity, and several of
the largest entries hit the analyzer's 60 000-instruction per-function limit.
Without a symbol source, a human would confirm each candidate in Ghidra/IDA.

### What this shows / what it does not

- **Shows:** the diff gives an exact, named shortlist (4 functions out of 3 600)
  and the pseudocode diff shows the structural footprint of the change. Combined
  with the release notes, this is a real "what did the patch do" answer in
  minutes, offline.
- **Does not show:** intent. Paranoia cannot tell you what the new field is; that
  needed the source. It also cannot tell you whether the new code is *correct* —
  the fix could still be wrong, and the pseudocode gives no confidence interval.
  And the result depends entirely on the two builds being comparable: same
  compiler, names present, no packing.

### Reproduce it

```powershell
$env:TEMP='D:\temp'; $env:TMP='D:\temp'
# downloads, hashes and extraction: see "The samples" above
paranoia info      D:\temp\cases\fzf\v0.44.0\fzf.exe
paranoia functions D:\temp\cases\fzf\v0.44.0\fzf.exe --json
paranoia diff -n 4 D:\temp\cases\fzf\v0.44.0\fzf.exe D:\temp\cases\fzf\v0.44.1\fzf.exe
$f='github.com/junegunn/fzf/src.(*Terminal).Loop.func7.1'
paranoia pseudo D:\temp\cases\fzf\v0.44.0\fzf.exe $f > old.c
paranoia pseudo D:\temp\cases\fzf\v0.44.1\fzf.exe $f > new.c
git diff --no-index -- old.c new.c
# optional, for the comparison in the previous subsection:
paranoia diff D:\temp\cases\fzf-old\v0.46.0\fzf.exe D:\temp\cases\fzf-old\v0.46.1\fzf.exe
```

`paranoia diff --json` emits the same report as one object (`a`/`b` file records
with SHA-256, `report.matches`, `only_a`, `only_b`, `similarity`) — convenient
for a script. The MCP server offers the same function as `compare_binaries`, so
an agent can ask "what changed between these two files" and get the shortlist
plus both pseudocodes via `decompile`. The agent can then read the release notes
or the source diff, as we did; what it must not do is invent the field name from
the pseudocode alone.

---

## Where a professional still opens IDA/Ghidra

These studies were chosen to be *good* cases for Paranoia. The honest summary of
the gaps that remain, quoting the project's own measured results where they exist:

- **Types and language semantics.** The C view is not C++ and not Go. Classes,
  templates, Rust monomorphisations and Go interfaces are not reconstructed; the
  typed-variable work shown for x86/x64 covers scalars, locals and pointer fields,
  not class hierarchies. [ROADMAP.md](ROADMAP.md) lists C++ decompilation as out
  of scope; AArch64 pseudocode is experimental.
- **Symbol recovery gaps.** The benchmark measures what is missing: GNU COFF
  symbols in Rust PE binaries are not imported (5.6 % named vs Ghidra's 33.8 %),
  and PE32 function discovery finds 380 functions in `comctl32` where Ghidra finds
  1 883. Those are the cases where IDA/Ghidra's loaders still do more of the work.
  See the tables in [BENCHMARK.md](BENCHMARK.md).
- **Hard targets.** Packed/obfuscated binaries, JIT code, cross-architecture
  firmware and raw images are on the roadmap as future work; the decompiler
  covers x86/x64, with AArch64 experimental, and other architectures have
  disassembly and graphs only.
- **Correctness.** Nothing here proves the C is semantically right. The benchmark
  is explicit that coverage means "non-empty C", not "correct C" (threat 6 in
  [BENCHMARK.md](BENCHMARK.md)). A security conclusion needs differential
  execution, source review or a second tool — not just a readable listing.
- **Human judgement.** The fzf study is the pattern for the rest: the tool
  narrows the haystack and shows the shape; the *meaning* came from release notes
  and source. On a target without public source or notes, that last step is where
  an analyst with IDA/Ghidra, debugger and domain knowledge is still required.

What Paranoia contributes in all three studies is the same: an offline, fast,
reproducible first pass whose claims can be checked by re-running a command, with
the output in text and JSON so an agent or a script can consume it.

## Files used and their hashes

Everything below was created under `D:\temp\cases` on the analysis host; none of
it is committed to the repository.

| File | SHA-256 | Provenance |
| --- | --- | --- |
| `paranoia.exe` (analyzer) | `5a975e95627021684c549497889de9d67888755e9d87ed4736e2c519cadd82d1` | `cargo build --release -p paranoia-cli`, working tree 0.8.0 |
| `gofmt-stripped.exe` | `e7019df5c7faf657e55dd82c3d5f44e34f5ac18ed26bae067ba7e3fc7e19ef72` | Go 1.23.4, `GOAMD64=v1 go build -trimpath -ldflags "-s -w"` |
| `hello.exe` (`/MT`) | `8e23e449797dca4f4841261590f04fe5b6a8b693533d5c0d318448830de4bb5d` | MSVC 19.44.35219, `cl /nologo /O2 /MT hello.c` |
| `hello-md.exe` (`/MD`) | `ef2451863f22a24d9de7ac3f2e2a851c6ceb2a4a500990471bfed63b36d7942e` | same compiler, `cl /nologo /O2 /MD hello.c` |
| `fzf-0.44.0-windows_amd64.zip` | `d1c3f874ac712e5ce274d72158ed77f35d957d8425e2c09df36bd10948e1446a` | GitHub Releases, URL in study 3 |
| `fzf-0.44.1-windows_amd64.zip` | `bb8f1d47d9aea2a40b5460ee0399f406ae9081ea4e1cb532593ce5b90b9b620f` | GitHub Releases, URL in study 3 |
| `fzf.exe` 0.44.0 | `b2534a2d2c3651c3a0ce1c3d947dcecbbf836d0666cd6d03dfd3443fdccfe6c8` | extracted from the 0.44.0 zip |
| `fzf.exe` 0.44.1 | `496f31fe02437c39fc7cb161fd39220733c61fa34ccf50cb0bc46c015a2ba0d0` | extracted from the 0.44.1 zip |
| `fzf.exe` 0.46.0 | `dcb07f87c89b4683c9fb621365dfbf5c5472958c10843f20cd85f3ff47e2567e` | official Windows zip, Go 1.21.6; used in "When the diff is mostly the toolchain" |
| `fzf.exe` 0.46.1 | `f2a5e000016d0865fffb88be1de6727c091b4f7a1efe16b7b3348a5444294fc6` | official Windows zip, Go 1.20.13; same comparison |
| `fzf.exe` 0.75.0 | `5708f0b7fa6e8b3e736c8f37596a43ed2514e45dd56737f9663c5cde4f4933c6` | official Windows zip, Go 1.27.3; unnamed in this build (study 1, last bullet) |
| `rg.exe` 15.1.0 | `decdd4992f3f1b9a5ef9898f1b40ab16886d579d6516b4efd3d5eaa19364e408` | official GitHub release `ripgrep-15.1.0-x86_64-pc-windows-msvc.zip`, used in "When the diff is mostly the toolchain" |
| `rg.exe` 15.2.0 | `14231169855ec5205cf5a1b6f1db358ff4aed4247c86b69ce8aae647c77f6680` | official GitHub release `ripgrep-15.2.0-x86_64-pc-windows-msvc.zip`, same comparison |

The benchmark's own corpus manifest lists the same `gofmt` hash under
`gofmt_go123_amd64v1_stripped.exe`; the `-trimpath` build is reproducible, so a
rebuild should match. MSVC builds are not bit-reproducible without `/Brepro`
because of the PE timestamp, so the hash above identifies this particular
analysis file, not a build recipe. SHA-256 of downloaded archives is recorded for
provenance only — Paranoia itself never needs a network connection.
