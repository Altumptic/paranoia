# Benchmark: the Paranoia decompiler against Ghidra

This is a reproducible measurement of Paranoia's x86/x86-64 decompiler on real
binaries, compared side by side with Ghidra on the same files, the same machine
and the same metrics. It exists to answer a concrete question: **do the
decompiled listings hold up on code we did not write, and where exactly do they
not?** It is also the project's answer to "AI slop" accusations: every number
here comes from a script in this repository, the raw JSON is committed, the
binaries are identified by SHA-256, and the failures are listed next to the
successes.

Scope and honesty up front:

- This is a **benchmark of the decompiler's output text and symbol handling**,
  not a proof that the C is semantically correct. Coverage below means "the
  decompiler produced non-empty C for the function", not "the C is right".
  Establishing correctness needs differential execution or round-trip
  recompilation, which this benchmark does not do (see Threats to validity).
- The corpus is small and deliberately laptop-sized: **13 binaries** are in the
  published results (34 were built; the rest are listed as skipped for the
  timebox, see [Corpus](#corpus)).
- The Ghidra numbers were produced by actually running Ghidra on the same
  machine; nothing is estimated, copied from other benchmarks or extrapolated.
- Numbers for two tools are only compared where both tools processed the same
  binary with the same sampling rule.

## Headline numbers

| Question | Paranoia 0.8.0 | Ghidra 12.2 |
| --- | ---: | ---: |
| Non-thunk functions found (13 binaries) | 23,085 | 24,789 |
| Functions in the decompile sample | 3,393 functions | 3,411 functions |
| Decompilation coverage of the sample | 100.0 % (0 failures) | 99.4 % (21 failures) |
| Ground-truth function entries found | 89.1 % | 100.0 % |
| Ground-truth entries named correctly | 52.2 % | 66.5 % |
| Call-edge name recall / precision | 75.2 % / 98.0 % | 87.0 % / 92.8 % |
| Decompiler time for the sampled functions | 215.5 s (≈15.7/s) | 205.3 s (≈16.5/s) |
| Auto-analysis time for all 13 binaries | 3.6 s | 22.3 min |
| Total wall time for all 13 binaries | 4.0 min | 37.2 min |

A short reading of these numbers, including where Paranoia loses, is in
[What the numbers say](#what-the-numbers-say).

## Corpus

The harness builds (or copies) the corpus; `bench/corpus/manifest.json` records
every binary's id, SHA-256, size, format/architecture, category, provenance and
the toolchain versions used. **Binaries are never committed** — only the
manifest and the scripts that recreate them (`bench/build-corpus.mjs`).

Corpus design:

- **Go (built here).** `gofmt` from the local Go 1.23.4 tree, built with
  `GOAMD64=v1` and with `-ldflags "-s -w"`, plus a small std-library-heavy
  program (`bench/corpus/src/gojson.go`). Go binaries carry a pclntab even when
  stripped, which gives a complete function/name ground truth.
- **Rust (built here).** Two std-only programs (`rust-hello`, `rust-algo`) built
  with `rustc -O`, plus two real-world Rust binaries shipped in the rustup
  toolchain (`cargo-fmt`, `rustfmt`). GNU-linked PE images keep a COFF symbol
  table, which is the ground truth here.
- **System PE (Windows).** Signed Microsoft DLLs copied unmodified from
  `System32` (x64) and `SysWOW64` (x86). These exercise compiler-generated
  x86/x64 code with export tables as partial ground truth.
- **No malware.** Nothing is downloaded from untrusted sources and corpus
  binaries are only parsed, never executed.

The published run benchmarks 13 of the 34 built binaries. The rest were built
but **skipped for the timebox**: Ghidra spends 15-60 s of JVM startup plus
auto-analysis per binary, so the marginal cost per extra binary is minutes, and
the run was capped to keep the deliverable reproducible within one sitting. The
full 34-binary list with "in results / skipped" markers is in the corpus table
in the generated results below. The harness supports the full corpus —
`node bench/run.mjs --jobs 3 --max-functions 0` — it just takes considerably
longer.

Why this corpus: it is small enough to re-run, it covers the project's main
target formats and two compilers with very different code generation (Go stack
maps/ABI wrappers, Rust monomorphisation), and it is legally redistributable as
a manifest rather than as binaries. It is **not** a random sample of all
software; see Threats to validity.

## Ground truth

All ground truth is derived from the binaries themselves, never from either
tool's output (`bench/lib/`):

| Corpus category | Ground truth | Notes |
| --- | --- | --- |
| Go | `pclntab` function table (`lib/gopcln.mjs`) | Survives `-s -w`; includes every Go function, including runtime and assembly wrappers. Also read from the PE import table for external callee names. |
| Rust (GNU PE) | COFF symbol table (`lib/pe.mjs`) | GNU ld leaves function symbols in the PE header's symbol table. Includes CRT helpers; ~20 % of entries are labels that are not usable function starts (see the discovery table). |
| System PE | PE export table + import table | Exports are only a *partial* truth: a DLL's internal functions are not named. For these binaries, "GT entries found/named" means "every exported entry was found/named", not "all functions". Imports give ground-truth names for calls through the IAT. |

For call-name agreement, an address in the ground-truth maps to a name; names
are compared as normalized short names (last path component, lowercase,
alphanumeric/underscore only, common tool prefixes such as `FUN_`/`sub_`/
`thunk_` stripped — see `bench/lib/names.mjs`). This is deliberately liberal,
because the same symbol is rendered as `runtime.panicIndex` by Paranoia,
`runtime::runtime_panicIndex` by Ghidra and `internal/abi.(*Type).Kind` by the
Go symbol table. The normalization has known false-positive potential
(namespace collisions); it is applied identically to both tools.

## Metrics

Per binary and per tool (`bench/lib/metrics.mjs`):

1. **Functions found** — non-thunk functions the tool discovered after full
   auto-analysis. Import thunks are excluded from all decompilation metrics;
   they are counted separately.
2. **Ground-truth discovery** — of the function entries the binary's metadata
   declares, what fraction has a function in the tool's listing at that address.
   Computed over the **full listing**, not the sample.
3. **Naming accuracy** — of those entries, what fraction the tool names with the
   ground-truth name (after normalization). Also full listing.
4. **Decompilation coverage** — of the sampled functions (see below), the
   fraction for which the decompiler returned non-empty C. Failures are
   captured with the error/timeout message and listed in the raw results (up to
   25 per binary).
5. **Call-edge name agreement** — for every direct call the tool's *own*
   disassembly found in a sampled function whose target address maps to a
   ground-truth symbol, export or import name, does that function's decompiled
   C spell the name as a call? Micro-averaged precision/recall/F1 over all
   sampled functions. Recursive self-calls are excluded. Indirect calls,
   inlined callees and calls whose target has no ground-truth name are not
   counted for either tool.
6. **C output size** — lines and characters of generated C for the sample.
7. **Time** — analysis time, decompiler time (sum of per-call wall time) and
   wall time of the whole import + analysis + decompile step. For Ghidra, wall
   time includes JVM startup (reported separately as `startupOverheadMs`); for
   Paranoia it includes CLI process start and the Python batch harness.

### Sampling

Decompiling *every* function of large binaries is where a decompiler benchmark
turns into a multi-hour job (Ghidra: 235 s just to decompile gofmt's 3 283
functions for a single binary; Paranoia: 3.5 min for the same file), so the
published run uses:

> **For each binary, the first 300 non-thunk functions by ascending entry
> address are decompiled and used for coverage, output-size and call-name
> metrics. Function discovery and naming use the complete listing.**

This rule is deterministic and identical for both tools, and it is implemented
inside the adapters (`PARANOIA_BENCH_MAX_FUNCS`, `--max-functions` in the
runner). Analysis always runs on the whole binary, so discovery metrics are not
sampled. The limitation is real: low addresses over-represent compiler/runtime
support code (CRT, Go runtime, Rust std) relative to application code. A random
or size-stratified sample would be better; the harness accepts
`--max-functions 0` to decompile everything, and the raw dumps can be re-scored
without re-running either tool.

## Versions and environment

| Component | Version |
| --- | --- |
| Paranoia | 0.8.0, commit `c168f454482e4fecde0a4d5f13772fd3750d6ebc` ("Release 0.8.0: CLI builds for Linux and macOS"), release build; CLI SHA-256 `32689ae821c4266143b5c92f3be06d3e7d6abab9cc0646a0c4c5f9089c3e3f4f` |
| Ghidra | 12.2 PUBLIC build `20261016` (`ghidra_12.2_PUBLIC_20261016.zip`, GitHub release `Ghidra_12.2_build`) |
| JDK (for Ghidra) | Eclipse Temurin 25.0.5+8 |
| Go | 1.23.4 windows/amd64 |
| Rust | 1.94.1 (e408947bf 2026-03-25), `stable-x86_64-pc-windows-gnu` |
| Node.js | 22.14.0 |
| OS | Windows 11 Home 10.0.26200, 12 logical CPUs (Intel i5-12450H), 16 GiB RAM |

Both tools run on the same machine, sequentially per binary but across binaries
in parallel: Paranoia with `--jobs 6`, Ghidra with `--jobs 3` (Ghidra instances
are separate JVMs, one per binary, so wall times include startup). The machine
was also used for other work during part of the run; the timing columns are
therefore *indicative*, not a controlled performance measurement. All accuracy
metrics are unaffected by machine load.

Paranoia was built from a `git archive HEAD` export of commit
`c168f45` because the working tree contained unrelated in-progress edits at
benchmark time; the exported tree is byte-identical to that commit. Exact
build: `cargo build --release -p paranoia-cli` with the repo's pinned
toolchain. Ghidra ran with default headless analysis; no user scripts other than
the exporter below, no debugger, no decompiler options tuned, no DWARF
overrides.

The published run predates the ready-made signature packs for the MSVC CRT, Rust
std and musl libc (added after 0.8.0, [SIGNATURES.md](SIGNATURES.md)). Those packs
only add names to library functions, so the naming percentages below are a floor
for later builds, not a ceiling; re-running the harness after a release that
includes them is the way to update the numbers.

## What the numbers say

<!-- The report script embeds the tables below. Numbers are discussed in
docs (this section), not in the generated tables. -->

Key observations from the published run (all visible in the tables):

- **Coverage is not the differentiator on this corpus.** Paranoia produced
  non-empty C for all 3,393 sampled functions; Ghidra missed 21 of 3,411
  (`Low-level Error` inside very large Go runtime and Rust std functions, e.g.
  "Bad instruction count exceeded" and "Cannot specify logical size for multiple
  piece join"). Both are far from failing on ordinary code; the interesting
  differences are below.
- **Paranoia is competitive with Ghidra on Go and on Windows PE**, where its
  symbol import works (Go pclntab/`.symtab`, PE exports/imports): Go naming
  100 % vs 100 %, PE x64/x86 naming 100 % vs 99.6 %/97.7 %, call-name recall
  93.7 %/100 %/100 % vs 97.9 %/99.7 %/98.2 %. On these groups the two tools are
  in the same league.
- **Paranoia loses badly on GNU-linked Rust PE binaries.** It does not import
  the COFF symbol table GNU ld stores in the PE header (Go's linker emits a
  `.symtab` *section*, which Paranoia does read), so 5.6 % of GNU COFF entries
  get their name versus 33.8 % in Ghidra, and 78.5 % of those entries are even
  recognised as function starts versus 99.9 % in Ghidra. Call-name recall drops
  to 28.3 % vs 62.0 %. This is a concrete, fixable gap — not a decompiler
  weakness — and it is why the "all" naming row is so much worse for Paranoia.
- **Ghidra finds far more functions in 32-bit PE:** 1,883 vs Paranoia's 380
  non-thunk functions in `comctl32_win_x86` (1,944 vs 422 across the two x86
  DLLs), while both still find 100 % of the export entries. Export-only ground
  truth cannot arbitrate which listing is "right", but a 5× function-count gap
  on PE32 is a red flag for Paranoia's 32-bit function discovery (PE32 has no
  `.pdata` to seed function starts) and is on the project's follow-up list.
- **Call-name precision favors Paranoia** (98.0 % vs 92.8 % overall), with a
  caveat: a GT-named call token in the C that the tool's own listing did not
  record as a direct call counts as a false positive. Ghidra resolves more
  indirect/pointer calls to names, which look like "extra" names to this metric.
  Read precision as "names present are explained by direct calls", not as an
  error rate; recall is the more meaningful of the two here.
- **Ghidra burns its time in JVM startup and auto-analysis**, not in the
  decompiler: 22.3 min of analysis plus 15-85 s of JVM startup/save per binary
  gave 37.2 min wall for the corpus, while the decompiler itself spent 205 s on
  the same kind of sample that took Paranoia 215 s. Paranoia's analysis is
  3.6 s for all 13 binaries and the whole corpus wall time is 4.0 min. In other
  words: comparable decompiler throughput on this sample, very different
  infrastructure cost.
- **Paranoia writes ~40 % more C lines** for the same sample (292,146 vs
  209,963) and far more for Rust (124,102 vs 63,578, partly because Ghidra fails
  earlier on some huge functions). Ghidra emits typed `undefined8`/`uint` C with
  casts; Paranoia emits register-heavy pseudo-C. Size is reported for
  transparency, not as a quality score.

## Threats to validity

Be suspicious of these numbers in exactly these ways:

1. **Small, non-random corpus.** 13 published binaries, 23 k functions in the
   listings and 3.4 k decompiled functions in the sample, are enough to catch
   systematic differences and not enough to claim population-level accuracy.
   Categories are PE-heavy; Go and Rust are static-link + runtime-heavy; there
   is no C++/MSVC, no JIT/self-modifying code, no packed or obfuscated binaries,
   and no malware.
2. **Partial ground truth for system PE.** Exports name only the public entry
   points; internal DLL functions are unnamed on both sides. The discovery and
   naming percentages for those binaries therefore measure export handling,
   not internal-function naming.
3. **Address sampling bias.** The 300-function sample is the low-address prefix:
   CRT/runtime/std functions are over-represented relative to application code.
   Results can shift with `--max-functions 0` or a different rule.
4. **Name normalization is liberal.** Short-name matching is required to compare
   two tools' renderings at all, but it can treat different qualified names as
   the same and (via namespace-suffix candidates) can over-match on namespaces.
   Both tools get the same treatment, so the *relative* difference is
   meaningful; absolute percentages are approximate.
5. **Call precision is a proxy.** A ground-truth-named call token in the C that
   the tool's own listing did not record as a direct call counts as a false
   positive, so a decompiler that resolves more pointer/indirect calls (Ghidra)
   is penalized by this metric. Precision is "how many of the names present are
   explained by direct calls", not an error rate. Recall is the primary
   call-agreement signal.
6. **Coverage ≠ correctness.** A function that produces 40 lines of C can still
   be wrong. This benchmark cannot detect wrong output; it only detects missing
   output and wrong/missing symbol names in call positions. A correctness
   benchmark (differential execution, round-trip recompilation, or a review of
   sampled functions against source where available) is future work.
7. **Default settings only.** No decompiler options were tuned for either tool;
   a Ghidra user could load PDBs, set prototypes or use a different
   simplification style, and Paranoia was measured with its default line-based
   pseudocode, not the SSA-based C view (`--from-ssa`). Results may change with
   non-default settings.
8. **Time is contaminated.** The machine was shared, analysis and decompilation
   ran with several binaries in flight (Paranoia `--jobs 6`, Ghidra `--jobs 3`),
   and Ghidra's per-binary JVM startup is included in wall time. Only large time
   ratios should be read as signal.
9. **This is not a security tool comparison.** Neither tool was asked to find
   bugs or identify malware; nothing in the corpus was executed.
10. **Host-system drift.** System DLL bytes depend on the host's Windows build;
    Go/Rust binaries depend on the pinned toolchains. The manifest records
    SHA-256 for every file used here, and `node bench/build-corpus.mjs --check`
    verifies them.

## Reproduction

```bash
# 0. Prerequisites: Rust toolchain, Go 1.23 (full source tree), Python 3,
#    Node 22, curl. Ghidra needs JDK 25 (see bench/README.md).
cd <repo root>

# 1. Build the pinned CLI (this run: commit c168f45, 0.8.0)
cargo build --release -p paranoia-cli

# 2. Recreate the corpus + verify it against the committed manifest
node bench/build-corpus.mjs
node bench/build-corpus.mjs --check   # optional: SHA-256 verification

# 3. Install Ghidra 12.2 + Temurin JDK 25 under bench/.ghidra/ (gitignored)
#    Exact URLs are in bench/README.md

# 4. Run the benchmark with the published sampling rule.
#    The published run used --jobs 6 for Paranoia and --jobs 3 for Ghidra
#    (separate invocations, see "Versions and environment"); this single command
#    works too, just slower.
node bench/run.mjs --jobs 3 --max-functions 300

# 5. Regenerate the tables in this document from bench/results/bench.json
node bench/report.mjs --embed docs/BENCHMARK.md
```

On a host with a full system drive, set `TEMP`/`TMP` to a writable directory
first; the Ghidra adapter additionally redirects the JVM's temp and user-config
directories under `bench/work/`. Expected wall time for the 13-binary run on
this hardware: about 37 minutes for Ghidra (dominated by per-binary JVM startup
and auto-analysis) plus about 4 minutes for Paranoia; the sampled 300-function
decompile itself is a few minutes of that for each tool.

`bench/work/` (binaries, per-function dumps, Ghidra projects) and
`bench/.ghidra/` are gitignored. Committed inputs/outputs: the corpus manifest,
the harness sources, and `bench/results/bench.json` (aggregated + per-binary
metrics, including failure samples).

## Why this is not "AI slop"

The accusation behind this section is that an AI-assisted project can produce
impressive-sounding claims that were never measured, cherry-picked, or
unrepeatable. This benchmark is structured to make that checkable:

- **Everything is a script in the repository.** Corpus creation, tool adapters,
  metric definitions, the sampled rule and the tables are code; nothing is a
  hard-coded number in prose.
- **The comparison tool is real and current.** Ghidra 12.2 PUBLIC was downloaded
  from the official GitHub release, run headless with default analysis on the
  same files, and its per-function dumps are produced by
  `bench/tools/ghidra/DecompileAll.java`. If the adapter could not run, this
  document would say so instead of printing numbers.
- **Failures and losses are published.** The failures tables list functions
  where each tool produced nothing; the Rust groups show Paranoia losing badly
  on symbol naming, and the numbers say so plainly. The corpus table marks the
  binaries that were *not* benchmarked.
- **Raw data is committed.** `bench/results/bench.json` carries the per-binary
  metrics, failure samples, versions and environment, and the full per-function
  dumps can be regenerated from the manifest alone.
- **The claims are bounded.** Coverage is labeled as coverage, not correctness;
  threats to validity are enumerated above; timings are labeled indicative.
  The honest summary is: on this small corpus Paranoia's coverage and call-name
  agreement are competitive with Ghidra on Go and Windows PE, while it loses on
  GNU-linked Rust PE symbol import, and both tools are fast enough that the
  bottleneck is Ghidra's analysis/JVM startup. That is a narrower claim than
  "as good as IDA/Ghidra" — and it is the claim the data supports.

Third parties can break the last leg of trust: re-run the five commands above on
any machine, change the corpus, or raise `--max-functions` and see what happens
to the numbers.

<!-- bench:tables:start -->

#### Corpus

| # | Corpus id | Category | Format / arch | Size | Ground truth | In results |
| ---: | --- | --- | --- | ---: | --- | --- |
| 1 | `cargo_fmt_gnu` | Rust (built here / rustup) | pe/x86_64 | 3757 KiB | COFF symbol table | yes |
| 2 | `comctl32_win_x64` | Windows PE x64 | pe/x86_64 | 725 KiB | PE exports only | yes |
| 3 | `comctl32_win_x86` | Windows PE x86 | pe/x86 | 571 KiB | PE exports only | yes |
| 4 | `gofmt_go123_amd64v1` | Go (built here) | pe/x86_64 | 4415 KiB | Go pclntab function table | yes |
| 5 | `gofmt_go123_amd64v1_stripped` | Go (built here) | pe/x86_64 | 2909 KiB | Go pclntab function table | yes |
| 6 | `gojson_go123_amd64v1` | Go (built here) | pe/x86_64 | 2752 KiB | Go pclntab function table | yes |
| 7 | `rust_algo_gnu` | Rust (built here / rustup) | pe/x86_64 | 2079 KiB | COFF symbol table | yes |
| 8 | `rust_hello_gnu` | Rust (built here / rustup) | pe/x86_64 | 2038 KiB | COFF symbol table | yes |
| 9 | `shlwapi_win_x64` | Windows PE x64 | pe/x86_64 | 431 KiB | PE exports only | yes |
| 10 | `version_win_x64` | Windows PE x64 | pe/x86_64 | 54 KiB | PE exports only | yes |
| 11 | `version_win_x86` | Windows PE x86 | pe/x86 | 28 KiB | PE exports only | yes |
| 12 | `winmm_win_x64` | Windows PE x64 | pe/x86_64 | 235 KiB | PE exports only | yes |
| 13 | `xmllite_win_x64` | Windows PE x64 | pe/x86_64 | 288 KiB | PE exports only | yes |
| 14 | `credui_win_x64` | Windows PE x64 | pe/x86_64 | 112 KiB | PE exports only | skipped (timebox) |
| 15 | `credui_win_x86` | Windows PE x86 | pe/x86 | 65 KiB | PE exports only | skipped (timebox) |
| 16 | `crypt32_win_x64` | Windows PE x64 | pe/x86_64 | 1550 KiB | PE exports only | skipped (timebox) |
| 17 | `crypt32_win_x86` | Windows PE x86 | pe/x86 | 1090 KiB | PE exports only | skipped (timebox) |
| 18 | `fltlib_win_x64` | Windows PE x64 | pe/x86_64 | 58 KiB | PE exports only | skipped (timebox) |
| 19 | `fltlib_win_x86` | Windows PE x86 | pe/x86 | 29 KiB | PE exports only | skipped (timebox) |
| 20 | `gofmt_go123_amd64v3` | Go (built here) | pe/x86_64 | 4411 KiB | Go pclntab function table | skipped (timebox) |
| 21 | `gofmt_go123_amd64v3_stripped` | Go (built here) | pe/x86_64 | 2905 KiB | Go pclntab function table | skipped (timebox) |
| 22 | `gojson_go123_amd64v1_stripped` | Go (built here) | pe/x86_64 | 1849 KiB | Go pclntab function table | skipped (timebox) |
| 23 | `mpr_win_x64` | Windows PE x64 | pe/x86_64 | 143 KiB | PE exports only | skipped (timebox) |
| 24 | `mpr_win_x86` | Windows PE x86 | pe/x86 | 93 KiB | PE exports only | skipped (timebox) |
| 25 | `msimg32_win_x64` | Windows PE x64 | pe/x86_64 | 32 KiB | PE exports only | skipped (timebox) |
| 26 | `msimg32_win_x86` | Windows PE x86 | pe/x86 | 7 KiB | PE exports only | skipped (timebox) |
| 27 | `ole32_win_x64` | Windows PE x64 | pe/x86_64 | 1680 KiB | PE exports only | skipped (timebox) |
| 28 | `ole32_win_x86` | Windows PE x86 | pe/x86 | 1395 KiB | PE exports only | skipped (timebox) |
| 29 | `rustfmt_gnu` | Rust (built here / rustup) | pe/x86_64 | 9543 KiB | COFF symbol table | skipped (timebox) |
| 30 | `shlwapi_win_x86` | Windows PE x86 | pe/x86 | 341 KiB | PE exports only | skipped (timebox) |
| 31 | `winmm_win_x86` | Windows PE x86 | pe/x86 | 208 KiB | PE exports only | skipped (timebox) |
| 32 | `wkscli_win_x64` | Windows PE x64 | pe/x86_64 | 118 KiB | PE exports only | skipped (timebox) |
| 33 | `wkscli_win_x86` | Windows PE x86 | pe/x86 | 68 KiB | PE exports only | skipped (timebox) |
| 34 | `xmllite_win_x86` | Windows PE x86 | pe/x86 | 211 KiB | PE exports only | skipped (timebox) |

#### Decompilation coverage (sampled)

| Group | Binaries | Functions (full listing) | Decompile sample | Decompiled | Coverage | Failed | C lines |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| paranoia · Go (built here) | 3 | 8,773 | 900 | 900 | 100.0 % | 0 | 73,110 |
| paranoia · Rust (built here / rustup) | 3 | 9,552 | 900 | 900 | 100.0 % | 0 | 124,102 |
| paranoia · Windows PE x64 | 5 | 4,338 | 1,251 | 1,251 | 100.0 % | 0 | 75,557 |
| paranoia · Windows PE x86 | 2 | 422 | 342 | 342 | 100.0 % | 0 | 19,377 |
| **paranoia · all** | **13** | **23,085** | **3,393** | **3,393** | **100.0 %** | **0** | **292,146** |
| ghidra · Go (built here) | 3 | 8,761 | 900 | 885 | 98.3 % | 15 | 72,458 |
| ghidra · Rust (built here / rustup) | 3 | 9,335 | 900 | 894 | 99.3 % | 6 | 63,578 |
| ghidra · Windows PE x64 | 5 | 4,749 | 1,250 | 1,250 | 100.0 % | 0 | 56,906 |
| ghidra · Windows PE x86 | 2 | 1,944 | 361 | 361 | 100.0 % | 0 | 17,021 |
| **ghidra · all** | **13** | **24,789** | **3,411** | **3,390** | **99.4 %** | **21** | **209,963** |

#### Ground-truth function discovery and naming (full listing)

| Group | GT entries | Found | Found % | Named right | Named % |
| --- | ---: | ---: | ---: | ---: | ---: |
| paranoia · Go (built here) | 8,690 | 8,690 | 100.0 % | 8,690 | 100.0 % |
| paranoia · Rust (built here / rustup) | 9,741 | 7,646 | 78.5 % | 546 | 5.6 % |
| paranoia · Windows PE x64 | 688 | 688 | 100.0 % | 688 | 100.0 % |
| paranoia · Windows PE x86 | 128 | 128 | 100.0 % | 128 | 100.0 % |
| **paranoia · all** | **19,247** | **17,152** | **89.1 %** | **10,052** | **52.2 %** |
| ghidra · Go (built here) | 8,690 | 8,690 | 100.0 % | 8,690 | 100.0 % |
| ghidra · Rust (built here / rustup) | 9,741 | 9,733 | 99.9 % | 3,294 | 33.8 % |
| ghidra · Windows PE x64 | 688 | 688 | 100.0 % | 685 | 99.6 % |
| ghidra · Windows PE x86 | 128 | 128 | 100.0 % | 125 | 97.7 % |
| **ghidra · all** | **19,247** | **19,239** | **100.0 %** | **12,794** | **66.5 %** |

#### Call-edge name agreement (sampled functions)

| Group | GT-named direct callees | Matched in C | Recall | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| paranoia · Go (built here) | 3,594 | 3,369 | 93.7 % | 99.7 % | 96.6 % |
| paranoia · Rust (built here / rustup) | 2,260 | 639 | 28.3 % | 92.3 % | 43.3 % |
| paranoia · Windows PE x64 | 1,031 | 1,031 | 100.0 % | 95.5 % | 97.7 % |
| paranoia · Windows PE x86 | 561 | 561 | 100.0 % | 99.5 % | 99.7 % |
| **paranoia · all** | **7,446** | **5,600** | **75.2 %** | **98.0 %** | **85.1 %** |
| ghidra · Go (built here) | 3,658 | 3,582 | 97.9 % | 91.7 % | 94.7 % |
| ghidra · Rust (built here / rustup) | 2,526 | 1,566 | 62.0 % | 88.3 % | 72.8 % |
| ghidra · Windows PE x64 | 1,121 | 1,118 | 99.7 % | 98.8 % | 99.3 % |
| ghidra · Windows PE x86 | 815 | 800 | 98.2 % | 99.8 % | 99.0 % |
| **ghidra · all** | **8,120** | **7,066** | **87.0 %** | **92.8 %** | **89.8 %** |

#### Time

| Group | Analysis (sum) | Decompiler (sum) | Wall (sum) | Functions/s (decompiler) |
| --- | ---: | ---: | ---: | ---: |
| paranoia · Go (built here) | 0.6 s | 51.7 s | 57.7 s | 17.4 |
| paranoia · Rust (built here / rustup) | 2.7 s | 100.6 s | 1.9 min | 8.9 |
| paranoia · Windows PE x64 | 0.2 s | 51.1 s | 55.3 s | 24.5 |
| paranoia · Windows PE x86 | 0.0 s | 12.0 s | 13.3 s | 28.4 |
| **paranoia · all** | **3.6 s** | **215.5 s** | **4.0 min** | **15.7** |
| ghidra · Go (built here) | 483.0 s | 67.7 s | 11.1 min | 13.1 |
| ghidra · Rust (built here / rustup) | 495.0 s | 91.0 s | 12.4 min | 9.8 |
| ghidra · Windows PE x64 | 227.0 s | 32.6 s | 9.6 min | 38.3 |
| ghidra · Windows PE x86 | 130.0 s | 14.0 s | 4.1 min | 25.7 |
| **ghidra · all** | **1335.0 s** | **205.3 s** | **37.2 min** | **16.5** |

#### Per binary: paranoia

| Binary | Category | Functions | Coverage | Failed | GT found | Call recall | Call precision | Wall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `cargo_fmt_gnu` | Rust (built here / rustup) | 4,712 | 100.0 % | 0 | 76.7 % | 11.0 % | 98.8 % | 24.9 s |
| `comctl32_win_x64` | Windows PE x64 | 1,611 | 100.0 % | 0 | 100.0 % | 100.0 % | 98.3 % | 15.3 s |
| `comctl32_win_x86` | Windows PE x86 | 380 | 100.0 % | 0 | 100.0 % | 100.0 % | 99.8 % | 12.0 s |
| `gofmt_go123_amd64v1` | Go (built here) | 3,284 | 100.0 % | 0 | 100.0 % | 93.8 % | 99.7 % | 19.6 s |
| `gofmt_go123_amd64v1_stripped` | Go (built here) | 3,284 | 100.0 % | 0 | 100.0 % | 93.8 % | 99.7 % | 19.2 s |
| `gojson_go123_amd64v1` | Go (built here) | 2,205 | 100.0 % | 0 | 100.0 % | 93.7 % | 99.7 % | 18.9 s |
| `rust_algo_gnu` | Rust (built here / rustup) | 2,441 | 100.0 % | 0 | 80.4 % | 35.3 % | 90.3 % | 44.1 s |
| `rust_hello_gnu` | Rust (built here / rustup) | 2,399 | 100.0 % | 0 | 80.5 % | 38.7 % | 92.4 % | 42.0 s |
| `shlwapi_win_x64` | Windows PE x64 | 1,194 | 100.0 % | 0 | 100.0 % | 100.0 % | 92.5 % | 11.6 s |
| `version_win_x64` | Windows PE x64 | 51 | 100.0 % | 0 | 100.0 % | 100.0 % | 95.3 % | 1.2 s |
| `version_win_x86` | Windows PE x86 | 42 | 100.0 % | 0 | 100.0 % | 100.0 % | 96.9 % | 1.3 s |
| `winmm_win_x64` | Windows PE x64 | 710 | 100.0 % | 0 | 100.0 % | 100.0 % | 95.0 % | 8.3 s |
| `xmllite_win_x64` | Windows PE x64 | 772 | 100.0 % | 0 | 100.0 % | 100.0 % | 68.8 % | 18.9 s |

#### Per binary: Ghidra

| Binary | Category | Functions | Coverage | Failed | GT found | Call recall | Call precision | Wall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `cargo_fmt_gnu` | Rust (built here / rustup) | 4,956 | 100.0 % | 0 | 99.9 % | 30.3 % | 83.1 % | 4.9 min |
| `comctl32_win_x64` | Windows PE x64 | 1,652 | 100.0 % | 0 | 100.0 % | 100.0 % | 98.6 % | 3.1 min |
| `comctl32_win_x86` | Windows PE x86 | 1,883 | 100.0 % | 0 | 100.0 % | 97.9 % | 99.7 % | 3.1 min |
| `gofmt_go123_amd64v1` | Go (built here) | 3,280 | 98.3 % | 5 | 100.0 % | 97.9 % | 91.7 % | 4.2 min |
| `gofmt_go123_amd64v1_stripped` | Go (built here) | 3,280 | 98.3 % | 5 | 100.0 % | 97.9 % | 91.7 % | 3.7 min |
| `gojson_go123_amd64v1` | Go (built here) | 2,201 | 98.3 % | 5 | 100.0 % | 98.0 % | 91.6 % | 3.2 min |
| `rust_algo_gnu` | Rust (built here / rustup) | 2,213 | 99.0 % | 3 | 99.9 % | 72.0 % | 88.5 % | 3.9 min |
| `rust_hello_gnu` | Rust (built here / rustup) | 2,166 | 99.0 % | 3 | 99.9 % | 75.3 % | 89.7 % | 3.7 min |
| `shlwapi_win_x64` | Windows PE x64 | 1,448 | 100.0 % | 0 | 100.0 % | 100.0 % | 98.7 % | 2.9 min |
| `version_win_x64` | Windows PE x64 | 50 | 100.0 % | 0 | 100.0 % | 100.0 % | 99.0 % | 1.1 min |
| `version_win_x86` | Windows PE x86 | 61 | 100.0 % | 0 | 100.0 % | 100.0 % | 100.0 % | 1.0 min |
| `winmm_win_x64` | Windows PE x64 | 750 | 100.0 % | 0 | 100.0 % | 98.8 % | 99.2 % | 1.3 min |
| `xmllite_win_x64` | Windows PE x64 | 849 | 100.0 % | 0 | 100.0 % | 100.0 % | 100.0 % | 1.2 min |

#### Failures: paranoia

| Binary | Failed functions (non-thunk) |
| --- | ---: |
| `cargo_fmt_gnu` | 0 |
| `comctl32_win_x64` | 0 |
| `comctl32_win_x86` | 0 |
| `gofmt_go123_amd64v1` | 0 |
| `gofmt_go123_amd64v1_stripped` | 0 |
| `gojson_go123_amd64v1` | 0 |
| `rust_algo_gnu` | 0 |
| `rust_hello_gnu` | 0 |
| `shlwapi_win_x64` | 0 |
| `version_win_x64` | 0 |
| `version_win_x86` | 0 |
| `winmm_win_x64` | 0 |
| `xmllite_win_x64` | 0 |

#### Failures: Ghidra

| Binary | Failed functions (non-thunk) |
| --- | ---: |
| `cargo_fmt_gnu` | 0 |
| `comctl32_win_x64` | 0 |
| `comctl32_win_x86` | 0 |
| `gofmt_go123_amd64v1` | 5 |
| `gofmt_go123_amd64v1_stripped` | 5 |
| `gojson_go123_amd64v1` | 5 |
| `rust_algo_gnu` | 3 |
| `rust_hello_gnu` | 3 |
| `shlwapi_win_x64` | 0 |
| `version_win_x64` | 0 |
| `version_win_x86` | 0 |
| `winmm_win_x64` | 0 |
| `xmllite_win_x64` | 0 |

<!-- bench:tables:end -->
