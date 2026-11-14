# Benchmark harness

Reproducible measurement of the Paranoia decompiler on a real-binary corpus,
side by side with Ghidra. The published numbers and methodology are in
[docs/BENCHMARK.md](../docs/BENCHMARK.md); this file explains how to run the
harness.

Everything here is plain Node.js (>= 20, tested on 22) with no npm dependencies
and Node's built-in child_process/fs only. It works on Windows and Linux; the
published run is Windows (see `docs/BENCHMARK.md` for why the corpus is
PE/Go/Rust heavy).

## What is measured

Per binary and per tool:

| Metric | Definition |
| --- | --- |
| Functions found | Non-thunk functions the tool discovered (after full auto-analysis). |
| Ground-truth function discovery | Fraction of entries known from the binary's own metadata (Go pclntab, COFF symbols, PE exports) where the tool has a function. |
| Naming accuracy | Fraction of ground-truth entries whose name the tool reproduces (short-name normalization, see `lib/names.mjs`). |
| Decompilation coverage | Fraction of non-thunk functions for which the decompiler produced non-empty C. Failures are listed per binary. |
| Call-edge name agreement | For every direct call the tool's own disassembly found whose target maps to a ground-truth symbol/export/import name: does the caller's decompiled C spell that name as a call? Micro precision/recall over all functions. |
| C output size | Lines and characters of generated C. |
| Time | Analysis time, decompiler time (sum of per-function wall time) and total wall time of the import+analysis+decompile step. |

Ground truth is derived only from the binary itself, never from either tool's
output: `lib/gopcln.mjs` reads the Go pclntab (which survives `-ldflags "-s -w"`),
`lib/pe.mjs` reads PE exports/imports and the COFF symbol table that GNU
toolchains leave in linked images, `lib/gt.mjs` assembles the maps.

### Sampling

Decompiling every function of every binary takes hours (mostly Ghidra's
per-binary JVM startup + analysis), so `run.mjs` defaults to
`--max-functions 300`: for each binary the adapters decompile the **first 300
non-thunk functions by ascending entry address** and record the rest of the
listing without C. Coverage, output-size and call-name metrics use that sample;
function-discovery and naming metrics always use the full listing. The rule is
identical for both tools and is implemented inside the adapters
(`PARANOIA_BENCH_MAX_FUNCS`). Use `--max-functions 0` (and a lot of time) for a
full decompile. See the sampling discussion and its bias in
[docs/BENCHMARK.md](../docs/BENCHMARK.md).

## Quick start

```bash
# 1. Build the pinned CLI (a release build; ~5-10 min from scratch)
cargo build --release -p paranoia-cli

# 2. Build/copy the corpus (writes bench/work/corpus, updates corpus/manifest.json)
node bench/build-corpus.mjs

# 3. Install Ghidra + a JDK 25 (only needed for the Ghidra comparison)
#    Ghidra 12.2 public build, JDK 25 (Temurin) -- unpack both under bench/.ghidra/
curl.exe -L -o bench/.ghidra/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip
tar.exe -xf bench/.ghidra/ghidra.zip -C bench/.ghidra/
# JDK 25 (Adoptium Temurin), then unpack to bench/.ghidra/jdk-25*
curl.exe -L -o bench/.ghidra/jdk25.zip "https://api.adoptium.net/v3/binary/latest/25/ga/windows/x64/jdk/hotspot/normal/eclipse"
tar.exe -xf bench/.ghidra/jdk25.zip -C bench/.ghidra/

# 4. Run the benchmark (adapters cache their dumps under bench/work/)
#    The runner samples 300 non-thunk functions per binary by default; see below.
node bench/run.mjs --jobs 4

# 5. Markdown tables from bench/results/bench.json
node bench/report.mjs
```

On a machine with a full system drive, point temp at the workspace before
running (the Ghidra adapter also redirects its JVM's temp/settings dirs under
`bench/work/`):

```powershell
$env:TEMP='D:\temp'; $env:TMP='D:\temp'
```

## Layout

| Path | Purpose |
| --- | --- |
| `corpus/src/` | Source of the small Go/Rust programs compiled into the corpus. |
| `corpus/manifest.json` | Committed record of every corpus binary: id, SHA-256, size, format/arch, category, provenance, expected ground-truth source, and the toolchain versions used to build it. |
| `corpus/manifest.json` + `build-corpus.mjs` | System DLLs are copied from the host; their bytes therefore follow the host's Windows build. |
| `lib/pe.mjs`, `lib/gopcln.mjs`, `lib/gt.mjs` | Ground-truth parsers. |
| `lib/metrics.mjs` | Metric definitions. |
| `tools/paranoia.mjs`, `tools/paranoia-dump.py` | Paranoia adapter: one `paranoia query <file> inventory` (call edges + imports) and one `paranoia script` run (all functions decompiled in one process through the Python API). |
| `tools/ghidra/DecompileAll.java` | Ghidra headless post-script: decompiles every function and writes JSONL. |
| `tools/ghidra.mjs` | Ghidra adapter: locates Ghidra/JDK, runs `analyzeHeadless` per binary, caches the dump. |
| `results/bench.json` | Raw results of the published run (committed). |
| `work/` | Built/copied binaries, tool dumps, cached projects (gitignored). |

## Notes and gotchas

- The Ghidra adapter imports each binary in a **fresh JVM** so that per-binary
  wall time is meaningful. Ghidra's JVM startup (~15 s) is included in the wall
  time and reported separately as `startupOverheadMs`.
- Ghidra 12.2 requires JDK 25+. The adapter looks at `$GHIDRA_JAVA_HOME`, then
  `bench/.ghidra/jdk-25*`, then `$JAVA_HOME`, then `java` on PATH.
- `bench/.ghidra` and `bench/work` are gitignored: Ghidra, the JDK, and the
  corpus binaries (including Microsoft DLLs) are never committed.
- The corpus is a *sample*, not a leaderboard. It is deliberately small enough
  to re-run on a laptop; see "Threats to validity" in `docs/BENCHMARK.md`.
- No malware is downloaded or executed; the harness only parses code, it never
  runs corpus binaries.
