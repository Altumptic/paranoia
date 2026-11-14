// Benchmark orchestrator.
//
//   node bench/run.mjs                      # both tools, cached adapters reused
//   node bench/run.mjs --tool paranoia      # only (re)compute paranoia metrics
//   node bench/run.mjs --tool ghidra --force
//   node bench/run.mjs --only 'gofmt|rust'  # regex filter on corpus ids
//   node bench/run.mjs --jobs 2             # parallel per-binary adapters
//
// Results: bench/results/bench.json (aggregated + per-binary), with the raw
// tool dumps kept under bench/work/ (gitignored).
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { buildGroundTruth, gtSummary } from './lib/gt.mjs';
import { computeMetrics, aggregate } from './lib/metrics.mjs';
import { pool } from './lib/proc.mjs';
import { findCli, cliVersion, loadOrRun as loadParanoia } from './tools/paranoia.mjs';
import { loadOrRun as loadGhidra, findGhidra, findJava } from './tools/ghidra.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const workDir = path.join(here, 'work');
const corpusDir = path.join(workDir, 'corpus');
const resultsDir = path.join(here, 'results');
const manifestPath = path.join(here, 'corpus', 'manifest.json');

function parseArgs(argv) {
    const opts = { tool: 'all', only: null, exclude: null, force: false, out: null, jobs: 1, list: false, maxFunctions: 300 };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--tool') opts.tool = argv[++i];
        else if (a === '--only') opts.only = argv[++i];
        else if (a === '--exclude') opts.exclude = argv[++i];
        else if (a === '--force') opts.force = true;
        else if (a === '--out') opts.out = argv[++i];
        else if (a === '--jobs') opts.jobs = Math.max(1, parseInt(argv[++i], 10));
        else if (a === '--max-functions') opts.maxFunctions = Math.max(0, parseInt(argv[++i], 10));
        else if (a === '--list') opts.list = true;
        else if (a === '--help' || a === '-h') {
            console.log(
                'usage: node bench/run.mjs [--tool paranoia|ghidra|all] [--only regex] [--exclude regex] [--force] [--jobs N] [--max-functions N] [--out file] [--list]',
            );
            process.exit(0);
        } else {
            console.error('unknown argument: ' + a);
            process.exit(2);
        }
    }
    return opts;
}

function sha256File(p) {
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function fmtPct(v) {
    return v === null || v === undefined ? '-' : v.toFixed(1) + '%';
}

function fmtMs(v) {
    if (v === null || v === undefined) return '-';
    if (v < 1000) return Math.round(v) + ' ms';
    if (v < 60000) return (v / 1000).toFixed(1) + ' s';
    return (v / 60000).toFixed(1) + ' min';
}

function printTable(rows) {
    const widths = [];
    for (const row of rows) row.forEach((c, i) => (widths[i] = Math.max(widths[i] ?? 0, String(c).length)));
    for (const [ri, row] of rows.entries()) {
        console.log(row.map((c, i) => String(c).padEnd(widths[i])).join('  '));
        if (ri === 0) console.log(widths.map((w) => '-'.repeat(w)).join('  '));
    }
}

const opts = parseArgs(process.argv.slice(2));
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const wantedTools = opts.tool === 'all' ? ['paranoia', 'ghidra'] : [opts.tool];
for (const t of wantedTools) {
    if (!['paranoia', 'ghidra'].includes(t)) {
        console.error(`unknown tool: ${t}`);
        process.exit(2);
    }
}

const filter = opts.only ? new RegExp(opts.only) : null;
const excludeFilter = opts.exclude ? new RegExp(opts.exclude) : null;
const entries = manifest.entries.filter((e) => (!filter || filter.test(e.id)) && (!excludeFilter || !excludeFilter.test(e.id)));
if (opts.list) {
    for (const e of entries) console.log(`${e.id.padEnd(30)} ${e.category.padEnd(16)} ${e.format}/${e.arch} ${(e.size / 1024).toFixed(0)} KiB  gt=${e.gtSource}`);
    process.exit(0);
}

fs.mkdirSync(resultsDir, { recursive: true });
for (const t of wantedTools) fs.mkdirSync(path.join(workDir, 'metrics', t), { recursive: true });

const versions = {
    paranoia: { version: null, cli: null, cliSha256: null, builtFrom: 'git archive HEAD of the paranoia repository at benchmark time (see docs/BENCHMARK.md)' },
    ghidra: null,
    java: null,
    node: process.version,
    corpus: manifest.toolchain,
};
try {
    const cli = findCli(repoRoot);
    versions.paranoia.cli = cli;
    versions.paranoia.version = cliVersion(cli);
    versions.paranoia.cliSha256 = sha256File(cli);
} catch (e) {
    versions.paranoia.error = e.message.split('\n')[0];
}
try {
    const g = findGhidra(repoRoot);
    versions.ghidra = { version: g.version, home: g.home };
    const j = findJava(repoRoot);
    versions.java = j ? { version: j.version, home: j.home } : null;
} catch (e) {
    versions.ghidra = { error: e.message.split('\n')[0] };
}

console.log(`corpus: ${entries.length} binaries from ${path.relative(repoRoot, manifestPath)}`);
console.log(`tools:  ${wantedTools.join(', ')} with ${opts.jobs} parallel job(s)`);
if (opts.maxFunctions > 0) {
    console.log(
        `decompile sample: first ${opts.maxFunctions} non-thunk functions per binary by address (discovery/naming metrics use the full listing)`,
    );
}
if (versions.paranoia.version) console.log(`paranoia: ${versions.paranoia.version} (${versions.paranoia.cli})`);
if (versions.ghidra?.version) console.log(`ghidra: ${versions.ghidra.version} / java ${versions.java?.version ?? '?'}`);
console.log('');

for (const entry of entries) {
    const binaryPath = path.join(corpusDir, entry.file);
    if (!fs.existsSync(binaryPath)) {
        console.error(`missing corpus file: ${binaryPath} (run: node bench/build-corpus.mjs)`);
        process.exit(1);
    }
    const actualSha = sha256File(binaryPath);
    if (actualSha !== entry.sha256) {
        console.error(`SHA-256 mismatch for ${entry.id}: manifest ${entry.sha256}, file ${actualSha}`);
        console.error('the corpus on disk differs from the manifest; rebuild or update the manifest deliberately');
        process.exit(1);
    }
}

const perBinary = new Array(entries.length);

await pool(entries, opts.jobs, async (entry, index) => {
    const binaryPath = path.join(corpusDir, entry.file);
    const gt = buildGroundTruth(binaryPath);
    const gtSum = gtSummary(gt);
    const tools = [];
    const errors = {};
    for (const tool of wantedTools) {
        const adapter = tool === 'paranoia' ? loadParanoia : loadGhidra;
        const t0 = Date.now();
        let dump;
        try {
            dump = await adapter({
                repoRoot,
                binaryPath,
                sha256: entry.sha256,
                workDir,
                force: opts.force,
                maxFunctions: opts.maxFunctions,
            });
        } catch (e) {
            const msg = e.message.split('\n').slice(0, 5).join(' / ');
            errors[tool] = msg;
            console.error(`[${tool}] ${entry.id}: FAILED: ${msg}`);
            continue;
        }
        const metrics = computeMetrics({
            tool,
            id: entry.id,
            category: entry.category,
            sha256: entry.sha256,
            functions: dump.functions,
            callsByAddr: dump.callsByAddr,
            gt,
            timing: dump.timing,
            maxFunctions: opts.maxFunctions,
        });
        metrics.adapterCached = dump.cached;
        metrics.secondsThisRun = Math.round((Date.now() - t0) / 10) / 100;
        const metricsPath = path.join(workDir, 'metrics', tool, entry.id + '.json');
        fs.writeFileSync(metricsPath, JSON.stringify({ metrics, gt: gtSum, manifest: entry }, null, 2) + '\n');
        tools.push(metrics);
        console.log(
            `[${tool}] ${entry.id.padEnd(30)} funcs=${String(metrics.functions.nonThunk).padStart(6)} ` +
                `cov=${fmtPct(metrics.decompilation.coveragePct).padStart(6)} ` +
                `gt=${fmtPct(metrics.functions.gtFoundPct).padStart(6)} ` +
                `callRecall=${fmtPct(metrics.calls.recallPct).padStart(6)} ` +
                `wall=${fmtMs(metrics.timing.wallMs)}${dump.cached ? ' (cached)' : ''}`,
        );
    }
    perBinary[index] = {
        id: entry.id,
        file: entry.file,
        sha256: entry.sha256,
        size: entry.size,
        format: entry.format,
        arch: entry.arch,
        category: entry.category,
        provenance: entry.provenance,
        gtSource: entry.gtSource,
        gt: gtSum,
        errors: Object.keys(errors).length ? errors : undefined,
        metrics: Object.fromEntries(tools.map((m) => [m.tool, m])),
    };
});

// Results gathered from a previous invocation for tools not run this time, so the
// result file always covers every tool that has cached metrics.
const allMetrics = [];
for (const tool of ['paranoia', 'ghidra']) {
    if (wantedTools.includes(tool)) {
        for (const b of perBinary) if (b?.metrics[tool]) allMetrics.push(b.metrics[tool]);
        continue;
    }
    const dir = path.join(workDir, 'metrics', tool);
    if (!fs.existsSync(dir)) continue;
    for (const entry of entries) {
        const p = path.join(dir, entry.id + '.json');
        if (!fs.existsSync(p)) continue;
        try {
            const saved = JSON.parse(fs.readFileSync(p, 'utf8'));
            allMetrics.push(saved.metrics);
        } catch {
            /* ignore corrupt cache entry */
        }
    }
}

const aggregates = aggregate(allMetrics);
const binarySummaries = perBinary.filter(Boolean).map((b) => ({
    id: b.id,
    category: b.category,
    format: b.format,
    arch: b.arch,
    size: b.size,
    gtSource: b.gt?.gtSource ?? b.gtSource,
    errors: b.errors ?? null,
    tools: Object.fromEntries(
        Object.entries(b.metrics).map(([tool, m]) => [
            tool,
            {
                functions: m.functions.nonThunk,
                sampled: m.functions.sampled,
                thunks: m.functions.thunks,
                coveragePct: m.decompilation.coveragePct,
                failed: m.decompilation.failed,
                gtEntries: m.functions.gtEntries,
                gtFoundPct: m.functions.gtFoundPct,
                gtNamedPct: m.functions.gtNamedPct,
                callRecallPct: m.calls.recallPct,
                callPrecisionPct: m.calls.precisionPct,
                expectedEdges: m.calls.expected,
                matchedEdges: m.calls.matched,
                cLines: m.decompilation.cLines,
                cChars: m.decompilation.cChars,
                wallMs: m.timing.wallMs,
                analysisMs: m.timing.analysisMs,
                decompileMs: m.timing.decompileMs,
                failureSamples: m.decompilation.failedFunctions,
                missingCallSamples: m.calls.functionsWithMissing,
            },
        ]),
    ),
}));

const result = {
    schema: 'paranoia-bench/1',
    generatedAt: new Date().toISOString(),
    host: {
        platform: process.platform,
        arch: process.arch,
        release: os.release(),
        cpus: os.cpus().length,
        cpuModel: os.cpus()[0]?.model ?? null,
        totalMemGiB: Number((os.totalmem() / 1024 ** 3).toFixed(1)),
    },
    jobs: opts.jobs,
    maxFunctions: opts.maxFunctions,
    runNotes: {
        sampling:
            opts.maxFunctions > 0
                ? `decompile metrics use the first ${opts.maxFunctions} non-thunk functions per binary by address; discovery/naming use the full listing`
                : 'decompile metrics use every non-thunk function',
        jobs: 'the adapter dumps behind this file were produced with --jobs 6 (paranoia) and --jobs 3 (ghidra); the final aggregation pass used --jobs 1 with cached dumps',
        timing: 'wall/analysis times are indicative: machine shared with other work and several tool instances ran in parallel',
    },
    versions,
    corpus: {
        manifestSchema: manifest.schema,
        corpusVersion: manifest.corpusVersion,
        binaries: entries.length,
        note: 'SHA-256 per binary is in bench/corpus/manifest.json',
    },
    aggregate: aggregates,
    binaries: binarySummaries,
};

const outPath = opts.out ?? path.join(resultsDir, 'bench.json');
fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n');
console.log(`\nwrote ${path.relative(repoRoot, outPath)}`);

const rows = [['group', 'binaries', 'functions', 'coverage', 'GT found', 'call recall', 'call precision', 'wall']];
const keys = Object.keys(aggregates).filter((k) => k.startsWith('tool:') && k.split(':').length === 3);
for (const key of keys) {
    const a = aggregates[key];
    rows.push([
        key,
        a.binaries,
        a.functions.nonThunk,
        fmtPct(a.functions.coveragePct),
        fmtPct(a.discovery.gtFoundPct),
        fmtPct(a.calls.recallPct),
        fmtPct(a.calls.precisionPct),
        fmtMs(a.timing.wallMs),
    ]);
}
console.log('');
printTable(rows);
