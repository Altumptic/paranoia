// Renders Markdown tables from bench/results/bench.json -- the numbers quoted in
// docs/BENCHMARK.md. No dependencies.
//
//   node bench/report.mjs
//   node bench/report.mjs --result bench/results/bench.json
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const resultsPath = process.argv.includes('--result') ? process.argv[process.argv.indexOf('--result') + 1] : path.join(here, 'results', 'bench.json');
const result = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
const manifestPath = path.join(here, 'corpus', 'manifest.json');
const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : { entries: [] };
const manifestById = new Map(manifest.entries.map((e) => [e.id, e]));

const CATEGORY_LABEL = {
    go: 'Go (built here)',
    rust: 'Rust (built here / rustup)',
    'system-pe-x64': 'Windows PE x64',
    'system-pe-x86': 'Windows PE x86',
    'system-elf': 'Linux ELF',
};
const CATEGORIES = ['go', 'rust', 'system-pe-x64', 'system-pe-x86', 'system-elf'];
const TOOLS = ['paranoia', 'ghidra'];

const GT_LABEL = {
    'go-pclntab': 'Go pclntab function table',
    'coff-symbols': 'COFF symbol table',
    'pe-exports': 'PE exports only',
    'elf-symbols': 'ELF symbol table',
    none: 'none (metrics without names)',
};

function pct(v) {
    return v === null || v === undefined ? '–' : v.toFixed(1) + ' %';
}
function int(v) {
    return v === null || v === undefined ? '–' : v.toLocaleString('en-US');
}
function ms(v) {
    if (v === null || v === undefined) return '–';
    if (v < 1000) return Math.round(v) + ' ms';
    if (v < 60000) return (v / 1000).toFixed(1) + ' s';
    return (v / 60000).toFixed(1) + ' min';
}
function secs(v) {
    return v === null || v === undefined ? '–' : (v / 1000).toFixed(1) + ' s';
}
function kib(v) {
    return v === null || v === undefined ? '–' : (v / 1024).toFixed(0) + ' KiB';
}

function agg(tool, category) {
    return result.aggregate[category ? `tool:${tool}:${category}` : `tool:${tool}`];
}

function corpusTable() {
    const benchmarked = new Map(result.binaries.map((b) => [b.id, b]));
    const rows = [];
    for (const e of manifest.entries) {
        const b = benchmarked.get(e.id);
        rows.push({
            id: e.id,
            category: b?.category ?? e.category,
            format: b?.format ?? e.format,
            arch: b?.arch ?? e.arch,
            size: e.size,
            gtSource: b?.gtSource ?? e.gtSource,
            benchmarked: Boolean(b),
        });
    }
    rows.sort((a, b) => Number(b.benchmarked) - Number(a.benchmarked) || a.id.localeCompare(b.id));
    const lines = [];
    lines.push('| # | Corpus id | Category | Format / arch | Size | Ground truth | In results |');
    lines.push('| ---: | --- | --- | --- | ---: | --- | --- |');
    rows.forEach((r, i) => {
        lines.push(
            `| ${i + 1} | \`${r.id}\` | ${CATEGORY_LABEL[r.category] ?? r.category} | ${r.format}/${r.arch} | ${kib(r.size)} | ${GT_LABEL[r.gtSource] ?? r.gtSource} | ${r.benchmarked ? 'yes' : 'skipped (timebox)'} |`,
        );
    });
    return lines.join('\n');
}

function coverageTable() {
    const lines = [];
    lines.push('| Group | Binaries | Functions (full listing) | Decompile sample | Decompiled | Coverage | Failed | C lines |');
    lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
    for (const tool of TOOLS) {
        for (const cat of CATEGORIES) {
            const a = agg(tool, cat);
            if (!a) continue;
            lines.push(
                `| ${tool} · ${CATEGORY_LABEL[cat]} | ${a.binaries} | ${int(a.functions.nonThunk)} | ${int(a.functions.sampled)} | ${int(a.functions.decompiled)} | ${pct(a.functions.coveragePct)} | ${int(a.functions.failed)} | ${int(a.output.cLines)} |`,
            );
        }
        const all = agg(tool);
        if (all)
            lines.push(
                `| **${tool} · all** | **${all.binaries}** | **${int(all.functions.nonThunk)}** | **${int(all.functions.sampled)}** | **${int(all.functions.decompiled)}** | **${pct(all.functions.coveragePct)}** | **${int(all.functions.failed)}** | **${int(all.output.cLines)}** |`,
            );
    }
    return lines.join('\n');
}

function discoveryTable() {
    const lines = [];
    lines.push('| Group | GT entries | Found | Found % | Named right | Named % |');
    lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
    for (const tool of TOOLS) {
        for (const cat of CATEGORIES) {
            const a = agg(tool, cat);
            if (!a) continue;
            lines.push(
                `| ${tool} · ${CATEGORY_LABEL[cat]} | ${int(a.discovery.gtEntries)} | ${int(a.discovery.gtFound)} | ${pct(a.discovery.gtFoundPct)} | ${int(a.discovery.gtNamed)} | ${pct(a.discovery.gtNamedPct)} |`,
            );
        }
        const all = agg(tool);
        if (all)
            lines.push(
                `| **${tool} · all** | **${int(all.discovery.gtEntries)}** | **${int(all.discovery.gtFound)}** | **${pct(all.discovery.gtFoundPct)}** | **${int(all.discovery.gtNamed)}** | **${pct(all.discovery.gtNamedPct)}** |`,
            );
    }
    return lines.join('\n');
}

function callsTable() {
    const lines = [];
    lines.push('| Group | GT-named direct callees | Matched in C | Recall | Precision | F1 |');
    lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
    for (const tool of TOOLS) {
        for (const cat of CATEGORIES) {
            const a = agg(tool, cat);
            if (!a) continue;
            lines.push(
                `| ${tool} · ${CATEGORY_LABEL[cat]} | ${int(a.calls.expected)} | ${int(a.calls.matched)} | ${pct(a.calls.recallPct)} | ${pct(a.calls.precisionPct)} | ${pct(a.calls.f1Pct)} |`,
            );
        }
        const all = agg(tool);
        if (all) lines.push(`| **${tool} · all** | **${int(all.calls.expected)}** | **${int(all.calls.matched)}** | **${pct(all.calls.recallPct)}** | **${pct(all.calls.precisionPct)}** | **${pct(all.calls.f1Pct)}** |`);
    }
    return lines.join('\n');
}

function timingTable() {
    const lines = [];
    lines.push('| Group | Analysis (sum) | Decompiler (sum) | Wall (sum) | Functions/s (decompiler) |');
    lines.push('| --- | ---: | ---: | ---: | ---: |');
    for (const tool of TOOLS) {
        for (const cat of CATEGORIES) {
            const a = agg(tool, cat);
            if (!a) continue;
            const fps = a.timing.decompileMs > 0 ? (1000 * a.functions.decompiled) / a.timing.decompileMs : null;
            lines.push(
                `| ${tool} · ${CATEGORY_LABEL[cat]} | ${secs(a.timing.analysisMs)} | ${secs(a.timing.decompileMs)} | ${ms(a.timing.wallMs)} | ${fps === null ? '–' : fps.toFixed(1)} |`,
            );
        }
        const all = agg(tool);
        if (all) {
            const fps = all.timing.decompileMs > 0 ? (1000 * all.functions.decompiled) / all.timing.decompileMs : null;
            lines.push(
                `| **${tool} · all** | **${secs(all.timing.analysisMs)}** | **${secs(all.timing.decompileMs)}** | **${ms(all.timing.wallMs)}** | **${fps === null ? '–' : fps.toFixed(1)}** |`,
            );
        }
    }
    return lines.join('\n');
}

function perBinaryTable(tool) {
    const lines = [];
    lines.push('| Binary | Category | Functions | Coverage | Failed | GT found | Call recall | Call precision | Wall |');
    lines.push('| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
    for (const b of result.binaries) {
        const m = b.tools?.[tool];
        if (!m) {
            lines.push(`| \`${b.id}\` | ${CATEGORY_LABEL[b.category] ?? b.category} | – | – | – | – | – | – | – |`);
            continue;
        }
        lines.push(
            `| \`${b.id}\` | ${CATEGORY_LABEL[b.category] ?? b.category} | ${int(m.functions)} | ${pct(m.coveragePct)} | ${int(m.failed)} | ${pct(m.gtFoundPct)} | ${pct(m.callRecallPct)} | ${pct(m.callPrecisionPct)} | ${ms(m.wallMs)} |`,
        );
    }
    return lines.join('\n');
}

function failureTable(tool) {
    const lines = [];
    lines.push('| Binary | Failed functions (non-thunk) |');
    lines.push('| --- | ---: |');
    for (const b of result.binaries) {
        const m = b.tools?.[tool];
        if (!m) continue;
        lines.push(`| \`${b.id}\` | ${int(m.failed)} |`);
    }
    return lines.join('\n');
}

const sections = [
    ['Corpus', corpusTable()],
    ['Decompilation coverage (sampled)', coverageTable()],
    ['Ground-truth function discovery and naming (full listing)', discoveryTable()],
    ['Call-edge name agreement (sampled functions)', callsTable()],
    ['Time', timingTable()],
    ['Per binary: paranoia', perBinaryTable('paranoia')],
    ['Per binary: Ghidra', perBinaryTable('ghidra')],
    ['Failures: paranoia', failureTable('paranoia')],
    ['Failures: Ghidra', failureTable('ghidra')],
];

const embedTarget = process.argv.includes('--embed') ? process.argv[process.argv.indexOf('--embed') + 1] : null;
const markdown = sections.map(([title, table]) => `#### ${title}\n\n${table}\n`).join('\n');

if (embedTarget) {
    const start = '<!-- bench:tables:start -->';
    const end = '<!-- bench:tables:end -->';
    const doc = fs.readFileSync(embedTarget, 'utf8');
    if (!doc.includes(start) || !doc.includes(end)) {
        console.error(`could not find ${start} / ${end} in ${embedTarget}`);
        process.exit(1);
    }
    const before = doc.slice(0, doc.indexOf(start) + start.length);
    const after = doc.slice(doc.indexOf(end));
    fs.writeFileSync(embedTarget, `${before}\n\n${markdown}\n${after}`);
    console.log(`embedded tables into ${embedTarget}`);
} else {
    for (const [title, table] of sections) {
        console.log(`\n### ${title}\n`);
        console.log(table);
    }
}
