// Adapter: run paranoia's CLI (built from the pinned commit) over one binary and
// cache its machine-readable output under bench/work/.
//
// Outputs (for a binary with SHA-256 S):
//   work/paranoia/S.paranoia.jsonl    one JSON object per function (C text, errors)
//   work/paranoia/S.paranoia.summary  timings and totals written by the Python script
//   work/paranoia/S.inventory.json    `paranoia query <file> inventory` output (call edges)
//   work/paranoia/S.paranoia.adapter.json  wall times for both steps
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runAsync } from '../lib/proc.mjs';

export const TOOL = 'paranoia';

export function findCli(repoRoot) {
    const candidates = [
        process.env.PARANOIA_CLI,
        path.join(repoRoot, 'bench', '.build', 'target', 'release', process.platform === 'win32' ? 'paranoia.exe' : 'paranoia'),
        path.join(repoRoot, 'target', 'release', process.platform === 'win32' ? 'paranoia.exe' : 'paranoia'),
    ].filter(Boolean);
    for (const c of candidates) {
        if (fs.existsSync(c)) return c;
    }
    throw new Error(
        'paranoia CLI not found. Build it first:\n' +
            '  cargo build --release -p paranoia-cli\n' +
            'or point PARANOIA_CLI at the executable',
    );
}

export function cliVersion(cli) {
    const r = spawnSync(cli, ['--version'], { encoding: 'utf8' });
    return (r.stdout || r.stderr || '').trim() || null;
}

function readJsonl(file) {
    const out = [];
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
        if (!line.trim()) continue;
        out.push(JSON.parse(line));
    }
    return out;
}

async function runCommand(cmd, args, opts = {}) {
    const r = await runAsync(cmd, args, { maxBuffer: 1024 * 1024 * 1024, ...opts });
    if (r.code !== 0) {
        const tail = (r.stderr || r.stdout || '').split(/\r?\n/).slice(-12).join('\n');
        throw new Error(`${cmd} ${args.join(' ')} exited ${r.code}\n${tail}`);
    }
    return { wallMs: r.wallMs, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/**
 * Runs both adapter steps for one binary, or returns the cached result.
 * @returns {Promise<{functions: object[], callsByAddr: Map<string, object[]>, timing: object, cached: boolean}>}
 */
export async function loadOrRun({ repoRoot, binaryPath, sha256, workDir, force = false, maxFunctions = 0 }) {
    const outDir = path.join(workDir, 'paranoia');
    fs.mkdirSync(outDir, { recursive: true });
    const jsonlPath = path.join(outDir, sha256 + '.paranoia.jsonl');
    const summaryPath = path.join(outDir, sha256 + '.paranoia.summary');
    const inventoryPath = path.join(outDir, sha256 + '.inventory.json');
    const adapterPath = path.join(outDir, sha256 + '.paranoia.adapter.json');

    let timing = null;
    let cached = false;
    if (!force && fs.existsSync(jsonlPath) && fs.existsSync(summaryPath) && fs.existsSync(inventoryPath) && fs.existsSync(adapterPath)) {
        try {
            timing = JSON.parse(fs.readFileSync(adapterPath, 'utf8'));
            cached = (timing.maxFunctions ?? 0) === maxFunctions;
        } catch {
            cached = false;
        }
    }

    if (!cached) {
        const cli = findCli(repoRoot);
        // `paranoia script` creates a private temp dir; keep it off a possibly
        // full system drive when the caller redirected TMP/TEMP.
        const env = { ...process.env, PARANOIA_BENCH_OUT: outDir, PARANOIA_BENCH_MAX_FUNCS: String(maxFunctions) };
        // 1. One-shot inventory: functions, imports and *all* direct call edges.
        const inv = await runCommand(cli, ['query', binaryPath, 'inventory']);
        fs.writeFileSync(inventoryPath, inv.stdout);
        // 2. Per-function decompilation inside one CLI process (paranoia script).
        const dumpScript = path.join(repoRoot, 'bench', 'tools', 'paranoia-dump.py');
        const script = await runCommand(cli, ['script', binaryPath, dumpScript], { env });
        if (!script.stdout.includes('PARANOIA_BENCH_DONE')) {
            throw new Error(`paranoia script did not finish for ${binaryPath}\n${(script.stderr || '').split(/\r?\n/).slice(-10).join('\n')}`);
        }
        const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8').split(/\r?\n/)[0]);
        timing = {
            tool: TOOL,
            sha256,
            maxFunctions,
            cli,
            cliVersion: cliVersion(cli),
            inventoryWallMs: Math.round(inv.wallMs * 10) / 10,
            dumpWallMs: Math.round(script.wallMs * 10) / 10,
            wallMs: Math.round((inv.wallMs + script.wallMs) * 10) / 10,
            analysisMs: summary.analysisMs ?? null,
            decompileMs: summary.decompileMs ?? null,
            scriptWallMs: summary.wallMs ?? null,
        };
        fs.writeFileSync(adapterPath, JSON.stringify(timing, null, 2) + '\n');
    }

    const records = readJsonl(jsonlPath).filter((r) => r.kind === 'function');
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
    const callsByAddr = new Map();
    // Tail calls (`jmp` to another function or an import) read as calls in the decompiled C.
    for (const [from, to] of [...(inventory.result?.calls ?? []), ...(inventory.result?.tail_calls ?? [])]) {
        if (!callsByAddr.has(from)) callsByAddr.set(from, []);
        callsByAddr.get(from).push({ addr: to });
    }
    return { functions: records, callsByAddr, timing, cached };
}
