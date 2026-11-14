// Adapter: locate Ghidra + JDK, run one headless import+analysis+post-script per
// binary, and cache the per-function JSONL dump under bench/work/ghidra/.
//
// Ghidra 12.2 requires JDK 25+; the harness uses $GHIDRA_JAVA_HOME, then a JDK
// unpacked under bench/.ghidra/jdk-*, then $JAVA_HOME, then `java` on PATH.
//
// Environment hygiene for reproducibility and for hosts with a full system
// drive: TMP/TEMP, USERPROFILE, APPDATA and LOCALAPPDATA for the Ghidra JVM are
// redirected into bench/work/ so every temp/lock/settings write stays there.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runAsync } from '../lib/proc.mjs';

export const TOOL = 'ghidra';

export function findGhidra(repoRoot) {
    const candidates = [process.env.GHIDRA_HOME, ...listDirs(path.join(repoRoot, 'bench', '.ghidra'), /^ghidra_/)]
        .filter(Boolean)
        .map((h) => path.resolve(h));
    for (const home of candidates) {
        const exe = path.join(home, 'support', process.platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless');
        if (fs.existsSync(exe)) return { home, exe, version: path.basename(home) };
    }
    throw new Error(
        'Ghidra not found. Download a public build from GitHub and unpack it under bench/.ghidra/, e.g.\n' +
            '  curl.exe -L -o bench/.ghidra/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip\n' +
            '  tar.exe -xf bench/.ghidra/ghidra.zip -C bench/.ghidra/\n' +
            'then install a JDK 25+ and point GHIDRA_JAVA_HOME at it (see bench/README.md)',
    );
}

function listDirs(dir, re) {
    try {
        return fs
            .readdirSync(dir, { withFileTypes: true })
            .filter((d) => d.isDirectory() && re.test(d.name))
            .map((d) => path.join(dir, d.name))
            .sort()
            .reverse();
    } catch {
        return [];
    }
}

function javaVersion(javaExe) {
    const r = spawnSync(javaExe, ['-version'], { encoding: 'utf8' });
    const text = (r.stderr || '') + (r.stdout || '');
    const m = /version "([^"]+)"/.exec(text);
    return { version: m ? m[1] : null, raw: text.split(/\r?\n/)[0] ?? null };
}

export function findJava(repoRoot) {
    const candidates = [
        process.env.GHIDRA_JAVA_HOME,
        ...listDirs(path.join(repoRoot, 'bench', '.ghidra'), /^jdk-?2[5-9]/),
        process.env.JAVA_HOME,
    ].filter(Boolean);
    const javaBin = process.platform === 'win32' ? 'java.exe' : 'java';
    let fallback = null;
    for (const home of candidates) {
        const exe = path.join(home, 'bin', javaBin);
        if (!fs.existsSync(exe)) continue;
        const v = javaVersion(exe);
        const major = v.version ? parseInt(v.version.split(/[.+-]/)[0], 10) : 0;
        if (major >= 25) return { home, exe, ...v, major };
        if (!fallback) fallback = { home, exe, ...v, major };
    }
    const onPath = spawnSync('java', ['-version'], { encoding: 'utf8' });
    if (!onPath.error) {
        const text = (onPath.stderr || '') + (onPath.stdout || '');
        const m = /version "([^"]+)"/.exec(text);
        return { home: null, exe: 'java', version: m ? m[1] : null, major: m ? parseInt(m[1], 10) : 0 };
    }
    return fallback;
}

function parseLog(log) {
    const text = fs.readFileSync(log, 'utf8');
    let analysisSecs = 0;
    for (const m of text.matchAll(/^.*Total Time\s+(\d+)\s+secs\s*$/gm)) analysisSecs += Number(m[1]);
    const bench = [...text.matchAll(/BENCH ghidra: .* functions=(\d+) dumped=(\d+) decompilMs=(\d+)/g)].pop();
    const failed = /REPORT SCRIPT ERROR|ERROR REPORT SCRIPT ERROR/.test(text);
    return {
        analysisSecs,
        functions: bench ? Number(bench[1]) : null,
        dumped: bench ? Number(bench[2]) : null,
        decompilMs: bench ? Number(bench[3]) : null,
        scriptError: failed,
    };
}

/** Per-run scratch directories so the host's temp/system drive is not used. */
function scratchEnv(workDir) {
    const tmp = path.join(workDir, 'tmp');
    const home = path.join(workDir, 'home');
    fs.mkdirSync(tmp, { recursive: true });
    fs.mkdirSync(path.join(home, 'AppData', 'Roaming'), { recursive: true });
    fs.mkdirSync(path.join(home, 'AppData', 'Local'), { recursive: true });
    return {
        TMP: tmp,
        TEMP: tmp,
        USERPROFILE: home,
        APPDATA: path.join(home, 'AppData', 'Roaming'),
        LOCALAPPDATA: path.join(home, 'AppData', 'Local'),
    };
}

/**
 * Runs analyzeHeadless for one binary (import + auto-analysis + post-script), or
 * returns the cached dump. Each invocation is a fresh JVM; wall time therefore
 * includes Ghidra's startup (documented in docs/BENCHMARK.md).
 * @returns {Promise<{functions: object[], callsByAddr: Map<string, object[]>, timing: object, cached: boolean}>}
 */
export async function loadOrRun({ repoRoot, binaryPath, sha256, workDir, force = false, timeoutMs = 90 * 60 * 1000, maxFunctions = 0 }) {
    const outDir = path.join(workDir, 'ghidra');
    fs.mkdirSync(outDir, { recursive: true });
    const jsonlPath = path.join(outDir, sha256 + '.ghidra.jsonl');
    const summaryPath = path.join(outDir, sha256 + '.ghidra.summary');
    const adapterPath = path.join(outDir, sha256 + '.ghidra.adapter.json');
    const logPath = path.join(outDir, sha256 + '.ghidra.log');

    const ghidra = findGhidra(repoRoot);
    const java = findJava(repoRoot);
    if (!java || !java.major || java.major < 25) {
        throw new Error(
            `Ghidra ${ghidra.version} needs JDK 25+, but Java ${java?.version ?? 'not found'} was selected. ` +
                'Install Temurin 25 under bench/.ghidra/jdk-25* or set GHIDRA_JAVA_HOME.',
        );
    }

    let timing = null;
    let cached = false;
    if (!force && fs.existsSync(jsonlPath) && fs.existsSync(summaryPath) && fs.existsSync(adapterPath)) {
        try {
            timing = JSON.parse(fs.readFileSync(adapterPath, 'utf8'));
            cached = (timing.maxFunctions ?? 0) === maxFunctions;
        } catch {
            cached = false;
        }
    }

    if (!cached) {
        // One project directory per binary so parallel headless runs never share
        // a project lock.
        const projDir = path.join(workDir, 'ghidra-proj', sha256);
        fs.rmSync(projDir, { recursive: true, force: true });
        fs.mkdirSync(projDir, { recursive: true });
        const scriptDir = path.join(repoRoot, 'bench', 'tools', 'ghidra');
        const args = [
            projDir,
            'BenchProj',
            '-import',
            binaryPath,
            '-postScript',
            'DecompileAll.java',
            '-scriptPath',
            scriptDir,
            '-deleteProject',
            '-analysisTimeoutPerFile',
            '1800',
        ];
        const env = {
            ...process.env,
            ...scratchEnv(workDir),
            PARANOIA_BENCH_OUT: outDir,
            PARANOIA_BENCH_MAX_FUNCS: String(maxFunctions),
            JAVA_HOME: java.home ?? process.env.JAVA_HOME,
        };
        if (java.home) env.PATH = path.join(java.home, 'bin') + path.delimiter + (env.PATH ?? '');
        const t0 = process.hrtime.bigint();
        const r = await runAsync(ghidra.exe, args, { env, timeoutMs, cwd: repoRoot });
        const wallMs = Number(process.hrtime.bigint() - t0) / 1e6;
        fs.writeFileSync(logPath, (r.stdout ?? '') + (r.stderr ?? ''));
        const logInfo = parseLog(logPath);
        if (!fs.existsSync(jsonlPath)) {
            throw new Error(`Ghidra produced no dump for ${binaryPath} (exit ${r.code}); see ${logPath}`);
        }
        if (logInfo.scriptError) {
            throw new Error(`Ghidra post-script failed for ${binaryPath}; see ${logPath}`);
        }
        const summary = fs.existsSync(summaryPath) ? JSON.parse(fs.readFileSync(summaryPath, 'utf8').split(/\r?\n/)[0]) : {};
        timing = {
            tool: TOOL,
            sha256,
            maxFunctions,
            ghidraVersion: ghidra.version,
            ghidraHome: ghidra.home,
            javaVersion: java.version,
            javaHome: java.home,
            wallMs: Math.round(wallMs * 10) / 10,
            analysisMs: logInfo.analysisSecs * 1000,
            decompileMs: logInfo.decompilMs ?? summary.totalDecompMs ?? null,
            scriptFunctions: logInfo.functions,
            startupOverheadMs: Math.round((wallMs - logInfo.analysisSecs * 1000 - (logInfo.decompilMs ?? 0)) * 10) / 10,
        };
        fs.writeFileSync(adapterPath, JSON.stringify(timing, null, 2) + '\n');
    }

    const records = fs
        .readFileSync(jsonlPath, 'utf8')
        .split(/\r?\n/)
        .filter((l) => l.trim())
        .map((l) => JSON.parse(l))
        .filter((r) => r.kind === 'function');

    const callsByAddr = new Map();
    for (const f of records) {
        const list = (f.calls ?? [])
            .map((c) => (c.entry ? { addr: c.entry, name: c.name ?? null } : c.name ? { name: c.name } : null))
            .filter(Boolean);
        callsByAddr.set(f.entry, list);
    }
    return { functions: records, callsByAddr, timing, cached };
}
