// Builds (or re-copies) the benchmark corpus and writes corpus/manifest.json.
//
//   node bench/build-corpus.mjs               # build into bench/work/corpus and update the manifest
//   node bench/build-corpus.mjs --check       # build into a temp dir and verify the manifest SHA-256s
//
// The corpus is: Go binaries built from the local Go toolchain, Rust binaries
// built with the local rustc plus two real rustup toolchain binaries, and (on
// Windows) a set of signed Microsoft PE DLLs with export tables. Binaries are
// never committed; the manifest (SHA-256, size, arch, provenance) is.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parsePe } from './lib/pe.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const corpusDir = path.join(here, 'work', 'corpus');
const srcDir = path.join(here, 'corpus', 'src');
const manifestPath = path.join(here, 'corpus', 'manifest.json');

const args = new Set(process.argv.slice(2));
const checkOnly = args.has('--check');

const isWindows = process.platform === 'win32';

function log(msg) {
    console.log(msg);
}

function exec(cmd, cmdArgs, opts = {}) {
    return execFileSync(cmd, cmdArgs, { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024, ...opts }).trim();
}

function sha256File(p) {
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function archOf(file) {
    const buf = fs.readFileSync(file);
    if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
        const pe = parsePe(buf);
        const machine = { 0x8664: 'x86_64', 0x14c: 'x86', 0xaa64: 'aarch64' }[pe.machine] ?? 'pe-unknown';
        return { format: 'pe', arch: machine, bits: pe.bits };
    }
    if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
        const bits = buf[4] === 2 ? 64 : 32;
        const machine = buf.readUInt16LE(18);
        const arch = { 0x3e: 'x86_64', 0x03: 'x86', 0xb7: 'aarch64' }[machine] ?? 'elf-unknown';
        return { format: 'elf', arch, bits };
    }
    if (buf.length >= 4 && buf.readUInt32BE(0) === 0xfeedfacf) return { format: 'macho', arch: 'x86_64', bits: 64 };
    return { format: 'unknown', arch: 'unknown', bits: 0 };
}

function goCommand() {
    const go = process.env.GO ?? 'go';
    return go;
}

function goVersion() {
    return exec(goCommand(), ['version']);
}

function goRoot() {
    return exec(goCommand(), ['env', 'GOROOT']);
}

function rustcVersion() {
    return exec('rustc', ['--version']);
}

function rustSysroot() {
    return exec('rustc', ['--print', 'sysroot']);
}

// --- corpus specification ---------------------------------------------------------------
// Each build item appends a manifest entry. `provenance` is the human-readable
// "where did these bytes come from" line used in docs/BENCHMARK.md.

const entries = [];

function addFile(id, file, category, provenance, gtSource) {
    const abs = file;
    const { format, arch, bits } = archOf(abs);
    entries.push({
        id,
        file: path.basename(abs),
        sha256: sha256File(abs),
        size: fs.statSync(abs).size,
        format,
        arch,
        bits,
        category,
        gtSource,
        provenance,
    });
    log(`  ${id.padEnd(38)} ${format}/${arch} ${(fs.statSync(abs).size / 1024).toFixed(0).padStart(7)} KiB`);
}

function goBuilds() {
    const goroot = goRoot();
    const goVersionStr = goVersion();
    const srcRoot = path.join(goroot, 'src');
    if (!fs.existsSync(path.join(srcRoot, 'cmd', 'gofmt'))) {
        throw new Error(`Go source tree not found under ${srcRoot}; set GO/GOROOT to a full Go 1.23 install`);
    }
    log(`Go builds from ${srcRoot} (${goVersionStr})`);
    const gofmtVariants = [
        { id: 'gofmt_go123_amd64v1', env: { GOAMD64: 'v1' }, flags: [], note: 'GOAMD64=v1' },
        { id: 'gofmt_go123_amd64v1_stripped', env: { GOAMD64: 'v1' }, flags: ['-ldflags', '-s -w'], note: 'GOAMD64=v1, -ldflags "-s -w"' },
        { id: 'gofmt_go123_amd64v3', env: { GOAMD64: 'v3' }, flags: [], note: 'GOAMD64=v3' },
        { id: 'gofmt_go123_amd64v3_stripped', env: { GOAMD64: 'v3' }, flags: ['-ldflags', '-s -w'], note: 'GOAMD64=v3, -ldflags "-s -w"' },
    ];
    for (const v of gofmtVariants) {
        const out = path.join(corpusDir, v.id + '.exe');
        exec(goCommand(), ['build', '-trimpath', ...v.flags, '-o', out, 'cmd/gofmt'], {
            cwd: srcRoot,
            env: { ...process.env, ...v.env },
        });
        addFile(v.id, out, 'go', `built by ${v.note} with ${goVersionStr}: go build -trimpath ${v.flags.join(' ')} -o ${v.id}.exe cmd/gofmt (cwd $GOROOT/src)`, 'go-pclntab');
    }
    const gojsonVariants = [
        { id: 'gojson_go123_amd64v1', flags: [], note: 'default flags' },
        { id: 'gojson_go123_amd64v1_stripped', flags: ['-ldflags', '-s -w'], note: '-ldflags "-s -w"' },
    ];
    for (const v of gojsonVariants) {
        const out = path.join(corpusDir, v.id + '.exe');
        exec(goCommand(), ['build', '-trimpath', ...v.flags, '-o', out, path.join(srcDir, 'gojson.go')], {
            cwd: srcDir,
            env: { ...process.env, GOAMD64: 'v1' },
        });
        addFile(v.id, out, 'go', `built from bench/corpus/src/gojson.go (${v.note}) with ${goVersionStr}`, 'go-pclntab');
    }
}

function rustBuilds() {
    const version = rustcVersion();
    log(`Rust builds with ${version}`);
    const sysroot = rustSysroot();
    const jobs = [
        { id: 'rust_hello_gnu', src: 'rust-hello.rs', flags: ['-O', '-C', 'debuginfo=0'] },
        { id: 'rust_algo_gnu', src: 'rust-algo.rs', flags: ['-O', '-C', 'debuginfo=0', '-C', 'codegen-units=1'] },
    ];
    for (const j of jobs) {
        const out = path.join(corpusDir, j.id + '.exe');
        exec('rustc', [...j.flags, path.join(srcDir, j.src), '-o', out]);
        addFile(j.id, out, 'rust', `built from bench/corpus/src/${j.src} with ${version}: rustc ${j.flags.join(' ')}`, 'coff-symbols');
    }
    // Two real-world Rust binaries shipped in the rustup toolchain.
    const toolchainBins = [
        { id: 'rustfmt_gnu', bin: 'rustfmt.exe' },
        { id: 'cargo_fmt_gnu', bin: 'cargo-fmt.exe' },
    ];
    for (const t of toolchainBins) {
        const src = path.join(sysroot, 'bin', t.bin);
        if (!fs.existsSync(src)) {
            log(`  (skipping ${t.id}: ${src} not found)`);
            continue;
        }
        const out = path.join(corpusDir, t.id + '.exe');
        fs.copyFileSync(src, out);
        addFile(t.id, out, 'rust', `copied unmodified from the rustup toolchain: ${src} (${version})`, 'coff-symbols');
    }
}

const WINDOWS_DLLS = [
    'comctl32.dll',
    'version.dll',
    'winmm.dll',
    'msimg32.dll',
    'shlwapi.dll',
    'xmllite.dll',
    'crypt32.dll',
    'ole32.dll',
    'mpr.dll',
    'wkscli.dll',
    'credui.dll',
    'fltlib.dll',
];

function windowsDlls() {
    log('Windows system DLLs (x64 from System32, x86 from SysWOW64)');
    const winDir = process.env.WINDIR ?? 'C:\\Windows';
    for (const [dir, archDir, category] of [
        ['System32', 'x64', 'system-pe-x64'],
        ['SysWOW64', 'x86', 'system-pe-x86'],
    ]) {
        for (const dll of WINDOWS_DLLS) {
            const src = path.join(winDir, dir, dll);
            if (!fs.existsSync(src)) {
                log(`  (skipping ${dll}: ${src} not found)`);
                continue;
            }
            const id = dll.replace(/\.dll$/i, '') + '_win_' + archDir;
            const out = path.join(corpusDir, id + '.dll');
            fs.copyFileSync(src, out);
            addFile(id, out, category, `copied unmodified from ${src} (present on this host; version tied to the Windows build)`, 'pe-exports');
        }
    }
}

function linuxSystemElves() {
    log('Linux system ELF binaries (no export ground truth unless they have dynamic symbols)');
    for (const p of ['/usr/bin/true', '/usr/bin/ls', '/bin/cat']) {
        if (!fs.existsSync(p)) continue;
        const id = 'sys_' + path.basename(p);
        const out = path.join(corpusDir, id);
        fs.copyFileSync(p, out);
        addFile(id, out, 'system-elf', `copied unmodified from ${p}`, 'none');
    }
}

// --- main ---------------------------------------------------------------------------------
fs.mkdirSync(corpusDir, { recursive: true });
if (checkOnly) {
    log('check mode: rebuilding the corpus, not touching manifest.json');
}

goBuilds();
rustBuilds();
if (isWindows) windowsDlls();
else linuxSystemElves();

// Go/Rust binaries are deterministic for a pinned toolchain; Microsoft DLLs are not
// (they follow the host's Windows build), so the manifest is the record of this
// host's corpus. Rebuild + commit the manifest on a new host.
entries.sort((a, b) => a.id.localeCompare(b.id));

let previous = null;
try {
    previous = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
} catch {
    previous = null;
}

const manifest = {
    schema: 'paranoia-bench-corpus/1',
    corpusVersion: 1,
    host: {
        platform: process.platform,
        arch: process.arch,
        note: 'System DLL/ELF bytes depend on the host OS build; Go/Rust bytes depend on the pinned toolchain versions.',
    },
    toolchain: {
        go: goVersion(),
        goRoot: goRoot(),
        rustc: rustcVersion(),
        rustSysroot: rustSysroot(),
        node: process.version,
    },
    entries,
};

if (!checkOnly) {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    log(`\nwrote ${manifestPath} (${entries.length} binaries)`);
}

if (checkOnly) {
    if (!previous) {
        console.error(`no manifest at ${manifestPath} to check against`);
        process.exit(1);
    }
    const before = new Map(previous.entries.map((e) => [e.id, e.sha256]));
    let bad = 0;
    for (const e of entries) {
        const want = before.get(e.id);
        if (!want) {
            console.error(`  missing from manifest: ${e.id}`);
            bad++;
        } else if (want !== e.sha256) {
            console.error(`  sha256 differs: ${e.id} (manifest ${want}, built ${e.sha256})`);
            bad++;
        }
    }
    for (const id of before.keys()) {
        if (!entries.find((e) => e.id === id)) {
            console.error(`  no longer built: ${id}`);
            bad++;
        }
    }
    log(bad === 0 ? 'OK: corpus matches the manifest' : `${bad} mismatches`);
    process.exit(bad === 0 ? 0 : 1);
}
