#!/usr/bin/env node
// Builds the ready-made FLIRT-style signature packs in `sigs/`.
//
// A pack is an IDA FLAIR `.pat` file generated from a standard library that the
// project links into every program: the Microsoft C/C++ runtime, the Rust
// standard library and musl libc. `paranoia sigmake` writes a `.pat` from a
// binary with symbols, so this script compiles "whole archive" sample binaries
// (every object file of the library linked in), turns them into `.pat` files and
// measures the result on independently built programs.
//
// The same script is used by `.github/workflows/sigpacks.yml`, so every number in
// `sigs/manifest.json` and docs/SIGNATURES.md can be reproduced.
//
// Usage:
//   node scripts/build-sigpack.mjs                  # everything this host can build
//   node scripts/build-sigpack.mjs msvc             # one pack (msvc, rust, musl, go)
//   node scripts/build-sigpack.mjs rust musl        # several
//   node scripts/build-sigpack.mjs --out sigs       # where the packs go
//   node scripts/build-sigpack.mjs --check          # verify committed packs, do not rewrite
//   node scripts/build-sigpack.mjs --keep-work      # keep the generated sample sources
//
// Requirements:
//   msvc  Windows, MSVC Build Tools 2022 (cl/link); the pack matches the exact
//         MSVC version recorded in the manifest.
//   rust  rustc with the x86_64-unknown-linux-musl target and rust-lld
//         (`rustup target add x86_64-unknown-linux-musl`).
//   musl  On Windows the script drives WSL; on Linux it uses bash/gcc directly.
//         It downloads the musl.cc x86_64-linux-musl cross toolchain (pinned by
//         SHA-256 below) and generates the pack from that toolchain's libc.a.
//   go    Only checks that Go's function table makes a pack unnecessary.

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WIN = process.platform === 'win32';
const EXE = WIN ? '.exe' : '';
const CLI = process.env.PARANOIA_CLI || path.join(ROOT, 'target', 'release', `paranoia${EXE}`);
const PACK_FORMAT = 1;
// Pinned musl.cc cross toolchain. musl.cc rebuilds its tarballs occasionally; a
// changing digest is reported instead of silently producing different signatures.
const MUSLCC_URL = 'https://musl.cc/x86_64-linux-musl-cross.tgz';
const MUSLCC_SHA256 = process.env.MUSLCC_SHA256 || 'c5d410d9f82a4f24c549fe5d24f988f85b2679b452413a9f7e5f7b956f2fe7ea';
const MUSL_VERSION = '1.2.5';
const MSVC_FORCE = '/FORCE:MULTIPLE /FORCE:UNRESOLVED';

const args = process.argv.slice(2);
const outDir = path.resolve(ROOT, option('--out', 'sigs'));
const workRoot = path.resolve(ROOT, option('--work', path.join('target', 'sigpack-work')));
const checkOnly = args.includes('--check');
const keepWork = args.includes('--keep-work');
const requested = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
const kinds = requested.length ? requested : defaultKinds();
const manifestPath = path.join(outDir, 'manifest.json');

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function option(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback;
}

function defaultKinds() {
  return WIN ? ['msvc', 'rust', 'musl', 'go'] : ['rust', 'musl', 'go'];
}

function log(msg) {
  process.stderr.write(`${msg}\n`);
}

function fail(msg) {
  throw new Error(msg);
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function write(file, text) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, text);
}

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

function sha256(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function run(cmd, cmdArgs, opts = {}) {
  const r = spawnSync(cmd, cmdArgs, {
    cwd: opts.cwd || ROOT,
    env: { ...process.env, ...(opts.env || {}) },
    encoding: 'utf8',
    maxBuffer: opts.maxBuffer || 1 << 30,
    timeout: opts.timeout || 30 * 60 * 1000,
    windowsHide: true,
  });
  if (r.error) throw new Error(`${cmd} ${cmdArgs.join(' ')}: ${r.error.message}`);
  if (r.status !== 0 && !opts.allowFail) {
    fail(`${cmd} ${cmdArgs.join(' ')} failed with exit code ${r.status}\n${(r.stdout || '').slice(-4000)}${(r.stderr || '').slice(-4000)}`);
  }
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// Runs one command line through cmd.exe with verbatim quoting, so paths with
// spaces (this repository's checkout path) work.
function cmdRun(commandLine, opts = {}) {
  const r = spawnSync('cmd.exe', ['/d', '/s', '/c', commandLine], {
    cwd: opts.cwd || ROOT,
    env: process.env,
    encoding: 'utf8',
    maxBuffer: opts.maxBuffer || 1 << 30,
    timeout: opts.timeout || 30 * 60 * 1000,
    windowsHide: true,
    windowsVerbatimArguments: true,
  });
  if (r.error) throw new Error(`${commandLine}: ${r.error.message}`);
  if (r.status !== 0 && !opts.allowFail) {
    fail(`${commandLine} failed with exit code ${r.status}\n${(r.stdout || '').slice(-4000)}${(r.stderr || '').slice(-4000)}`);
  }
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function paranoia(cmdArgs, opts = {}) {
  return run(CLI, cmdArgs, { cwd: ROOT, ...opts });
}

function paranoiaJson(cmdArgs) {
  const r = paranoia([...cmdArgs, '--json']);
  const text = r.stdout.trim();
  // `functions --json` prints an array, `sigapply --json` an object; skip any
  // preamble (there is none today, but `paranoia` may print diagnostics).
  const starts = [text.indexOf('['), text.indexOf('{')].filter((i) => i >= 0).sort((a, b) => a - b);
  for (const start of starts) {
    try {
      return JSON.parse(text.slice(start));
    } catch {
      /* try the next bracket */
    }
  }
  fail(`paranoia ${cmdArgs.join(' ')} printed no JSON:\n${text.slice(0, 2000)}\n${r.stderr.slice(0, 2000)}`);
}

// ---------------------------------------------------------------------------
// `.pat` handling: read/merge packs and reproduce paranoia's matcher for the
// "wrong name or the twin of a byte-identical function" measurement.
// ---------------------------------------------------------------------------

function parsePat(text) {
  const sigs = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('#') || line === '---') continue;
    const fields = line.split(/\s+/);
    if (fields.length !== 6) continue; // names with spaces cannot be represented in .pat
    const [patternHex, crcLenHex, crcHex, lenHex, offsetToken, name] = fields;
    if (!offsetToken.startsWith(':') || parseInt(offsetToken.slice(1), 16) !== 0) continue;
    if (patternHex.length % 2 !== 0 || patternHex.length > 64) continue;
    const pattern = [];
    for (let i = 0; i < patternHex.length; i += 2) {
      const byte = patternHex.slice(i, i + 2);
      pattern.push(byte === '..' ? null : parseInt(byte, 16));
    }
    sigs.push({
      pattern,
      crcLen: parseInt(crcLenHex, 16),
      crc: parseInt(crcHex, 16),
      len: parseInt(lenHex, 16),
      name,
      fixed: pattern.filter((b) => b !== null).length + parseInt(crcLenHex, 16),
    });
  }
  return sigs;
}

function crc16(data) {
  let crc = 0xffff;
  for (const byte of data) {
    let d = byte;
    for (let k = 0; k < 8; k++) {
      crc = (crc ^ d) & 1 ? ((crc >>> 1) ^ 0x8408) : crc >>> 1;
      d >>>= 1;
    }
  }
  crc = ~crc & 0xffff;
  return ((crc << 8) | (crc >> 8)) & 0xffff;
}

function matcher(sigs) {
  const byHead = new Map();
  const wild = [];
  sigs.forEach((s, i) => {
    if (s.fixed < 24) return;
    const [a, b] = [s.pattern[0], s.pattern[1]];
    if (a !== null && a !== undefined && b !== null && b !== undefined) {
      const key = (a << 8) | b;
      if (!byHead.has(key)) byHead.set(key, []);
      byHead.get(key).push(i);
    } else {
      wild.push(i);
    }
  });
  return (bytes) => {
    const names = [];
    if (!bytes || bytes.length < 2) return names;
    for (const i of [...(byHead.get((bytes[0] << 8) | bytes[1]) || []), ...wild]) {
      const s = sigs[i];
      if (s.fixed < 24) continue;
      const need = Math.max(s.pattern.length, 32 + s.crcLen);
      if (bytes.length < need || bytes.length < s.pattern.length) continue;
      let ok = true;
      for (let k = 0; k < s.pattern.length; k++) {
        if (s.pattern[k] !== null && s.pattern[k] !== bytes[k]) { ok = false; break; }
      }
      if (!ok) continue;
      const at = s.pattern.length;
      if (s.crcLen > 0 && (bytes.length < at + s.crcLen || crc16(bytes.subarray(at, at + s.crcLen)) !== s.crc)) continue;
      names.push(s.name);
    }
    return [...new Set(names)];
  };
}

// ---------------------------------------------------------------------------
// VA -> file bytes for the collision measurement (PE and ELF64 little-endian).
// ---------------------------------------------------------------------------

function imageBytes(file) {
  const buf = fs.readFileSync(file);
  if (buf.readUInt16LE(0) === 0x5a4d) {
    const pe = buf.readUInt32LE(0x3c);
    const numSections = buf.readUInt16LE(pe + 6);
    const optSize = buf.readUInt16LE(pe + 20);
    const opt = pe + 24;
    const magic = buf.readUInt16LE(opt);
    const imageBase = magic === 0x20b ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
    const sections = [];
    for (let i = 0; i < numSections; i++) {
      const o = opt + optSize + i * 40;
      sections.push({
        va: buf.readUInt32LE(o + 12),
        vsize: buf.readUInt32LE(o + 8),
        rawSize: buf.readUInt32LE(o + 16),
        rawPtr: buf.readUInt32LE(o + 20),
      });
    }
    return (va) => {
      const rva = va - imageBase;
      for (const s of sections) {
        if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) {
          const off = s.rawPtr + (rva - s.va);
          return off < buf.length ? buf.subarray(off, Math.min(buf.length, off + 0x1000)) : null;
        }
      }
      return null;
    };
  }
  if (buf.readUInt32BE(0) === 0x7f454c46 && buf[4] === 2) {
    const shoff = Number(buf.readBigUInt64LE(0x28));
    const shentsize = buf.readUInt16LE(0x3a);
    const shnum = buf.readUInt16LE(0x3c);
    const sections = [];
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shentsize;
      const type = buf.readUInt32LE(o + 4);
      if (type !== 1) continue; // SHT_PROGBITS (code/data)
      const addr = Number(buf.readBigUInt64LE(o + 0x10));
      const offset = Number(buf.readBigUInt64LE(o + 0x18));
      const size = Number(buf.readBigUInt64LE(o + 0x20));
      if (addr !== 0 && size !== 0) sections.push({ addr, offset, size });
    }
    return (va) => {
      for (const s of sections) {
        if (va >= s.addr && va < s.addr + s.size) {
          const off = s.offset + (va - s.addr);
          return buf.subarray(off, Math.min(buf.length, off + 0x1000));
        }
      }
      return null;
    };
  }
  return () => null;
}

// ---------------------------------------------------------------------------
// Measurement: matches of a pack applied to a test binary, compared with the
// names the test binary itself carries (PDB or symbol table).
//
// `gt` are the functions of an unstripped / PDB-symbolised twin of `target`;
// `target` is either the same PE image (PDB loaded separately for ground truth)
// or a stripped copy of the ELF image.
// ---------------------------------------------------------------------------

// Functions that count as "library functions this pack should recognize":
// a PDB library flag (MSVC) and/or a name the pack itself carries. User code
// with unrelated names is not part of the recall denominator.
// Rust's legacy mangling escapes symbols whose source name is not a plain
// identifier; Paranoia's demangler shows those escapes for `.llvm.*`-suffixed
// local symbols. Two renderings of the same symbol therefore compare unequal
// even though the signature is right, so measurement normalises both sides.
function normalizeRustSymbol(name) {
  return name
    .replace(/\.llvm\.[0-9a-f]+.*$/, '')
    .replace(/_?\$LT\$/g, '<')
    .replace(/\$GT\$/g, '>')
    .replace(/\$LP\$\(/g, '(')
    .replace(/\$RP\$\)/g, ')')
    .replace(/\$RF\$/g, '&')
    .replace(/\$BP\$/g, '*')
    .replace(/\$C\$/g, ',')
    .replace(/\$u([0-9a-fA-F]{2})\$/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/::h[0-9a-f]{16}$/g, '')
    .replace(/\.\./g, '::')
    .replace(/_/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isRelevant(f, packNames, normalize = (n) => n) {
  if (!f.name || /^sub_|^j_/.test(f.name)) return false;
  return Boolean(f.library) || packNames.has(normalize(f.name));
}

function summarize({ packName, packText, target, gt, discovered, applied, normalize = (n) => n }) {
  const sigs = parsePat(packText);
  const packNames = new Set(sigs.map((s) => normalize(s.name)));
  const matchAt = matcher(sigs);
  const gtByAddr = new Map(gt.map((f) => [f.address, f]));
  const discAddrs = new Set(discovered.map((f) => f.address));
  const namedGt = gt.filter((f) => discAddrs.has(f.address) && f.name && !/^sub_|^j_/.test(f.name));
  const relevantGt = namedGt.filter((f) => isRelevant(f, packNames, normalize));
  const gtCount = relevantGt.length;
  const bytesAt = imageBytes(target);
  let correct = 0;
  let wrong = 0;
  let collisions = 0;
  let unverifiable = 0;
  const examples = [];
  for (const [va, name] of applied) {
    const g = gtByAddr.get(va);
    if (!g || !g.name || /^sub_|^j_/.test(g.name)) {
      unverifiable++;
      continue;
    }
    if (normalize(g.name) === normalize(name)) {
      correct++;
      continue;
    }
    // A byte-identical function can legitimately carry several names (linker
    // ICF folding): if more than one signature in the pack matches these bytes,
    // the applied name is a twin name, not a wrong one.
    const twins = matchAt(bytesAt(va)).filter((n) => normalize(n) !== normalize(name));
    if (twins.length > 0) {
      collisions++;
      if (examples.length < 5) examples.push(`${va.toString(16)}: ${name} (twin: ${twins[0]}; truth: ${g.name})`);
    } else {
      wrong++;
      if (examples.length < 10) examples.push(`${va.toString(16)}: ${name} != ${g.name}`);
    }
  }
  const matched = applied.size;
  return {
    pack: packName,
    binary: path.basename(target),
    signatures: sigs.length,
    discovered: discovered.length,
    named_functions: namedGt.length,
    relevant_functions: gtCount,
    coverage_pct: namedGt.length ? round1((100 * gtCount) / namedGt.length) : 0,
    matched,
    correct,
    wrong,
    collisions,
    unverifiable,
    recall_pct: gtCount ? round1((100 * correct) / gtCount) : 0,
    precision_pct: matched ? round1((100 * (correct + collisions)) / matched) : 0,
    wrong_pct: matched ? round1((100 * wrong) / matched) : 0,
    examples,
  };
}

function round1(x) {
  return Math.round(x * 10) / 10;
}

function applyReport(target, packFile) {
  const r = paranoiaJson(['sigapply', target, packFile]);
  return new Map(r.names.map(([va, name]) => [va, name]));
}

// The pack whose recognition is measured: in `--check` mode that is the pack
// committed under sigs/ (what users actually get), otherwise the freshly built
// one. Building both and comparing their size makes toolchain drift visible.
function measurementPack(fileName, generatedFile, generatedText) {
  if (!checkOnly) return { file: generatedFile, text: generatedText };
  const committed = path.join(outDir, fileName);
  if (!fs.existsSync(committed)) fail(`committed pack ${committed} is missing; run the build without --check first`);
  const committedText = read(committed);
  const fresh = parsePat(generatedText).length;
  const current = parsePat(committedText).length;
  log(`check: ${fileName}: ${current} committed signatures, ${fresh} freshly built${fresh === current ? '' : ' (toolchain drift?)'}`);
  return { file: committed, text: committedText };
}

// ---------------------------------------------------------------------------
// Packs: the sample sources are embedded so the script is self-contained.
// ---------------------------------------------------------------------------

const MSVC_PACK_SAMPLE = `/* Paranoia signature pack sample: a tiny /MT x64 C program. It is linked with
 * /WHOLEARCHIVE for libcmt, libvcruntime and libucrt so every object file of the
 * static CRT is present, and /DEBUG so the PDB names all of them. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

static int helper(const char *s) { return (int)strlen(s); }

int main(void) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s-%d", "sigpack", helper("crt"));
    puts(buf);
    printf("%f\\n", sqrt(2.0));
    printf("%d\\n", atoi("42"));
    printf("%d\\n", rand() % 7);
    printf("%d\\n", (int)strtol("ff", NULL, 16));
    printf("%d\\n", abs(-3));
    return 0;
}
`;

const MSVC_VERIFY_C1 = `/* Independent /MT C program, /O1: not the pack sample. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <direct.h>
#include <process.h>

static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }

int main(int argc, char **argv) {
    int v[16] = {5, 3, 9, 1, 7, 2, 8, 6, 4, 0, 15, 11, 13, 12, 14, 10};
    qsort(v, 16, sizeof v[0], cmp);
    char path[260];
    _getcwd(path, sizeof path);
    printf("%s %d %d\\n", path, argc, v[0]);
    char *dup = _strdup("hello from verify 1");
    printf("%s %d\\n", dup, (int)strlen(dup));
    free(dup);
    struct tm tmv;
    time_t now = time(NULL);
    localtime_s(&tmv, &now);
    printf("%04d-%02d-%02d\\n", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
    printf("%d %d\\n", atoi(argv[0]), (int)getpid());
    _putenv_s("SIGPACK_TEST", "1");
    printf("%d\\n", _mkdir(".\\\\sigpack-test-dir"));
    return 0;
}
`;

const MSVC_VERIFY_C2 = `// Independent /MT C++ program, /O2, using the STL: not the pack sample.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>

std::string join(const std::vector<std::string> &v) {
    std::string out;
    for (const auto &s : v) out += s + ",";
    return out;
}

int main() {
    std::vector<std::string> v{"alpha", "beta", "gamma"};
    std::map<std::string, int> m;
    for (size_t i = 0; i < v.size(); ++i) m[v[i]] = static_cast<int>(i);
    std::stringstream ss;
    for (const auto &kv : m) ss << kv.first << '=' << kv.second << ';';
    std::cout << join(v) << ss.str() << std::endl;
    std::vector<int> nums(32);
    std::iota(nums.begin(), nums.end(), 1);
    std::mt19937 rng(42);
    std::shuffle(nums.begin(), nums.end(), rng);
    std::printf("%d %d\\n", nums.front(), nums.back());
    auto p = std::make_unique<std::string>("owned");
    std::printf("%s %zu\\n", p->c_str(), p->size());
    return 0;
}
`;

const MSVC_VERIFY_C3 = `/* Independent minimal /MT hello program, /O2: mostly CRT startup code. */
#include <stdio.h>

int main(void) {
    printf("hello sigpack\\n");
    return 0;
}
`;

const RUST_PACK_SAMPLE = String.raw`// Rust std signature-pack sample: exercise a broad slice of std so the linker
// pulls in many monomorphised standard-library functions.
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;

fn main() {
    let mut s = String::from("hello");
    s.push_str(" world");
    let v: Vec<u32> = (0..100).collect();
    let sum: u32 = v.iter().sum();
    let mut v2 = v.clone();
    v2.sort_unstable();
    let mut map: HashMap<String, usize> = HashMap::new();
    for (i, w) in s.split_whitespace().enumerate() {
        map.insert(w.to_string(), i);
    }
    let mut btree: BTreeMap<u64, String> = BTreeMap::new();
    btree.insert(7, "seven".into());
    let mut dq: VecDeque<u8> = VecDeque::new();
    dq.push_back(1);
    let mut out = String::new();
    writeln!(out, "{:?} {} {} {:?}", v2.get(..5), sum, map.len(), btree.len()).unwrap();
    print!("{out}");
    let parsed: Result<i64, _> = "12345".parse();
    println!("{:?} {:05.2} {:x} {:?}", parsed, std::f64::consts::PI, 255, Path::new("/tmp/x").extension());
    let path = std::env::temp_dir().join("paranoia-sigpack-rust-sample.txt");
    fs::write(&path, b"sigpack").unwrap();
    let mut f = fs::File::open(&path).unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    let _ = fs::read_dir(std::env::temp_dir());
    let _ = fs::metadata(&path);
    let _ = fs::remove_file(&path);
    let (tx, rx) = mpsc::channel::<u32>();
    let h = thread::spawn(move || {
        for i in 0..8 {
            tx.send(i * i).unwrap();
        }
    });
    let total: u32 = rx.iter().sum();
    h.join().unwrap();
    println!("{total} {}", io::stdin().lock().lines().next().is_some());
    let boxed: Box<dyn std::error::Error> = "boom".into();
    println!("{boxed}");
    let mut stdout = io::stdout();
    let _ = stdout.write_all(b"done\n");
    let _ = stdout.flush();
}
`;

const RUST_VERIFY1 = String.raw`// Independent Rust program 1 (not the pack sample).
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::process::Command;

fn main() {
    let mut set = BTreeSet::new();
    for x in [5u64, 1, 9, 3] {
        set.insert(x);
    }
    let mut h: HashMap<String, Vec<u8>> = HashMap::new();
    h.insert("a".to_string(), set.iter().map(|x| *x as u8).collect());
    let joined: String = set.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    println!("{joined} {:?}", h.get("a"));
    let mut f = fs::File::create(std::env::temp_dir().join("p-sigpack-v1.txt")).unwrap();
    writeln!(f, "{joined}").unwrap();
    let text = fs::read_to_string(std::env::temp_dir().join("p-sigpack-v1.txt")).unwrap();
    println!("{}", text.trim().len());
    let out = Command::new("echo").arg("hi").output();
    println!("{:?}", out.map(|o| o.status.success()));
    let n: i32 = "42".parse().unwrap_or(-1);
    println!("{n} {}{}", 1.5f32 * 2.0, std::char::from_u32(65).unwrap());
}
`;

const RUST_VERIFY2 = String.raw`// Independent Rust program 2 (not the pack sample).
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::time::Instant;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Point {
    x: i64,
    y: i64,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

fn main() {
    let start = Instant::now();
    let mut m = BTreeMap::new();
    for i in 0..16i64 {
        m.insert(Point { x: i, y: i * i }, i as f64);
    }
    let s: String = m.keys().map(|p| p.to_string()).collect::<Vec<_>>().join(" ");
    println!("{} {:?}", s, start.elapsed());
    let mut data = fs::read(std::env::temp_dir().join("p-sigpack-v2.txt")).unwrap_or_default();
    data.extend_from_slice(b"sigpack");
    fs::write(std::env::temp_dir().join("p-sigpack-v2.txt"), &data).unwrap();
    println!("{} {:?}", data.len(), std::env::args().count());
    let r: Result<u64, _> = "not-a-number".parse();
    println!("{:?}", r.is_err());
}
`;

const MUSL_WHOLE_ARCHIVE_C = `/* Linked with every object of musl's libc.a (--whole-archive) so the pack covers
 * the whole C library, not only the functions this program calls. */
#include <stdio.h>
int main(void) { puts("sigpack musl"); return 0; }
`;

const MUSL_VERIFY1 = `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <dirent.h>
static int cmp(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
int main(int argc, char **argv) {
    char buf[128];
    snprintf(buf, sizeof buf, "%s/%d", argv[0], argc);
    printf("%s %zu %f\\n", buf, strlen(buf), sqrt(2.0));
    int v[8] = {3, 1, 2, 8, 5, 7, 6, 4};
    qsort(v, 8, sizeof v[0], cmp);
    printf("%d %d\\n", v[0], v[7]);
    char *p = strdup(buf);
    printf("%d %ld\\n", p != NULL, (long)time(NULL) > 0);
    free(p);
    DIR *d = opendir("/");
    if (d) closedir(d);
    printf("%d\\n", abs(-7) + atoi("11"));
    return 0;
}
`;

const MUSL_VERIFY2 = `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
int main(void) {
    char out[64];
    strcpy(out, "sigpack");
    strcat(out, "-v2");
    sprintf(out + strlen(out), ":%d", 42);
    puts(out);
    printf("%d %s\\n", (int)strtol("ff", NULL, 16), strerror(ENOENT));
    wchar_t w[16];
    mbstowcs(w, out, 16);
    printf("%zu\\n", wcslen(w));
    void *m = malloc(128);
    memset(m, 0, 128);
    memcpy(m, out, 8);
    printf("%d\\n", memcmp(m, out, 8));
    free(m);
    return 0;
}
`;

const GO_SAMPLE = `// Go sample: Paranoia names Go functions from the pclntab, so a signature pack is
// not needed for Go binaries. Used to prove that claim on a stripped build.
package main

import (
	"fmt"
	"sort"
	"strings"
)

func fib(n int) int {
	if n < 2 {
		return n
	}
	return fib(n-1) + fib(n-2)
}

func main() {
	words := strings.Fields("the quick brown fox jumps over the lazy dog")
	sort.Strings(words)
	out := strings.Join(words, " ")
	fmt.Println(fib(10), len(out), out)
}
`;

// ---------------------------------------------------------------------------
// MSVC pack
// ---------------------------------------------------------------------------

function findMsvc() {
  const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  const vswhere = path.join(programFilesX86, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
  const candidates = [];
  if (fs.existsSync(vswhere)) {
    const r = run(vswhere, ['-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], { allowFail: true });
    if (r.status === 0 && r.stdout.trim()) candidates.push(r.stdout.trim().split(/\r?\n/)[0]);
  }
  candidates.push(
    'C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools',
    'C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools',
    'C:\\Program Files\\Microsoft Visual Studio\\2022\\Community',
    'C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional',
    'C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise',
  );
  for (const dir of candidates) {
    const vcvars = path.join(dir, 'VC', 'Auxiliary', 'Build', 'vcvars64.bat');
    const toolsDir = path.join(dir, 'VC', 'Tools', 'MSVC');
    if (!fs.existsSync(vcvars) || !fs.existsSync(toolsDir)) continue;
    const versions = fs
      .readdirSync(toolsDir)
      .filter((v) => /^\d+\./.test(v))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    const version = versions[versions.length - 1];
    const cl = path.join(toolsDir, version, 'bin', 'Hostx64', 'x64', 'cl.exe');
    const link = path.join(toolsDir, version, 'bin', 'Hostx64', 'x64', 'link.exe');
    if (!fs.existsSync(cl) || !fs.existsSync(link)) continue;
    const r = cmdRun(`"${cl}" 2>&1`, { allowFail: true });
    const banner = `${r.stdout}\n${r.stderr}`;
    const compiler = (banner.match(/Version\s+([\d.]+)/) || [])[1] || version;
    return { installDir: dir, vcvars, version, cl, link, compiler };
  }
  fail('MSVC Build Tools not found (cl.exe/link.exe). Install "Visual Studio Build Tools" with the C++ workload.');
}

function msvcBatch(dir, body) {
  const file = path.join(dir, 'build.cmd');
  write(file, `@echo off\r\ncall "${MSVC.vcvars}" >nul 2>&1\r\nif errorlevel 1 (echo VCVARS FAILED & exit /b 1)\r\ncd /d "${dir}"\r\n${body}\r\n`);
  // `cmd /s /c` strips the outer quotes it sees; doubling them leaves a quoted
  // path, which is what a checkout path with spaces needs.
  return cmdRun(`""${file}""`);
}

let MSVC = null;

function buildMsvc() {
  if (!WIN) fail('the MSVC pack must be built on Windows with the MSVC Build Tools installed');
  MSVC = findMsvc();
  log(`msvc: ${MSVC.installDir} (VC tools ${MSVC.version})`);
  const dir = path.join(workRoot, 'msvc');
  fs.rmSync(dir, { recursive: true, force: true });
  ensureDir(dir);
  write(path.join(dir, 'pack.c'), MSVC_PACK_SAMPLE);
  msvcBatch(
    dir,
    [
      `cl /nologo /c /O2 /MT /Zi /GS- /W3 pack.c /Fopack.obj /Fdpack_cl.pdb`,
      `link /nologo /DEBUG:FULL /INCREMENTAL:NO /OPT:NOREF /OPT:NOICF ${MSVC_FORCE} /PDB:pack.pdb /OUT:pack.exe /ENTRY:mainCRTStartup pack.obj /WHOLEARCHIVE:libcmt.lib /WHOLEARCHIVE:libvcruntime.lib /WHOLEARCHIVE:libucrt.lib`,
    ].join('\r\n'),
  );
  const exe = path.join(dir, 'pack.exe');
  const pdb = path.join(dir, 'pack.pdb');
  const libPat = path.join(dir, 'lib.pat');
  const allPat = path.join(dir, 'all.pat');
  log('msvc: sigmake --library (whole-archive CRT)');
  paranoia(['sigmake', exe, '--pdb', pdb, '--library', '-o', libPat]);
  log('msvc: sigmake (all named functions, for the header-inline CRT wrappers)');
  paranoia(['sigmake', exe, '--pdb', pdb, '-o', allPat]);
  const libLines = read(libPat)
    .split('\n')
    .filter((l) => l.trim() && !l.trim().startsWith(';') && l.trim() !== '---')
    .filter((l) => parsePat(l).length === 1);
  const libNames = new Set(parsePat(libLines.join('\n')).map((s) => s.name));
  const inlineNames = new Set(['main', 'helper']);
  const inlineLines = read(allPat)
    .split('\n')
    .filter((l) => l.trim() && !l.trim().startsWith(';') && l.trim() !== '---')
    .filter((l) => {
      const sig = parsePat(l)[0];
      if (!sig) return false;
      if (libNames.has(sig.name) || inlineNames.has(sig.name)) return false;
      return true;
    });
  const header = [
    '; Paranoia ready-made signatures: Microsoft C/C++ runtime (static /MT), x86-64.',
    '; Generated by scripts/build-sigpack.mjs from the MSVC static CRT linked whole-archive:',
    '; libcmt.lib, libvcruntime.lib and libucrt.lib, with /DEBUG so the PDB names every',
    '; function. Also includes the UCRT header inline wrappers (printf and friends) that',
    '; the compiler emits into the program itself. Format: IDA FLAIR .pat.',
    '; Do not edit by hand: run `node scripts/build-sigpack.mjs msvc`.',
  ].join('\n');
  const text = `${header}\n${libLines.join('\n')}\n${inlineLines.join('\n')}\n---\n`;
  const packFile = path.join(dir, `msvc_x64${checkOnly ? '.tmp' : ''}.pat`);
  write(packFile, text);
  const measured = measurementPack('msvc_x64.pat', packFile, text);

  // Build the independent verification programs and measure.
  write(path.join(dir, 'verify1.c'), MSVC_VERIFY_C1);
  write(path.join(dir, 'verify2.cpp'), MSVC_VERIFY_C2);
  write(path.join(dir, 'verify3.c'), MSVC_VERIFY_C3);
  msvcBatch(
    dir,
    [
      `cl /nologo /c /O1 /MT /Zi /GS- /W3 verify1.c /Foverify1.obj /Fdverify1_cl.pdb`,
      `link /nologo /DEBUG:FULL /INCREMENTAL:NO /OPT:REF /PDB:verify1.pdb /OUT:verify1.exe verify1.obj`,
      `cl /nologo /c /O2 /MT /EHsc /Zi /GS- /std:c++17 /W3 verify2.cpp /Foverify2.obj /Fdverify2_cl.pdb`,
      `link /nologo /DEBUG:FULL /INCREMENTAL:NO /OPT:REF /PDB:verify2.pdb /OUT:verify2.exe verify2.obj`,
      `cl /nologo /c /O2 /MT /Zi /GS- /W3 verify3.c /Foverify3.obj /Fdverify3_cl.pdb`,
      `link /nologo /DEBUG:FULL /INCREMENTAL:NO /OPT:REF /PDB:verify3.pdb /OUT:verify3.exe verify3.obj`,
    ].join('\r\n'),
  );
  const results = [];
  for (const n of [1, 2, 3]) {
    const target = path.join(dir, `verify${n}.exe`);
    const pdbFile = path.join(dir, `verify${n}.pdb`);
    const gt = paranoiaJson(['functions', target, '--pdb', pdbFile]);
    const discovered = paranoiaJson(['functions', target]);
    const applied = applyReport(target, measured.file);
    results.push(summarize({ packName: 'msvc_x64', packText: measured.text, target, gt, discovered, applied }));
  }
  const info = {
    name: 'msvc-crt-x64',
    file: 'msvc_x64.pat',
    kind: 'msvc',
    library: 'Microsoft C/C++ runtime (libcmt, libvcruntime, libucrt)',
    version: MSVC.version,
    compiler: `MSVC ${MSVC.version} (cl ${MSVC.compiler})`,
    target: 'x86_64-pc-windows-msvc',
    applies_to: 'x86-64 PE images linked against the Microsoft static CRT (/MT)',
    source: 'Visual Studio Build Tools static libraries',
    text,
    results,
  };
  if (!checkOnly) {
    write(path.join(outDir, 'msvc_x64.pat'), text);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Rust std pack
// ---------------------------------------------------------------------------

function rustTarget() {
  return 'x86_64-unknown-linux-musl';
}

function findRustc() {
  const rustc = process.env.RUSTC || 'rustc';
  const r = run(rustc, ['-Vv'], { allowFail: true });
  if (r.status !== 0) fail('rustc not found; install a Rust toolchain');
  const version = (r.stdout.match(/^release: (.+)$/m) || [])[1] || r.stdout.split('\n')[0];
  return { rustc, version, host: (r.stdout.match(/^host: (.+)$/m) || [])[1] || '' };
}

// Builds `sourceFile` twice (once normal, once stripped) so both binaries have
// exactly the same layout: only the symbol table is removed.
function rustBuild(dir, sourceFile, outName, extra = []) {
  run(RUSTC.rustc, [
    '--target', rustTarget(),
    '-C', 'linker=rust-lld',
    '-C', 'link-self-contained=yes',
    '-O',
    ...extra,
    sourceFile,
    '-o', path.join(dir, outName),
  ]);
}

let RUSTC = null;

function buildRust() {
  RUSTC = findRustc();
  log(`rust: rustc ${RUSTC.version} (host ${RUSTC.host}), target ${rustTarget()}`);
  const dir = path.join(workRoot, 'rust');
  fs.rmSync(dir, { recursive: true, force: true });
  ensureDir(dir);
  try {
    write(path.join(dir, 'pack_sample.rs'), RUST_PACK_SAMPLE);
    rustBuild(dir, path.join(dir, 'pack_sample.rs'), 'pack_sample');
  } catch (e) {
    fail(`cannot build for ${rustTarget()}: ${e.message}\nInstall the target with: rustup target add ${rustTarget()}`);
  }
  const packRaw = path.join(dir, 'rust_all.pat');
  log('rust: sigmake (std + the musl libc bundled with the Rust target)');
  paranoia(['sigmake', path.join(dir, 'pack_sample'), '-o', packRaw]);
  const lines = read(packRaw)
    .split('\n')
    .filter((l) => l.trim() && !l.trim().startsWith(';') && l.trim() !== '---')
    .filter((l) => {
      const sig = parsePat(l)[0];
      if (!sig) return false;
      if (sig.name === 'main' || /pack_sample/.test(sig.name)) return false;
      return true;
    });
  const header = [
    '; Paranoia ready-made signatures: Rust standard library (std/core/alloc) and the',
    `; musl libc bundled with ${rustTarget()}.`,
    '; Generated by scripts/build-sigpack.mjs from an optimized sample program built with',
    '; the same rustc; names come from the ELF symbol table. Generic monomorphisations',
    '; that collapse to identical code are ambiguous and are not matched by Paranoia.',
    '; Format: IDA FLAIR .pat. Do not edit by hand: run `node scripts/build-sigpack.mjs rust`.',
  ].join('\n');
  const text = `${header}\n${lines.join('\n')}\n---\n`;
  const packFile = path.join(dir, 'rust_x64.pat');
  write(packFile, text);
  const measured = measurementPack('rust_std_x64.pat', packFile, text);

  const results = [];
  for (const [name, source] of [
    ['verify1', RUST_VERIFY1],
    ['verify2', RUST_VERIFY2],
  ]) {
    write(path.join(dir, `${name}.rs`), source);
    rustBuild(dir, path.join(dir, `${name}.rs`), name);
    rustBuild(dir, path.join(dir, `${name}.rs`), `${name}.strip`, ['-C', 'strip=symbols']);
    const gt = paranoiaJson(['functions', path.join(dir, name)]);
    const discovered = paranoiaJson(['functions', path.join(dir, `${name}.strip`)]);
    const applied = applyReport(path.join(dir, `${name}.strip`), measured.file);
    results.push(
      summarize({
        packName: 'rust_std_x64',
        packText: measured.text,
        target: path.join(dir, `${name}.strip`),
        gt,
        discovered,
        applied,
        normalize: normalizeRustSymbol,
      }),
    );
  }
  const info = {
    name: 'rust-std-x64',
    file: 'rust_std_x64.pat',
    kind: 'rust',
    library: 'Rust standard library (std, core, alloc) and the bundled musl libc',
    version: RUSTC.version,
    compiler: `rustc ${RUSTC.version}`,
    target: `${rustTarget()} (x86-64 ELF)`,
    applies_to: 'x86-64 ELF images built with this rustc (Rust std code is not stripped from the binary)',
    source: 'rustup toolchain, x86_64-unknown-linux-musl target',
    text,
    results,
  };
  if (!checkOnly) write(path.join(outDir, 'rust_std_x64.pat'), text);
  return info;
}

// ---------------------------------------------------------------------------
// musl libc pack: built by a bash script (WSL on Windows, bash on Linux) so the
// same steps run locally and on the ubuntu CI job.
// ---------------------------------------------------------------------------

function toPosix(p) {
  return p.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d) => `/mnt/${d.toLowerCase()}`);
}

function shellQuote(s) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function buildMusl() {
  const dir = path.join(workRoot, 'musl');
  fs.rmSync(dir, { recursive: true, force: true });
  ensureDir(dir);
  write(path.join(dir, 'allcrt.c'), MUSL_WHOLE_ARCHIVE_C);
  write(path.join(dir, 'verify1.c'), MUSL_VERIFY1);
  write(path.join(dir, 'verify2.c'), MUSL_VERIFY2);
  const script = `#!/bin/bash
set -euo pipefail
CACHE="\${TMPDIR:-/tmp}/paranoia-sigpack-musl"
WORK=${shellQuote(toPosix(dir))}
mkdir -p "$CACHE" "$WORK"
cd "$CACHE"
TARBALL=x86_64-linux-musl-cross.tgz
if [ ! -f "$TARBALL" ]; then
  curl -fSL --retry 3 --retry-delay 3 -o "$TARBALL" "${MUSLCC_URL}"
fi
ACTUAL=$(sha256sum "$TARBALL" | cut -d' ' -f1)
if [ -n "${MUSLCC_SHA256}" ]; then
  if [ "$ACTUAL" != "${MUSLCC_SHA256}" ]; then
    echo "musl.cc toolchain SHA-256 changed: expected ${MUSLCC_SHA256}, got $ACTUAL" >&2
    echo "Re-pin MUSLCC_SHA256 in scripts/build-sigpack.mjs (musl.cc rebuilds its tarballs)." >&2
    exit 1
  fi
else
  echo "MUSLCC_SHA256=$ACTUAL"
fi
if [ ! -d x86_64-linux-musl-cross ]; then
  tar xzf "$TARBALL"
fi
TC="$CACHE/x86_64-linux-musl-cross"
CC="$TC/bin/x86_64-linux-musl-gcc"
"$CC" --version | head -1
LIBC=$("$CC" -print-file-name=libc.a)
CRT1=$("$CC" -print-file-name=crt1.o)
CRTI=$("$CC" -print-file-name=crti.o)
CRTN=$("$CC" -print-file-name=crtn.o)
"$CC" -c -O2 -g -o "$WORK/allcrt.o" "$WORK/allcrt.c"
# Every libc object is force-included; crt1/crti/crtn come from the same
# toolchain so the usual startup references resolve.
"$CC" -nostdlib -static -O2 -g -o "$WORK/allcrt" \\
  "$CRT1" "$CRTI" "$WORK/allcrt.o" \\
  -Wl,--whole-archive "$LIBC" -Wl,--no-whole-archive -lgcc "$CRTN"
for v in verify1 verify2; do
  "$CC" -O2 -g -static -o "$WORK/$v" "$WORK/$v.c"
  cp "$WORK/$v" "$WORK/$v.unstripped"
  "$TC/bin/x86_64-linux-musl-strip" -o "$WORK/$v.stripped" "$WORK/$v"
done
echo MUSL_BUILD_OK
`;
  const scriptFile = path.join(dir, 'build_musl.sh');
  write(scriptFile, script);
  write(path.join(dir, 'muslcc_sha.txt'), MUSLCC_SHA256 || '(not pinned)\n');
  log('musl: building the pack from the musl.cc cross toolchain (bash/WSL)');
  if (WIN) {
    run('wsl.exe', ['-e', 'bash', toPosix(scriptFile)]);
  } else {
    run('bash', [scriptFile]);
  }
  const exe = path.join(dir, 'allcrt');
  const packRaw = path.join(dir, 'musl_all.pat');
  log('musl: sigmake (whole libc.a)');
  paranoia(['sigmake', exe, '-o', packRaw]);
  const lines = read(packRaw)
    .split('\n')
    .filter((l) => l.trim() && !l.trim().startsWith(';') && l.trim() !== '---')
    .filter((l) => {
      const sig = parsePat(l)[0];
      return sig && sig.name !== 'main';
    });
  const header = [
    '; Paranoia ready-made signatures: musl libc, x86-64, statically linked.',
    `; Generated by scripts/build-sigpack.mjs from musl ${MUSL_VERSION} as shipped in the`,
    `; musl.cc x86_64-linux-musl cross toolchain (${MUSLCC_URL}), every object of libc.a`,
    '; linked with --whole-archive. Format: IDA FLAIR .pat.',
    "; Only binaries linked against this exact toolchain's libc.a match: other musl",
    '; builds (Alpine packages, other cross toolchains) compile the same source to',
    '; different machine code. Do not edit by hand: run the script.',
  ].join('\n');
  const text = `${header}\n${lines.join('\n')}\n---\n`;
  const packFile = path.join(dir, 'musl_x64.pat');
  write(packFile, text);
  const measured = measurementPack('musl_x64.pat', packFile, text);
  const results = [];
  for (const n of [1, 2]) {
    const stripped = path.join(dir, `verify${n}.stripped`);
    const gtFile = path.join(dir, `verify${n}.unstripped`);
    const gt = paranoiaJson(['functions', gtFile]);
    const discovered = paranoiaJson(['functions', stripped]);
    const applied = applyReport(stripped, measured.file);
    results.push(summarize({ packName: 'musl_x64', packText: measured.text, target: stripped, gt, discovered, applied }));
  }
  const info = {
    name: 'musl-libc-x64',
    file: 'musl_x64.pat',
    kind: 'musl',
    library: 'musl libc',
    version: MUSL_VERSION,
    compiler: 'musl.cc x86_64-linux-musl cross toolchain (musl-cross-make)',
    target: 'x86_64-linux-musl (x86-64 ELF, static)',
    applies_to: 'x86-64 ELF images statically linked against this musl.cc toolchain snapshot',
    source: MUSLCC_URL,
    text,
    results,
  };
  if (!checkOnly) write(path.join(outDir, 'musl_x64.pat'), text);
  return info;
}

// ---------------------------------------------------------------------------
// Go: prove that the pclntab makes a signature pack unnecessary.
// ---------------------------------------------------------------------------

function buildGo() {
  const go = process.env.GO || 'go';
  const probe = run(go, ['version'], { allowFail: true });
  if (probe.status !== 0) {
    log('go: not installed, skipping the Go check (the docs record the previous run)');
    return null;
  }
  const version = probe.stdout.trim();
  log(`go: ${version}`);
  const dir = path.join(workRoot, 'go');
  fs.rmSync(dir, { recursive: true, force: true });
  ensureDir(dir);
  write(path.join(dir, 'hello.go'), GO_SAMPLE);
  run(go, ['build', '-trimpath', '-o', path.join(dir, 'hello.exe'), 'hello.go'], { cwd: dir });
  run(go, ['build', '-trimpath', '-ldflags=-s -w', '-o', path.join(dir, 'hello.stripped.exe'), 'hello.go'], { cwd: dir });
  const funs = paranoiaJson(['functions', path.join(dir, 'hello.stripped.exe')]);
  const named = funs.filter((f) => !/^sub_|^j_|^go_func_/.test(f.name)).map((f) => f.name);
  const wanted = ['main.main', 'main.fib'];
  const found = wanted.filter((w) => named.includes(w));
  const result = {
    go: version,
    mode: 'Go pclntab (no signature pack needed)',
    stripped_functions: funs.length,
    named_functions: named.length,
    expected: wanted,
    found,
    ok: found.length === wanted.length,
  };
  if (!result.ok) fail(`Go pclntab check failed: expected ${wanted.join(', ')}, found ${found.join(', ') || 'none'} among ${named.length} names`);
  return result;
}

// ---------------------------------------------------------------------------
// Manifest and CLI
// ---------------------------------------------------------------------------

function manifestEntry(info, text) {
  const tmp = path.join(workRoot, info.file);
  write(tmp, text);
  const entry = {
    name: info.name,
    file: info.file,
    library: info.library,
    version: info.version,
    compiler: info.compiler,
    target: info.target,
    applies_to: info.applies_to,
    source: info.source,
    format: 'IDA FLAIR .pat',
    signatures: parsePat(text).length,
    bytes: Buffer.byteLength(text),
    sha256: sha256(tmp),
    verification: info.results,
  };
  fs.rmSync(tmp, { force: true });
  return entry;
}

function main() {
  if (!fs.existsSync(CLI)) fail(`paranoia CLI not found at ${CLI}; run: cargo build --release -p paranoia-cli`);
  const version = run(CLI, ['--version'], { allowFail: true }).stdout.trim();
  log(`paranoia: ${version} (${CLI})`);
  ensureDir(workRoot);
  ensureDir(outDir);
  const built = [];
  const results = [];
  for (const kind of kinds) {
    if (kind === 'msvc') {
      const info = buildMsvc();
      built.push(manifestEntry(info, info.text));
      results.push(...info.results);
    } else if (kind === 'rust') {
      const info = buildRust();
      built.push(manifestEntry(info, info.text));
      results.push(...info.results);
    } else if (kind === 'musl') {
      const info = buildMusl();
      built.push(manifestEntry(info, info.text));
      results.push(...info.results);
    } else if (kind === 'go') {
      const go = buildGo();
      if (go) results.push(go);
    } else {
      fail(`unknown pack kind "${kind}" (expected msvc, rust, musl or go)`);
    }
  }
  if (checkOnly) {
    // Compare against the committed manifest without rewriting packs.
    if (fs.existsSync(manifestPath)) {
      const committed = JSON.parse(read(manifestPath));
      for (const entry of built) {
        const old = (committed.packs || []).find((p) => p.file === entry.file);
        if (!old) {
          log(`check: ${entry.file} is not in the committed manifest`);
          continue;
        }
        if (old.signatures !== entry.signatures) log(`check: ${entry.file} signatures ${old.signatures} -> ${entry.signatures}`);
        if (old.sha256 !== entry.sha256) log(`check: ${entry.file} sha256 differs from the committed pack (toolchain change?)`);
      }
    }
    const report = { format: PACK_FORMAT, kind: 'verification', cli: version, packs: built, verification: results };
    write(path.join(workRoot, 'verification.json'), JSON.stringify(report, null, 2) + '\n');
    log(`check: measurements in ${path.relative(ROOT, path.join(workRoot, 'verification.json'))}`);
    printSummary(results);
    assertThresholds(results, true);
    return;
  }
  const manifest = {
    format: PACK_FORMAT,
    description: 'Ready-made library signatures embedded in Paranoia (generated; see docs/SIGNATURES.md).',
    packs: built,
    verification: results.filter((r) => r.pack),
    go: results.find((r) => r.go) || null,
    cli: version,
  };
  write(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  log(`wrote ${path.relative(ROOT, manifestPath)} (${built.reduce((n, p) => n + p.bytes, 0)} bytes)`);
  printSummary(results);
  assertThresholds(results, false);
}

// Documented minimums. They guard against a toolchain or matcher change silently
// degrading what a shipped pack recognises; update them with measured facts.
const MIN_RECALL = { msvc_x64: 45, rust_std_x64: 70, musl_x64: 80 };
const MIN_PRECISION = { msvc_x64: 90, rust_std_x64: 95, musl_x64: 95 };

function assertThresholds(results, hard) {
  const packs = new Map();
  for (const r of results.filter((x) => x.pack)) {
    const agg = packs.get(r.pack) || { correct: 0, relevant: 0, matched: 0, good: 0 };
    agg.correct += r.correct;
    agg.relevant += r.relevant_functions;
    agg.matched += r.matched;
    agg.good += r.correct + r.collisions;
    packs.set(r.pack, agg);
  }
  for (const [pack, agg] of packs) {
    const recall = agg.relevant ? round1((100 * agg.correct) / agg.relevant) : 0;
    const precision = agg.matched ? round1((100 * agg.good) / agg.matched) : 0;
    const minRecall = MIN_RECALL[pack] ?? 0;
    const minPrecision = MIN_PRECISION[pack] ?? 0;
    const ok = recall >= minRecall && precision >= minPrecision;
    const line = `thresholds: ${pack} recall=${recall}% (min ${minRecall}%), precision=${precision}% (min ${minPrecision}%)`;
    if (ok) {
      log(line);
    } else if (hard) {
      fail(`${line} - the shipped pack no longer meets the documented quality bar`);
    } else {
      log(`WARNING: ${line} - below the documented bar`);
    }
  }
}

function printSummary(results) {
  for (const r of results.filter((x) => x.pack)) {
    log(
      `${r.pack} on ${r.binary}: signatures=${r.signatures} named=${r.named_functions} relevant=${r.relevant_functions} ` +
        `matched=${r.matched} correct=${r.correct} wrong=${r.wrong} collisions=${r.collisions} ` +
        `recall=${r.recall_pct}% coverage=${r.coverage_pct}% precision=${r.precision_pct}%`,
    );
  }
  const go = results.find((r) => r.go);
  if (go) log(`go: ${go.named_functions} functions named by the pclntab in a stripped Go binary (${go.found.join(', ')})`);
}

main();
