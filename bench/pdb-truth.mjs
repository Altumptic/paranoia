#!/usr/bin/env node
// How good is the 32-bit PE function list against real symbols?
//
// The PDB Microsoft publishes for a system DLL names the functions the linker saw (public
// symbols). That is not every function (static ones are missing), but every name in it is a
// function the compiler really emitted, so it is the nearest thing to ground truth for
// compiler-generated x86 code. For each DLL this script
//   1. lists the functions the CLI finds from the file alone (no PDB),
//   2. lists the functions the PDB names (the CLI with --pdb; `source: "symbol"`),
//   3. reports how many of the PDB's functions the file-only analysis found (recall), which of
//      the missed ones are tiny stubs (16 bytes or less: thunks and interceptors, often in
//      tables of hundreds), and how many functions it lists that the PDB does not name. The
//      last number is not an error count: public PDBs leave out static functions, so a function
//      missing from the PDB can still be real. (Precision against Ghidra is in bench.json.)
// Ghidra's dump, when the benchmark has one for the same file, is scored the same way.
//
//   node bench/pdb-truth.mjs --pdbs D:/rust/tmp/pdb [--out bench/results/pdb-truth.json]
//
// <pdbs>/<dll>/<name>.pdb is expected for each DLL in System32/SysWOW64's x86 set below. PDBs
// come from https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><age>/<pdb>; the GUID is in
// `paranoia info`.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n, d) => (args.includes(n) ? args[args.indexOf(n) + 1] : d);
const pdbRoot = opt("--pdbs");
const out = opt("--out", join(here, "results", "pdb-truth.json"));
const cli = process.env.PARANOIA_CLI ?? join(here, "..", "target", "release", process.platform === "win32" ? "paranoia.exe" : "paranoia");
if (!pdbRoot) {
  console.error("usage: node bench/pdb-truth.mjs --pdbs DIR [--out FILE]");
  process.exit(2);
}
const sysDir = process.env.SYSWOW64 ?? "C:/Windows/SysWOW64";
const DLLS = ["comctl32", "crypt32", "ole32", "shlwapi", "xmllite"];

const run = (argv) => JSON.parse(execFileSync(cli, argv, { maxBuffer: 1 << 28 }).toString().replace(/^PDB [^\n]*\n/, ""));
const hex = (n) => `0x${n.toString(16)}`;

/** Ghidra's function entries for this exact file, if the benchmark dumped them. */
function ghidraStarts(file) {
  const sha = createHash("sha256").update(readFileSync(file)).digest("hex");
  const p = join(here, "work", "ghidra", `${sha}.ghidra.jsonl`);
  if (!existsSync(p)) return null;
  const starts = new Set();
  for (const line of readFileSync(p, "utf8").split("\n")) {
    if (!line.startsWith('{"kind":"function"')) continue;
    const f = JSON.parse(line);
    if (!f.external && !f.thunk) starts.add(Number.parseInt(f.entry, 16));
  }
  return starts;
}

const rows = [];
for (const dll of DLLS) {
  const file = join(sysDir, `${dll}.dll`);
  const dir = join(pdbRoot, dll);
  const pdb = existsSync(dir) ? readdirSync(dir).find((n) => n.toLowerCase().endsWith(".pdb")) : undefined;
  if (!existsSync(file) || !pdb) {
    console.error(`${dll}: missing file or PDB, skipped`);
    continue;
  }
  const own = run(["--json", "functions", file]);
  const withPdb = run(["--json", "functions", file, "--pdb", join(dir, pdb)]);
  const truth = withPdb.filter((f) => f.source === "symbol");
  const truthAt = new Set(truth.map((f) => f.address));
  const ownAt = new Set(own.map((f) => f.address));
  const found = truth.filter((f) => ownAt.has(f.address));
  const extra = own.filter((f) => !truthAt.has(f.address));
  const bySource = (list) => Object.fromEntries([...list.reduce((m, f) => m.set(f.source, (m.get(f.source) ?? 0) + 1), new Map())]);
  const missed = truth.filter((f) => !ownAt.has(f.address));
  const missedTiny = missed.filter((f) => f.size <= 16);
  const substantial = truth.length - truth.filter((f) => f.size <= 16).length;
  const row = {
    dll,
    sha256: createHash("sha256").update(readFileSync(file)).digest("hex"),
    pdb,
    pdbFunctions: truth.length,
    found: found.length,
    recall: found.length / truth.length,
    extra: extra.length,
    missedTiny: missedTiny.length,
    recallWithoutTinyStubs: (found.length - truth.filter((f) => f.size <= 16 && ownAt.has(f.address)).length) / substantial,
    extraBySource: bySource(extra),
    foundBySource: bySource(own.filter((f) => truthAt.has(f.address))),
    missedSample: missed.slice(0, 5).map((f) => `${hex(f.address)} ${f.name}`),
  };
  const g = ghidraStarts(file);
  if (g) {
    const gFound = truth.filter((f) => g.has(f.address)).length;
    row.ghidra = { functions: g.size, found: gFound, recall: gFound / truth.length, extra: [...g].filter((a) => !truthAt.has(a)).length };
  }
  rows.push(row);
  console.error(`${dll}: PDB names ${truth.length}, found ${found.length} (${(100 * row.recall).toFixed(1)} %), extra ${extra.length} (missed ${missed.length}, of them ${missedTiny.length} tiny)${row.ghidra ? `, Ghidra ${(100 * row.ghidra.recall).toFixed(1)} %` : ""}`);
}

const sum = (k) => rows.reduce((a, r) => a + r[k], 0);
const total = { pdbFunctions: sum("pdbFunctions"), found: sum("found"), extra: sum("extra"), missedTiny: sum("missedTiny") };
total.recall = total.found / total.pdbFunctions;
writeFileSync(out, JSON.stringify({ tool: "paranoia", cli: execFileSync(cli, ["--version"]).toString().trim(), rows, total }, null, 2) + "\n");
console.error(`all: ${total.found}/${total.pdbFunctions} (${(100 * total.recall).toFixed(1)} %), extra ${total.extra}, missed tiny stubs ${total.missedTiny}`);
console.error(`wrote ${resolve(out)}`);
