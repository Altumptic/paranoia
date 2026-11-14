#!/usr/bin/env node
// Release bookkeeping, so a release cannot be cut from inconsistent files.
//
//   node scripts/release.mjs check [--tag vX.Y.Z[-rc.N]]   versions agree everywhere; changelog entry exists
//   node scripts/release.mjs notes --tag vX.Y.Z[-rc.N] [--out FILE]   GitHub release notes from CHANGELOG.md
//   node scripts/release.mjs bump X.Y.Z [--date YYYY-MM-DD]   set the version everywhere, close "Unreleased"
//
// Versioning rules are in docs/RELEASING.md. In short: the files carry the plain version
// (`0.10.0`); a tag is `v0.10.0` for the release and `v0.10.0-rc.1` for a release candidate
// of that same version, which the publish job marks as a pre-release.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const file = (...p) => join(root, ...p);
const read = (p) => readFileSync(file(p), "utf8").replace(/\r\n/g, "\n");

export const VERSION = /^(\d+)\.(\d+)\.(\d+)$/;
export const TAG = /^v(\d+\.\d+\.\d+)(?:-rc\.(\d+))?$/;

/** `v0.10.0-rc.2` -> { version: "0.10.0", rc: 2, pre: true }; null when the tag is not ours. */
export function parseTag(tag) {
  const m = TAG.exec(tag);
  if (!m) return null;
  return { version: m[1], rc: m[2] ? Number(m[2]) : null, pre: m[2] !== undefined };
}

const WORKSPACE_CRATES = ["paranoia-cli", "paranoia-core", "paranoia-db", "paranoia-engine", "paranoia-wasm"];

/** Every place a version number lives, as { where, version } pairs. */
export function versions() {
  const out = [];
  const cargo = read("Cargo.toml");
  const ws = /\[workspace\.package\][^[]*?\nversion\s*=\s*"([^"]+)"/.exec(cargo);
  out.push({ where: "Cargo.toml [workspace.package]", version: ws?.[1] });
  const lock = read("Cargo.lock");
  for (const name of WORKSPACE_CRATES) {
    const m = new RegExp(`\\[\\[package\\]\\]\\nname = "${name}"\\nversion = "([^"]+)"`).exec(lock);
    out.push({ where: `Cargo.lock ${name}`, version: m?.[1] });
  }
  const pkg = JSON.parse(read("apps/desktop/package.json"));
  out.push({ where: "apps/desktop/package.json", version: pkg.version });
  const plock = JSON.parse(read("apps/desktop/package-lock.json"));
  out.push({ where: "apps/desktop/package-lock.json", version: plock.version });
  out.push({ where: 'apps/desktop/package-lock.json packages[""]', version: plock.packages?.[""]?.version });
  return out;
}

/** The CHANGELOG sections in file order: { title, version|null, date|null, body }. */
export function sections(changelog) {
  const parts = changelog.split(/^## /m).slice(1);
  return parts.map((p) => {
    const nl = p.indexOf("\n");
    const title = p.slice(0, nl).trim();
    const m = /^(\d+\.\d+\.\d+)\s+—\s+(\d{4}-\d{2}-\d{2})$/.exec(title);
    return { title, version: m?.[1] ?? null, date: m?.[2] ?? null, body: p.slice(nl + 1).trim() };
  });
}

/** Problems that stop a release; an empty list means the files agree. */
export function check({ tag } = {}) {
  const problems = [];
  const found = versions();
  for (const v of found) {
    if (!v.version) problems.push(`${v.where}: no version found`);
    else if (!VERSION.test(v.version)) problems.push(`${v.where}: "${v.version}" is not MAJOR.MINOR.PATCH`);
  }
  const base = found[0].version;
  for (const v of found) if (v.version && v.version !== base) problems.push(`${v.where} is ${v.version}, Cargo.toml says ${base}`);

  const all = sections(read("CHANGELOG.md"));
  const unreleased = all.find((s) => s.title.toLowerCase() === "unreleased");
  const entry = all.find((s) => s.version === base);
  const parsed = tag ? parseTag(tag) : null;
  if (tag && !parsed) problems.push(`tag "${tag}" is not vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N`);
  if (parsed && parsed.version !== base) problems.push(`tag ${tag} is for ${parsed.version} but the files say ${base}`);

  if (tag) {
    if (!entry) problems.push(`CHANGELOG.md has no "## ${base} — YYYY-MM-DD" section`);
    else if (!/^###? /m.test(entry.body) && !/^- /m.test(entry.body)) problems.push(`CHANGELOG.md section ${base} is empty`);
    if (parsed && !parsed.pre && unreleased && /^- /m.test(unreleased.body)) {
      problems.push('CHANGELOG.md still lists entries under "Unreleased"; move them into the release section');
    }
  }
  // Newest first, each version once, versions strictly decreasing: catches a mis-pasted heading.
  const dated = all.filter((s) => s.version);
  for (let i = 1; i < dated.length; i++) {
    if (cmp(dated[i - 1].version, dated[i].version) <= 0) problems.push(`CHANGELOG.md: ${dated[i - 1].version} must come before ${dated[i].version} (newest first, no repeats)`);
  }
  for (const s of all) if (s.title !== "Unreleased" && !s.version) problems.push(`CHANGELOG.md: heading "## ${s.title}" is neither "Unreleased" nor "X.Y.Z — YYYY-MM-DD"`);
  return problems;
}

function cmp(a, b) {
  const x = a.split(".").map(Number), y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

/** Release notes: the CHANGELOG section, then the download table and verification steps from the template. */
export function notes(tag) {
  const parsed = parseTag(tag);
  if (!parsed) throw new Error(`tag "${tag}" is not vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N`);
  const entry = sections(read("CHANGELOG.md")).find((s) => s.version === parsed.version);
  if (!entry) throw new Error(`CHANGELOG.md has no section for ${parsed.version}`);
  let template = read(".github/release-notes.md");
  template = template.replaceAll("{{version}}", parsed.version).replaceAll("{{tag}}", tag);
  const head = parsed.pre
    ? `> **Release candidate ${parsed.rc} of ${parsed.version}.** For testing: it is built and checked like a release, and becomes ${parsed.version} unchanged unless problems are found. The version inside the files is ${parsed.version}.\n\n`
    : "";
  return `${head}${entry.body}\n\n${template}`.replace(/\n{3,}/g, "\n\n").trim() + "\n";
}

/** Set the version in every file and turn "Unreleased" into the new release section. */
export function bump(version, date) {
  if (!VERSION.test(version)) throw new Error(`"${version}" is not MAJOR.MINOR.PATCH`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`"${date}" is not YYYY-MM-DD`);
  const edit = (p, fn) => writeFileSync(file(p), fn(readFileSync(file(p), "utf8")));
  edit("Cargo.toml", (t) => t.replace(/(\[workspace\.package\][^[]*?\nversion\s*=\s*")[^"]+(")/, `$1${version}$2`));
  edit("Cargo.lock", (t) => {
    for (const name of WORKSPACE_CRATES) t = t.replace(new RegExp(`(\\[\\[package\\]\\]\\r?\\nname = "${name}"\\r?\\nversion = ")[^"]+(")`), `$1${version}$2`);
    return t;
  });
  edit("apps/desktop/package.json", (t) => t.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`));
  edit("apps/desktop/package-lock.json", (t) => {
    const lock = JSON.parse(t);
    lock.version = version;
    if (lock.packages?.[""]) lock.packages[""].version = version;
    return JSON.stringify(lock, null, 2) + "\n";
  });
  edit("CHANGELOG.md", (t) => {
    if (!/^## Unreleased\s*$/m.test(t)) throw new Error('CHANGELOG.md has no "## Unreleased" section');
    return t.replace(/^## Unreleased\s*$/m, `## Unreleased\n\n## ${version} — ${date}`);
  });
}

function main(argv) {
  const [cmd, ...rest] = argv;
  const opt = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
  try {
    if (cmd === "check") {
      const tag = opt("--tag");
      const problems = check({ tag });
      if (problems.length) { for (const p of problems) console.error(`release check: ${p}`); process.exit(1); }
      console.log(`release check: ok (${versions()[0].version}${tag ? `, tag ${tag}` : ""})`);
    } else if (cmd === "notes") {
      const tag = opt("--tag");
      if (!tag) throw new Error("--tag is required");
      const text = notes(tag);
      const out = opt("--out");
      if (out) writeFileSync(out, text); else process.stdout.write(text);
    } else if (cmd === "bump") {
      const version = rest[0];
      bump(version, opt("--date") ?? new Date().toISOString().slice(0, 10));
      console.log(`bumped to ${version}; review with git diff, then run: node scripts/release.mjs check`);
    } else {
      console.error("usage: release.mjs check [--tag TAG] | notes --tag TAG [--out FILE] | bump X.Y.Z [--date YYYY-MM-DD]");
      process.exit(2);
    }
  } catch (e) {
    console.error(`release: ${e.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
