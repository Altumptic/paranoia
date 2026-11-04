// CI gate for `npm audit`: any known advisory fails the build, except the ones listed in
// ACCEPTED below. Each accepted advisory carries a reason and an expiry date (PSB §12:
// an exception without an expiry date is a violation); once a date passes the advisory
// fails the build again, which forces a review. Keep docs/PSB.md in sync with this list.
//
//   cd apps/desktop && node ../../scripts/npm-audit-gate.mjs

import { spawnSync } from "node:child_process";

/** advisory id -> { pkg, reason, until } */
const ACCEPTED = {
  "GHSA-g3hv-75wg-m249": {
    pkg: "minimatch",
    until: "2027-01-31",
    reason:
      "minimatch < 11.0.1 (DoS through glob amplification) is used only by electron-builder's packaging tools " +
      "(@electron/asar, @electron/universal, dir-compare, filelist) with fixed glob patterns from our own " +
      "package.json. The app has no runtime dependencies and app.asar contains no node_modules (PSB-EX-4).",
  },
};

const today = new Date().toISOString().slice(0, 10);
const r = spawnSync("npm", ["audit", "--json"], { encoding: "utf8", shell: process.platform === "win32", maxBuffer: 64 * 1024 * 1024 });
let report;
try {
  report = JSON.parse(r.stdout);
} catch {
  console.error("npm audit did not return JSON:\n" + (r.stdout || "") + (r.stderr || ""));
  process.exit(2);
}
if (report.error) {
  console.error("npm audit failed: " + (report.error.summary ?? JSON.stringify(report.error)));
  process.exit(2);
}

/** Every advisory in the report, once, with the packages it hits. */
const advisories = new Map();
for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of v.via ?? []) {
    if (typeof via !== "object") continue; // a pointer to another vulnerable package
    const id = (via.url ?? "").split("/").pop() || via.source;
    const a = advisories.get(id) ?? { id, title: via.title, severity: via.severity, url: via.url, packages: new Set() };
    a.packages.add(name);
    advisories.set(id, a);
  }
}

let failed = 0;
for (const a of advisories.values()) {
  const ok = ACCEPTED[a.id];
  const pkgs = [...a.packages].join(", ");
  if (ok && today <= ok.until) {
    console.log(`accepted until ${ok.until}: ${a.id} (${a.severity}) ${a.title} — ${pkgs}\n  ${ok.reason}`);
  } else {
    failed++;
    console.error(`${ok ? `EXPIRED ${ok.until}` : "FAIL"}: ${a.id} (${a.severity}) ${a.title} — ${pkgs}\n  ${a.url}`);
  }
}
const total = report.metadata?.vulnerabilities?.total ?? 0;
console.log(`\n${advisories.size} advisories (${total} affected packages): ${advisories.size - failed} accepted, ${failed} blocking`);
process.exit(failed ? 1 : 0);
