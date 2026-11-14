import test from "node:test";
import assert from "node:assert/strict";
import { parseTag, sections, check, notes, versions } from "./release.mjs";

test("tags: release, candidate, and everything else", () => {
  assert.deepEqual(parseTag("v0.10.0"), { version: "0.10.0", rc: null, pre: false });
  assert.deepEqual(parseTag("v1.2.3-rc.4"), { version: "1.2.3", rc: 4, pre: true });
  for (const bad of ["0.10.0", "v0.10", "v0.10.0-beta.1", "v0.10.0-rc", "v0.10.0-rc.1.2", "v0.10.0+build", "latest"]) {
    assert.equal(parseTag(bad), null, bad);
  }
});

test("changelog sections", () => {
  const s = sections("# Changelog\n\nintro\n\n## Unreleased\n\n### Changed\n- a\n\n## 0.2.0 — 2026-01-02\n\n- b\n\n## 0.1.0 — 2025-12-01\n\n- c\n");
  assert.deepEqual(s.map((x) => x.version), [null, "0.2.0", "0.1.0"]);
  assert.equal(s[1].date, "2026-01-02");
  assert.equal(s[1].body, "- b");
});

test("the repository's files agree with each other", () => {
  assert.deepEqual(check(), []);
});

test("a tag for another version is refused", () => {
  const problems = check({ tag: "v99.0.0" });
  assert.ok(problems.some((p) => p.includes("tag v99.0.0")), problems.join("\n"));
});

test("a candidate of the current version gets a banner and the download table", () => {
  const base = versions()[0].version;
  const text = notes(`v${base}-rc.2`);
  assert.match(text, new RegExp(`^> \\*\\*Release candidate 2 of ${base.replaceAll(".", "\\.")}`));
  assert.ok(text.includes(`Paranoia-Setup-${base}.exe`));
  assert.ok(text.includes(`paranoia-cli-v${base}-rc.2-linux-x64.tar.gz`));
  assert.ok(!text.includes("{{"), "unreplaced placeholder");
  assert.ok(!notes(`v${base}`).includes("Release candidate"));
});
