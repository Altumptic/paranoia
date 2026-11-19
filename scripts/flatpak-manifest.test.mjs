import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generate, parseSums } from "./flatpak-manifest.mjs";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "packaging", "flatpak");
const template = readFileSync(join(dir, "app.paranoia.Paranoia.yml.in"), "utf8");
const metainfo = readFileSync(join(dir, "app.paranoia.Paranoia.metainfo.xml.in"), "utf8");
const a = "a".repeat(64);
const b = "b".repeat(64);
const sums = parseSums(`${a}  Paranoia-0.10.0-linux-amd64.deb\n${b} *Paranoia-0.10.0-linux-arm64.deb\n${"c".repeat(64)}  other.zip\nnot a line\n`);

test("sums are read the way sha256sum writes them", () => {
  assert.equal(sums["Paranoia-0.10.0-linux-amd64.deb"], a);
  assert.equal(sums["Paranoia-0.10.0-linux-arm64.deb"], b);
  assert.equal(Object.keys(sums).length, 3);
});

test("the manifest gets the release's URLs and sums, and no placeholder is left", () => {
  const r = generate({ tag: "v0.10.0", sums, date: "2026-12-01", template, metainfo });
  assert.match(r.manifest, new RegExp(`url: "https://github.com/Altumptic/paranoia/releases/download/v0.10.0/Paranoia-0.10.0-linux-amd64.deb"\\n\\s+sha256: "${a}"`));
  assert.match(r.manifest, new RegExp(`sha256: "${b}"`));
  assert.match(r.metainfo, /<release version="0.10.0" date="2026-12-01">/);
  assert.doesNotMatch(r.manifest + r.metainfo, /@[A-Z0-9_]+@/);
  // The security-relevant defaults stay: no network, no home folder.
  assert.doesNotMatch(r.manifest, /--share=network|--filesystem=(home|host)/);
});

test("release candidates, missing files and bad dates are refused", () => {
  assert.throws(() => generate({ tag: "v0.10.0-rc.1", sums, date: "2026-12-01", template, metainfo }), /release candidate/);
  assert.throws(() => generate({ tag: "v0.10.1", sums, date: "2026-12-01", template, metainfo }), /not in the SHA256SUMS/);
  assert.throws(() => generate({ tag: "v0.10.0", sums, date: "yesterday", template, metainfo }), /YYYY-MM-DD/);
});
