#!/usr/bin/env node
// Fills in packaging/flatpak from a release: the version, the .deb URLs and their SHA-256 sums, taken from the
// release's own SHA256SUMS (which CI signs; verify it first, docs/VERIFY.md). Nothing is downloaded here.
//
//   node scripts/flatpak-manifest.mjs --tag v0.10.0 --sums SHA256SUMS --date 2026-12-01 --out build/flatpak
import { mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = join(dirname(fileURLToPath(import.meta.url)), "..", "packaging", "flatpak");
const TAG = /^v(\d+\.\d+\.\d+)$/;

/** `sha256sum` output → { file: hash }. */
export function parseSums(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const m = /^([0-9a-f]{64}) [ *](\S+)$/.exec(line.trim());
    if (m) out[m[2]] = m[1];
  }
  return out;
}

/** The generated manifest and metainfo for a release tag (not a release candidate: Flathub tracks releases). */
export function generate({ tag, sums, date, template, metainfo }) {
  const m = TAG.exec(tag);
  if (!m) throw new Error(`"${tag}" is not a release tag (vMAJOR.MINOR.PATCH); a release candidate is not packaged`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`"${date}" is not YYYY-MM-DD`);
  const version = m[1];
  const file = (arch) => `Paranoia-${version}-linux-${arch}.deb`;
  const url = (arch) => `https://github.com/Altumptic/paranoia/releases/download/${tag}/${file(arch)}`;
  const sha = (arch) => {
    const h = sums[file(arch)];
    if (!h) throw new Error(`${file(arch)} is not in the SHA256SUMS`);
    return h;
  };
  const fill = (text) =>
    text
      .replaceAll("@DEB_X64_URL@", url("amd64"))
      .replaceAll("@DEB_X64_SHA256@", sha("amd64"))
      .replaceAll("@DEB_ARM64_URL@", url("arm64"))
      .replaceAll("@DEB_ARM64_SHA256@", sha("arm64"))
      .replaceAll("@VERSION@", version)
      .replaceAll("@TAG@", tag)
      .replaceAll("@DATE@", date);
  const manifest = fill(template);
  const info = fill(metainfo);
  if (/@[A-Z0-9_]+@/.test(manifest + info)) throw new Error("a placeholder was left unfilled");
  return { manifest, metainfo: info };
}

function main(argv) {
  const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : undefined);
  const [tag, sumsFile, date, out] = [opt("--tag"), opt("--sums"), opt("--date"), opt("--out") ?? "build/flatpak"];
  if (!tag || !sumsFile || !date) {
    console.error("usage: flatpak-manifest.mjs --tag vX.Y.Z --sums SHA256SUMS --date YYYY-MM-DD [--out DIR]");
    process.exit(2);
  }
  try {
    const r = generate({
      tag,
      sums: parseSums(readFileSync(sumsFile, "utf8")),
      date,
      template: readFileSync(join(here, "app.paranoia.Paranoia.yml.in"), "utf8"),
      metainfo: readFileSync(join(here, "app.paranoia.Paranoia.metainfo.xml.in"), "utf8"),
    });
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "app.paranoia.Paranoia.yml"), r.manifest);
    writeFileSync(join(out, "app.paranoia.Paranoia.metainfo.xml"), r.metainfo);
    for (const f of ["app.paranoia.Paranoia.desktop", "app.paranoia.Paranoia.png"]) copyFileSync(join(here, f), join(out, f));
    console.log(`wrote ${out}: flatpak-builder --user --install --force-clean build-dir ${join(out, "app.paranoia.Paranoia.yml")}`);
  } catch (e) {
    console.error(`flatpak-manifest: ${e.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
