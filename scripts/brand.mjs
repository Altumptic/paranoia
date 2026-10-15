// Generates the brand SVGs (icon, mark, lockups) from the traced whale path.
// Rasterizing to PNG/ICO is done by scripts/render-icons.mjs.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = readFileSync(path.join(root, "apps/desktop/src/brand/whale.ts"), "utf8");
const d = /WHALE_PATH =\s*"([^"]+)"/.exec(src)[1];
const [, cx, cy, r] = /cx: ([\d.]+), cy: ([\d.]+), r: ([\d.]+)/.exec(src).map(Number);

// Anthropic-like warm palette: clay, ivory, graphite.
export const CLAY = "#D97757";
export const CLAY_DEEP = "#C6613F";
export const IVORY = "#FAF9F5";
export const GRAPHITE = "#1F1E1D";

const whale = (fill, eye, transform) =>
  `<g transform="${transform}"><path d="${d}" fill="${fill}"/><circle cx="${cx}" cy="${cy}" r="${r}" fill="${eye}"/></g>`;

// App icon: clay tile, ivory whale, a quiet ivory swell line beneath it.
const icon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
  <rect x="48" y="48" width="928" height="928" rx="212" fill="${CLAY}"/>
  ${whale(IVORY, CLAY, "translate(188 300) scale(5.4)")}
  <path d="M330 716 C 410 694, 470 694, 540 712 S 668 732, 740 708" fill="none" stroke="${IVORY}" stroke-opacity=".45" stroke-width="14" stroke-linecap="round"/>
</svg>
`;

// Plain mark for light backgrounds (clay) and dark backgrounds (ivory).
// The eye is cut out with a mask so the background shows through.
const mark = (fill) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 60.2">
  <mask id="e"><rect width="120" height="61" fill="#fff"/><circle cx="${cx}" cy="${cy}" r="${r}" fill="#000"/></mask>
  <path d="${d}" fill="${fill}" mask="url(#e)"/>
</svg>
`;

mkdirSync(path.join(root, "assets/brand"), { recursive: true });
writeFileSync(path.join(root, "assets/brand/app-icon.svg"), icon);
writeFileSync(path.join(root, "assets/brand/paranoia-mark.svg"), mark(CLAY));
writeFileSync(path.join(root, "assets/brand/paranoia-mark-ivory.svg"), mark(IVORY));
writeFileSync(path.join(root, "apps/desktop/public/favicon.svg"), icon);
console.log("brand svgs written");
