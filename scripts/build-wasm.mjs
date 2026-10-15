// Builds the engine for the browser (cargo -> wasm32) and copies the module
// next to the worker that loads it. Plain C ABI: no wasm-bindgen needed.
//   rustup target add wasm32-unknown-unknown
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
execFileSync("cargo", ["build", "--release", "-p", "paranoia-wasm", "--target", "wasm32-unknown-unknown"], {
  cwd: root,
  stdio: "inherit",
});
const targetDir = process.env.CARGO_TARGET_DIR ?? path.join(root, "target");
const src = path.join(targetDir, "wasm32-unknown-unknown/release/paranoia_wasm.wasm");
const dest = path.join(root, "apps/desktop/src/engine/paranoia.wasm");
mkdirSync(path.dirname(dest), { recursive: true });
copyFileSync(src, dest);
console.log(`engine -> ${path.relative(root, dest)}`);
