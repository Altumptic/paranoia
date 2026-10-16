// Scripting API exposed to the console as `pn` — the Paranoia counterpart of
// IDC / IDAPython. Scripts are the user's own code and run in the UI context.

import type { SearchKind } from "./engine/types";
import { useStore } from "./store";

function session() {
  const s = useStore.getState().session;
  if (!s) throw new Error("no file is open");
  return s;
}

async function edited(reanalyzed = false) {
  await useStore.getState().afterEdit(reanalyzed);
}

const hexStr = (v: number) => "0x" + v.toString(16).toUpperCase();

export function makeApi(print: (...a: unknown[]) => void) {
  const pn = {
    /** File summary (format, arch, hashes, sections, imports, exports, …). */
    info: () => session().info(),
    /** All functions: { address, name, size, blocks, instructions, xrefs, … } */
    functions: () => session().functions(),
    /** Every named address. */
    names: () => session().names(),
    strings: () => session().strings(),
    /** Name shown for an address (or null). */
    name: async (va: number) => (await session().addressInfo(va)).name,
    /** The function containing `va`. */
    functionAt: (va: number) => session().functionAt(va),
    /** Cross references to `va`. */
    xrefs: (va: number) => session().xrefs(va),
    /** Functions called from the function containing `va`. */
    callees: (va: number) => session().callees(va),
    /** Listing lines (code or data) starting at `va`. */
    disasm: (va: number, count = 20) => session().disassemble(va, count),
    /** Pseudocode text of the function containing `va`. */
    pseudo: async (va: number) => {
      const p = await session().pseudocode(va);
      return p ? p.lines.map((l) => "    ".repeat(l.indent) + l.tokens.map((t) => t.t).join("")).join("\n") : null;
    },
    /** Bytes at a virtual address. */
    read: async (va: number, len: number) => {
      const off = await session().vaToOffset(va);
      if (off == null) throw new Error(`${hexStr(va)} has no file bytes`);
      return Array.from(await session().read(off, len));
    },
    /** Searches: kind = "bytes" | "text" | "immediate". */
    search: (kind: SearchKind, query: string) => session().searchAdvanced(kind, query),
    rename: async (va: number, name: string) => {
      await session().rename(va, name);
      await edited();
    },
    comment: async (va: number, text: string) => {
      await session().setComment(va, text);
      await edited();
    },
    bookmark: async (va: number, text: string | null) => {
      await session().setBookmark(va, text);
      await edited();
    },
    makeFunction: async (va: number) => {
      await session().makeFunction(va);
      await edited(true);
    },
    /** Writes bytes at a virtual address. */
    patch: async (va: number, bytes: number[]) => {
      const off = await session().vaToOffset(va);
      if (off == null) throw new Error(`${hexStr(va)} has no file bytes`);
      await session().patch(off, bytes.map((b) => (b & 0xff).toString(16).padStart(2, "0")).join(""));
      await edited();
    },
    /** Moves the cursor (and the views) to `va`. */
    goto: (va: number) => useStore.getState().goto(va),
    /** Current cursor address. */
    here: () => useStore.getState().cursor,
    hex: hexStr,
    print,
  };
  return pn;
}

export const EXAMPLES: { title: string; code: string }[] = [
  {
    title: "Largest functions",
    code: `const fns = await pn.functions();
fns.sort((a, b) => b.size - a.size);
for (const f of fns.slice(0, 10)) print(pn.hex(f.address), f.name, f.size, "bytes");`,
  },
  {
    title: "Callers of an import",
    code: `const name = "CreateFileW";
const imp = (await pn.info()).imports.find((i) => i.name === name);
if (!imp) print("not imported:", name);
else for (const x of await pn.xrefs(imp.address)) print(pn.hex(x.from), x.function_name, x.text);`,
  },
  {
    title: "Rename thunks to their targets",
    code: `let n = 0;
for (const f of await pn.functions()) {
  if (!f.is_import_thunk || !f.name.startsWith("sub_")) continue;
  const [line] = await pn.disasm(f.address, 1);
  const target = line?.operands.map((t) => t.t).join("");
  if (target) { await pn.rename(f.address, "j_" + target.replace(/\\W/g, "")); n++; }
}
print("renamed", n);`,
  },
  {
    title: "Strings referenced from code",
    code: `const s = (await pn.strings()).filter((x) => x.xrefs > 0);
for (const x of s.slice(0, 50)) print(pn.hex(x.address ?? 0), JSON.stringify(x.value));
print(s.length, "referenced strings");`,
  },
  {
    title: "Find XOR loops (decryption candidates)",
    code: `for (const f of (await pn.functions()).filter((f) => f.blocks > 1 && f.instructions < 400)) {
  const lines = await pn.disasm(f.address, Math.min(f.instructions, 200));
  const xors = lines.filter((l) => l.mnemonic === "xor" && !/^(\\w+), \\1$/.test(l.operands.map((t) => t.t).join("")));
  if (xors.length >= 2) print(pn.hex(f.address), f.name, xors.length, "xor");
}`,
  },
];

/** Runs a script with `pn` and `print` in scope. Top-level `await` is allowed. */
export async function runScript(code: string, print: (...a: unknown[]) => void): Promise<unknown> {
  const pn = makeApi(print);
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (...args: string[]) => (...a: unknown[]) => Promise<unknown>;
  const fn = new AsyncFunction("pn", "print", `"use strict";\n${code}`);
  return fn(pn, print);
}
