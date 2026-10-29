// Runs console scripts away from the UI: a dedicated worker per run, with no DOM and no
// access to the desktop bridge. The only way out is the `pn` API below, which asks the
// page to call the analysis engine for the open file. This keeps `eval`-style code out
// of the page itself, whose Content-Security-Policy forbids it.

export {};

type Msg = { type: "run"; code: string; cursor: number | null } | { type: "reply"; id: number; ok: boolean; value?: unknown; error?: string };

const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
let seq = 0;

function call<T = unknown>(method: string, args?: Record<string, unknown>): Promise<T> {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    postMessage({ type: "call", id, method, args: args ?? null });
  });
}

const fmt = (v: unknown): unknown => (v instanceof Error ? `${v.name}: ${v.message}` : v);
const print = (...a: unknown[]) => postMessage({ type: "print", args: a.map(fmt) });
const edited = (reanalyzed = false) => postMessage({ type: "edited", reanalyzed });
const hex = (v: number) => "0x" + v.toString(16).toUpperCase();

function makeApi(cursor: number | null) {
  const offsetOf = async (va: number) => {
    const off = await call<number | null>("vaToOffset", { va });
    if (off == null) throw new Error(`${hex(va)} has no file bytes`);
    return off;
  };
  return {
    /** File summary (format, arch, hashes, sections, imports, exports, …). */
    info: () => call("info"),
    /** All functions: { address, name, size, blocks, instructions, xrefs, library, … } */
    functions: () => call<Record<string, unknown>[]>("functions"),
    /** Every named address. */
    names: () => call("names"),
    strings: () => call<Record<string, unknown>[]>("strings"),
    /** Name shown for an address (or null). */
    name: async (va: number) => (await call<{ name: string | null }>("addressInfo", { va })).name,
    /** The function containing `va`. */
    functionAt: (va: number) => call("functionAt", { va }),
    /** Cross references to `va`. */
    xrefs: (va: number) => call<Record<string, unknown>[]>("xrefs", { va }),
    /** Functions called from the function containing `va`. */
    callees: (va: number) => call("callees", { va }),
    /** Listing lines (code or data) starting at `va`. */
    disasm: (va: number, count = 20) => call<Record<string, unknown>[]>("disassemble", { va, count }),
    /** Pseudocode text of the function containing `va`. */
    pseudo: async (va: number) => {
      const p = await call<{ lines: { indent: number; tokens: { t: string }[] }[] } | null>("pseudocode", { va });
      return p ? p.lines.map((l) => "    ".repeat(l.indent) + l.tokens.map((t) => t.t).join("")).join("\n") : null;
    },
    /** Bytes at a virtual address. */
    read: async (va: number, len: number) => {
      const h = await call<string>("read", { offset: await offsetOf(va), len });
      const out: number[] = [];
      for (let i = 0; i + 1 < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
      return out;
    },
    /** Searches: kind = "bytes" | "text" | "immediate". */
    search: (kind: string, query: string) => call("searchAdvanced", { kind, query }),
    rename: async (va: number, name: string) => {
      await call("rename", { va, text: name });
      edited();
    },
    comment: async (va: number, text: string) => {
      await call("setComment", { va, text });
      edited();
    },
    bookmark: async (va: number, text: string | null) => {
      await call("setBookmark", { va, text });
      edited();
    },
    makeFunction: async (va: number) => {
      await call("makeFunction", { va });
      edited(true);
    },
    /** Writes bytes at a virtual address. */
    patch: async (va: number, bytes: number[]) => {
      await call("patch", { offset: await offsetOf(va), hex: bytes.map((b) => (b & 0xff).toString(16).padStart(2, "0")).join("") });
      edited();
    },
    /** Moves the cursor (and the views) to `va`. */
    goto: (va: number) => postMessage({ type: "goto", va }),
    /** Cursor address when the script started. */
    here: () => cursor,
    hex,
    print,
  };
}

self.onmessage = async (e: MessageEvent<Msg>) => {
  const m = e.data;
  if (m.type === "reply") {
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    if (m.ok) p.resolve(m.value);
    else p.reject(new Error(m.error ?? "engine error"));
    return;
  }
  if (m.type === "run") {
    try {
      const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (...args: string[]) => (...a: unknown[]) => Promise<unknown>;
      const fn = new AsyncFunction("pn", "print", `"use strict";\n${m.code}`);
      const result = await fn(makeApi(m.cursor), print);
      let value: unknown = result;
      try {
        value = structuredClone(result);
      } catch {
        value = String(result);
      }
      postMessage({ type: "done", ok: true, value });
    } catch (err) {
      postMessage({ type: "done", ok: false, error: err instanceof Error ? `${err.name}: ${err.message}` : String(err) });
    }
  }
};
