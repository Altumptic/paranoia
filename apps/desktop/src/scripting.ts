// JavaScript console: the Paranoia counterpart of IDC. Each run gets a fresh, dedicated
// worker (src/script-worker.ts) with no DOM and no desktop bridge; the `pn` API there
// reaches the engine through `call()` requests that this module forwards for the open
// file. The page itself never evaluates script text, so its CSP can forbid `eval`.

import { useStore } from "./store";

let current: { worker: Worker; cancel: () => void } | null = null;

/** Stops the running script, if any. */
export function stopScript() {
  const c = current;
  current = null;
  c?.worker.terminate();
  c?.cancel();
}

/** Runs `code` with `pn` and `print` in scope (top-level `await` allowed); resolves with its value. */
export function runScript(code: string, print: (...a: unknown[]) => void): Promise<unknown> {
  stopScript();
  const st = useStore.getState();
  const session = st.session;
  if (!session) return Promise.reject(new Error("no file is open"));
  const worker = new Worker(new URL("./script-worker.ts", import.meta.url), { type: "module", name: "paranoia-script" });
  return new Promise((resolve, reject) => {
    current = { worker, cancel: () => reject(new Error("stopped")) };
    let edits = false;
    let reanalyzed = false;
    const finish = async () => {
      worker.terminate();
      if (current?.worker === worker) current = null;
      if (edits) await useStore.getState().afterEdit(reanalyzed);
    };
    worker.onmessage = async (e: MessageEvent) => {
      const m = e.data as { type: string; [k: string]: unknown };
      switch (m.type) {
        case "call":
          try {
            const value = await session.backend.call(session.handle, String(m.method), m.args ?? null);
            worker.postMessage({ type: "reply", id: m.id, ok: true, value });
          } catch (err) {
            worker.postMessage({ type: "reply", id: m.id, ok: false, error: err instanceof Error ? err.message : String(err) });
          }
          break;
        case "print":
          print(...(m.args as unknown[]));
          break;
        case "goto":
          useStore.getState().goto(Number(m.va));
          break;
        case "edited":
          edits = true;
          reanalyzed ||= Boolean(m.reanalyzed);
          break;
        case "done":
          await finish();
          if (m.ok) resolve(m.value);
          else reject(new Error(String(m.error)));
          break;
      }
    };
    worker.onerror = async (e) => {
      await finish();
      reject(new Error(e.message || "script worker failed"));
    };
    worker.postMessage({ type: "run", code, cursor: st.cursor });
  });
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
