import { create } from "zustand";

import type { DebugSnapshot } from "./debug";
import { desktop, getBackend, Session, type OpenSource, type PluginInfo, type RecentFile } from "./engine/client";
import { memory, type DiffReport } from "./engine/memory";
import { pickFile } from "./files";
import { runScript } from "./scripting";
import type { AnalysisStats, Annotations, BinaryInfo, FunctionSummary, InsnPatch, Instruction, SearchKind } from "./engine/types";

export type SidebarTab = "functions" | "names" | "imports" | "exports" | "strings" | "sections" | "symbols" | "types" | "bookmarks";
export type CenterTab = "overview" | "disasm" | "graph" | "pseudo" | "calls" | "hex";

export interface Toast {
  id: number;
  kind: "info" | "error" | "success";
  text: string;
}

interface State {
  session: Session | null;
  info: BinaryInfo | null;
  stats: AnalysisStats | null;
  functions: FunctionSummary[];
  /** Path on disk (desktop only), used for "recent files". */
  path: string | null;

  loading: { name: string; phase: string } | null;
  recent: RecentFile[];

  cursor: number | null;
  history: number[];
  historyIndex: number;

  sidebarTab: SidebarTab;
  centerTab: CenterTab;
  sidebarOpen: boolean;
  inspectorOpen: boolean;
  paletteOpen: boolean;
  showBytes: boolean;
  /** Bumped after edits so views refetch. */
  revision: number;
  toasts: Toast[];
  dialog: null | { kind: "rename" | "comment" | "bookmark" | "struct" | "enum" | "vartype" | "varname" | "assemble"; va: number; initial: string; value?: number; ins?: Instruction; varName?: string };
  annotations: Annotations;
  search: SearchKind | null;
  menuOpen: boolean;
  aboutOpen: boolean;
  /** Help → Check for updates (desktop app only). */
  updateOpen: boolean;
  aiSettingsOpen: boolean;
  /** Analysis → Function memory dialog. */
  memoryOpen: boolean;
  /** Analysis → Compare with another file: the second file and the match report. */
  compare: null | { other: Session; name: string; report: DiffReport };
  assistant: null | { title: string; fn: string; va: number | null; state: "busy" | "done" | "error"; text: string; name: { name: string; reason: string } | null; host: string; local: boolean };
  plugins: { dir: string; list: PluginInfo[]; errors: { id: string; error: string }[] };
  /** Token text highlighted across views (IDA's yellow highlight). */
  highlight: string | null;
  /** Address whose cross references are shown in the X dialog. */
  xrefsFor: number | null;
  contextMenu: null | { x: number; y: number; va: number; ins: Instruction | null };
  consoleOpen: boolean;
  debugOpen: boolean;
  debug: DebugSnapshot | null;
  /** Breakpoints as static VAs (kept across debug sessions). */
  breakpoints: Set<number>;
  log: { t: number; kind: "info" | "error" | "out"; text: string }[];
  undoDepth: [number, number];

  open(src: OpenSource): Promise<void>;
  close(): Promise<void>;
  loadRecent(): Promise<void>;
  goto(va: number, opts?: { tab?: CenterTab; record?: boolean }): void;
  setCursor(va: number): void;
  back(): void;
  forward(): void;
  rename(va: number, name: string): Promise<void>;
  comment(va: number, text: string): Promise<void>;
  makeFunction(va: number): Promise<void>;
  bookmark(va: number, text: string | null): Promise<void>;
  reanalyze(): Promise<void>;
  patch(offset: number, hex: string): Promise<void>;
  revertPatches(): Promise<void>;
  exportIdc(): Promise<void>;
  /** Apply a `.pat` signature file chosen by the user. */
  applySignatures(): Promise<void>;
  /** Save a `.pat` file for this binary's named functions. */
  makeSignatures(): Promise<void>;
  loadPdb(src?: { path: string } | { bytes: ArrayBuffer }): Promise<void>;
  savePatched(): Promise<void>;
  item(op: "undefine" | "code" | "data" | "string", va: number): Promise<void>;
  patchInsn(va: number, op: InsnPatch): Promise<void>;
  undo(): Promise<void>;
  redo(): Promise<void>;
  /** Refreshes derived state after an engine-side edit. */
  afterEdit(reanalyzed: boolean): Promise<void>;
  askAssistant(task: "explain" | "name" | "suspicious"): Promise<void>;
  /** Opens a second file and matches its functions against the open one. */
  compareWith(): Promise<void>;
  closeCompare(): Promise<void>;
  loadPlugins(): Promise<void>;
  runPlugin(id: string, commandId: string): Promise<void>;
  print(text: string, kind?: "info" | "error" | "out"): void;
  set<K extends keyof State>(key: K, value: State[K]): void;
  toast(text: string, kind?: Toast["kind"]): void;
}

let toastSeq = 0;

export const useStore = create<State>((set, get) => ({
  session: null,
  info: null,
  stats: null,
  functions: [],
  path: null,
  loading: null,
  recent: [],
  cursor: null,
  history: [],
  historyIndex: -1,
  sidebarTab: "functions",
  centerTab: "overview",
  sidebarOpen: true,
  inspectorOpen: true,
  paletteOpen: false,
  showBytes: false,
  revision: 0,
  toasts: [],
  dialog: null,
  annotations: { names: {}, comments: {} },
  search: null,
  menuOpen: false,
  aboutOpen: false,
  updateOpen: false,
  aiSettingsOpen: false,
  memoryOpen: false,
  compare: null,
  assistant: null,
  plugins: { dir: "", list: [], errors: [] },
  highlight: null,
  xrefsFor: null,
  contextMenu: null,
  consoleOpen: false,
  debugOpen: false,
  debug: null,
  breakpoints: new Set<number>(),
  log: [],
  undoDepth: [0, 0],

  async open(src) {
    const name = src.kind === "bytes" ? src.name : (src.path.split(/[\\/]/).pop() ?? src.path);
    set({ loading: { name, phase: "Parsing headers and analyzing code…" } });
    const prev = get().session;
    try {
      const session = await Session.open(src);
      set({ loading: { name, phase: "Building function list…" } });
      const info = await session.info();
      const backend = getBackend();
      const saved = await backend.loadAnnotations(info.hashes.sha256).catch(() => null);
      if (saved) await session.setAnnotations(saved);
      const [stats, functions, annotations] = await Promise.all([session.stats(), session.functions(), session.annotations()]);
      if (prev) prev.close().catch(() => {});
      const path = src.kind === "path" ? src.path : null;
      const start = info.entry || functions[0]?.address || null;
      set({
        session,
        info,
        stats,
        functions,
        annotations,
        path,
        loading: null,
        cursor: start,
        history: start != null ? [start] : [],
        historyIndex: start != null ? 0 : -1,
        centerTab: "overview",
        revision: get().revision + 1,
      });
      get().print(
        `${info.file_name}: ${info.format.toUpperCase()} ${info.arch} — ${stats.functions} functions, ${stats.instructions} instructions, ${stats.strings} strings` +
          (stats.millis ? ` in ${stats.millis} ms` : ""),
        "info",
      );
      set({ undoDepth: await session.history() });
      if (path && info.format === "pe") {
        const pdb = await session.findPdb(path).catch(() => null);
        if (pdb) await get().loadPdb({ path: pdb });
      }
      await backend.addRecent({
        name: info.file_name,
        path,
        sha256: info.hashes.sha256,
        format: info.format,
        arch: info.arch,
        size: info.file_size,
        openedAt: Date.now(),
      });
      get().loadRecent();
    } catch (e) {
      set({ loading: null });
      get().toast(`Could not open ${name}: ${e instanceof Error ? e.message : String(e)}`, "error");
    }
  },

  async close() {
    await get().closeCompare();
    const s = get().session;
    set({ session: null, info: null, stats: null, functions: [], cursor: null, history: [], historyIndex: -1, path: null, debug: null, debugOpen: false, breakpoints: new Set() });
    await s?.close().catch(() => {});
    get().loadRecent();
  },

  async loadRecent() {
    set({ recent: await getBackend().recent().catch(() => []) });
  },

  goto(va, opts) {
    const { history, historyIndex, centerTab } = get();
    const record = opts?.record ?? true;
    let tab = opts?.tab ?? centerTab;
    if (tab === "overview") tab = "disasm";
    // Data (import slots, strings, globals) is shown as bytes rather than bogus instructions.
    if (!opts?.tab && (tab === "graph" || tab === "pseudo" || tab === "calls") && !isCode(get().info, va)) tab = "disasm";
    if (record && history[historyIndex] !== va) {
      const h = history.slice(0, historyIndex + 1);
      h.push(va);
      if (h.length > 200) h.shift();
      set({ history: h, historyIndex: h.length - 1 });
    }
    set({ cursor: va, centerTab: tab });
  },

  setCursor(va) {
    // Moving the caret inside a view updates the current history slot instead of adding one.
    const { history, historyIndex } = get();
    if (historyIndex >= 0) {
      const h = history.slice();
      h[historyIndex] = va;
      set({ history: h });
    }
    set({ cursor: va });
  },

  back() {
    const { history, historyIndex } = get();
    if (historyIndex > 0) set({ historyIndex: historyIndex - 1, cursor: history[historyIndex - 1] });
  },

  forward() {
    const { history, historyIndex } = get();
    if (historyIndex < history.length - 1) set({ historyIndex: historyIndex + 1, cursor: history[historyIndex + 1] });
  },

  async rename(va, name) {
    const { session, info } = get();
    if (!session || !info) return;
    await session.rename(va, name);
    await get().afterEdit(false);
    set({ functions: await session.functions() });
  },

  async comment(va, text) {
    const { session, info } = get();
    if (!session || !info) return;
    await session.setComment(va, text);
    await get().afterEdit(false);
  },

  async item(op, va) {
    const { session, info } = get();
    if (!session || !info) return;
    try {
      let reanalyzed = false;
      if (op === "undefine") reanalyzed = await session.undefine(va);
      else if (op === "code") await session.makeCode(va);
      else if (op === "string") await session.makeString(va);
      else get().toast(`Defined ${await session.cycleData(va)}`, "info");
      await get().afterEdit(reanalyzed);
    } catch (e) {
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async patchInsn(va, op) {
    const { session } = get();
    if (!session) return;
    try {
      await session.patchInstruction(va, op);
      await get().afterEdit(false);
      get().toast(op === "nop" ? "Instruction replaced with NOPs" : op === "invert" ? "Condition inverted" : "Jump made unconditional", "success");
    } catch (e) {
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async undo() {
    const { session } = get();
    if (!session) return;
    const r = await session.undo();
    if (r == null) return get().toast("Nothing to undo");
    await get().afterEdit(r);
    get().toast("Undone", "info");
  },

  async redo() {
    const { session } = get();
    if (!session) return;
    const r = await session.redo();
    if (r == null) return get().toast("Nothing to redo");
    await get().afterEdit(r);
    get().toast("Redone", "info");
  },

  async afterEdit(reanalyzed) {
    const { session, info } = get();
    if (!session || !info) return;
    const [annotations, undoDepth] = await Promise.all([persist(session, info), session.history()]);
    const extra = reanalyzed ? { functions: await session.functions(), stats: await session.stats() } : {};
    set({ annotations, undoDepth, revision: get().revision + 1, ...extra });
  },

  async compareWith() {
    const { session } = get();
    if (!session || !desktop) return;
    const src = await pickFile();
    if (!src) return;
    const name = src.kind === "bytes" ? src.name : (src.path.split(/[\\/]/).pop() ?? src.path);
    set({ loading: { name, phase: "Analyzing the second file…" } });
    let other: Session | null = null;
    try {
      other = await Session.open(src);
      const info = await other.info();
      // Its names from the workspace, so they can be carried over.
      const saved = await getBackend().loadAnnotations(info.hashes.sha256).catch(() => null);
      if (saved) await other.setAnnotations(saved);
      await other.stats();
      set({ loading: { name, phase: "Matching functions…" } });
      const report = await memory.diff(session, other);
      await get().closeCompare();
      set({ loading: null, compare: { other, name: info.file_name, report } });
    } catch (e) {
      set({ loading: null });
      other?.close().catch(() => {});
      get().toast(`Compare failed: ${e instanceof Error ? e.message : String(e)}`, "error");
    }
  },

  async closeCompare() {
    const c = get().compare;
    if (!c) return;
    set({ compare: null });
    await c.other.close().catch(() => {});
  },

  async askAssistant(task) {
    const { session, cursor, info } = get();
    if (!desktop || !session || cursor == null) return;
    const titles = { explain: "Explain function", name: "Suggest a name", suspicious: "Flag suspicious behaviour" } as const;
    const title = titles[task];
    try {
      const f = await session.functionAt(cursor);
      if (!f) return get().toast("Put the cursor inside a function first", "error");
      const s = await desktop.ai.get();
      if (!s.endpoint) {
        get().toast("The assistant is off — set it up first", "info");
        set({ aiSettingsOpen: true });
        return;
      }
      set({ assistant: { title, fn: f.name, va: f.address, state: "busy", text: "", name: null, host: s.host, local: s.local } });
      const pc = await session.pseudocode(f.address);
      if (!pc || pc.lines.length === 0) throw new Error("There is no pseudocode for this function (x86 / x64 only)");
      const code = pc.lines.map((l) => "  ".repeat(l.indent) + l.tokens.map((t) => t.t).join("")).join("\n");
      // Redaction needs the file's strings: they give literals their numbering and the engine's
      // auto names (`aHelloWorld`), the same way `paranoia mcp` does it.
      const strings = s.redactStrings || s.redactIps ? (await session.strings()).map((x) => x.value) : undefined;
      const r = await desktop.ai.ask({
        task,
        name: f.name,
        address: `0x${f.address.toString(16)}`,
        arch: info?.arch ?? "unknown",
        format: info?.format ?? "unknown",
        code,
        ...(strings ? { strings } : {}),
        redactStrings: s.redactStrings,
        redactIps: s.redactIps,
      });
      if (get().assistant?.va !== f.address) return; // closed or replaced while waiting
      set({ assistant: { title, fn: f.name, va: f.address, state: "done", text: r.text, name: r.name, host: r.host, local: r.local } });
    } catch (e) {
      const msg = (e instanceof Error ? e.message : String(e)).replace(/^Error invoking remote method '[^']+': (Error: )?/, "");
      if (/^Cancelled$/i.test(msg)) return set({ assistant: null });
      set({ assistant: { title, fn: "", va: null, state: "error", text: msg, name: null, host: "", local: true } });
    }
  },

  async loadPlugins() {
    if (!desktop) return;
    try {
      const r = await desktop.plugins.list();
      set({ plugins: { dir: r.dir, list: r.plugins, errors: r.errors } });
    } catch (e) {
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async runPlugin(id, commandId) {
    const { session, plugins } = get();
    const p = plugins.list.find((x) => x.id === id);
    const title = p?.commands.find((c) => c.id === commandId)?.title ?? commandId;
    if (!desktop || !session) return;
    try {
      // The native dialog (first run of this version) and the fresh read of the script happen in the main process.
      const r = await desktop.plugins.run(id, commandId);
      set({ consoleOpen: true });
      get().print(`› ${r.name}: ${title}`, "info");
      const t0 = performance.now();
      if (r.language === "py") {
        await desktop.python.run(r.code, session.handle, get().cursor ?? 0);
        return;
      }
      const out = await runScript(r.code, (...a: unknown[]) => get().print(a.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join(" ")));
      if (out !== undefined) get().print(typeof out === "string" ? out : JSON.stringify(out));
      get().print(`done in ${Math.round(performance.now() - t0)} ms`, "info");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (!/cancelled/i.test(msg)) get().print(`${title}: ${msg}`, "error");
      get().toast(msg, /cancelled/i.test(msg) ? undefined : "error");
    }
  },

  print(text, kind = "out") {
    const log = get().log.concat({ t: Date.now(), kind, text });
    set({ log: log.length > 2000 ? log.slice(-2000) : log });
  },

  async makeFunction(va) {
    const { session, info } = get();
    if (!session || !info) return;
    try {
      await session.makeFunction(va);
      const [functions, stats] = await Promise.all([session.functions(), session.stats()]);
      set({ functions, stats, annotations: await persist(session, info), revision: get().revision + 1 });
      get().toast(`Function created at ${hex(va)}`, "success");
    } catch (e) {
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async bookmark(va, text) {
    const { session, info } = get();
    if (!session || !info) return;
    await session.setBookmark(va, text);
    set({ annotations: await persist(session, info) });
  },

  async reanalyze() {
    const { session } = get();
    if (!session) return;
    set({ loading: { name: get().info?.file_name ?? "", phase: "Re-running auto-analysis…" } });
    const stats = await session.reanalyze();
    set({ stats, functions: await session.functions(), loading: null, revision: get().revision + 1 });
  },

  async patch(offset, hexBytes) {
    const { session, info } = get();
    if (!session || !info) return;
    try {
      await session.patch(offset, hexBytes);
      set({ annotations: await persist(session, info), revision: get().revision + 1 });
    } catch (e) {
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async revertPatches() {
    const { session, info } = get();
    if (!session || !info) return;
    await session.revertPatches();
    set({ annotations: await persist(session, info), revision: get().revision + 1 });
    get().toast("All patches reverted", "success");
  },

  async loadPdb(src) {
    const { session } = get();
    if (!session) return;
    const { desktop } = await import("./engine/client");
    let source = src;
    if (!source) {
      if (desktop) {
        const p = await desktop.pdbDialog();
        if (!p) return;
        source = { path: p };
      } else {
        source = await new Promise<{ bytes: ArrayBuffer } | undefined>((resolve) => {
          const input = document.createElement("input");
          input.type = "file";
          input.accept = ".pdb";
          input.onchange = async () => resolve(input.files?.[0] ? { bytes: await input.files[0].arrayBuffer() } : undefined);
          input.click();
        });
        if (!source) return;
      }
    }
    const run = (force: boolean) => ("path" in source! ? session.loadPdbPath(source.path, force) : session.loadPdbBytes(source!.bytes, force));
    set({ loading: { name: get().info?.file_name ?? "", phase: "Loading PDB symbols…" } });
    try {
      let r;
      try {
        r = await run(false);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        set({ loading: null });
        if (!/does not match/.test(msg) || !window.confirm(`${msg}\n\nLoad it anyway?`)) throw e;
        set({ loading: { name: get().info?.file_name ?? "", phase: "Loading PDB symbols…" } });
        r = await run(true);
      }
      const [functions, stats] = await Promise.all([session.functions(), session.stats()]);
      set({ functions, stats, loading: null, revision: get().revision + 1 });
      const text = `PDB ${r.guid}: ${r.names} names, ${r.functions} functions, ${r.types} types${r.matched ? "" : " (GUID mismatch)"}`;
      get().print(text, "info");
      get().toast(`Loaded symbols: ${r.names} names${r.types ? `, ${r.types} types` : ""}`, "success");
    } catch (e) {
      set({ loading: null });
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async applySignatures() {
    const { session } = get();
    if (!session) return;
    const file = await new Promise<File | undefined>((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".sig,.pat,.txt";
      input.onchange = () => resolve(input.files?.[0]);
      input.click();
    });
    if (!file) return;
    try {
      const r = /\.sig$/i.test(file.name) ? await session.applySig(await file.arrayBuffer()) : await session.applyPat(await file.text());
      await get().afterEdit(false);
      get().print(`Signatures${r.library ? ` (${r.library})` : ""}: ${r.matched} of ${r.signatures} matched${r.names.length ? " — " + r.names.slice(0, 12).map((n) => n[1]).join(", ") + (r.names.length > 12 ? ", …" : "") : ""}`, "info");
      get().toast(r.matched ? `Recognised ${r.matched} library function${r.matched === 1 ? "" : "s"}` : "No function matched these signatures", r.matched ? "success" : "info");
    } catch (e) {
      get().toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async makeSignatures() {
    const { session, info } = get();
    if (!session || !info) return;
    const text = await session.makePat(false);
    const count = text.split("\n").filter((l) => l && l !== "---").length;
    if (!count) {
      get().toast("No named functions to make signatures from — load symbols first", "info");
      return;
    }
    await saveText(`${info.file_name}.pat`, text, [{ name: "FLAIR pattern file", extensions: ["pat"] }]);
  },

  async exportIdc() {
    const { session, info } = get();
    if (!session || !info) return;
    const text = await session.exportIdc();
    const name = `${info.file_name}.idc`;
    await saveText(name, text, [{ name: "IDC script", extensions: ["idc"] }]);
  },

  async savePatched() {
    const { session, info } = get();
    if (!session || !info) return;
    const { desktop } = await import("./engine/client");
    const dot = info.file_name.lastIndexOf(".");
    const name = dot > 0 ? `${info.file_name.slice(0, dot)}.patched${info.file_name.slice(dot)}` : `${info.file_name}.patched`;
    if (desktop) {
      const path = await desktop.saveDialog(name, [{ name: "All files", extensions: ["*"] }]);
      if (!path) return;
      await session.exportPatched(path);
      get().toast(`Saved ${path}`, "success");
    } else {
      const bytes = await session.exportPatched(null);
      if (bytes) download(name, new Blob([bytes as BlobPart]));
    }
  },

  set(key, value) {
    set({ [key]: value } as Partial<State>);
  },

  toast(text, kind = "info") {
    const id = ++toastSeq;
    set({ toasts: [...get().toasts, { id, kind, text }] });
    setTimeout(() => set({ toasts: get().toasts.filter((t) => t.id !== id) }), kind === "error" ? 7000 : 3500);
  },
}));

function isCode(info: BinaryInfo | null, va: number): boolean {
  if (!info) return true;
  const s = info.sections.filter((s) => s.vaddr && va >= s.vaddr && va < s.vaddr + Math.max(s.vsize, 1));
  return s.length === 0 ? true : s.some((x) => x.perms.x);
}

async function persist(session: Session, info: BinaryInfo): Promise<Annotations> {
  const a = await session.annotations();
  await getBackend().saveAnnotations(info.hashes.sha256, a);
  return a;
}

function download(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function saveText(name: string, text: string, filters: { name: string; extensions: string[] }[]) {
  const { desktop } = await import("./engine/client");
  if (desktop) {
    const path = await desktop.saveDialog(name, filters);
    if (!path) return;
    await desktop.writeText(path, text);
    useStore.getState().toast(`Saved ${path}`, "success");
  } else {
    download(name, new Blob([text], { type: "text/plain" }));
  }
}

// ------------------------------------------------------------------------------------------------
// Formatting helpers shared by views.

export function hex(v: number, pad = 0): string {
  return v.toString(16).toUpperCase().padStart(pad, "0");
}

export function addrWidth(info: BinaryInfo | null): number {
  return info && info.bits === 64 ? 12 : 8;
}

export function fmtAddr(v: number, info: BinaryInfo | null): string {
  return hex(v, addrWidth(info));
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function archLabel(a: string): string {
  return (
    { x86: "x86", x86_64: "x86-64", arm: "ARM", thumb: "ARM (Thumb-2)", arm64: "AArch64", mips: "MIPS", powerpc: "PowerPC", riscv: "RISC-V" } as Record<
      string,
      string
    >
  )[a] ?? a;
}

export function formatLabel(f: string): string {
  return ({ pe: "PE", elf: "ELF", macho: "Mach-O" } as Record<string, string>)[f] ?? f;
}

export function parseAddress(s: string): number | null {
  const t = s.trim().replace(/^0x/i, "").replace(/h$/i, "").replace(/[`_]/g, "");
  if (!/^[0-9a-f]+$/i.test(t) || t.length > 13) return null;
  return parseInt(t, 16);
}
