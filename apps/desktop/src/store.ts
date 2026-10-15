import { create } from "zustand";

import { getBackend, Session, type OpenSource, type RecentFile } from "./engine/client";
import type { AnalysisStats, BinaryInfo, FunctionSummary } from "./engine/types";

export type SidebarTab = "functions" | "imports" | "exports" | "strings" | "sections" | "symbols";
export type CenterTab = "overview" | "disasm" | "graph" | "hex";

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
  dialog: null | { kind: "rename" | "comment"; va: number; initial: string };

  open(src: OpenSource): Promise<void>;
  close(): Promise<void>;
  loadRecent(): Promise<void>;
  goto(va: number, opts?: { tab?: CenterTab; record?: boolean }): void;
  setCursor(va: number): void;
  back(): void;
  forward(): void;
  rename(va: number, name: string): Promise<void>;
  comment(va: number, text: string): Promise<void>;
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
      const [stats, functions] = await Promise.all([session.stats(), session.functions()]);
      if (prev) prev.close().catch(() => {});
      const path = src.kind === "path" ? src.path : null;
      const start = info.entry || functions[0]?.address || null;
      set({
        session,
        info,
        stats,
        functions,
        path,
        loading: null,
        cursor: start,
        history: start != null ? [start] : [],
        historyIndex: start != null ? 0 : -1,
        centerTab: "overview",
        revision: get().revision + 1,
      });
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
    const s = get().session;
    set({ session: null, info: null, stats: null, functions: [], cursor: null, history: [], historyIndex: -1, path: null });
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
    if (!opts?.tab && (tab === "disasm" || tab === "graph") && !isCode(get().info, va)) tab = "hex";
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
    await persist(session, info);
    set({ functions: await session.functions(), revision: get().revision + 1 });
  },

  async comment(va, text) {
    const { session, info } = get();
    if (!session || !info) return;
    await session.setComment(va, text);
    await persist(session, info);
    set({ revision: get().revision + 1 });
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

async function persist(session: Session, info: BinaryInfo) {
  const a = await session.annotations();
  await getBackend().saveAnnotations(info.hashes.sha256, a);
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
    { x86: "x86", x86_64: "x86-64", arm: "ARM", arm64: "AArch64", mips: "MIPS", powerpc: "PowerPC", riscv: "RISC-V" } as Record<
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
