// Engine client. Two interchangeable backends speak the same method/args
// protocol defined in crates/paranoia-core/src/api.rs:
//  * Native — the `paranoia-engine` process driven by the desktop shell, workspace store in redb.
//  * WASM   — the same engine compiled to WebAssembly in a Web Worker (browser build).

import type {
  AddressInfo,
  AnalysisStats,
  Annotations,
  BinaryInfo,
  Callee,
  CallGraph,
  Frame,
  Hit,
  InsnPatch,
  ItemKind,
  NameEntry,
  Pseudocode,
  SearchKind,
  FunctionGraph,
  FunctionSummary,
  Instruction,
  SearchHit,
  StringEntry,
  Symbol,
  Xref,
} from "./types";
import type { WorkerRequest, WorkerResponse } from "./wasm.worker";

type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;

export type OpenSource = { kind: "bytes"; name: string; bytes: ArrayBuffer } | { kind: "path"; path: string };

export interface RecentFile {
  name: string;
  path: string | null;
  sha256: string;
  format: string;
  arch: string;
  size: number;
  openedAt: number;
}

export interface Backend {
  readonly kind: "native" | "wasm";
  open(src: OpenSource): Promise<number>;
  call<T>(handle: number, method: string, args?: unknown): Promise<T>;
  close(handle: number): Promise<void>;
  loadAnnotations(sha256: string): Promise<Annotations | null>;
  saveAnnotations(sha256: string, a: Annotations): Promise<void>;
  recent(): Promise<RecentFile[]>;
  addRecent(r: RecentFile): Promise<void>;
  removeRecent(sha256: string): Promise<void>;
  /** Engine-level request (desktop only). */
  raw(req: Record<string, unknown>): Promise<unknown>;
}

// ------------------------------------------------------------------------------------------------

class WasmBackend implements Backend {
  readonly kind = "wasm" as const;
  private worker = new Worker(new URL("./wasm.worker.ts", import.meta.url), { type: "module" });
  private seq = 0;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  constructor() {
    this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
      const p = this.pending.get(e.data.id);
      if (!p) return;
      this.pending.delete(e.data.id);
      if (e.data.ok) p.resolve(e.data.value);
      else p.reject(new Error(e.data.error));
    };
  }

  private send<T>(req: DistributiveOmit<WorkerRequest, "id">, transfer: Transferable[] = []): Promise<T> {
    const id = ++this.seq;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.worker.postMessage({ ...req, id }, transfer);
    });
  }

  open(src: OpenSource): Promise<number> {
    if (src.kind !== "bytes") throw new Error("The browser build can only open uploaded files.");
    return this.send({ op: "open", name: src.name, bytes: src.bytes }, [src.bytes]);
  }

  call<T>(handle: number, method: string, args?: unknown): Promise<T> {
    return this.send<T>({ op: "call", handle, method, args });
  }

  async close(handle: number): Promise<void> {
    await this.send({ op: "close", handle });
  }

  raw(): Promise<unknown> {
    return Promise.reject(new Error("not available in the browser build"));
  }

  // Browser persistence is best-effort: storage can be unavailable (private mode, quotas).
  async loadAnnotations(sha: string): Promise<Annotations | null> {
    try {
      const raw = localStorage.getItem(`paranoia.ann.${sha}`);
      return raw ? (JSON.parse(raw) as Annotations) : null;
    } catch {
      return null;
    }
  }

  async saveAnnotations(sha: string, a: Annotations): Promise<void> {
    try {
      localStorage.setItem(`paranoia.ann.${sha}`, JSON.stringify(a));
    } catch {
      /* storage unavailable */
    }
  }

  async recent(): Promise<RecentFile[]> {
    try {
      return JSON.parse(localStorage.getItem("paranoia.recent") ?? "[]") as RecentFile[];
    } catch {
      return [];
    }
  }

  async addRecent(r: RecentFile): Promise<void> {
    const list = (await this.recent()).filter((x) => x.sha256 !== r.sha256);
    list.unshift(r);
    try {
      localStorage.setItem("paranoia.recent", JSON.stringify(list.slice(0, 20)));
    } catch {
      /* storage unavailable */
    }
  }

  async removeRecent(sha: string): Promise<void> {
    const list = (await this.recent()).filter((x) => x.sha256 !== sha);
    try {
      localStorage.setItem("paranoia.recent", JSON.stringify(list));
    } catch {
      /* storage unavailable */
    }
  }
}

// ------------------------------------------------------------------------------------------------

/** Bridge exposed by electron/preload.cjs. */
export interface DesktopBridge {
  engine(req: Record<string, unknown>): Promise<unknown>;
  openDialog(): Promise<string | null>;
  info(): Promise<{ version: string; engine: string; electron: string; platform: string }>;
  reveal(path: string): Promise<void>;
  saveDialog(defaultName: string, filters: { name: string; extensions: string[] }[]): Promise<string | null>;
  writeText(path: string, text: string): Promise<void>;
  setTitleBar(color: string, symbolColor: string): void;
  pathForFile(file: File): string | null;
  onOpenPath(cb: (path: string) => void): () => void;
  onEngineRestarted(cb: (reason: string) => void): () => void;
}

declare global {
  interface Window {
    paranoia?: DesktopBridge;
  }
}

/** Native engine process (desktop app). */
class DesktopBackend implements Backend {
  readonly kind = "native" as const;
  constructor(private bridge: DesktopBridge) {}

  private req<T>(r: Record<string, unknown>): Promise<T> {
    return this.bridge.engine(r) as Promise<T>;
  }

  raw(r: Record<string, unknown>): Promise<unknown> {
    return this.bridge.engine(r);
  }

  open(src: OpenSource): Promise<number> {
    if (src.kind !== "path") throw new Error("The desktop engine opens files by path.");
    return this.req<number>({ op: "open", path: src.path });
  }

  call<T>(handle: number, method: string, args?: unknown): Promise<T> {
    return this.req<T>({ op: "call", handle, method, args: args ?? null });
  }

  async close(handle: number): Promise<void> {
    await this.req({ op: "close", handle });
  }

  private store<T>(method: string, args?: unknown): Promise<T> {
    return this.req<T>({ op: "store", method, args: args ?? null });
  }

  loadAnnotations(sha256: string): Promise<Annotations | null> {
    return this.store("annotations_get", { sha256 });
  }

  saveAnnotations(sha256: string, annotations: Annotations): Promise<void> {
    return this.store("annotations_set", { sha256, annotations });
  }

  recent(): Promise<RecentFile[]> {
    return this.store("recent_list");
  }

  addRecent(entry: RecentFile): Promise<void> {
    return this.store("recent_add", { entry });
  }

  removeRecent(sha256: string): Promise<void> {
    return this.store("recent_remove", { sha256 });
  }
}

export const desktop: DesktopBridge | null = typeof window !== "undefined" ? (window.paranoia ?? null) : null;
export const isDesktop = desktop != null;

let backend: Backend | null = null;
export function getBackend(): Backend {
  backend ??= desktop ? new DesktopBackend(desktop) : new WasmBackend();
  return backend;
}

// ------------------------------------------------------------------------------------------------

/** A typed handle on one open binary. */
export class Session {
  constructor(
    readonly backend: Backend,
    readonly handle: number,
  ) {}

  static async open(src: OpenSource): Promise<Session> {
    const b = getBackend();
    return new Session(b, await b.open(src));
  }

  private c<T>(method: string, args?: unknown) {
    return this.backend.call<T>(this.handle, method, args);
  }

  info = () => this.c<BinaryInfo>("info");
  stats = () => this.c<AnalysisStats>("stats");
  functions = () => this.c<FunctionSummary[]>("functions");
  symbols = () => this.c<Symbol[]>("symbols");
  strings = () => this.c<StringEntry[]>("strings");
  disassemble = (va: number, count: number) => this.c<Instruction[]>("disassemble", { va, count });
  previousAnchor = (va: number) => this.c<number | null>("previousAnchor", { va });
  graph = (va: number) => this.c<FunctionGraph | null>("graph", { va });
  functionAt = (va: number) => this.c<FunctionSummary | null>("functionAt", { va });
  xrefs = (va: number) => this.c<Xref[]>("xrefs", { va });
  addressInfo = (va: number) => this.c<AddressInfo>("addressInfo", { va });
  search = (query: string, limit = 200) => this.c<SearchHit[]>("search", { query, limit });
  vaToOffset = (va: number) => this.c<number | null>("vaToOffset", { va });
  offsetToVa = (offset: number) => this.c<number | null>("offsetToVa", { offset });
  rename = (va: number, text: string) => this.c<null>("rename", { va, text });
  setComment = (va: number, text: string) => this.c<null>("setComment", { va, text });
  annotations = () => this.c<Annotations>("annotations");
  setAnnotations = (a: Annotations) => this.c<null>("setAnnotations", a);
  pseudocode = (va: number) => this.c<Pseudocode | null>("pseudocode", { va });
  callees = (va: number) => this.c<Callee[]>("callees", { va });
  searchAdvanced = (kind: SearchKind, query: string) => this.c<Hit[]>("searchAdvanced", { kind, query });
  makeFunction = (va: number) => this.c<null>("makeFunction", { va });
  reanalyze = () => this.c<AnalysisStats>("reanalyze");
  patch = (offset: number, hex: string) => this.c<null>("patch", { offset, hex });
  revertPatches = () => this.c<null>("revertPatches");
  patchedOffsets = () => this.c<number[]>("patchedOffsets");
  exportIdc = () => this.c<string>("exportIdc");
  setBookmark = (va: number, text: string | null) => this.c<null>("setBookmark", { va, text });
  frame = (va: number) => this.c<Frame | null>("frame", { va });
  names = () => this.c<NameEntry[]>("names");
  callGraph = (va: number, up = 1, down = 2) => this.c<CallGraph | null>("callGraph", { va, up, down });
  setItem = (va: number, kind: ItemKind, count = 1) => this.c<null>("setItem", { va, kind, count });
  cycleData = (va: number) => this.c<ItemKind>("cycleData", { va });
  makeString = (va: number) => this.c<null>("makeString", { va });
  makeCode = (va: number) => this.c<null>("makeCode", { va });
  /** Returns true when analysis re-ran (function undefined). */
  undefine = (va: number) => this.c<boolean>("undefine", { va });
  patchInstruction = (va: number, op: InsnPatch) => this.c<null>("patchInstruction", { va, op });
  /** null when there is nothing to undo; otherwise whether analysis re-ran. */
  undo = () => this.c<boolean | null>("undo");
  redo = () => this.c<boolean | null>("redo");
  history = () => this.c<[number, number]>("history");

  /** Writes the (patched) file. Desktop: straight to disk; browser: returns the bytes. */
  async exportPatched(path: string | null): Promise<Uint8Array | null> {
    if (this.backend.kind === "native" && path) {
      await this.backend.raw({ op: "export_patched", handle: this.handle, path });
      return null;
    }
    const info = await this.info();
    const out = new Uint8Array(info.file_size);
    for (let off = 0; off < info.file_size; off += 1 << 20) out.set(await this.read(off, Math.min(1 << 20, info.file_size - off)), off);
    return out;
  }

  async read(offset: number, len: number): Promise<Uint8Array> {
    const hex = await this.c<string>("read", { offset, len });
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  close = () => this.backend.close(this.handle);
}
