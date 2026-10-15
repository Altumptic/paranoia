// Engine client. Two interchangeable backends speak the same method/args
// protocol defined in crates/paranoia-core/src/api.rs:
//  * Native — the `paranoia-engine` process driven by the desktop shell, workspace store in redb.
//  * WASM   — the same engine compiled to WebAssembly in a Web Worker (browser build).

import type {
  AddressInfo,
  AnalysisStats,
  Annotations,
  BinaryInfo,
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

  async read(offset: number, len: number): Promise<Uint8Array> {
    const hex = await this.c<string>("read", { offset, len });
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  close = () => this.backend.close(this.handle);
}
