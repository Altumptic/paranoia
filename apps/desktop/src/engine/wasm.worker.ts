/// <reference lib="webworker" />
// Runs the WebAssembly engine off the UI thread. Speaks the same
// method/args protocol as the Tauri backend (see crates/paranoia-core/src/api.rs).

import wasmUrl from "./paranoia.wasm?url";

interface Exports {
  memory: WebAssembly.Memory;
  pn_alloc(len: number): number;
  pn_free(ptr: number, len: number): void;
  pn_result_ptr(): number;
  pn_result_len(): number;
  pn_open(namePtr: number, nameLen: number, dataPtr: number, dataLen: number): number;
  pn_call(handle: number, mPtr: number, mLen: number, aPtr: number, aLen: number): number;
  pn_close(handle: number): void;
}

export type WorkerRequest =
  | { id: number; op: "open"; name: string; bytes: ArrayBuffer }
  | { id: number; op: "call"; handle: number; method: string; args: unknown }
  | { id: number; op: "close"; handle: number };

export type WorkerResponse = { id: number; ok: true; value: unknown } | { id: number; ok: false; error: string };

const enc = new TextEncoder();
const dec = new TextDecoder();

const instantiate = (): Promise<Exports> =>
  WebAssembly.instantiateStreaming(fetch(wasmUrl), {}).then((r) => r.instance.exports as unknown as Exports);

let ready = instantiate();

function put(ex: Exports, bytes: Uint8Array): [number, number] {
  const ptr = ex.pn_alloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

function result(ex: Exports): string {
  // Copy before decoding: TextDecoder rejects views on shared/growable buffers in some engines.
  const view = new Uint8Array(ex.memory.buffer, ex.pn_result_ptr(), ex.pn_result_len());
  return dec.decode(view.slice());
}

async function handle(req: WorkerRequest): Promise<unknown> {
  const ex = await ready;
  switch (req.op) {
    case "open": {
      const [np, nl] = put(ex, enc.encode(req.name));
      const [dp, dl] = put(ex, new Uint8Array(req.bytes));
      const ok = ex.pn_open(np, nl, dp, dl); // takes ownership of the data buffer
      ex.pn_free(np, nl);
      const text = result(ex);
      if (!ok) throw new Error(text);
      return Number(text);
    }
    case "call": {
      const [mp, ml] = put(ex, enc.encode(req.method));
      const [ap, al] = put(ex, enc.encode(JSON.stringify(req.args ?? null)));
      const ok = ex.pn_call(req.handle, mp, ml, ap, al);
      ex.pn_free(mp, ml);
      ex.pn_free(ap, al);
      const text = result(ex);
      if (!ok) throw new Error(text);
      return JSON.parse(text);
    }
    case "close":
      ex.pn_close(req.handle);
      return null;
  }
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const req = e.data;
  try {
    const value = await handle(req);
    (self as DedicatedWorkerGlobalScope).postMessage({ id: req.id, ok: true, value } satisfies WorkerResponse);
  } catch (err) {
    let error = err instanceof Error ? err.message : String(err);
    if (err instanceof WebAssembly.RuntimeError) {
      // A trap leaves the instance in an undefined state: start over with a fresh one.
      ready = instantiate();
      error = `The analysis engine crashed on this input and was restarted (${error}). Please report the file hash.`;
    }
    (self as DedicatedWorkerGlobalScope).postMessage({ id: req.id, ok: false, error } satisfies WorkerResponse);
  }
};
