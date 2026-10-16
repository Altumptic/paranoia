// Debugger client: talks to the native engine's `debug` op and keeps the UI in sync.

import { desktop } from "./engine/client";
import { useStore } from "./store";

export interface DebugSnapshot {
  state: "idle" | "running" | "paused" | "exited";
  reason: string;
  pc: number | null;
  pc_runtime: number;
  base: number;
  regs: [string, number][];
  stack: [number, number][];
  breakpoints: number[];
  log: string[];
  exit_code: number | null;
}

async function dbg<T>(method: string, args?: Record<string, unknown>): Promise<T> {
  const s = useStore.getState().session;
  if (!desktop || !s) throw new Error("The debugger is available in the desktop app");
  return (await desktop.engine({ op: "debug", method, handle: s.handle, args: args ?? null })) as T;
}

let timer: ReturnType<typeof setInterval> | null = null;

function startPolling() {
  if (timer) return;
  timer = setInterval(async () => {
    try {
      const snap = await dbg<DebugSnapshot>("poll");
      const st = useStore.getState();
      for (const l of snap.log ?? []) st.print(l, "info");
      const prev = st.debug;
      useStore.setState({ debug: snap });
      if (snap.state === "paused" && (prev?.state !== "paused" || prev?.pc_runtime !== snap.pc_runtime)) {
        st.print(`⏸ ${snap.reason} at ${snap.pc != null ? "0x" + snap.pc.toString(16).toUpperCase() : "0x" + snap.pc_runtime.toString(16).toUpperCase() + " (outside the image)"}`, "info");
        if (snap.pc != null) st.goto(snap.pc, { tab: st.centerTab === "graph" ? "graph" : "disasm" });
      }
      if (snap.state === "exited" || snap.state === "idle") {
        if (snap.state === "exited" && prev?.state !== "exited") st.print(snap.reason, "info");
        stopPolling();
      }
    } catch {
      stopPolling();
    }
  }, 150);
}

function stopPolling() {
  if (timer) clearInterval(timer);
  timer = null;
}

export const debug = {
  available: () => desktop != null && useStore.getState().info?.format === "pe" && useStore.getState().info?.arch === "x86_64",

  async start() {
    const st = useStore.getState();
    const ok = window.confirm(
      "Debugging runs this program on your computer.\n\nOnly debug files you trust, or do it inside a virtual machine. Malware will execute with your user's permissions.\n\nStart the program now?",
    );
    if (!ok) return;
    try {
      await dbg("start", { breakpoints: [...st.breakpoints], break_on_entry: true });
      useStore.setState({ debug: { state: "running", reason: "Starting…", pc: null, pc_runtime: 0, base: 0, regs: [], stack: [], breakpoints: [], log: [], exit_code: null }, debugOpen: true });
      st.print(`▶ Debugging ${st.info?.file_name}`, "info");
      startPolling();
    } catch (e) {
      st.toast(e instanceof Error ? e.message : String(e), "error");
    }
  },

  async cmd(name: "continue" | "step_into" | "step_over" | "pause" | "stop") {
    const d = useStore.getState().debug;
    if (!d || d.state === "exited" || d.state === "idle") {
      if (name === "continue") return debug.start();
      return;
    }
    if (name !== "pause" && name !== "stop" && d.state !== "paused") return;
    await dbg(name).catch((e) => useStore.getState().toast(String(e), "error"));
    startPolling();
  },

  async runTo(va: number) {
    const d = useStore.getState().debug;
    if (d?.state !== "paused") return;
    await dbg("run_to", { va });
    startPolling();
  },

  async toggleBreakpoint(va: number) {
    const st = useStore.getState();
    const bps = new Set(st.breakpoints);
    const on = !bps.has(va);
    if (on) bps.add(va);
    else bps.delete(va);
    useStore.setState({ breakpoints: bps });
    const d = st.debug;
    if (d && (d.state === "paused" || d.state === "running")) await dbg(on ? "set_bp" : "clear_bp", { va }).catch(() => {});
  },

  async read(va: number, len: number): Promise<Uint8Array> {
    const hex = await dbg<string>("read", { va, len });
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  },

  async end() {
    stopPolling();
    await dbg("end").catch(() => {});
    useStore.setState({ debug: null });
  },
};
