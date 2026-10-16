import { ArrowDownToLine, CornerDownRight, Pause, Play, Redo2, Square, Trash2, X } from "lucide-react";

import { debug } from "../debug";
import { fmtAddr, hex, useStore } from "../store";

/** Debugger panel: controls, registers, stack and breakpoints. */
export function DebugPanel() {
  const open = useStore((s) => s.debugOpen);
  const d = useStore((s) => s.debug);
  const bps = useStore((s) => s.breakpoints);
  const info = useStore((s) => s.info);
  const cursor = useStore((s) => s.cursor);
  if (!open) return null;
  const st = useStore.getState;
  const paused = d?.state === "paused";
  const live = d?.state === "paused" || d?.state === "running";
  const inImage = (rt: number) => (d && d.base && rt >= d.base ? rt - d.base + (info?.image_base ?? 0) : null);

  return (
    <section className="console debug-panel">
      <div className="console-bar">
        <span className="side-title">Debugger</span>
        <span className={`dbg-state dbg-${d?.state ?? "idle"}`}>{d ? (d.state === "paused" ? d.reason || "Paused" : d.state === "running" ? "Running" : d.reason || d.state) : "Not started"}</span>
        <span className="flex1" />
        <button className="btn sm" onClick={() => (live ? debug.cmd("continue") : debug.start())} disabled={d?.state === "running"} title={live ? "Continue (F9)" : "Start (F9)"}>
          <Play size={13} /> {live ? "Continue" : "Start"} <span className="kbd">F9</span>
        </button>
        <button className="icon-btn" onClick={() => debug.cmd("pause")} disabled={d?.state !== "running"} title="Pause">
          <Pause size={15} />
        </button>
        <button className="icon-btn" onClick={() => debug.cmd("step_into")} disabled={!paused} title="Step into (F7)">
          <ArrowDownToLine size={15} />
        </button>
        <button className="icon-btn" onClick={() => debug.cmd("step_over")} disabled={!paused} title="Step over (F8)">
          <Redo2 size={15} />
        </button>
        <button className="icon-btn" onClick={() => cursor != null && debug.runTo(cursor)} disabled={!paused || cursor == null} title="Run to cursor (F4)">
          <CornerDownRight size={15} />
        </button>
        <button className="icon-btn" onClick={() => debug.cmd("stop")} disabled={!live} title="Stop (Shift+F5)">
          <Square size={14} />
        </button>
        <button
          className="icon-btn"
          title="Close"
          onClick={() => {
            if (live) debug.cmd("stop");
            st().set("debugOpen", false);
          }}
        >
          <X size={14} />
        </button>
      </div>
      <div className="debug-body">
        <div className="dbg-col">
          <div className="dbg-title">Registers</div>
          <div className="regs mono">
            {(d?.regs ?? []).map(([n, v]) => {
              const sva = inImage(v);
              return (
                <div key={n} className="reg">
                  <span className="reg-n">{n}</span>
                  <button className={`reg-v ${sva != null ? "link-tok" : ""}`} onClick={() => sva != null && st().goto(sva)} title={sva != null ? `Go to ${fmtAddr(sva, info)}` : undefined}>
                    {hex(v, 16)}
                  </button>
                </div>
              );
            })}
            {!d?.regs?.length && <div className="muted small">Registers appear when the program is paused.</div>}
          </div>
        </div>
        <div className="dbg-col">
          <div className="dbg-title">Stack</div>
          <div className="mono stack">
            {(d?.stack ?? []).map(([a, v], i) => {
              const sva = inImage(v);
              return (
                <div key={a} className="reg">
                  <span className="reg-n">{i === 0 ? "rsp" : `+${(i * 8).toString(16)}`}</span>
                  <button className={`reg-v ${sva != null ? "link-tok" : ""}`} onClick={() => sva != null && st().goto(sva)}>
                    {hex(v, 16)}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
        <div className="dbg-col">
          <div className="dbg-title">
            Breakpoints <span className="count">{bps.size}</span>
          </div>
          <div className="mono">
            {[...bps].sort((a, b) => a - b).map((b) => (
              <div key={b} className="reg bp-row">
                <span className="bp-dot" />
                <button className="reg-v link-tok" onClick={() => st().goto(b)}>
                  {fmtAddr(b, info)}
                </button>
                <button className="icon-btn" title="Remove" onClick={() => debug.toggleBreakpoint(b)}>
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
            {bps.size === 0 && <div className="muted small">Press F2 on a line to set a breakpoint.</div>}
          </div>
        </div>
      </div>
    </section>
  );
}
