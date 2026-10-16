import { BookOpen, Eraser, Play, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { EXAMPLES, runScript } from "../scripting";
import { useStore } from "../store";

const KEY = "paranoia.script";

function fmt(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "number") return Number.isInteger(v) && Math.abs(v) > 0xffff ? `0x${v.toString(16).toUpperCase()}` : String(v);
  try {
    return JSON.stringify(v, null, 1)?.slice(0, 4000) ?? String(v);
  } catch {
    return String(v);
  }
}

/** Output log + JavaScript console (IDA's output window and script box). */
export function Console() {
  const open = useStore((s) => s.consoleOpen);
  const log = useStore((s) => s.log);
  const [code, setCode] = useState(() => {
    try {
      return localStorage.getItem(KEY) ?? EXAMPLES[0].code;
    } catch {
      return EXAMPLES[0].code;
    }
  });
  const [busy, setBusy] = useState(false);
  const [examples, setExamples] = useState(false);
  const out = useRef<HTMLDivElement>(null);

  useEffect(() => {
    out.current?.scrollTo({ top: out.current.scrollHeight });
  }, [log, open]);

  if (!open) return null;
  const st = useStore.getState;
  const run = async () => {
    try {
      localStorage.setItem(KEY, code);
    } catch {
      /* storage unavailable */
    }
    setBusy(true);
    st().print(`› ${code.split("\n")[0]}${code.includes("\n") ? " …" : ""}`, "info");
    const t0 = performance.now();
    try {
      const r = await runScript(code, (...a: unknown[]) => st().print(a.map(fmt).join(" ")));
      if (r !== undefined) st().print(fmt(r));
      st().print(`done in ${Math.round(performance.now() - t0)} ms`, "info");
    } catch (e) {
      st().print(e instanceof Error ? `${e.name}: ${e.message}` : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="console">
      <div className="console-bar">
        <span className="side-title">Console</span>
        <span className="muted small">JavaScript with the <span className="mono">pn</span> API · Ctrl+Enter to run</span>
        <span className="flex1" />
        <div className="menu-anchor">
          <button className="btn sm ghost" onClick={() => setExamples(!examples)}>
            <BookOpen size={13} /> Examples
          </button>
          {examples && (
            <div className="menu" style={{ bottom: 34, top: "auto" }}>
              {EXAMPLES.map((e) => (
                <button
                  key={e.title}
                  className="menu-item"
                  onClick={() => {
                    setCode(e.code);
                    setExamples(false);
                  }}
                >
                  <span>{e.title}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="icon-btn" title="Clear output" onClick={() => st().set("log", [])}>
          <Eraser size={14} />
        </button>
        <button className="icon-btn" title="Close (Ctrl+`)" onClick={() => st().set("consoleOpen", false)}>
          <X size={14} />
        </button>
      </div>
      <div className="console-body">
        <div className="console-out mono selectable" ref={out}>
          {log.length === 0 && <div className="muted">Output from scripts and the engine appears here.</div>}
          {log.map((l, i) => (
            <div key={i} className={`log-${l.kind}`}>
              {l.text}
            </div>
          ))}
        </div>
        <div className="console-in">
          <textarea
            className="mono"
            value={code}
            spellCheck={false}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                run();
              }
              if (e.key === "Tab") {
                e.preventDefault();
                const t = e.currentTarget;
                const p = t.selectionStart;
                setCode(code.slice(0, p) + "  " + code.slice(t.selectionEnd));
                requestAnimationFrame(() => t.setSelectionRange(p + 2, p + 2));
              }
            }}
          />
          <button className="btn primary sm run-btn" onClick={run} disabled={busy}>
            <Play size={13} /> Run
          </button>
        </div>
      </div>
    </section>
  );
}
