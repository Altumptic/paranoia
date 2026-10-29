import { BookOpen, Eraser, Play, Square, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { desktop } from "../engine/client";
import { PY_EXAMPLES } from "../pyexamples";
import { EXAMPLES, runScript, stopScript } from "../scripting";
import { useStore } from "../store";

type Lang = "js" | "py";
const KEY = { js: "paranoia.script", py: "paranoia.script.py" } as const;
const LANG_KEY = "paranoia.script.lang";

function load(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
}

function fmt(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "number") return Number.isInteger(v) && Math.abs(v) > 0xffff ? `0x${v.toString(16).toUpperCase()}` : String(v);
  try {
    return JSON.stringify(v, null, 1)?.slice(0, 4000) ?? String(v);
  } catch {
    return String(v);
  }
}

/** Output log + script console: JavaScript in the app, Python in the user's interpreter (desktop). */
export function Console() {
  const open = useStore((s) => s.consoleOpen);
  const log = useStore((s) => s.log);
  const [lang, setLang] = useState<Lang>(() => (desktop && load(LANG_KEY, "js") === "py" ? "py" : "js"));
  const [code, setCode] = useState(() => load(KEY[lang], lang === "py" ? PY_EXAMPLES[0].code : EXAMPLES[0].code));
  const [busy, setBusy] = useState(false);
  const [examples, setExamples] = useState(false);
  const [python, setPython] = useState<string | null | undefined>(undefined);
  const out = useRef<HTMLDivElement>(null);
  const t0 = useRef(0);

  useEffect(() => {
    out.current?.scrollTo({ top: out.current.scrollHeight });
  }, [log, open]);

  // Python events: output lines, navigation, refresh after edits, completion.
  useEffect(() => {
    if (!desktop) return;
    return desktop.python.on((ev, payload) => {
      const st = useStore.getState();
      if (ev === "output") {
        const p = payload as { stream: string; text: string };
        st.print(p.text, p.stream === "err" ? "error" : undefined);
      } else if (ev === "goto") {
        st.goto(Number(payload));
      } else if (ev === "refresh") {
        st.afterEdit(false);
      } else if (ev === "exit") {
        const p = payload as { code: number | null };
        st.print(p.code === 0 ? `done in ${Math.round(performance.now() - t0.current)} ms` : `Python exited with code ${p.code}`, p.code === 0 ? "info" : "error");
        setBusy(false);
      }
    });
  }, []);

  useEffect(() => {
    if (lang === "py" && desktop && python === undefined) {
      desktop.python
        .status()
        .then((s) => setPython(s.available ? (s.version ?? "") : null))
        .catch(() => setPython(null));
    }
  }, [lang, python]);

  if (!open) return null;
  const st = useStore.getState;
  const list = lang === "py" ? PY_EXAMPLES : EXAMPLES;

  const switchLang = (l: Lang) => {
    if (l === lang) return;
    save(KEY[lang], code);
    save(LANG_KEY, l);
    setLang(l);
    setCode(load(KEY[l], l === "py" ? PY_EXAMPLES[0].code : EXAMPLES[0].code));
    setExamples(false);
  };

  const run = async () => {
    save(KEY[lang], code);
    st().print(`› ${code.split("\n")[0]}${code.includes("\n") ? " …" : ""}`, "info");
    t0.current = performance.now();
    if (lang === "py") {
      const s = st().session;
      if (!desktop || !s) return;
      setBusy(true);
      try {
        await desktop.python.run(code, s.handle, st().cursor ?? 0);
      } catch (e) {
        st().print(e instanceof Error ? e.message : String(e), "error");
        setBusy(false);
      }
      return;
    }
    setBusy(true);
    try {
      const r = await runScript(code, (...a: unknown[]) => st().print(a.map(fmt).join(" ")));
      if (r !== undefined) st().print(fmt(r));
      st().print(`done in ${Math.round(performance.now() - t0.current)} ms`, "info");
    } catch (e) {
      st().print(e instanceof Error ? `${e.name}: ${e.message}` : String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const hint =
    lang === "py"
      ? python === null
        ? "Python 3 not found — install it or set PARANOIA_PYTHON"
        : `Python ${python ?? ""} · paranoia module + idc / idautils · Ctrl+Enter to run`
      : "JavaScript with the pn API · Ctrl+Enter to run";

  return (
    <section className="console">
      <div className="console-bar">
        <span className="side-title">Console</span>
        {desktop && (
          <div className="seg">
            <button className={`seg-btn ${lang === "js" ? "on" : ""}`} onClick={() => switchLang("js")}>
              JavaScript
            </button>
            <button className={`seg-btn ${lang === "py" ? "on" : ""}`} onClick={() => switchLang("py")}>
              Python
            </button>
          </div>
        )}
        <span className="muted small">{hint}</span>
        <span className="flex1" />
        <div className="menu-anchor">
          <button className="btn sm ghost" onClick={() => setExamples(!examples)}>
            <BookOpen size={13} /> Examples
          </button>
          {examples && (
            <div className="menu" style={{ bottom: 34, top: "auto" }}>
              {list.map((e) => (
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
                if (!busy) run();
              }
              if (e.key === "Tab") {
                e.preventDefault();
                const t = e.currentTarget;
                const p = t.selectionStart;
                const indent = lang === "py" ? "    " : "  ";
                setCode(code.slice(0, p) + indent + code.slice(t.selectionEnd));
                requestAnimationFrame(() => t.setSelectionRange(p + indent.length, p + indent.length));
              }
            }}
          />
          {busy ? (
            <button
              className="btn sm run-btn"
              onClick={() => {
                if (lang === "py") {
                  desktop?.python.stop();
                } else {
                  stopScript();
                }
              }}
            >
              <Square size={12} /> Stop
            </button>
          ) : (
            <button className="btn primary sm run-btn" onClick={run} disabled={busy || (lang === "py" && python === null)}>
              <Play size={13} /> Run
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
