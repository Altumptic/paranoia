import { useEffect, useMemo, useState } from "react";

import { memory, type KnowledgeStats, type Recall } from "../engine/memory";
import { useStore } from "../store";

const hex = (v: number) => `0x${v.toString(16)}`;
const pct = (v: number) => `${Math.round(v * 100)}%`;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e)).replace(/^Error invoking remote method '[^']+': (Error: )?/, "");

/** Recalls at or above this score are ticked by default. */
const PRESELECT = 0.85;

/** Analysis → Function memory: teach the local knowledge base this file's names, or
 *  recognise functions it already knows from other files. */
export function MemoryDialog() {
  const open = useStore((s) => s.memoryOpen);
  const session = useStore((s) => s.session);
  const info = useStore((s) => s.info);
  const userNames = useStore((s) => Object.keys(s.annotations.names ?? {}).length);
  const [stats, setStats] = useState<KnowledgeStats | null>(null);
  const [recalls, setRecalls] = useState<Recall[] | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [symbols, setSymbols] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [sourcesOpen, setSourcesOpen] = useState(false);
  const [forgetting, setForgetting] = useState<string | null>(null);
  const close = () => useStore.getState().set("memoryOpen", false);

  const refresh = () =>
    memory
      .stats()
      .then(setStats)
      .catch((e) => setErr(message(e)));

  useEffect(() => {
    if (!open) return;
    setErr(null);
    setNote(null);
    setRecalls(null);
    refresh();
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [open]);

  const chosen = useMemo(() => (recalls ?? []).filter((r) => picked.has(r.address)), [recalls, picked]);
  if (!open || !session || !info) return null;

  const run = async (label: string, f: () => Promise<void>) => {
    setBusy(label);
    setErr(null);
    setNote(null);
    try {
      await f();
    } catch (e) {
      setErr(message(e));
    } finally {
      setBusy(null);
    }
  };

  const learn = () =>
    run("learn", async () => {
      const r = await memory.learn(session, symbols);
      const n = r.added + r.updated;
      setNote(
        n
          ? `Remembered ${n} function${n === 1 ? "" : "s"} (${r.added} new, ${r.updated} updated).`
          : "Nothing to remember yet: name some functions first, or include names from symbols.",
      );
      await refresh();
    });

  const recall = () =>
    run("recall", async () => {
      const r = await memory.recall(session);
      r.sort((a, b) => b.score - a.score || a.address - b.address);
      setRecalls(r);
      setPicked(new Set(r.filter((x) => x.exact || x.score >= PRESELECT).map((x) => x.address)));
      if (!r.length) setNote("No remembered functions found in this file.");
    });

  const apply = () =>
    run("apply", async () => {
      const r = await memory.apply(session, chosen);
      const st = useStore.getState();
      await st.afterEdit(false);
      useStore.setState({ functions: await session.functions() });
      setRecalls((list) => (list ?? []).filter((x) => !picked.has(x.address)));
      setPicked(new Set());
      st.toast(`Applied ${r.renamed} name${r.renamed === 1 ? "" : "s"}, ${r.comments} comments, ${r.variables} variables. Ctrl+Z undoes it.`, "success");
    });

  const forget = (sha: string) =>
    run("forget", async () => {
      if (forgetting !== sha) {
        setForgetting(sha);
        return;
      }
      setForgetting(null);
      const n = await memory.forget(sha);
      setNote(`Forgot ${n} function${n === 1 ? "" : "s"}.`);
      await refresh();
    });

  const toggle = (va: number) =>
    setPicked((p) => {
      const n = new Set(p);
      if (n.has(va)) n.delete(va);
      else n.add(va);
      return n;
    });
  const allPicked = recalls != null && recalls.length > 0 && picked.size === recalls.length;

  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal mem-modal" role="dialog" aria-label="Function memory" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">Function memory</div>
        <p className="muted small">
          Remembers the functions you name and recognises them in other files: new versions, other builds, related samples. It keeps names, comments and
          variable names with a fingerprint of the code, in a database on this computer. Nothing is sent anywhere.
        </p>

        <div className="mem-stats small">
          {stats ? (
            <>
              <span>
                <b>{stats.functions.toLocaleString()}</b> functions from <b>{stats.sources.length}</b> file{stats.sources.length === 1 ? "" : "s"}
              </span>
              {stats.sources.length > 0 && (
                <button className="btn sm ghost" onClick={() => setSourcesOpen(!sourcesOpen)}>
                  {sourcesOpen ? "Hide files" : "Show files"}
                </button>
              )}
            </>
          ) : (
            <span className="muted">Loading…</span>
          )}
        </div>
        {sourcesOpen && stats && (
          <div className="mem-sources">
            {stats.sources.map((s) => (
              <div key={s.sha256} className="mem-source">
                <span className="mem-file" title={s.sha256}>
                  {s.file}
                </span>
                <span className="muted small">{s.functions} functions</span>
                <span className="muted small">{new Date(s.time * 1000).toLocaleDateString()}</span>
                <button className="btn sm ghost danger" disabled={busy != null} onClick={() => forget(s.sha256)}>
                  {forgetting === s.sha256 ? "Forget, sure?" : "Forget"}
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="mem-section">
          <div>
            <div className="mem-head">Learn from {info.file_name}</div>
            <div className="muted small">
              {userNames} name{userNames === 1 ? "" : "s"} you gave in this file. Learning again later updates them.
            </div>
            <label className="mem-check small">
              <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} /> Also names from symbols, exports and debug info
            </label>
          </div>
          <button className="btn" disabled={busy != null} onClick={learn}>
            {busy === "learn" ? "Learning…" : "Learn this file"}
          </button>
        </div>

        <div className="mem-section">
          <div>
            <div className="mem-head">Recognise functions</div>
            <div className="muted small">Finds functions this file shares with what was learned, by code and by the calls around it.</div>
          </div>
          <button className="btn primary" disabled={busy != null || !stats?.functions} onClick={recall}>
            {busy === "recall" ? "Searching…" : "Recognise"}
          </button>
        </div>

        {recalls && recalls.length > 0 && (
          <>
            <div className="mem-row mem-row-head small">
              <input type="checkbox" checked={allPicked} onChange={() => setPicked(allPicked ? new Set() : new Set(recalls.map((r) => r.address)))} />
              <span>Address</span>
              <span>Now</span>
              <span>Remembered as</span>
              <span>Match</span>
              <span>From</span>
            </div>
            <div className="mem-list">
              {recalls.map((r) => (
                <label key={r.address} className="mem-row small">
                  <input type="checkbox" checked={picked.has(r.address)} onChange={() => toggle(r.address)} />
                  <button
                    className="link mono"
                    onClick={(e) => {
                      e.preventDefault();
                      useStore.getState().goto(r.address, { tab: "pseudo" });
                    }}
                  >
                    {hex(r.address)}
                  </button>
                  <span className="mono muted ellipsis">{r.current}</span>
                  <span className="mono ellipsis" title={r.known.comment ?? r.known.name}>
                    {r.known.name}
                  </span>
                  <span className={r.exact ? "mem-score exact" : "mem-score"} title={r.exact ? "Identical code: comments inside the function are applied too" : "Similar code"}>
                    {r.exact ? "identical" : pct(r.score)}
                  </span>
                  <span className="muted ellipsis" title={r.known.source_sha256}>
                    {r.known.source}
                  </span>
                </label>
              ))}
            </div>
          </>
        )}

        {note && <div className="muted small mem-note">{note}</div>}
        {err && <div className="ai-warn">{err}</div>}

        <div className="modal-actions">
          <span className="muted small">{recalls && recalls.length > 0 ? `${picked.size} of ${recalls.length} selected` : ""}</span>
          <button className="btn" onClick={close}>
            Close
          </button>
          {recalls && recalls.length > 0 && (
            <button className="btn primary" disabled={busy != null || chosen.length === 0} onClick={apply}>
              {busy === "apply" ? "Applying…" : `Apply ${chosen.length}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
