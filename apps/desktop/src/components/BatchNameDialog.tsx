import { useEffect, useState } from "react";

import { useStore } from "../store";

const hex = (v: number) => v.toString(16).toUpperCase();
const NAME = /^[A-Za-z_.$@?][\w.$@?:<>~-]*$/;

/**
 * Assistant → Name many functions…: asks the model for a name for each of the most-referenced functions
 * that still have an automatic one, then lets you pick which suggestions to keep and edit them before
 * anything is renamed. One request per function; each is recorded in the disclosure ledger, and for a
 * model that is not on this computer the main process asks you to approve the whole batch first.
 */
export function BatchNameDialog() {
  const b = useStore((s) => s.batchName);
  const [count, setCount] = useState(20);

  useEffect(() => {
    if (b?.phase === "setup") setCount(b.count);
  }, [b?.phase]);

  useEffect(() => {
    if (!b) return;
    const key = (e: KeyboardEvent) => e.key === "Escape" && useStore.getState().cancelBatchName();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [b]);

  if (!b) return null;
  const st = useStore.getState;
  const set = (va: number, patch: Partial<{ suggestion: string; picked: boolean }>) =>
    useStore.setState({ batchName: { ...b, items: b.items.map((it) => (it.va === va ? { ...it, ...patch } : it)) } });
  const done = b.items.filter((i) => i.status === "done");
  const picked = done.filter((i) => i.picked && NAME.test(i.suggestion));
  const where = b.local ? "the model on this computer" : b.host;

  return (
    <div className="modal-veil" onMouseDown={() => b.phase !== "running" && st().cancelBatchName()}>
      <div className="modal batch-modal" role="dialog" aria-label="Name many functions" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">Name many functions</div>
        {b.phase === "setup" && (
          <>
            <p className="muted small">
              {b.items.length} functions still have automatic names. Paranoia will send the decompiled code of the most-referenced ones, one request each, to {where}
              {b.local ? "" : " (you will be asked to approve the batch)"}, and show the suggestions for you to review. Nothing is renamed until you apply it.
            </p>
            <label className="ai-field">
              <span>How many functions (1–{Math.min(100, b.items.length)})</span>
              <input className="input mono" type="number" min={1} max={Math.min(100, b.items.length)} value={count} onChange={(e) => setCount(Math.max(1, Math.min(Number(e.target.value) || 1, b.items.length, 100)))} />
            </label>
          </>
        )}
        {b.phase !== "setup" && (
          <>
            <div className="muted small">
              {b.phase === "running" ? `Asking ${where}… ${done.length + b.items.filter((i) => i.status === "error" || (i.status === "skipped" && i.note !== "not asked")).length} of ${b.count}` : `${done.length} suggestion${done.length === 1 ? "" : "s"} from ${where}. They can be wrong: read the code before you keep one.`}
            </div>
            <div className="batch-list">
              {b.items
                .filter((i) => i.status !== "waiting" || b.phase === "running")
                .slice(0, b.count)
                .map((i) => (
                  <div key={i.va} className="batch-row">
                    <input type="checkbox" checked={i.picked} disabled={i.status !== "done"} onChange={(e) => set(i.va, { picked: e.target.checked })} aria-label={`Keep the name for ${i.name}`} />
                    <span className="mono" title={`0x${hex(i.va)}`}>
                      {i.name}
                    </span>
                    {i.status === "done" ? (
                      <input
                        className={`input mono ${NAME.test(i.suggestion) ? "" : "invalid"}`}
                        value={i.suggestion}
                        title={i.reason}
                        onChange={(e) => set(i.va, { suggestion: e.target.value })}
                        disabled={b.phase === "running"}
                      />
                    ) : (
                      <span className="muted small">{i.status === "busy" ? "asking…" : i.status === "waiting" ? "waiting" : (i.note ?? i.status)}</span>
                    )}
                  </div>
                ))}
            </div>
          </>
        )}
        <div className="modal-actions">
          <span className="muted small">Esc to {b.phase === "running" ? "stop" : "close"}</span>
          {b.phase === "setup" && (
            <button className="btn sm primary" onClick={() => void st().runBatchName(count)}>
              Ask {count}
            </button>
          )}
          {b.phase === "running" && (
            <button className="btn sm" onClick={() => st().cancelBatchName()}>
              Stop
            </button>
          )}
          {b.phase === "review" && (
            <button className="btn sm primary" disabled={picked.length === 0} onClick={() => void st().applyBatchName()}>
              Rename {picked.length}
            </button>
          )}
          <button className="btn sm" onClick={() => useStore.setState({ batchName: null })} disabled={b.phase === "running"}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
