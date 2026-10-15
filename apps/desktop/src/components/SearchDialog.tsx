import { Binary, Hash, Loader2, Type } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { Hit, SearchKind } from "../engine/types";
import { fmtAddr, hex, useStore } from "../store";

const MODES: { id: SearchKind; label: string; icon: typeof Hash; hint: string; key: string }[] = [
  { id: "bytes", label: "Byte pattern", icon: Binary, hint: "48 8B ?? 24 10 — use ?? for any byte", key: "Alt B" },
  { id: "text", label: "Text", icon: Type, hint: "Finds ASCII and UTF-16 occurrences", key: "Alt T" },
  { id: "immediate", label: "Immediate", icon: Hash, hint: "0x1F4, 500 or 1F4h — constants in instructions", key: "Alt I" },
];

export function SearchDialog() {
  const mode = useStore((s) => s.search);
  const session = useStore((s) => s.session);
  const info = useStore((s) => s.info);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (mode) {
      setHits(null);
      setError(null);
      setTimeout(() => input.current?.select(), 0);
    }
  }, [mode]);

  if (!mode || !session) return null;
  const close = () => useStore.getState().set("search", null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setHits(await session.searchAdvanced(mode, q));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setHits(null);
    } finally {
      setBusy(false);
    }
  };
  const m = MODES.find((x) => x.id === mode)!;

  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal search-modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="seg">
          {MODES.map((x) => (
            <button key={x.id} className={`seg-btn ${x.id === mode ? "on" : ""}`} onClick={() => useStore.getState().set("search", x.id)}>
              <x.icon size={13} /> {x.label} <span className="kbd">{x.key}</span>
            </button>
          ))}
        </div>
        <div className="search-row">
          <input
            ref={input}
            autoFocus
            className="input mono"
            value={q}
            placeholder={m.hint}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") run();
              if (e.key === "Escape") close();
            }}
          />
          <button className="btn primary" onClick={run} disabled={busy}>
            {busy ? <Loader2 size={14} className="spin" /> : "Search"}
          </button>
        </div>
        {error && <div className="search-error">{error}</div>}
        {hits && (
          <div className="search-results">
            <div className="muted small search-count">
              {hits.length === 0 ? "No matches" : `${hits.length.toLocaleString()} match${hits.length === 1 ? "" : "es"}${hits.length >= 2000 ? " (first 2000)" : ""}`}
            </div>
            <ul>
              {hits.map((h, i) => (
                <li key={i}>
                  <button
                    className="hit"
                    onClick={() => {
                      close();
                      if (h.address != null) useStore.getState().goto(h.address, mode === "immediate" ? { tab: "disasm" } : undefined);
                      else useStore.getState().toast(`Match at file offset 0x${hex(h.offset)} is outside mapped memory — see the hex view.`);
                    }}
                  >
                    <span className="mono hit-addr">{h.address != null ? fmtAddr(h.address, info) : `+${hex(h.offset)}`}</span>
                    <span className="hit-fn">{h.function ?? "—"}</span>
                    <span className="mono hit-prev">{h.preview}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
