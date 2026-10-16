import { ArrowDown, ArrowUp } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { Xref } from "../engine/types";
import { fmtAddr, useStore } from "../store";

const TYPE: Record<Xref["kind"], string> = { call: "p", jump: "j", data: "o" };

/** IDA's "xrefs to" dialog: direction, type, location and the referencing instruction. */
export function XrefsDialog() {
  const va = useStore((s) => s.xrefsFor);
  const session = useStore((s) => s.session);
  const info = useStore((s) => s.info);
  const [rows, setRows] = useState<Xref[] | null>(null);
  const [name, setName] = useState<string | null>(null);
  const [sel, setSel] = useState(0);
  const list = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (va == null || !session) return;
    let live = true;
    setRows(null);
    setSel(0);
    Promise.all([session.xrefs(va), session.addressInfo(va)]).then(([x, a]) => {
      if (!live) return;
      setRows(x);
      setName(a.name);
    });
    return () => {
      live = false;
    };
  }, [va, session]);

  useEffect(() => {
    list.current?.querySelector(`[data-i="${sel}"]`)?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  if (va == null) return null;
  const close = () => useStore.getState().set("xrefsFor", null);
  const go = (x: Xref | undefined) => {
    if (!x) return;
    close();
    useStore.getState().goto(x.from, { tab: "disasm" });
  };

  return (
    <div className="modal-veil" onMouseDown={close}>
      <div
        className="modal xrefs-modal"
        onMouseDown={(e) => e.stopPropagation()}
        tabIndex={-1}
        ref={(el) => el?.focus()}
        onKeyDown={(e) => {
          if (e.key === "Escape") close();
          else if (e.key === "ArrowDown") setSel((s) => Math.min(s + 1, (rows?.length ?? 1) - 1));
          else if (e.key === "ArrowUp") setSel((s) => Math.max(s - 1, 0));
          else if (e.key === "Enter") go(rows?.[sel]);
        }}
      >
        <div className="modal-title">
          xrefs to <span className="mono xr-name">{name ?? fmtAddr(va, info)}</span>
          {rows && <span className="count">{rows.length}</span>}
        </div>
        <div className="xr-head mono">
          <span>Dir</span>
          <span>T</span>
          <span>Address</span>
          <span>Text</span>
        </div>
        <div className="xr-list" ref={list}>
          {rows == null && <div className="muted small xr-empty">Loading…</div>}
          {rows?.length === 0 && <div className="muted small xr-empty">No cross references.</div>}
          {rows?.map((x, i) => (
            <div key={`${x.from}-${i}`} data-i={i} className={`xr-row mono ${i === sel ? "sel" : ""}`} onMouseMove={() => setSel(i)} onClick={() => go(x)}>
              <span className="xr-dir">{x.from < va ? <ArrowUp size={12} /> : <ArrowDown size={12} />}</span>
              <span className={`xr-type xk-${x.kind}`}>{TYPE[x.kind]}</span>
              <span className="xr-addr">
                {x.function_name ? `${x.function_name}+${(x.from - (x.function ?? x.from)).toString(16).toUpperCase()}` : fmtAddr(x.from, info)}
              </span>
              <span className="xr-text">{x.text ?? ""}</span>
            </div>
          ))}
        </div>
        <div className="modal-actions">
          <span className="muted small">↑↓ select · Enter jump · Esc close · p = call, j = jump, o = data</span>
        </div>
      </div>
    </div>
  );
}
