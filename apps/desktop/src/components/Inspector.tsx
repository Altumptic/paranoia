import { ArrowDownRight, Braces, MessageSquare, PenLine, Share2 } from "lucide-react";
import { useEffect, useState } from "react";

import type { AddressInfo, FunctionSummary, Xref } from "../engine/types";
import { fmtAddr, hex, useStore } from "../store";

const KIND_LABEL: Record<Xref["kind"], string> = { call: "call", jump: "jmp", data: "data" };

export function Inspector() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info);
  const cursor = useStore((s) => s.cursor);
  const revision = useStore((s) => s.revision);
  const goto = useStore((s) => s.goto);
  const [addr, setAddr] = useState<AddressInfo | null>(null);
  const [fn, setFn] = useState<FunctionSummary | null>(null);
  const [xrefs, setXrefs] = useState<Xref[]>([]);
  const [fnXrefs, setFnXrefs] = useState<Xref[]>([]);
  const [comment, setComment] = useState<string | null>(null);

  useEffect(() => {
    if (cursor == null) return;
    let live = true;
    (async () => {
      const [a, f, x, ann] = await Promise.all([session.addressInfo(cursor), session.functionAt(cursor), session.xrefs(cursor), session.annotations()]);
      const fx = f && f.address !== cursor ? await session.xrefs(f.address) : [];
      if (!live) return;
      setAddr(a);
      setFn(f);
      setXrefs(x);
      setFnXrefs(fx);
      setComment(ann.comments[String(cursor)] ?? null);
    })();
    return () => {
      live = false;
    };
  }, [session, cursor, revision]);

  if (cursor == null || !addr) return <div className="inspector empty">Nothing selected</div>;

  const openDialog = (kind: "rename" | "comment") => {
    const initial = kind === "rename" ? (addr.name ?? "") : (comment ?? "");
    useStore.getState().set("dialog", { kind, va: kind === "rename" && fn && !addr.name ? fn.address : cursor, initial });
  };

  return (
    <div className="inspector">
      <div className="side-head">
        <span className="side-title">Inspector</span>
      </div>
      <div className="insp-scroll">
        <section className="insp-card">
          <div className="insp-addr mono selectable">{fmtAddr(cursor, info)}</div>
          {addr.name && <div className="insp-name mono selectable">{addr.name}</div>}
          <dl className="kv">
            <dt>Section</dt>
            <dd>{addr.section ?? "—"}</dd>
            <dt>File offset</dt>
            <dd className="mono">{addr.offset != null ? `0x${hex(addr.offset)}` : "not in file"}</dd>
            <dt>Memory</dt>
            <dd>{addr.executable ? "code (executable)" : "data"}</dd>
          </dl>
          <div className="insp-actions">
            <button className="btn sm" onClick={() => openDialog("rename")} title="Rename (N)">
              <PenLine size={13} /> Rename
            </button>
            <button className="btn sm" onClick={() => openDialog("comment")} title="Comment (;)">
              <MessageSquare size={13} /> Comment
            </button>
          </div>
          {comment && <div className="insp-comment selectable">{comment}</div>}
        </section>

        {fn && (
          <section className="insp-card">
            <div className="insp-card-title">
              <Braces size={13} /> Function
            </div>
            <button className="insp-fn mono" onClick={() => goto(fn.address)}>
              {fn.name}
            </button>
            <div className="insp-stats">
              <div>
                <b>{fn.instructions}</b>
                <span>instr.</span>
              </div>
              <div>
                <b>{fn.blocks}</b>
                <span>blocks</span>
              </div>
              <div>
                <b>{fn.calls}</b>
                <span>calls</span>
              </div>
              <div>
                <b>{fn.xrefs}</b>
                <span>callers</span>
              </div>
            </div>
            <div className="insp-sub mono">
              {fmtAddr(fn.address, info)} · {fn.size} bytes · via {fn.source === "exceptiontable" ? ".pdata" : fn.source}
            </div>
          </section>
        )}

        <XrefList title={`References to ${addr.name ?? fmtAddr(cursor, info)}`} xrefs={xrefs} />
        {fn && fn.address !== cursor && <XrefList title={`Callers of ${fn.name}`} xrefs={fnXrefs} />}
      </div>
    </div>
  );
}

function XrefList({ title, xrefs }: { title: string; xrefs: Xref[] }) {
  const info = useStore((s) => s.info);
  const goto = useStore((s) => s.goto);
  return (
    <section className="insp-card">
      <div className="insp-card-title">
        <Share2 size={13} /> <span className="ellipsis">{title}</span>
        <span className="count">{xrefs.length}</span>
      </div>
      {xrefs.length === 0 ? (
        <div className="muted small">No references found.</div>
      ) : (
        <ul className="xref-list">
          {xrefs.slice(0, 500).map((x) => (
            <li key={`${x.from}-${x.kind}`}>
              <button className="xref" onClick={() => goto(x.from, { tab: "disasm" })}>
                <ArrowDownRight size={12} className={`xk xk-${x.kind}`} />
                <span className={`xref-kind xk-${x.kind}`}>{KIND_LABEL[x.kind]}</span>
                <span className="xref-fn">{x.function_name ?? "—"}</span>
                <span className="mono xref-addr">{fmtAddr(x.from, info)}</span>
              </button>
            </li>
          ))}
          {xrefs.length > 500 && <li className="muted small">…and {xrefs.length - 500} more</li>}
        </ul>
      )}
    </section>
  );
}
