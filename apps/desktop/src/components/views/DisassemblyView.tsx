import { useVirtualizer } from "@tanstack/react-virtual";
import { ChevronsUp, Loader2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { Instruction } from "../../engine/types";
import { addrWidth, hex, useStore } from "../../store";
import { InstructionText } from "./Listing";

const ROW = 21;
const CHUNK = 600;

type Row = { kind: "gap" } | { kind: "fnhead"; ins: Instruction } | { kind: "label"; ins: Instruction } | { kind: "ins"; ins: Instruction; idx: number };

export function DisassemblyView() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info)!;
  const cursor = useStore((s) => s.cursor);
  const revision = useStore((s) => s.revision);
  const functions = useStore((s) => s.functions);
  const showBytes = useStore((s) => s.showBytes);
  const st = useStore.getState;

  const [insns, setInsns] = useState<Instruction[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [hasPrev, setHasPrev] = useState(false);
  const [atTop, setAtTop] = useState(true);
  const parent = useRef<HTMLDivElement>(null);
  const loadingMore = useRef(false);
  const pendingScroll = useRef<number | null>(null);
  const loadedRev = useRef(-1);
  /** First address before a prepend; the viewport is shifted so it stays put. */
  const keepAnchor = useRef<number | null>(null);

  const fnStarts = useMemo(() => new Map(functions.map((f) => [f.address, f])), [functions]);
  const sectionOf = useMemo(() => {
    const secs = info.sections.filter((s) => s.vaddr && s.vsize).sort((a, b) => a.vaddr - b.vaddr);
    return (va: number) => secs.find((s) => va >= s.vaddr && va < s.vaddr + s.vsize)?.name ?? "";
  }, [info]);

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    insns.forEach((ins, idx) => {
      if (ins.label) {
        if (fnStarts.has(ins.address)) {
          if (out.length) out.push({ kind: "gap" });
          out.push({ kind: "fnhead", ins });
        } else {
          out.push({ kind: "label", ins });
        }
      }
      out.push({ kind: "ins", ins, idx });
    });
    return out;
  }, [insns, fnStarts]);

  // IDA-style jump arrows for branches whose source and target are both loaded.
  const LANES = 8;
  const arrows = useMemo(() => {
    const rowByAddr = new Map<number, number>();
    rows.forEach((r, i) => {
      if (r.kind === "ins") rowByAddr.set(r.ins.address, i);
    });
    const list: { from: number; to: number; cond: boolean; src: number; dst: number; lane: number }[] = [];
    rows.forEach((r, i) => {
      if (r.kind !== "ins" || r.ins.target == null || (r.ins.flow !== "jump" && r.ins.flow !== "condjump")) return;
      const t = rowByAddr.get(r.ins.target);
      if (t == null || t === i) return;
      list.push({ from: i, to: t, cond: r.ins.flow === "condjump", src: r.ins.address, dst: r.ins.target, lane: 0 });
    });
    // Shorter spans take the inner lanes.
    list.sort((a, b) => Math.abs(a.to - a.from) - Math.abs(b.to - b.from));
    const used: [number, number][][] = Array.from({ length: LANES }, () => []);
    for (const a of list) {
      const lo = Math.min(a.from, a.to);
      const hi = Math.max(a.from, a.to);
      let lane = used.findIndex((spans) => spans.every(([l, h]) => hi < l || lo > h));
      if (lane < 0) lane = LANES - 1;
      used[lane].push([lo, hi]);
      a.lane = lane;
    }
    return list;
  }, [rows]);

  const rowOf = useCallback((va: number) => rows.findIndex((r) => r.kind === "ins" && r.ins.address <= va && va < r.ins.address + Math.max(1, r.ins.size)), [rows]);

  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => ROW, overscan: 30 });

  // (Re)load the window around the cursor when it leaves the loaded range or after edits.
  useEffect(() => {
    if (cursor == null || !info.disassembly_supported) return;
    const first = insns[0];
    const last = insns[insns.length - 1];
    const inside = first && last && cursor >= first.address && cursor < last.address + last.size;
    if (inside && loadedRev.current === revision) {
      pendingScroll.current = cursor;
      return;
    }
    let live = true;
    (async () => {
      setBusy(true);
      try {
        // Keep the current window on edits if the cursor is still inside it.
        const fn = await session.functionAt(cursor);
        let start = inside ? first.address : (fn && fn.address <= cursor ? fn.address : cursor);
        let list = await session.disassemble(start, CHUNK);
        for (let i = 0; i < 8 && list.length && list[list.length - 1].address + list[list.length - 1].size <= cursor; i++) {
          const l = list[list.length - 1];
          list = list.concat(await session.disassemble(l.address + l.size, CHUNK));
        }
        if (!list.some((x) => cursor >= x.address && cursor < x.address + Math.max(1, x.size))) {
          start = cursor;
          list = await session.disassemble(cursor, CHUNK);
        }
        const prev = await session.previousAnchor(list[0]?.address ?? start);
        if (!live) return;
        loadedRev.current = revision;
        setInsns(list);
        setHasPrev(prev != null);
        setError(null);
        pendingScroll.current = cursor;
      } catch (e) {
        if (live) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (live) setBusy(false);
      }
    })();
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cursor, revision, session, info]);

  // Keep the viewport visually still after prepending earlier code.
  useEffect(() => {
    if (keepAnchor.current == null || !parent.current) return;
    const a = keepAnchor.current;
    keepAnchor.current = null;
    const idx = rows.findIndex((r) => r.kind !== "gap" && r.ins.address === a);
    if (idx > 0) parent.current.scrollTop += idx * ROW;
  }, [rows]);

  // Scroll the cursor row into view once rows exist.
  useEffect(() => {
    if (pendingScroll.current == null) return;
    const r = rowOf(pendingScroll.current);
    if (r >= 0) {
      const el = parent.current;
      const top = r * ROW;
      if (el && (top < el.scrollTop + ROW * 2 || top > el.scrollTop + el.clientHeight - ROW * 3)) {
        v.scrollToIndex(Math.max(0, r - 6), { align: "start" });
      }
      pendingScroll.current = null;
    }
  }, [rows, rowOf, v]);

  const loadMore = useCallback(async () => {
    if (loadingMore.current || !insns.length) return;
    loadingMore.current = true;
    try {
      const last = insns[insns.length - 1];
      const more = await session.disassemble(last.address + last.size, CHUNK).catch(() => []);
      if (more.length) setInsns((cur) => cur.concat(more.filter((m) => m.address > cur[cur.length - 1].address)));
    } finally {
      loadingMore.current = false;
    }
  }, [insns, session]);

  const loadPrev = useCallback(async () => {
    if (loadingMore.current || !insns.length) return;
    loadingMore.current = true;
    try {
      const first = insns[0].address;
      const anchor = await session.previousAnchor(first);
      if (anchor == null) return setHasPrev(false);
      let prev = await session.disassemble(anchor, CHUNK);
      prev = prev.filter((p) => p.address < first);
      keepAnchor.current = first;
      setInsns((cur) => prev.concat(cur));
      setHasPrev((await session.previousAnchor(anchor)) != null);
    } finally {
      loadingMore.current = false;
    }
  }, [insns, session]);

  // Infinite scroll downward.
  const items = v.getVirtualItems();
  useEffect(() => {
    const lastItem = items[items.length - 1];
    if (lastItem && lastItem.index > rows.length - 80) loadMore();
  }, [items, rows.length, loadMore]);

  const cursorIdx = useMemo(() => (cursor == null ? -1 : insns.findIndex((i) => cursor >= i.address && cursor < i.address + Math.max(1, i.size))), [insns, cursor]);

  const onKey = (e: React.KeyboardEvent) => {
    const s = st();
    const cur = insns[cursorIdx];
    const move = (d: number) => {
      const n = insns[Math.min(insns.length - 1, Math.max(0, cursorIdx + d))];
      if (n) {
        s.setCursor(n.address);
        pendingScroll.current = n.address;
      }
    };
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        move(1);
        break;
      case "ArrowUp":
        e.preventDefault();
        move(-1);
        break;
      case "PageDown":
        e.preventDefault();
        move(30);
        break;
      case "PageUp":
        e.preventDefault();
        move(-30);
        break;
      case "Enter":
        if (cur?.target != null) s.goto(cur.target);
        break;
      case " ":
        e.preventDefault();
        s.set("centerTab", "graph");
        break;
      case "n":
      case "N": {
        e.preventDefault();
        if (cursor == null) break;
        const fn = [...fnStarts.values()].filter((f) => f.address <= cursor && cursor < f.address + Math.max(1, f.size)).pop();
        const va = fn?.address ?? cursor;
        s.set("dialog", { kind: "rename", va, initial: fn?.name ?? cur?.label ?? "" });
        break;
      }
      case ";":
      case ":":
        e.preventDefault();
        if (cursor != null) s.set("dialog", { kind: "comment", va: cur?.address ?? cursor, initial: cur?.user_comment ?? "" });
        break;
      case "x":
      case "X":
        s.set("inspectorOpen", true);
        break;
      case "p":
      case "P":
        e.preventDefault();
        if (cursor != null) s.makeFunction(cur?.address ?? cursor);
        break;
      case "Tab":
        e.preventDefault();
        s.set("centerTab", "pseudo");
        break;
      case "b":
      case "B":
        s.set("showBytes", !s.showBytes);
        break;
    }
  };

  if (!info.disassembly_supported) {
    return <div className="empty">Disassembly for this architecture is on the roadmap. Headers, imports, strings and hex view are available.</div>;
  }
  if (error) return <div className="empty">{error}</div>;

  const aw = addrWidth(info);
  return (
    <div className="listing-wrap">
      {busy && (
        <div className="view-busy">
          <Loader2 size={14} className="spin" /> Loading…
        </div>
      )}
      {hasPrev && atTop && (
        <button className="load-prev" onClick={loadPrev}>
          <ChevronsUp size={13} /> Load previous code
        </button>
      )}
      <div
        ref={parent}
        className={`listing mono ${showBytes ? "with-bytes" : ""}`}
        tabIndex={0}
        onKeyDown={onKey}
        onScroll={(e) => {
          const top = e.currentTarget.scrollTop < ROW * 2;
          if (top !== atTop) setAtTop(top);
        }}
      >
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          <svg className="jump-arrows" width={LANES * 6 + 12} height={v.getTotalSize()} aria-hidden>
            {(() => {
              const first = items[0]?.index ?? 0;
              const last = items[items.length - 1]?.index ?? 0;
              const right = LANES * 6 + 10;
              const curAddr = cursorIdx >= 0 ? insns[cursorIdx]?.address : undefined;
              return arrows
                .filter((a) => Math.max(a.from, a.to) >= first && Math.min(a.from, a.to) <= last)
                .map((a, k) => {
                  const x = right - 8 - a.lane * 6;
                  const y1 = a.from * ROW + ROW / 2;
                  const y2 = a.to * ROW + ROW / 2;
                  const hot = a.src === curAddr || a.dst === curAddr;
                  const cls = `ja ${a.cond ? "cond" : "uncond"} ${hot ? "hot" : ""} ${a.to < a.from ? "back" : ""}`;
                  return (
                    <g key={k} className={cls}>
                      <path d={`M${right},${y1} H${x} V${y2} H${right - 1}`} />
                      <path className="ja-head" d={`M${right - 5},${y2 - 3} L${right},${y2} L${right - 5},${y2 + 3} z`} />
                    </g>
                  );
                });
            })()}
          </svg>
          {items.map((vr) => {
            const r = rows[vr.index];
            const style = { transform: `translateY(${vr.start}px)`, height: ROW };
            if (r.kind === "gap") return <div key={vr.key} className="lrow gap" style={style} />;
            if (r.kind === "fnhead") {
              const f = fnStarts.get(r.ins.address);
              return (
                <div key={vr.key} className="lrow fnhead" style={style}>
                  <span className="l-addr">
                    <span className="l-sec">{sectionOf(r.ins.address)}:</span>
                    {hex(r.ins.address, aw)}
                  </span>
                  <span className="fn-title">
                    <span className="fn-kw">function</span> <span className="fn-name">{r.ins.label}</span>
                    {f && (
                      <span className="fn-meta">
                        {f.blocks} blocks · {f.instructions} instr · {f.xrefs} xref{f.xrefs === 1 ? "" : "s"}
                      </span>
                    )}
                  </span>
                </div>
              );
            }
            if (r.kind === "label") {
              return (
                <div key={vr.key} className="lrow lbl" style={style}>
                  <span className="l-addr">
                    <span className="l-sec">{sectionOf(r.ins.address)}:</span>
                    {hex(r.ins.address, aw)}
                  </span>
                  <span className="l-label">{r.ins.label}:</span>
                </div>
              );
            }
            const ins = r.ins;
            const selected = r.idx === cursorIdx;
            return (
              <div
                key={vr.key}
                className={`lrow ins ${selected ? "sel" : ""}`}
                style={style}
                onMouseDown={() => {
                  st().setCursor(ins.address);
                  parent.current?.focus();
                }}
                onDoubleClick={() => ins.target != null && st().goto(ins.target)}
              >
                <span className="l-addr">
                  <span className="l-sec">{sectionOf(ins.address)}:</span>
                  {hex(ins.address, aw)}
                </span>
                {showBytes && <span className="l-bytes">{ins.bytes.length > 20 ? ins.bytes.slice(0, 19) + "…" : ins.bytes}</span>}
                <span className="l-code">
                  <InstructionText ins={ins} onFollow={(va) => st().goto(va)} />
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
