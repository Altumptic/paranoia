import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState } from "react";

import { addrWidth, hex, parseAddress, useStore } from "../../store";

const ROW = 20;
const COLS = 16;
const PAGE = 8192;

function byteClass(b: number): string {
  if (b === 0) return "b0";
  if (b === 0xff) return "bff";
  if (b >= 0x20 && b < 0x7f) return "bp";
  if (b === 0x0a || b === 0x0d || b === 0x09) return "bw";
  return "bx";
}

export function HexView() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info)!;
  const cursor = useStore((s) => s.cursor);
  const revision = useStore((s) => s.revision);
  const patches = useStore((s) => s.annotations.patches ?? {});
  const [nibble, setNibble] = useState<number | null>(null);
  const [pages, setPages] = useState<Map<number, Uint8Array>>(new Map());
  const [sel, setSel] = useState<number | null>(null);
  const [gotoText, setGotoText] = useState("");
  const parent = useRef<HTMLDivElement>(null);
  const inflight = useRef(new Set<number>());

  const size = info.file_size;
  const rowCount = Math.ceil(size / COLS);
  const v = useVirtualizer({ count: rowCount, getScrollElement: () => parent.current, estimateSize: () => ROW, overscan: 20 });
  const items = v.getVirtualItems();

  // Offset -> VA through section raw ranges (done locally for speed).
  const vaOf = useMemo(() => {
    const secs = info.sections.filter((s) => s.raw_size > 0 && s.vaddr).sort((a, b) => a.offset - b.offset);
    return (off: number) => {
      const s = secs.find((s) => off >= s.offset && off < s.offset + s.raw_size);
      return s ? s.vaddr + (off - s.offset) : null;
    };
  }, [info]);

  // Fetch pages covering the visible rows.
  useEffect(() => {
    if (!items.length) return;
    const first = Math.floor((items[0].index * COLS) / PAGE);
    const last = Math.floor((items[items.length - 1].index * COLS + COLS) / PAGE);
    for (let p = first; p <= last; p++) {
      if (pages.has(p) || inflight.current.has(p)) continue;
      inflight.current.add(p);
      session.read(p * PAGE, PAGE).then((bytes) => {
        inflight.current.delete(p);
        setPages((m) => new Map(m).set(p, bytes));
      });
    }
  }, [items, pages, session]);

  useEffect(() => {
    inflight.current.clear();
    setPages(new Map());
  }, [revision]);

  // Follow the global cursor (VA -> file offset).
  useEffect(() => {
    if (cursor == null) return;
    let live = true;
    session.vaToOffset(cursor).then((off) => {
      if (!live || off == null) return;
      setSel(off);
      v.scrollToIndex(Math.floor(off / COLS), { align: "center" });
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cursor, session]);

  const byteAt = (off: number): number | undefined => pages.get(Math.floor(off / PAGE))?.[off % PAGE];

  const select = (off: number) => {
    setSel(off);
    setNibble(null);
    const va = vaOf(off);
    if (va != null) useStore.getState().setCursor(va);
  };

  const jump = () => {
    const off = parseAddress(gotoText);
    if (off == null || off >= size) return useStore.getState().toast("Offset is outside the file", "error");
    setSel(off);
    v.scrollToIndex(Math.floor(off / COLS), { align: "center" });
  };

  const aw = addrWidth(info);
  const selBytes = sel != null ? [0, 1, 2, 3, 4, 5, 6, 7].map((i) => byteAt(sel + i)) : [];
  const le = (n: number): number | null => {
    const bs = selBytes.slice(0, n);
    return bs.every((b) => b != null) ? bs.reduceRight<number>((acc, b) => acc * 256 + (b as number), 0) : null;
  };

  return (
    <div className="hexview">
      <div className="hex-toolbar">
        <input
          className="input mono"
          style={{ width: 200 }}
          placeholder="Go to file offset (hex)"
          value={gotoText}
          onChange={(e) => setGotoText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && jump()}
        />
        <span className="muted small">Select a byte and type hex digits to patch</span>
        {sel != null && (
          <div className="hex-inspect mono">
            <span>
              off <b>{hex(sel)}</b>
            </span>
            {vaOf(sel) != null && (
              <span>
                va <b>{hex(vaOf(sel)!, aw)}</b>
              </span>
            )}
            {le(1) != null && (
              <span>
                u8 <b>{le(1)}</b>
              </span>
            )}
            {le(2) != null && (
              <span>
                u16 <b>{le(2)}</b>
              </span>
            )}
            {le(4) != null && (
              <span>
                u32 <b>{le(4)}</b> <i>0x{hex(le(4)!)}</i>
              </span>
            )}
          </div>
        )}
      </div>
      <div className="hex-head mono">
        <span className="h-off">Offset</span>
        <span className="h-va">Address</span>
        <span className="h-bytes">
          {Array.from({ length: COLS }, (_, i) => (
            <span key={i} className={i === 8 ? "gap" : ""}>
              {hex(i, 2)}
            </span>
          ))}
        </span>
        <span className="h-ascii">ASCII</span>
      </div>
      <div
        ref={parent}
        className="hex-scroll mono"
        tabIndex={0}
        onKeyDown={(e) => {
          if (sel == null) return;
          const move = (d: number) => {
            const n = Math.min(size - 1, Math.max(0, sel + d));
            select(n);
            v.scrollToIndex(Math.floor(n / COLS), { align: "auto" });
          };
          if (e.key === "ArrowRight") return move(1), e.preventDefault();
          if (e.key === "ArrowLeft") return move(-1), e.preventDefault();
          if (e.key === "ArrowDown") return move(COLS), e.preventDefault();
          if (e.key === "ArrowUp") return move(-COLS), e.preventDefault();
          if (e.key === "Escape") return setNibble(null);
          // Typing hex digits patches the selected byte (two digits per byte).
          if (/^[0-9a-fA-F]$/.test(e.key) && !e.ctrlKey && !e.altKey) {
            e.preventDefault();
            const d = parseInt(e.key, 16);
            if (nibble == null) setNibble(d);
            else {
              const b = (nibble << 4) | d;
              setNibble(null);
              useStore.getState().patch(sel, b.toString(16).padStart(2, "0"));
              move(1);
            }
          }
        }}
      >
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          {items.map((r) => {
            const base = r.index * COLS;
            const va = vaOf(base);
            const cells = [];
            const chars = [];
            for (let i = 0; i < COLS; i++) {
              const off = base + i;
              if (off >= size) break;
              const b = byteAt(off);
              const s = sel === off;
              cells.push(
                <span
                  key={i}
                  className={`hb ${b == null ? "bl" : byteClass(b)} ${s ? "sel" : ""} ${s && nibble != null ? "editing" : ""} ${i === 8 ? "gap" : ""} ${String(off) in patches ? "patched" : ""}`}
                  onMouseDown={() => select(off)}
                  title={String(off) in patches ? "Patched byte" : undefined}
                >
                  {b == null ? "··" : s && nibble != null ? `${nibble.toString(16).toUpperCase()}_` : hex(b, 2)}
                </span>,
              );
              chars.push(
                <span key={i} className={`ha ${b == null ? "bl" : byteClass(b)} ${s ? "sel" : ""} ${String(off) in patches ? "patched" : ""}`} onMouseDown={() => select(off)}>
                  {b == null ? " " : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."}
                </span>,
              );
            }
            return (
              <div key={r.key} className="hrow" style={{ transform: `translateY(${r.start}px)`, height: ROW }}>
                <span className="h-off">{hex(base, 8)}</span>
                <span className="h-va">{va != null ? hex(va, aw) : ""}</span>
                <span className="h-bytes">{cells}</span>
                <span className="h-ascii">{chars}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
