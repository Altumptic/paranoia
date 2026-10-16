import { useEffect, useMemo, useRef, useState } from "react";

import { fmtAddr, useStore } from "../store";
import { cssVar, useTheme } from "../theme";

interface Span {
  start: number;
  end: number;
  kind: "func" | "code" | "data" | "bss" | "extern";
}

/** IDA's navigation band: the whole image at a glance, coloured by what lives there. */
export function NavBand() {
  const info = useStore((s) => s.info)!;
  const functions = useStore((s) => s.functions);
  const cursor = useStore((s) => s.cursor);
  const [, , theme] = useTheme();
  const ref = useRef<HTMLCanvasElement>(null);
  const [hover, setHover] = useState<{ x: number; va: number } | null>(null);

  // Address range covered by mapped sections, laid out contiguously (gaps squeezed out).
  const layout = useMemo(() => {
    const secs = info.sections.filter((s) => s.vaddr && s.vsize).sort((a, b) => a.vaddr - b.vaddr);
    let total = 0;
    const segs = secs.map((s) => {
      const seg = { s, base: total };
      total += s.vsize;
      return seg;
    });
    const spans: Span[] = [];
    for (const { s } of segs) {
      const extern = /idata|got|plt|la_symbol|nl_symbol|stubs/i.test(s.name);
      spans.push({ start: s.vaddr, end: s.vaddr + s.vsize, kind: extern ? "extern" : s.perms.x ? "code" : s.raw_size === 0 ? "bss" : "data" });
    }
    for (const f of functions) spans.push({ start: f.address, end: f.address + Math.max(1, f.size), kind: "func" });
    const toPos = (va: number) => {
      for (const { s, base } of segs) if (va >= s.vaddr && va < s.vaddr + s.vsize) return (base + (va - s.vaddr)) / Math.max(1, total);
      return null;
    };
    const toVa = (p: number) => {
      const off = p * total;
      for (const { s, base } of segs) if (off >= base && off < base + s.vsize) return s.vaddr + Math.floor(off - base);
      return segs[0]?.s.vaddr ?? 0;
    };
    return { spans, toPos, toVa };
  }, [info, functions]);

  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const draw = () => {
      const dpr = window.devicePixelRatio || 1;
      const w = c.clientWidth;
      const h = c.clientHeight;
      c.width = w * dpr;
      c.height = h * dpr;
      const g = c.getContext("2d")!;
      g.scale(dpr, dpr);
      const colors: Record<Span["kind"], string> = {
        code: cssVar("--danger"),
        func: cssVar("--info"),
        data: cssVar("--faint"),
        bss: cssVar("--bg-4"),
        extern: cssVar("--violet"),
      };
      g.fillStyle = cssVar("--bg-3");
      g.fillRect(0, 0, w, h);
      for (const kind of ["bss", "data", "extern", "code", "func"] as const) {
        g.fillStyle = colors[kind];
        for (const sp of layout.spans) {
          if (sp.kind !== kind) continue;
          const a = layout.toPos(sp.start);
          const b = layout.toPos(sp.end - 1);
          if (a == null || b == null) continue;
          g.fillRect(Math.floor(a * w), 0, Math.max(1, Math.ceil((b - a) * w)), h);
        }
      }
      if (cursor != null) {
        const p = layout.toPos(cursor);
        if (p != null) {
          g.fillStyle = cssVar("--warn");
          g.fillRect(Math.round(p * w) - 1, 0, 3, h);
        }
      }
    };
    draw();
    const ro = new ResizeObserver(draw);
    ro.observe(c);
    return () => ro.disconnect();
  }, [layout, cursor, theme]);

  const at = (e: React.MouseEvent) => {
    const r = e.currentTarget.getBoundingClientRect();
    return layout.toVa(Math.min(0.9999, Math.max(0, (e.clientX - r.left) / r.width)));
  };

  return (
    <div className="navband" title="Navigation band — blue: functions, red: code outside functions, grey: data, violet: imports">
      <canvas
        ref={ref}
        onMouseMove={(e) => setHover({ x: e.clientX - e.currentTarget.getBoundingClientRect().left, va: at(e) })}
        onMouseLeave={() => setHover(null)}
        onClick={(e) => useStore.getState().goto(at(e))}
      />
      {hover && (
        <div className="navband-tip mono" style={{ left: hover.x }}>
          {fmtAddr(hover.va, info)}
        </div>
      )}
    </div>
  );
}
