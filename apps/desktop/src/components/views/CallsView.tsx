import dagre from "@dagrejs/dagre";
import { Maximize } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import type { CallGraph } from "../../engine/types";
import { useStore } from "../../store";

const NODE_H = 34;

/** Call graph around the current function (IDA's proximity view). */
export function CallsView() {
  const session = useStore((s) => s.session)!;
  const cursor = useStore((s) => s.cursor);
  const revision = useStore((s) => s.revision);
  const st = useStore.getState;
  const [graph, setGraph] = useState<CallGraph | null>(null);
  const [depth, setDepth] = useState({ up: 1, down: 2 });
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);

  useEffect(() => {
    if (cursor == null) return;
    let live = true;
    session.callGraph(cursor, depth.up, depth.down).then((g) => live && setGraph(g));
    return () => {
      live = false;
    };
  }, [cursor, session, depth, revision]);

  const layout = useMemo(() => {
    if (!graph) return null;
    const d = new dagre.graphlib.Graph();
    d.setGraph({ rankdir: "TB", nodesep: 22, ranksep: 46, marginx: 30, marginy: 30 });
    d.setDefaultEdgeLabel(() => ({}));
    for (const n of graph.nodes) d.setNode(String(n.address), { width: Math.min(320, Math.max(110, n.name.length * 7.4 + 28)), height: NODE_H });
    for (const [a, b] of graph.edges) d.setEdge(String(a), String(b));
    dagre.layout(d);
    const nodes = graph.nodes.map((n) => {
      const p = d.node(String(n.address));
      return { ...n, x: p.x - p.width / 2, y: p.y - p.height / 2, w: p.width, h: p.height };
    });
    const edges = d.edges().map((e) => {
      const pts = (d.edge(e) as { points: { x: number; y: number }[] }).points;
      return { key: `${e.v}-${e.w}`, d: "M" + pts.map((p) => `${p.x},${p.y}`).join(" L") };
    });
    const g = d.graph();
    return { nodes, edges, width: g.width ?? 0, height: g.height ?? 0 };
  }, [graph]);

  const fit = useCallback(() => {
    const el = box.current;
    if (!el || !layout) return;
    const k = Math.min(1.2, Math.max(0.1, Math.min(el.clientWidth / layout.width, el.clientHeight / layout.height) * 0.92));
    setView({ k, x: (el.clientWidth - layout.width * k) / 2, y: Math.max(16, (el.clientHeight - layout.height * k) / 2) });
  }, [layout]);
  useLayoutEffect(fit, [fit]);

  return (
    <div
      ref={box}
      className="graph calls"
      onWheel={(e) => {
        const r = box.current!.getBoundingClientRect();
        const mx = e.clientX - r.left;
        const my = e.clientY - r.top;
        const f = Math.exp(-e.deltaY * 0.0015);
        setView((v) => {
          const k = Math.min(3, Math.max(0.08, v.k * f));
          return { k, x: mx - ((mx - v.x) * k) / v.k, y: my - ((my - v.y) * k) / v.k };
        });
      }}
      onPointerDown={(e) => {
        if ((e.target as HTMLElement).closest(".cnode")) return;
        (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
        drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
      }}
      onPointerMove={(e) => {
        const d = drag.current;
        if (d) setView((v) => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }));
      }}
      onPointerUp={() => (drag.current = null)}
    >
      <div className="graph-grid" style={{ backgroundPosition: `${view.x}px ${view.y}px`, backgroundSize: `${24 * view.k}px ${24 * view.k}px` }} />
      {layout && (
        <div className="graph-layer" style={{ transform: `translate3d(${view.x}px, ${view.y}px, 0) scale(${view.k})`, width: layout.width, height: layout.height }}>
          <svg className="graph-edges" width={layout.width} height={layout.height}>
            <defs>
              <marker id="carr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" className="arrow-fall" />
              </marker>
            </defs>
            {layout.edges.map((e) => (
              <path key={e.key} d={e.d} className="edge edge-fall" markerEnd="url(#carr)" />
            ))}
          </svg>
          {layout.nodes.map((n) => (
            <button
              key={n.address}
              className={`cnode mono cn-${n.kind}`}
              style={{ left: n.x, top: n.y, width: n.w, height: n.h }}
              title={`${n.name}\nDouble-click to open`}
              onClick={() => st().setCursor(n.address)}
              onDoubleClick={() => (n.kind === "import" ? st().goto(n.address, { tab: "disasm" }) : st().goto(n.address, { tab: "calls" }))}
            >
              {n.name}
            </button>
          ))}
        </div>
      )}
      <div className="graph-hud">
        <div className="graph-title mono">
          {graph?.nodes.find((n) => n.kind === "root")?.name ?? "Call graph"}
          <span className="muted"> · {graph?.nodes.length ?? 0} functions</span>
        </div>
        <div className="graph-tools">
          <span className="muted small">Callers</span>
          <select className="mini-select" value={depth.up} onChange={(e) => setDepth({ ...depth, up: Number(e.target.value) })}>
            {[0, 1, 2, 3].map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
          <span className="muted small">Callees</span>
          <select className="mini-select" value={depth.down} onChange={(e) => setDepth({ ...depth, down: Number(e.target.value) })}>
            {[0, 1, 2, 3].map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
          <button className="icon-btn" onClick={fit} title="Fit">
            <Maximize size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
