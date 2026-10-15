import dagre from "@dagrejs/dagre";
import { Code2, Maximize, Minus, Plus } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import type { FunctionGraph, GraphBlock } from "../../engine/types";
import { addrWidth, hex, useStore } from "../../store";
import { InstructionText } from "./Listing";

const CHAR_W = 7.22; // JetBrains Mono at 12px
const LINE_H = 18;
const PAD_X = 12;
const MAX_BLOCKS = 2500;

interface Node {
  b: GraphBlock;
  x: number;
  y: number;
  w: number;
  h: number;
}
interface EdgeL {
  from: number;
  to: number;
  kind: string;
  d: string;
  back: boolean;
}
interface Layout {
  nodes: Node[];
  edges: EdgeL[];
  width: number;
  height: number;
}

function blockWidth(b: GraphBlock, aw: number): number {
  let max = 0;
  for (const i of b.instructions) {
    const ops = i.operands.reduce((n, t) => n + t.t.length, 0);
    const cmt = (i.user_comment ? i.user_comment.length + 3 : 0) + (i.comment ? Math.min(i.comment.length, 60) + 3 : 0);
    max = Math.max(max, aw + 2 + 8 + ops + cmt);
  }
  return Math.min(900, Math.max(180, max * CHAR_W + PAD_X * 2));
}

function layoutGraph(g: FunctionGraph, aw: number): Layout {
  const d = new dagre.graphlib.Graph({ multigraph: true });
  d.setGraph({ rankdir: "TB", nodesep: 36, ranksep: 54, edgesep: 14, marginx: 40, marginy: 40 });
  d.setDefaultEdgeLabel(() => ({}));
  for (const b of g.blocks) {
    const labelRows = b.instructions[0]?.label ? 1 : 0;
    d.setNode(String(b.start), { width: blockWidth(b, aw), height: (b.instructions.length + labelRows) * LINE_H + 14 + (labelRows ? 0 : 0) });
  }
  const starts = new Set(g.blocks.map((b) => b.start));
  for (const b of g.blocks)
    for (const e of b.succs) if (starts.has(e.to)) d.setEdge(String(b.start), String(e.to), { kind: e.kind }, `${b.start}-${e.to}-${e.kind}`);
  dagre.layout(d);

  const pos = new Map<number, Node>();
  const nodes: Node[] = g.blocks.map((b) => {
    const n = d.node(String(b.start));
    const node = { b, x: n.x - n.width / 2, y: n.y - n.height / 2, w: n.width, h: n.height };
    pos.set(b.start, node);
    return node;
  });

  const edges: EdgeL[] = d.edges().map((e) => {
    const data = d.edge(e) as { kind: string; points: { x: number; y: number }[] };
    const pts = data.points;
    // Rounded orthogonal-ish path through dagre's control points.
    let path = `M${pts[0].x},${pts[0].y}`;
    for (let i = 1; i < pts.length - 1; i++) {
      const p = pts[i];
      const n = pts[i + 1];
      path += ` Q${p.x},${p.y} ${(p.x + n.x) / 2},${(p.y + n.y) / 2}`;
    }
    const last = pts[pts.length - 1];
    path += ` L${last.x},${last.y}`;
    const from = Number(e.v);
    const to = Number(e.w);
    return { from, to, kind: data.kind, d: path, back: (pos.get(to)?.y ?? 0) <= (pos.get(from)?.y ?? 0) };
  });
  const gr = d.graph();
  return { nodes, edges, width: gr.width ?? 0, height: gr.height ?? 0 };
}

export function GraphView() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info)!;
  const cursor = useStore((s) => s.cursor);
  const revision = useStore((s) => s.revision);
  const st = useStore.getState;

  const [graph, setGraph] = useState<FunctionGraph | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "none" | "big">("idle");
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const aw = addrWidth(info);

  // Load the function containing the cursor (skip if it is already shown).
  useEffect(() => {
    if (cursor == null) return;
    if (graph && graph.blocks.some((b) => cursor >= b.start && cursor < b.end) && state === "idle") return;
    let live = true;
    setState("loading");
    session.graph(cursor).then((g) => {
      if (!live) return;
      if (!g) {
        setGraph(null);
        setState("none");
      } else if (g.blocks.length > MAX_BLOCKS) {
        setGraph(null);
        setState("big");
      } else {
        setGraph(g);
        setState("idle");
      }
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cursor, session]);

  // Refresh contents after renames / comments without moving the camera.
  useEffect(() => {
    if (!graph) return;
    let live = true;
    session.graph(graph.address).then((g) => live && g && setGraph(g));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision]);

  const layout = useMemo(() => (graph ? layoutGraph(graph, aw) : null), [graph, aw]);

  const fit = useCallback(() => {
    const el = box.current;
    if (!el || !layout) return;
    const k = Math.min(1.1, Math.max(0.08, Math.min(el.clientWidth / layout.width, el.clientHeight / layout.height) * 0.94));
    setView({ k, x: (el.clientWidth - layout.width * k) / 2, y: Math.max(12, (el.clientHeight - layout.height * k) / 2) });
  }, [layout]);

  // New function: show the entry block at a readable zoom, or fit small graphs.
  const shownFor = useRef<number | null>(null);
  useLayoutEffect(() => {
    if (!layout || !graph || shownFor.current === graph.address) return;
    shownFor.current = graph.address;
    const el = box.current!;
    const fitK = Math.min(el.clientWidth / layout.width, el.clientHeight / layout.height) * 0.94;
    if (fitK >= 0.55) return fit();
    const k = 0.85;
    const entry = layout.nodes.find((n) => n.b.start === graph.address) ?? layout.nodes[0];
    setView({ k, x: el.clientWidth / 2 - (entry.x + entry.w / 2) * k, y: 30 - entry.y * k });
  }, [layout, graph, fit]);

  const onWheel = (e: React.WheelEvent) => {
    const el = box.current!;
    const r = el.getBoundingClientRect();
    const mx = e.clientX - r.left;
    const my = e.clientY - r.top;
    if (e.ctrlKey || e.metaKey || !e.shiftKey) {
      const f = Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0015));
      setView((v) => {
        const k = Math.min(3, Math.max(0.05, v.k * f));
        return { k, x: mx - ((mx - v.x) * k) / v.k, y: my - ((my - v.y) * k) / v.k };
      });
    } else {
      setView((v) => ({ ...v, x: v.x - e.deltaY }));
    }
  };

  const zoomBy = (f: number) => {
    const el = box.current!;
    const mx = el.clientWidth / 2;
    const my = el.clientHeight / 2;
    setView((v) => {
      const k = Math.min(3, Math.max(0.05, v.k * f));
      return { k, x: mx - ((mx - v.x) * k) / v.k, y: my - ((my - v.y) * k) / v.k };
    });
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === " ") {
      e.preventDefault();
      st().set("centerTab", "disasm");
    } else if (e.key === "f" || e.key === "F") fit();
    else if (e.key === "+" || e.key === "=") zoomBy(1.2);
    else if (e.key === "-") zoomBy(1 / 1.2);
    else if (e.key === "n" || e.key === "N") {
      if (graph) st().set("dialog", { kind: "rename", va: graph.address, initial: graph.name });
    } else if (e.key === ";" && cursor != null) st().set("dialog", { kind: "comment", va: cursor, initial: "" });
  };

  if (!info.disassembly_supported) return <div className="empty">Graphs need disassembly, which isn't available for this architecture yet.</div>;
  if (state === "none")
    return (
      <div className="empty">
        <div>
          <p>No function at this address.</p>
          <button className="btn sm" onClick={() => st().set("centerTab", "disasm")}>
            <Code2 size={13} /> Open listing
          </button>
        </div>
      </div>
    );
  if (state === "big") return <div className="empty">This function has more than {MAX_BLOCKS} blocks — use the listing view for now.</div>;

  return (
    <div
      ref={box}
      className="graph"
      tabIndex={0}
      onKeyDown={onKey}
      onWheel={onWheel}
      onPointerDown={(e) => {
        if ((e.target as HTMLElement).closest(".gblock")) return;
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
      {layout && graph && (
        <div className="graph-layer" style={{ transform: `translate3d(${view.x}px, ${view.y}px, 0) scale(${view.k})`, width: layout.width, height: layout.height }}>
          <svg className="graph-edges" width={layout.width} height={layout.height}>
            <defs>
              {["true", "false", "uncond", "fall"].map((k) => (
                <marker key={k} id={`arr-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M0,0 L10,5 L0,10 z" className={`arrow-${k}`} />
                </marker>
              ))}
            </defs>
            {layout.edges.map((e, i) => (
              <path key={i} d={e.d} className={`edge edge-${e.kind} ${e.back ? "back" : ""}`} markerEnd={`url(#arr-${e.kind})`} />
            ))}
          </svg>
          {layout.nodes.map((n) => {
            const active = cursor != null && cursor >= n.b.start && cursor < n.b.end;
            const entry = n.b.start === graph.address;
            return (
              <div key={n.b.start} className={`gblock mono ${active ? "active" : ""} ${entry ? "entry" : ""}`} style={{ left: n.x, top: n.y, width: n.w, height: n.h }}>
                {n.b.instructions[0]?.label && <div className="gb-label">{n.b.instructions[0].label}:</div>}
                {n.b.instructions.map((ins) => (
                  <div
                    key={ins.address}
                    className={`gb-line ${cursor === ins.address ? "sel" : ""}`}
                    onMouseDown={() => st().setCursor(ins.address)}
                    onDoubleClick={() => ins.target != null && st().goto(ins.target)}
                  >
                    <span className="gb-addr">{hex(ins.address, aw)}</span>
                    <InstructionText ins={ins} onFollow={(va) => st().goto(va)} />
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
      {state === "loading" && (
        <div className="view-busy">
          <div className="spinner" /> Laying out…
        </div>
      )}
      {graph && (
        <div className="graph-hud">
          <div className="graph-title mono">
            {graph.name}
            <span className="muted"> · {graph.blocks.length} blocks</span>
          </div>
          <div className="graph-tools">
            <button className="icon-btn" onClick={() => zoomBy(1 / 1.2)} title="Zoom out (-)">
              <Minus size={14} />
            </button>
            <span className="zoom mono">{Math.round(view.k * 100)}%</span>
            <button className="icon-btn" onClick={() => zoomBy(1.2)} title="Zoom in (+)">
              <Plus size={14} />
            </button>
            <button className="icon-btn" onClick={fit} title="Fit (F)">
              <Maximize size={14} />
            </button>
          </div>
        </div>
      )}
      {layout && box.current && (layout.width * view.k > box.current.clientWidth || layout.height * view.k > box.current.clientHeight) && <Minimap layout={layout} view={view} box={box} onMove={(x, y) => setView((v) => ({ ...v, x, y }))} />}
    </div>
  );
}

function Minimap({
  layout,
  view,
  box,
  onMove,
}: {
  layout: Layout;
  view: { x: number; y: number; k: number };
  box: React.RefObject<HTMLDivElement | null>;
  onMove(x: number, y: number): void;
}) {
  const W = 180;
  const s = W / Math.max(layout.width, 1);
  const H = Math.min(160, layout.height * s);
  const sc = Math.min(s, H / Math.max(layout.height, 1));
  const el = box.current;
  if (!el) return null;
  const vw = el.clientWidth / view.k;
  const vh = el.clientHeight / view.k;
  const vx = -view.x / view.k;
  const vy = -view.y / view.k;
  const jump = (e: React.PointerEvent) => {
    const r = (e.currentTarget as SVGElement).getBoundingClientRect();
    const gx = (e.clientX - r.left) / sc;
    const gy = (e.clientY - r.top) / sc;
    onMove(el.clientWidth / 2 - gx * view.k, el.clientHeight / 2 - gy * view.k);
  };
  return (
    <svg
      className="minimap"
      width={layout.width * sc}
      height={layout.height * sc}
      onPointerDown={(e) => {
        e.stopPropagation();
        (e.currentTarget as Element).setPointerCapture(e.pointerId);
        jump(e);
      }}
      onPointerMove={(e) => e.buttons === 1 && jump(e)}
    >
      {layout.nodes.map((n) => (
        <rect key={n.b.start} x={n.x * sc} y={n.y * sc} width={Math.max(1, n.w * sc)} height={Math.max(1, n.h * sc)} rx={1} />
      ))}
      <rect className="mm-view" x={vx * sc} y={vy * sc} width={vw * sc} height={vh * sc} />
    </svg>
  );
}
