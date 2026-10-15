import { AlertTriangle, Check, Copy, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { BinaryInfo } from "../../engine/types";
import { archLabel, fmtAddr, fmtSize, formatLabel, useStore } from "../../store";

export function OverviewView() {
  const info = useStore((s) => s.info)!;
  const stats = useStore((s) => s.stats);
  const goto = useStore((s) => s.goto);
  const enabled = info.mitigations.filter((m) => m.enabled && m.name !== "Stripped").length;

  return (
    <div className="overview">
      <section className="ov-hero">
        <div className="ov-hero-main">
          <div className="ov-badges">
            <span className={`fmt fmt-${info.format}`}>{formatLabel(info.format)}</span>
            <span className="badge">{archLabel(info.arch)}</span>
            <span className="badge">{info.bits}-bit</span>
            <span className="badge">{info.endian === "little" ? "little-endian" : "big-endian"}</span>
            {info.hashes.imphash && <span className="badge">imphash</span>}
          </div>
          <h2 className="ov-title selectable">{info.file_name}</h2>
          <div className="ov-sub">
            {info.kind} · {fmtSize(info.file_size)} · entry{" "}
            <button className="link mono" onClick={() => goto(info.entry)} disabled={!info.entry}>
              {info.entry ? fmtAddr(info.entry, info) : "none"}
            </button>
          </div>
        </div>
        <div className="ov-tiles">
          <Tile label="Functions" value={stats?.functions} />
          <Tile label="Instructions" value={stats?.instructions} />
          <Tile label="Strings" value={stats?.strings} />
          <Tile label="Imports" value={info.imports.length} />
          <Tile label="Exports" value={info.exports.length} />
          <Tile label="Sections" value={info.sections.length} />
        </div>
      </section>

      {info.warnings.length > 0 && (
        <section className="ov-warnings">
          {info.warnings.map((w) => (
            <div key={w} className="ov-warning">
              <AlertTriangle size={14} /> {w}
            </div>
          ))}
        </section>
      )}

      <div className="ov-grid">
        <section className="card">
          <div className="card-title">
            {enabled >= Math.ceil(info.mitigations.length / 2) ? <ShieldCheck size={15} className="ok" /> : <ShieldAlert size={15} className="bad" />}
            Mitigations
            <span className="count">
              {enabled}/{info.mitigations.filter((m) => m.name !== "Stripped").length}
            </span>
          </div>
          <div className="mitigations">
            {info.mitigations.map((m) => (
              <div key={m.name} className={`mitigation ${m.enabled ? "on" : "off"}`} title={m.detail}>
                <span className="mit-dot" />
                <span className="mit-name">{m.name}</span>
                <span className="mit-detail">{m.detail}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="card">
          <div className="card-title">Hashes</div>
          <div className="hashes">
            <HashRow k="SHA-256" v={info.hashes.sha256} />
            <HashRow k="SHA-1" v={info.hashes.sha1} />
            <HashRow k="MD5" v={info.hashes.md5} />
            {info.hashes.imphash && <HashRow k="Imphash" v={info.hashes.imphash} />}
          </div>
          <div className="card-title" style={{ marginTop: 18 }}>
            Entropy <span className="count">{info.entropy.toFixed(3)} / 8</span>
          </div>
          <EntropyChart info={info} />
        </section>

        <section className="card span-2">
          <div className="card-title">Section map</div>
          <SectionMap info={info} />
        </section>

        <section className="card">
          <div className="card-title">Headers</div>
          <dl className="kv headers">
            {info.headers.map((h) => (
              <div key={h.key} className="kv-row">
                <dt>{h.key}</dt>
                <dd className="selectable">{h.value}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="card">
          <div className="card-title">
            Libraries <span className="count">{info.libraries.length}</span>
          </div>
          {info.libraries.length === 0 ? (
            <div className="muted small">Statically linked or no dynamic dependencies.</div>
          ) : (
            <ul className="libs">
              {info.libraries.map((l) => {
                const n = info.imports.filter((i) => i.library === l).length;
                return (
                  <li key={l} className="mono">
                    <span className="ellipsis">{l}</span>
                    {n > 0 && <span className="count">{n}</span>}
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}

function Tile({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="tile">
      <div className="tile-value">{value == null ? "—" : value.toLocaleString()}</div>
      <div className="tile-label">{label}</div>
    </div>
  );
}

function HashRow({ k, v }: { k: string; v: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="hash-row">
      <span className="hash-k">{k}</span>
      <span className="hash-v mono selectable">{v}</span>
      <button
        className="icon-btn"
        title="Copy"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(v);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          } catch {
            useStore.getState().toast("Clipboard is not available", "error");
          }
        }}
      >
        {copied ? <Check size={13} /> : <Copy size={13} />}
      </button>
    </div>
  );
}

/** Area chart of entropy across the file, drawn on a canvas for crispness at any DPI. */
function EntropyChart({ info }: { info: BinaryInfo }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const [hover, setHover] = useState<{ x: number; i: number } | null>(null);
  const data = info.entropy_map;

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
      g.clearRect(0, 0, w, h);
      // Reference lines at 4, 6 and 7.2 (packed / encrypted territory).
      for (const [lvl, col] of [
        [4, "rgba(255,255,255,0.05)"],
        [6, "rgba(255,255,255,0.05)"],
        [7.2, "rgba(255,107,107,0.25)"],
      ] as const) {
        const y = h - (lvl / 8) * h;
        g.strokeStyle = col;
        g.setLineDash([3, 4]);
        g.beginPath();
        g.moveTo(0, y);
        g.lineTo(w, y);
        g.stroke();
      }
      g.setLineDash([]);
      if (data.length < 2) return;
      const grad = g.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, "rgba(46,230,166,0.45)");
      grad.addColorStop(1, "rgba(46,230,166,0.02)");
      const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - (v / 8) * (h - 2) - 1] as const);
      g.beginPath();
      g.moveTo(0, h);
      pts.forEach(([x, y]) => g.lineTo(x, y));
      g.lineTo(w, h);
      g.closePath();
      g.fillStyle = grad;
      g.fill();
      g.beginPath();
      pts.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y)));
      g.strokeStyle = "#2ee6a6";
      g.lineWidth = 1.25;
      g.stroke();
    };
    draw();
    const ro = new ResizeObserver(draw);
    ro.observe(c);
    return () => ro.disconnect();
  }, [data]);

  const chunk = info.file_size / Math.max(1, data.length);
  return (
    <div className="entropy-chart">
      <canvas
        ref={ref}
        onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const i = Math.min(data.length - 1, Math.max(0, Math.round(((e.clientX - r.left) / r.width) * (data.length - 1))));
          setHover({ x: e.clientX - r.left, i });
        }}
        onMouseLeave={() => setHover(null)}
      />
      {hover && (
        <div className="chart-tip mono" style={{ left: Math.min(hover.x, 9999) }}>
          +{Math.round(hover.i * chunk).toString(16).toUpperCase()} · {data[hover.i].toFixed(2)}
        </div>
      )}
      <div className="chart-axis">
        <span>0</span>
        <span>{fmtSize(info.file_size)}</span>
      </div>
    </div>
  );
}

/** Proportional bar of sections in file order, coloured by permissions. */
function SectionMap({ info }: { info: BinaryInfo }) {
  const goto = useStore((s) => s.goto);
  const secs = info.sections.filter((s) => s.raw_size > 0).sort((a, b) => a.offset - b.offset);
  const total = Math.max(1, info.file_size);
  return (
    <div className="secmap">
      <div className="secmap-bar">
        {secs.map((s, i) => (
          <button
            key={i}
            className={`secmap-seg ${s.perms.x ? "x" : s.perms.w ? "w" : "r"}`}
            style={{ left: `${(s.offset / total) * 100}%`, width: `max(3px, ${(s.raw_size / total) * 100}%)` }}
            title={`${s.name}\n${fmtSize(s.raw_size)} · entropy ${s.entropy.toFixed(2)}`}
            onClick={() => s.vaddr && goto(s.vaddr, { tab: s.perms.x ? "disasm" : "hex" })}
          />
        ))}
      </div>
      <div className="secmap-legend">
        <span>
          <i className="x" /> code
        </span>
        <span>
          <i className="w" /> writable data
        </span>
        <span>
          <i className="r" /> read-only
        </span>
      </div>
      <table className="sec-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Address</th>
            <th>Virtual size</th>
            <th>File offset</th>
            <th>Raw size</th>
            <th>Perms</th>
            <th>Entropy</th>
          </tr>
        </thead>
        <tbody>
          {info.sections.map((s, i) => (
            <tr key={i} onClick={() => s.vaddr && goto(s.vaddr, { tab: s.perms.x ? "disasm" : "hex" })}>
              <td className="mono">{s.segment ? `${s.segment},${s.name}` : s.name}</td>
              <td className="mono">{fmtAddr(s.vaddr, info)}</td>
              <td className="mono">{s.vsize.toString(16).toUpperCase()}</td>
              <td className="mono">{s.offset.toString(16).toUpperCase()}</td>
              <td className="mono">{s.raw_size.toString(16).toUpperCase()}</td>
              <td className="mono perms">
                <b className={s.perms.r ? "on" : ""}>r</b>
                <b className={s.perms.w ? "on w" : ""}>w</b>
                <b className={s.perms.x ? "on x" : ""}>x</b>
              </td>
              <td>
                <div className="ent-cell">
                  <div className="entropy-bar">
                    <i
                      style={{
                        width: `${(s.entropy / 8) * 100}%`,
                        background: s.entropy > 7.2 ? "var(--danger)" : s.entropy > 6.5 ? "var(--warn)" : "var(--accent)",
                      }}
                    />
                  </div>
                  <span className="mono">{s.entropy.toFixed(2)}</span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
