import { Binary, Cpu, FileCode2, FolderOpen, GitBranch, Lock, Network, Search, Trash2, Zap } from "lucide-react";

import { isDesktop } from "../engine/client";
import { pickFile } from "../files";
import { archLabel, fmtSize, formatLabel, useStore } from "../store";
import { Whale } from "./Logo";

const FEATURES = [
  { icon: FileCode2, title: "PE · ELF · Mach-O", text: "Headers, sections, imports, exports, symbols and universal binaries." },
  { icon: Cpu, title: "x86 · x86-64 · AArch64", text: "Fast disassembly with symbol-aware operands and IDA-style labels." },
  { icon: GitBranch, title: "Control-flow graphs", text: "Recursive-descent analysis, basic blocks and GPU-composited graphs." },
  { icon: Network, title: "Cross references", text: "Calls, jumps and data references — strings show where they're used." },
  { icon: Lock, title: "Local & private", text: "No accounts, no telemetry. Your binaries never leave this machine." },
  { icon: Zap, title: "Built in Rust", text: "Memory-safe engine hardened against malformed and hostile files." },
];

const SHORTCUTS: [string, string][] = [
  ["Ctrl O", "Open file"],
  ["Ctrl K", "Command palette / go to"],
  ["Space", "Toggle graph ↔ listing"],
  ["N", "Rename"],
  [";", "Comment"],
  ["X", "Cross references"],
  ["Esc", "Navigate back"],
];

function ago(ts: number): string {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function Welcome() {
  const open = useStore((s) => s.open);
  const recent = useStore((s) => s.recent);
  const toast = useStore((s) => s.toast);

  const choose = async () => {
    const src = await pickFile();
    if (src) open(src);
  };

  return (
    <div className="welcome">
      <div className="titlebar-drag" />
      <div className="welcome-bg" aria-hidden>
        <div className="welcome-grid" />
        <div className="welcome-glow" />
      </div>

      <div className="welcome-inner">
        <header className="hero">
          <div className="hero-mark">
            <div className="hero-ring" />
            <Whale size={150} glow />
          </div>
          <div className="hero-text">
            <h1>Paranoia</h1>
            <p className="tagline">Reverse engineering without limits.</p>
            <div className="hero-pills">
              <span>OPEN SOURCE</span>
              <i />
              <span className="hl">LOCAL-FIRST</span>
              <i />
              <span>FAST</span>
              <i />
              <span>MODULAR</span>
            </div>
          </div>
        </header>

        <div className="welcome-cols">
          <section className="dropzone" onClick={choose} role="button" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && choose()}>
            <div className="dropzone-icon">
              <Binary size={26} />
            </div>
            <div className="dropzone-title">Open a binary to start</div>
            <div className="dropzone-sub">
              Drop an executable, library or object file here, or <span className="link">browse</span>.
            </div>
            <div className="dropzone-actions">
              <button
                className="btn primary"
                onClick={(e) => {
                  e.stopPropagation();
                  choose();
                }}
              >
                <FolderOpen size={15} /> Open file
              </button>
              <span className="kbd">Ctrl</span>
              <span className="kbd">O</span>
            </div>
            <div className="dropzone-foot">
              <Lock size={12} /> Analysis runs {isDesktop ? "natively on this computer" : "in your browser via WebAssembly"} — nothing is uploaded.
            </div>
          </section>

          <section className="recent">
            <div className="section-title">
              Recent
              {recent.length > 0 && <span className="count">{recent.length}</span>}
            </div>
            {recent.length === 0 ? (
              <div className="recent-empty">
                <Search size={18} />
                <span>Files you analyze show up here. Renames and comments are saved per file hash.</span>
              </div>
            ) : (
              <ul className="recent-list">
                {recent.map((r) => (
                  <li key={r.sha256}>
                    <button
                      className="recent-item"
                      onClick={() => {
                        if (r.path) open({ kind: "path", path: r.path });
                        else {
                          toast(`Re-open ${r.name} to continue — your annotations are kept.`);
                          choose();
                        }
                      }}
                      title={r.path ?? r.sha256}
                    >
                      <span className={`fmt fmt-${r.format}`}>{formatLabel(r.format)}</span>
                      <span className="recent-name">{r.name}</span>
                      <span className="recent-meta">
                        {archLabel(r.arch)} · {fmtSize(r.size)} · {ago(r.openedAt)}
                      </span>
                    </button>
                    <button
                      className="icon-btn recent-x"
                      title="Remove from list"
                      onClick={async () => {
                        const { getBackend } = await import("../engine/client");
                        await getBackend().removeRecent(r.sha256);
                        useStore.getState().loadRecent();
                      }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </li>
                ))}
              </ul>
            )}

            <div className="section-title" style={{ marginTop: 22 }}>
              Shortcuts
            </div>
            <div className="shortcuts">
              {SHORTCUTS.map(([k, v]) => (
                <div key={k} className="shortcut">
                  <span>{v}</span>
                  <span className="keys">
                    {k.split(" ").map((p) => (
                      <span key={p} className="kbd">
                        {p}
                      </span>
                    ))}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="features">
          {FEATURES.map((f) => (
            <div key={f.title} className="feature">
              <f.icon size={18} className="feature-icon" />
              <div>
                <div className="feature-title">{f.title}</div>
                <div className="feature-text">{f.text}</div>
              </div>
            </div>
          ))}
        </div>

        <footer className="welcome-foot">
          <span>Paranoia Community Edition · v0.1.0</span>
          <span className="dot" />
          <span>Apache-2.0</span>
          <span className="dot" />
          <span>{isDesktop ? "Native engine" : "WebAssembly engine"}</span>
        </footer>
      </div>
    </div>
  );
}
