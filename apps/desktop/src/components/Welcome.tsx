import { ArrowUpRight, Binary, Cpu, FileCode2, FolderOpen, GitBranch, Lock, Network, Trash2, Zap } from "lucide-react";

import { getBackend, isDesktop } from "../engine/client";
import { pickFile } from "../files";
import { archLabel, fmtSize, formatLabel, useStore } from "../store";
import { AppIcon, Whale } from "./Logo";
import { ThemeToggle } from "./ThemeToggle";

const FEATURES = [
  { icon: FileCode2, title: "Every major format", text: "PE, ELF and Mach-O — including universal binaries, forwarders and chained fixups." },
  { icon: Cpu, title: "x86, x86-64, AArch64", text: "Symbol-aware disassembly with IDA-style labels, thunks and string annotations." },
  { icon: GitBranch, title: "Graphs & pseudocode", text: "Recursive-descent analysis, control-flow graphs and a readable C-like view." },
  { icon: Network, title: "Cross references", text: "Calls, jumps and data references, both directions, one keystroke away." },
  { icon: Lock, title: "Private by design", text: "No accounts and no telemetry. Files are analyzed on this machine only." },
  { icon: Zap, title: "Native Rust engine", text: "Fast, memory-safe and hardened against malformed and hostile inputs." },
];

const SHORTCUTS: [string, string][] = [
  ["Ctrl O", "Open file"],
  ["Ctrl K", "Go to anything"],
  ["Space", "Graph ↔ listing"],
  ["Tab", "Pseudocode"],
  ["N", "Rename"],
  [";", "Comment"],
  ["X", "Cross references"],
  ["Esc", "Back"],
];

function greeting(): string {
  const h = new Date().getHours();
  if (h < 5) return "Late night reversing?";
  if (h < 12) return "Good morning.";
  if (h < 18) return "Good afternoon.";
  return "Good evening.";
}

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
      <header className="welcome-top">
        <div className="brand">
          <Whale size={34} />
          <span className="wordmark">Paranoia</span>
        </div>
        <div className="welcome-top-right">
          <span className="badge">Community Edition</span>
          <ThemeToggle />
        </div>
      </header>

      <main className="welcome-inner">
        <section className="hero">
          <AppIcon size={88} className="hero-whale" />
          <h1>{greeting()}</h1>
          <p className="tagline">What are we taking apart today?</p>
        </section>

        <section
          className="composer"
          onClick={choose}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && choose()}
        >
          <div className="composer-body">
            <div className="composer-icon">
              <Binary size={20} />
            </div>
            <div>
              <div className="composer-title">Drop an executable, library or object file</div>
              <div className="composer-sub">or click to browse — PE · ELF · Mach-O · x86 · x86-64 · AArch64</div>
            </div>
          </div>
          <div className="composer-foot">
            <span className="composer-note">
              <Lock size={12} /> {isDesktop ? "Analyzed natively on this computer" : "Analyzed in your browser with WebAssembly"} — nothing is uploaded
            </span>
            <button
              className="btn primary"
              onClick={(e) => {
                e.stopPropagation();
                choose();
              }}
            >
              <FolderOpen size={15} /> Open file
              <span className="kbd on-accent">Ctrl O</span>
            </button>
          </div>
        </section>

        <div className="welcome-cols">
          <section className="panel-card">
            <div className="section-title">
              Recent files
              {recent.length > 0 && <span className="count">{recent.length}</span>}
            </div>
            {recent.length === 0 ? (
              <div className="recent-empty">
                Files you analyze appear here. Names and comments are kept per file hash, so they follow the binary wherever it lives.
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
                          toast(`Choose ${r.name} again to continue — your annotations are kept.`);
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
                      <ArrowUpRight size={14} className="recent-go" />
                    </button>
                    <button
                      className="icon-btn recent-x"
                      title="Remove from list"
                      onClick={async () => {
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
          </section>

          <section className="panel-card">
            <div className="section-title">Keyboard</div>
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

        <section className="features">
          {FEATURES.map((f) => (
            <div key={f.title} className="feature">
              <f.icon size={18} className="feature-icon" />
              <div className="feature-title">{f.title}</div>
              <div className="feature-text">{f.text}</div>
            </div>
          ))}
        </section>

        <footer className="welcome-foot">
          <span>Paranoia v0.1.1</span>
          <span className="dot" />
          <span>Open source · Apache-2.0</span>
          <span className="dot" />
          <span>{isDesktop ? "Native engine" : "WebAssembly engine"}</span>
        </footer>
      </main>
    </div>
  );
}
