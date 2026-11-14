import {
  ArrowLeft,
  ArrowRight,
  Binary,
  Bookmark,
  Box,
  FileText,
  Network,
  Bug,
  Shapes,
  Tags,
  Terminal,
  Braces,
  Code2,
  FileOutput,
  GitBranch,
  Import,
  LayoutDashboard,
  PanelLeft,
  PanelRight,
  Quote,
  Search,
} from "lucide-react";
import { Group, Panel, Separator, useDefaultLayout, type LayoutStorage } from "react-resizable-panels";

import { isDesktop } from "../engine/client";
import { archLabel, fmtAddr, formatLabel, useStore, type CenterTab, type SidebarTab } from "../store";
import { Inspector } from "./Inspector";
import { Mark } from "./Logo";
import { Sidebar } from "./Sidebar";
import { StatusBar } from "./StatusBar";
import { ThemeToggle } from "./ThemeToggle";
import { DisassemblyView } from "./views/DisassemblyView";
import { GraphView } from "./views/GraphView";
import { HexView } from "./views/HexView";
import { PseudocodeView } from "./views/PseudocodeView";
import { CallsView } from "./views/CallsView";
import { NavBand } from "./NavBand";
import { Console } from "./Console";
import { DebugPanel } from "./DebugPanel";
import { MenuBar } from "./MenuBar";
import { OverviewView } from "./views/OverviewView";

const SIDEBAR: { id: SidebarTab; icon: typeof Box; label: string }[] = [
  { id: "functions", icon: Braces, label: "Functions" },
  { id: "names", icon: Tags, label: "Names" },
  { id: "imports", icon: Import, label: "Imports" },
  { id: "exports", icon: FileOutput, label: "Exports" },
  { id: "strings", icon: Quote, label: "Strings" },
  { id: "sections", icon: Box, label: "Sections" },
  { id: "symbols", icon: Code2, label: "Symbols" },
  { id: "types", icon: Shapes, label: "Local types" },
  { id: "bookmarks", icon: Bookmark, label: "Bookmarks" },
];

const TABS: { id: CenterTab; icon: typeof Box; label: string; key: string }[] = [
  { id: "overview", icon: LayoutDashboard, label: "Overview", key: "1" },
  { id: "disasm", icon: Code2, label: "Disassembly", key: "2" },
  { id: "graph", icon: GitBranch, label: "Graph", key: "3" },
  { id: "pseudo", icon: FileText, label: "Pseudocode", key: "4" },
  { id: "calls", icon: Network, label: "Calls", key: "5" },
  { id: "hex", icon: Binary, label: "Hex", key: "6" },
];

/** Panel sizes are remembered per combination of visible panels. Storage can be unavailable
 *  (private windows, blocked site data), in which case the layout just isn't remembered. */
const layoutStorage: LayoutStorage = {
  getItem: (key) => {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  setItem: (key, value) => {
    try {
      localStorage.setItem(key, value);
    } catch {
      /* not remembered */
    }
  },
};

export function Workspace() {
  const info = useStore((s) => s.info)!;
  const st = useStore();
  const layout = useDefaultLayout({
    id: "paranoia.layout",
    panelIds: [...(st.sidebarOpen ? ["sidebar"] : []), "center", ...(st.inspectorOpen ? ["inspector"] : [])],
    storage: layoutStorage,
  });

  return (
    <div className="workspace">
      <header className="topbar">
        <button className="mark-btn" onClick={() => st.set("centerTab", "overview")} title="Paranoia — overview" aria-label="Paranoia overview">
          <Mark size={20} />
        </button>
        <MenuBar />

        <div className="topbar-center">
          <button className="icon-btn" disabled={st.historyIndex <= 0} onClick={st.back} title="Back (Esc / Alt+←)">
            <ArrowLeft size={15} />
          </button>
          <button className="icon-btn" disabled={st.historyIndex >= st.history.length - 1} onClick={st.forward} title="Forward (Alt+→)">
            <ArrowRight size={15} />
          </button>
          <button className="command-center" onClick={() => st.set("paletteOpen", true)} title={`${st.path ?? info.file_name}
Go to address, function or string (Ctrl K)`}>
            <Search size={13} />
            <span className={`fmt fmt-${info.format}`}>{formatLabel(info.format)}</span>
            <span className="cc-name">{info.file_name}</span>
            <span className="cc-arch">
              {archLabel(info.arch)} · {info.bits}-bit
            </span>
            <span className="kbd">Ctrl K</span>
          </button>
        </div>

        <div className="topbar-right">
          {isDesktop && (
            <button className={`icon-btn ${st.debugOpen ? "active" : ""}`} onClick={() => st.set("debugOpen", !st.debugOpen)} title="Debugger (F9 to start)">
              <Bug size={15} />
            </button>
          )}
          <button className={`icon-btn ${st.consoleOpen ? "active" : ""}`} onClick={() => st.set("consoleOpen", !st.consoleOpen)} title="Console (Ctrl+`)">
            <Terminal size={15} />
          </button>
          <ThemeToggle />
          <span className="tb-divider" />
          <button className={`icon-btn ${st.sidebarOpen ? "active" : ""}`} onClick={() => st.set("sidebarOpen", !st.sidebarOpen)} title="Toggle sidebar (Ctrl+B)">
            <PanelLeft size={15} />
          </button>
          <button
            className={`icon-btn ${st.inspectorOpen ? "active" : ""}`}
            onClick={() => st.set("inspectorOpen", !st.inspectorOpen)}
            title="Toggle inspector (Ctrl+J)"
          >
            <PanelRight size={15} />
          </button>
        </div>
      </header>

      <div className="workspace-body">
        <nav className="activity">
          {SIDEBAR.map((t) => (
            <button
              key={t.id}
              className={`activity-btn ${st.sidebarOpen && st.sidebarTab === t.id ? "active" : ""}`}
              title={t.label}
              onClick={() => {
                if (st.sidebarOpen && st.sidebarTab === t.id) st.set("sidebarOpen", false);
                else {
                  st.set("sidebarTab", t.id);
                  st.set("sidebarOpen", true);
                }
              }}
            >
              <t.icon size={18} />
            </button>
          ))}
        </nav>

        <Group orientation="horizontal" defaultLayout={layout.defaultLayout} onLayoutChanged={layout.onLayoutChanged} className="panels">
          {st.sidebarOpen && (
            <>
              <Panel id="sidebar" defaultSize="22%" minSize="14%" maxSize="45%" className="panel">
                <Sidebar />
              </Panel>
              <Separator className="resize-h" />
            </>
          )}
          <Panel id="center" minSize="30%" className="panel center">
            <div className="tabs">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  className={`tab ${st.centerTab === t.id ? "active" : ""}`}
                  onClick={() => st.set("centerTab", t.id)}
                  title={`${t.label} (${t.key})`}
                >
                  <t.icon size={14} />
                  {t.label}
                </button>
              ))}
              <div className="tabs-spacer" />
              {st.cursor != null && (
                <span className="tab-cursor mono" title="Current address">
                  {fmtAddr(st.cursor, info)}
                </span>
              )}
            </div>
            <NavBand />
            <div className="view">
              {st.centerTab === "overview" && <OverviewView />}
              {st.centerTab === "disasm" && <DisassemblyView />}
              {st.centerTab === "graph" && <GraphView />}
              {st.centerTab === "pseudo" && <PseudocodeView />}
              {st.centerTab === "calls" && <CallsView />}
              {st.centerTab === "hex" && <HexView />}
            </div>
          </Panel>
          {st.inspectorOpen && (
            <>
              <Separator className="resize-h" />
              <Panel id="inspector" defaultSize="22%" minSize="14%" maxSize="40%" className="panel">
                <Inspector />
              </Panel>
            </>
          )}
        </Group>
      </div>
      <DebugPanel />
      <Console />
      <StatusBar native={isDesktop} />
    </div>
  );
}
