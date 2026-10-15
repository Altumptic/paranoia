import {
  ArrowLeft,
  ArrowRight,
  Binary,
  Bookmark,
  Box,
  FileText,
  Braces,
  Code2,
  FileOutput,
  FolderOpen,
  GitBranch,
  Import,
  LayoutDashboard,
  PanelLeft,
  PanelRight,
  Quote,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";

import { isDesktop } from "../engine/client";
import { pickFile } from "../files";
import { archLabel, fmtAddr, formatLabel, useStore, type CenterTab, type SidebarTab } from "../store";
import { Inspector } from "./Inspector";
import { Whale } from "./Logo";
import { Sidebar } from "./Sidebar";
import { StatusBar } from "./StatusBar";
import { ThemeToggle } from "./ThemeToggle";
import { DisassemblyView } from "./views/DisassemblyView";
import { GraphView } from "./views/GraphView";
import { HexView } from "./views/HexView";
import { PseudocodeView } from "./views/PseudocodeView";
import { AppMenu } from "./AppMenu";
import { OverviewView } from "./views/OverviewView";

const SIDEBAR: { id: SidebarTab; icon: typeof Box; label: string }[] = [
  { id: "functions", icon: Braces, label: "Functions" },
  { id: "imports", icon: Import, label: "Imports" },
  { id: "exports", icon: FileOutput, label: "Exports" },
  { id: "strings", icon: Quote, label: "Strings" },
  { id: "sections", icon: Box, label: "Sections" },
  { id: "symbols", icon: Code2, label: "Symbols" },
  { id: "bookmarks", icon: Bookmark, label: "Bookmarks" },
];

const TABS: { id: CenterTab; icon: typeof Box; label: string; key: string }[] = [
  { id: "overview", icon: LayoutDashboard, label: "Overview", key: "1" },
  { id: "disasm", icon: Code2, label: "Disassembly", key: "2" },
  { id: "graph", icon: GitBranch, label: "Graph", key: "3" },
  { id: "pseudo", icon: FileText, label: "Pseudocode", key: "4" },
  { id: "hex", icon: Binary, label: "Hex", key: "5" },
];

export function Workspace() {
  const info = useStore((s) => s.info)!;
  const st = useStore();

  const chooseFile = async () => {
    const src = await pickFile();
    if (src) st.open(src);
  };

  return (
    <div className="workspace">
      <header className="topbar">
        <div className="brand" onClick={() => st.set("centerTab", "overview")} title="Overview">
          <Whale size={28} />
          <span className="wordmark">Paranoia</span>
        </div>
        <div className="nav-btns">
          <button className="icon-btn" disabled={st.historyIndex <= 0} onClick={st.back} title="Back (Esc / Alt+←)">
            <ArrowLeft size={16} />
          </button>
          <button className="icon-btn" disabled={st.historyIndex >= st.history.length - 1} onClick={st.forward} title="Forward (Alt+→)">
            <ArrowRight size={16} />
          </button>
        </div>

        <div className="file-chip" title={st.path ?? info.file_name}>
          <span className={`fmt fmt-${info.format}`}>{formatLabel(info.format)}</span>
          <span className="file-name">{info.file_name}</span>
          <span className="file-arch">
            {archLabel(info.arch)} · {info.bits}-bit
          </span>
          <button className="file-close" onClick={() => st.close()} title="Close file">
            <X size={13} />
          </button>
        </div>

        <button className="search-trigger" onClick={() => st.set("paletteOpen", true)}>
          <Search size={14} />
          <span>Go to address, function, string…</span>
          <span className="kbd">Ctrl K</span>
        </button>

        <div className="topbar-right">
          <ThemeToggle />
          <span className="badge accent" title="All analysis happens locally">
            <ShieldCheck size={12} /> Local
          </span>
          <button className="btn sm" onClick={chooseFile}>
            <FolderOpen size={14} /> Open
          </button>
          <button className={`icon-btn ${st.sidebarOpen ? "active" : ""}`} onClick={() => st.set("sidebarOpen", !st.sidebarOpen)} title="Toggle sidebar (Ctrl+B)">
            <PanelLeft size={16} />
          </button>
          <button
            className={`icon-btn ${st.inspectorOpen ? "active" : ""}`}
            onClick={() => st.set("inspectorOpen", !st.inspectorOpen)}
            title="Toggle inspector (Ctrl+J)"
          >
            <PanelRight size={16} />
          </button>
          <AppMenu />
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

        <PanelGroup direction="horizontal" autoSaveId="paranoia.layout" className="panels">
          {st.sidebarOpen && (
            <>
              <Panel id="sidebar" order={1} defaultSize={22} minSize={14} maxSize={45} className="panel">
                <Sidebar />
              </Panel>
              <PanelResizeHandle className="resize-h" />
            </>
          )}
          <Panel id="center" order={2} minSize={30} className="panel center">
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
            <div className="view">
              {st.centerTab === "overview" && <OverviewView />}
              {st.centerTab === "disasm" && <DisassemblyView />}
              {st.centerTab === "graph" && <GraphView />}
              {st.centerTab === "pseudo" && <PseudocodeView />}
              {st.centerTab === "hex" && <HexView />}
            </div>
          </Panel>
          {st.inspectorOpen && (
            <>
              <PanelResizeHandle className="resize-h" />
              <Panel id="inspector" order={3} defaultSize={22} minSize={14} maxSize={40} className="panel">
                <Inspector />
              </Panel>
            </>
          )}
        </PanelGroup>
      </div>
      <StatusBar native={isDesktop} />
    </div>
  );
}
