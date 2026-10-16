import { Binary, Bookmark, Database, FileCode, FolderOpen, Hash, MoreHorizontal, RefreshCw, RotateCcw, Save, Type, X } from "lucide-react";
import { useEffect, useRef } from "react";

import { pickFile } from "../files";
import { useStore } from "../store";

interface Entry {
  icon: typeof Hash;
  label: string;
  keys?: string;
  run(): void;
  danger?: boolean;
}

/** The "⋯" menu: actions that don't deserve a permanent button. */
export function AppMenu() {
  const open = useStore((s) => s.menuOpen);
  const patches = useStore((s) => Object.keys(s.annotations.patches ?? {}).length);
  const ref = useRef<HTMLDivElement>(null);
  const st = useStore.getState;

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && st().set("menuOpen", false);
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open, st]);

  const groups: Entry[][] = [
    [
      { icon: FolderOpen, label: "Open file…", keys: "Ctrl O", run: async () => { const s = await pickFile(); if (s) st().open(s); } },
      { icon: X, label: "Close file", run: () => st().close() },
    ],
    [
      { icon: Binary, label: "Search byte pattern…", keys: "Alt B", run: () => st().set("search", "bytes") },
      { icon: Type, label: "Search text…", keys: "Alt T", run: () => st().set("search", "text") },
      { icon: Hash, label: "Search immediate value…", keys: "Alt I", run: () => st().set("search", "immediate") },
      { icon: Bookmark, label: "Bookmarks", keys: "Ctrl M", run: () => { st().set("sidebarOpen", true); st().set("sidebarTab", "bookmarks"); } },
    ],
    [
      { icon: RefreshCw, label: "Re-run auto-analysis", run: () => st().reanalyze() },
      { icon: Database, label: "Load PDB symbols…", run: () => st().loadPdb() },
      { icon: FileCode, label: "Export names & comments as IDC…", run: () => st().exportIdc() },
      { icon: Save, label: patches ? `Save patched file (${patches} bytes)…` : "Save file copy…", run: () => st().savePatched() },
      ...(patches ? [{ icon: RotateCcw, label: "Revert all patches", run: () => st().revertPatches(), danger: true }] : []),
    ],
  ];

  return (
    <div className="menu-anchor" ref={ref}>
      <button className={`icon-btn ${open ? "active" : ""}`} onClick={() => st().set("menuOpen", !open)} title="More actions" aria-haspopup="menu">
        <MoreHorizontal size={16} />
      </button>
      {open && (
        <div className="menu" role="menu">
          {groups.map((g, i) => (
            <div key={i} className="menu-group">
              {g.map((e) => (
                <button
                  key={e.label}
                  role="menuitem"
                  className={`menu-item ${e.danger ? "danger" : ""}`}
                  onClick={() => {
                    st().set("menuOpen", false);
                    e.run();
                  }}
                >
                  <e.icon size={14} />
                  <span>{e.label}</span>
                  {e.keys && <span className="menu-keys">{e.keys}</span>}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
