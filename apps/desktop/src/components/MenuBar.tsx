import { Check } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { desktop } from "../engine/client";
import { debug } from "../debug";
import { pickFile } from "../files";
import { useStore } from "../store";
import { useTheme, type ThemePref } from "../theme";

/** One row of a drop-down. */
interface Item {
  label?: string;
  keys?: string;
  run?: () => void | Promise<void>;
  disabled?: boolean;
  checked?: boolean;
  danger?: boolean;
  /** A thin separator instead of an item. */
  sep?: boolean;
}

interface Menu {
  id: string;
  label: string;
  items: Item[];
}

const sep: Item = { sep: true };

/** Builds the menus from the current app state: items that cannot act yet are disabled, not hidden. */
function useMenus(): Menu[] {
  const session = useStore((s) => s.session);
  const cursor = useStore((s) => s.cursor);
  const undoDepth = useStore((s) => s.undoDepth);
  const patches = useStore((s) => Object.keys(s.annotations.patches ?? {}).length);
  const sidebarOpen = useStore((s) => s.sidebarOpen);
  const inspectorOpen = useStore((s) => s.inspectorOpen);
  const consoleOpen = useStore((s) => s.consoleOpen);
  const debugOpen = useStore((s) => s.debugOpen);
  const showBytes = useStore((s) => s.showBytes);
  const centerTab = useStore((s) => s.centerTab);
  const dbg = useStore((s) => s.debug);
  const history = useStore((s) => s.history);
  const historyIndex = useStore((s) => s.historyIndex);
  const [theme, setTheme] = useTheme();
  const st = useStore.getState;

  return useMemo(() => {
    const noFile = !session;
    const noCursor = !session || cursor == null;
    const paused = dbg?.state === "paused";
    const live = dbg?.state === "paused" || dbg?.state === "running";
    const at = () => cursor as number;

    const rename = async () => {
      const a = await st().session!.addressInfo(at());
      const va = a.function ?? at();
      st().set("dialog", { kind: "rename", va, initial: (a.function != null ? a.function_name : a.name) ?? "" });
    };

    const tab = (id: "overview" | "disasm" | "graph" | "pseudo" | "calls" | "hex", label: string, key: string): Item => ({
      label,
      keys: key,
      checked: centerTab === id,
      disabled: noFile,
      run: () => st().set("centerTab", id),
    });
    const themeItem = (id: ThemePref, label: string): Item => ({ label, checked: theme === id, run: () => setTheme(id) });

    const menus: Menu[] = [
      {
        id: "file",
        label: "File",
        items: [
          {
            label: "Open file…",
            keys: "Ctrl+O",
            run: async () => {
              const s = await pickFile();
              if (s) st().open(s);
            },
          },
          { label: "Close file", disabled: noFile, run: () => st().close() },
          sep,
          { label: patches ? `Save patched file (${patches} byte${patches === 1 ? "" : "s"})…` : "Save a copy of the file…", disabled: noFile, run: () => st().savePatched() },
          { label: "Export names & comments as IDC…", disabled: noFile, run: () => st().exportIdc() },
          sep,
          { label: "Apply signature file (.pat)…", disabled: noFile, run: () => st().applySignatures() },
          { label: "Create signature file (.pat)…", disabled: noFile, run: () => st().makeSignatures() },
        ],
      },
      {
        id: "edit",
        label: "Edit",
        items: [
          { label: "Undo", keys: "Ctrl+Z", disabled: noFile || undoDepth[0] === 0, run: () => st().undo() },
          { label: "Redo", keys: "Ctrl+Y", disabled: noFile || undoDepth[1] === 0, run: () => st().redo() },
          sep,
          { label: "Rename…", keys: "N", disabled: noCursor, run: rename },
          {
            label: "Comment…",
            keys: ";",
            disabled: noCursor,
            run: () => st().set("dialog", { kind: "comment", va: at(), initial: st().annotations.comments?.[String(at())] ?? "" }),
          },
          {
            label: "Bookmark…",
            keys: "Alt+M",
            disabled: noCursor,
            run: () => st().set("dialog", { kind: "bookmark", va: at(), initial: st().annotations.bookmarks?.[String(at())] ?? "" }),
          },
          sep,
          { label: "Code", keys: "C", disabled: noCursor, run: () => st().item("code", at()) },
          { label: "Data (cycle size)", keys: "D", disabled: noCursor, run: () => st().item("data", at()) },
          { label: "String", keys: "A", disabled: noCursor, run: () => st().item("string", at()) },
          { label: "Undefine", keys: "U", disabled: noCursor, run: () => st().item("undefine", at()) },
          { label: "Create function", keys: "P", disabled: noCursor, run: () => st().makeFunction(at()) },
          { label: "Apply struct…", keys: "Alt+Q", disabled: noCursor, run: () => st().set("dialog", { kind: "struct", va: at(), initial: "" }) },
          sep,
          { label: "Cross references…", keys: "X", disabled: noCursor, run: () => st().set("xrefsFor", at()) },
        ],
      },
      {
        id: "view",
        label: "View",
        items: [
          { label: "Command palette…", keys: "Ctrl+K", run: () => st().set("paletteOpen", true) },
          sep,
          tab("overview", "Overview", "1"),
          tab("disasm", "Disassembly", "2"),
          tab("graph", "Graph", "3"),
          tab("pseudo", "Pseudocode", "4"),
          tab("calls", "Calls", "5"),
          tab("hex", "Hex", "6"),
          sep,
          { label: "Back", keys: "Alt+←", disabled: historyIndex <= 0, run: () => st().back() },
          { label: "Forward", keys: "Alt+→", disabled: historyIndex >= history.length - 1, run: () => st().forward() },
          sep,
          { label: "Sidebar", keys: "Ctrl+B", checked: sidebarOpen, disabled: noFile, run: () => st().set("sidebarOpen", !sidebarOpen) },
          { label: "Inspector", keys: "Ctrl+J", checked: inspectorOpen, disabled: noFile, run: () => st().set("inspectorOpen", !inspectorOpen) },
          { label: "Console", keys: "Ctrl+`", checked: consoleOpen, disabled: noFile, run: () => st().set("consoleOpen", !consoleOpen) },
          ...(desktop ? [{ label: "Debugger panel", checked: debugOpen, disabled: noFile, run: () => st().set("debugOpen", !debugOpen) }] : []),
          { label: "Opcode bytes", checked: showBytes, disabled: noFile, run: () => st().set("showBytes", !showBytes) },
          sep,
          themeItem("system", "Theme: follow system"),
          themeItem("light", "Theme: light"),
          themeItem("dark", "Theme: dark"),
        ],
      },
      {
        id: "analysis",
        label: "Analysis",
        items: [
          { label: "Re-run auto-analysis", disabled: noFile, run: () => st().reanalyze() },
          { label: "Load PDB symbols…", disabled: noFile, run: () => st().loadPdb() },
          sep,
          { label: "Search byte pattern…", keys: "Alt+B", disabled: noFile, run: () => st().set("search", "bytes") },
          { label: "Search text…", keys: "Alt+T", disabled: noFile, run: () => st().set("search", "text") },
          { label: "Search immediate value…", keys: "Alt+I", disabled: noFile, run: () => st().set("search", "immediate") },
          sep,
          {
            label: "Bookmarks",
            keys: "Ctrl+M",
            disabled: noFile,
            run: () => {
              st().set("sidebarOpen", true);
              st().set("sidebarTab", "bookmarks");
            },
          },
          { label: "Revert all patches", disabled: noFile || patches === 0, danger: true, run: () => st().revertPatches() },
        ],
      },
      ...(desktop
        ? [
            {
              id: "debug",
              label: "Debug",
              items: [
                {
                  label: live ? "Continue" : "Start debugging",
                  keys: "F9",
                  disabled: noFile || dbg?.state === "running",
                  run: () => {
                    st().set("debugOpen", true);
                    return debug.cmd("continue");
                  },
                },
                { label: "Pause", disabled: dbg?.state !== "running", run: () => debug.cmd("pause") },
                { label: "Stop", keys: "Shift+F5", disabled: !live, run: () => debug.cmd("stop") },
                sep,
                { label: "Step into", keys: "F7", disabled: !paused, run: () => debug.cmd("step_into") },
                { label: "Step over", keys: "F8", disabled: !paused, run: () => debug.cmd("step_over") },
                { label: "Run to cursor", keys: "F4", disabled: !paused || noCursor, run: () => debug.runTo(at()) },
                sep,
                { label: "Toggle breakpoint", keys: "F2", disabled: noCursor, run: () => debug.toggleBreakpoint(at()) },
              ] as Item[],
            },
          ]
        : []),
      {
        id: "help",
        label: "Help",
        items: [
          { label: "Command palette…", keys: "Ctrl+K", run: () => st().set("paletteOpen", true) },
          sep,
          { label: "About Paranoia", run: () => st().set("aboutOpen", true) },
        ],
      },
    ];
    return menus;
  }, [session, cursor, undoDepth, patches, sidebarOpen, inspectorOpen, consoleOpen, debugOpen, showBytes, centerTab, dbg, history, historyIndex, theme, setTheme, st]);
}

/**
 * Title-bar menus. Click opens a menu; while one is open, hovering another title switches to it;
 * Esc, a click outside or the window losing focus closes it; arrow keys move through items.
 */
export function MenuBar({ only }: { only?: string[] }) {
  const all = useMenus();
  const menus = only ? all.filter((m) => only.includes(m.id)) : all;
  const [open, setOpen] = useState<number | null>(null);
  const root = useRef<HTMLDivElement>(null);

  // The global Esc handler ("go back") must not fire while a menu is open.
  useEffect(() => {
    useStore.getState().set("menuOpen", open !== null);
    return () => useStore.getState().set("menuOpen", false);
  }, [open]);

  const close = useCallback(() => setOpen(null), []);

  useEffect(() => {
    if (open === null) return;
    const away = (e: MouseEvent) => !root.current?.contains(e.target as Node) && close();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        close();
      }
    };
    window.addEventListener("mousedown", away);
    window.addEventListener("keydown", key, true);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", away);
      window.removeEventListener("keydown", key, true);
      window.removeEventListener("blur", close);
    };
  }, [open, close]);

  const focusItem = (menu: HTMLElement | null, dir: 1 | -1 | "first" | "last") => {
    const items = [...(menu?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not(:disabled)') ?? [])];
    if (!items.length) return;
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = dir === "first" ? 0 : dir === "last" ? items.length - 1 : (i + dir + items.length) % items.length;
    items[i === -1 && dir === -1 ? items.length - 1 : next].focus();
  };

  const onKey = (e: React.KeyboardEvent, idx: number) => {
    const menu = (e.currentTarget as HTMLElement).querySelector<HTMLElement>(".mb-menu");
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (open !== idx) setOpen(idx);
      requestAnimationFrame(() => focusItem(root.current?.querySelector<HTMLElement>(".mb-menu") ?? menu, e.key === "ArrowDown" ? 1 : -1));
    } else if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      if (open === null) return;
      e.preventDefault();
      const n = (idx + (e.key === "ArrowRight" ? 1 : -1) + menus.length) % menus.length;
      setOpen(n);
      requestAnimationFrame(() => focusItem(root.current?.querySelector<HTMLElement>(".mb-menu") ?? null, "first"));
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      focusItem(menu, e.key === "Home" ? "first" : "last");
    }
  };

  return (
    <div className="menubar" ref={root} role="menubar">
      {menus.map((m, idx) => (
        <div key={m.id} className="mb-anchor" onKeyDown={(e) => onKey(e, idx)}>
          <button
            className={`mb-title ${open === idx ? "open" : ""}`}
            role="menuitem"
            aria-haspopup="menu"
            aria-expanded={open === idx}
            onClick={() => setOpen(open === idx ? null : idx)}
            onMouseEnter={() => open !== null && setOpen(idx)}
          >
            {m.label}
          </button>
          {open === idx && (
            <div className="mb-menu" role="menu" aria-label={m.label}>
              {m.items.map((it, i) =>
                it.sep ? (
                  <div key={i} className="mb-sep" role="separator" />
                ) : (
                  <button
                    key={it.label}
                    role="menuitem"
                    className={`mb-item ${it.danger ? "danger" : ""}`}
                    disabled={it.disabled}
                    onClick={() => {
                      close();
                      void it.run?.();
                    }}
                  >
                    <span className="mb-check">{it.checked && <Check size={13} />}</span>
                    <span className="mb-label">{it.label}</span>
                    {it.keys && <span className="mb-keys">{it.keys}</span>}
                  </button>
                ),
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
