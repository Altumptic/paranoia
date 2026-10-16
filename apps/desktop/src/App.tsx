import { useEffect, useState } from "react";

import { CommandPalette } from "./components/CommandPalette";
import { EditDialog } from "./components/EditDialog";
import { SearchDialog } from "./components/SearchDialog";
import { ContextMenu } from "./components/ContextMenu";
import { XrefsDialog } from "./components/XrefsDialog";
import { Toasts } from "./components/Toasts";
import { Welcome } from "./components/Welcome";
import { Workspace } from "./components/Workspace";
import { desktop } from "./engine/client";
import { debug } from "./debug";
import { fromFile, pickFile } from "./files";
import { useStore } from "./store";

export function App() {
  const session = useStore((s) => s.session);
  const loading = useStore((s) => s.loading);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    useStore.getState().loadRecent();
    if (!desktop) return;
    const offOpen = desktop.onOpenPath((path) => useStore.getState().open({ kind: "path", path }));
    const offRestart = desktop.onEngineRestarted(() => {
      // Sessions lived in the engine process; return to the start screen cleanly.
      useStore.setState({ session: null, info: null, stats: null, functions: [], cursor: null, loading: null });
      useStore.getState().toast("The analysis engine restarted after an internal error. Please reopen the file.", "error");
    });
    return () => {
      offOpen();
      offRestart();
    };
  }, []);

  // Drag & drop (desktop resolves dropped files to paths in fromFile).
  useEffect(() => {
    let depth = 0;
    const enter = (e: DragEvent) => {
      if (!e.dataTransfer?.types.includes("Files")) return;
      e.preventDefault();
      depth++;
      setDragging(true);
    };
    const over = (e: DragEvent) => e.preventDefault();
    const leave = () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    };
    const drop = async (e: DragEvent) => {
      e.preventDefault();
      depth = 0;
      setDragging(false);
      const f = e.dataTransfer?.files[0];
      if (f) useStore.getState().open(await fromFile(f));
    };
    window.addEventListener("dragenter", enter);
    window.addEventListener("dragover", over);
    window.addEventListener("dragleave", leave);
    window.addEventListener("drop", drop);
    return () => {
      window.removeEventListener("dragenter", enter);
      window.removeEventListener("dragover", over);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("drop", drop);
    };
  }, []);

  // Global shortcuts. View-specific keys live in the views themselves.
  useEffect(() => {
    const onKey = async (e: KeyboardEvent) => {
      const st = useStore.getState();
      const mod = e.ctrlKey || e.metaKey;
      const typing = (e.target as HTMLElement)?.closest("input, textarea");
      if (mod && e.key.toLowerCase() === "o") {
        e.preventDefault();
        const src = await pickFile();
        if (src) st.open(src);
      } else if ((mod && e.key.toLowerCase() === "k") || (mod && e.key.toLowerCase() === "p")) {
        e.preventDefault();
        st.set("paletteOpen", !st.paletteOpen);
      } else if (mod && e.key === "`") {
        e.preventDefault();
        st.set("consoleOpen", !st.consoleOpen);
      } else if (typing || st.dialog || st.paletteOpen || st.search || st.xrefsFor != null || !st.session) {
        return;
      } else if (mod && !e.shiftKey && e.key.toLowerCase() === "z") {
        e.preventDefault();
        st.undo();
      } else if (mod && (e.key.toLowerCase() === "y" || (e.shiftKey && e.key.toLowerCase() === "z"))) {
        e.preventDefault();
        st.redo();
      } else if (e.altKey && ["b", "t", "i"].includes(e.key.toLowerCase())) {
        e.preventDefault();
        st.set("search", ({ b: "bytes", t: "text", i: "immediate" } as const)[e.key.toLowerCase() as "b" | "t" | "i"]);
      } else if (e.altKey && e.key.toLowerCase() === "m" && st.cursor != null) {
        e.preventDefault();
        const cur = st.annotations.bookmarks?.[String(st.cursor)];
        st.set("dialog", { kind: "bookmark", va: st.cursor, initial: cur ?? "" });
      } else if (mod && e.key.toLowerCase() === "m") {
        e.preventDefault();
        st.set("sidebarOpen", true);
        st.set("sidebarTab", "bookmarks");
      } else if (e.key === "F9" && desktop) {
        e.preventDefault();
        st.set("debugOpen", true);
        debug.cmd("continue");
      } else if (e.key === "F7" && st.debug) {
        e.preventDefault();
        debug.cmd("step_into");
      } else if (e.key === "F8" && st.debug) {
        e.preventDefault();
        debug.cmd("step_over");
      } else if (e.key === "F4" && st.debug && st.cursor != null) {
        e.preventDefault();
        debug.runTo(st.cursor);
      } else if (e.key === "F2" && st.cursor != null) {
        e.preventDefault();
        debug.toggleBreakpoint(st.cursor);
      } else if (e.key === "F5" && e.shiftKey && st.debug) {
        e.preventDefault();
        debug.cmd("stop");
      } else if (e.key === "F5") {
        e.preventDefault();
        st.set("centerTab", st.centerTab === "pseudo" ? "disasm" : "pseudo");
      } else if (e.key === "g" && !mod) {
        e.preventDefault();
        st.set("paletteOpen", true);
      } else if (e.key === "Escape" && st.highlight) {
        st.set("highlight", null);
      } else if ((e.altKey && e.key === "ArrowLeft") || (e.key === "Escape" && !st.paletteOpen && !st.menuOpen && !st.contextMenu)) {
        e.preventDefault();
        st.back();
      } else if (e.altKey && e.key === "ArrowRight") {
        e.preventDefault();
        st.forward();
      } else if (mod && e.key === "b") {
        e.preventDefault();
        st.set("sidebarOpen", !st.sidebarOpen);
      } else if (mod && e.key === "j") {
        e.preventDefault();
        st.set("inspectorOpen", !st.inspectorOpen);
      } else if (!mod && !e.altKey && ["1", "2", "3", "4", "5", "6"].includes(e.key)) {
        st.set("centerTab", (["overview", "disasm", "graph", "pseudo", "calls", "hex"] as const)[Number(e.key) - 1]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      {session ? <Workspace /> : <Welcome />}
      {loading && (
        <div className="loading-veil">
          <div className="loading-card">
            <div className="loading-orbit">
              <div className="spinner big" />
            </div>
            <div className="loading-name mono">{loading.name}</div>
            <div className="loading-phase">{loading.phase}</div>
          </div>
        </div>
      )}
      {dragging && (
        <div className="drop-veil">
          <div className="drop-card">
            <div className="drop-ring" />
            <div>Drop to analyze</div>
            <small>PE · ELF · Mach-O — processed locally, never uploaded</small>
          </div>
        </div>
      )}
      <CommandPalette />
      <EditDialog />
      <SearchDialog />
      <XrefsDialog />
      <ContextMenu />
      <Toasts />
    </>
  );
}
