import { Braces, Code2, CornerDownLeft, FileOutput, FolderOpen, Hash, Import, Quote, Search, type LucideIcon } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { SearchHit } from "../engine/types";
import { pickFile } from "../files";
import { fmtAddr, parseAddress, useStore } from "../store";

interface Item {
  key: string;
  icon: LucideIcon;
  label: string;
  detail?: string;
  hint?: string;
  run(): void;
}

const KIND_ICON: Record<SearchHit["kind"], LucideIcon> = {
  address: Hash,
  function: Braces,
  import: Import,
  export: FileOutput,
  string: Quote,
};

export function CommandPalette() {
  const open = useStore((s) => s.paletteOpen);
  const session = useStore((s) => s.session);
  const info = useStore((s) => s.info);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);

  const close = () => useStore.getState().set("paletteOpen", false);

  // Reset on close (not on open) so keystrokes typed right after opening are never lost.
  useEffect(() => {
    if (!open) {
      setQ("");
      setHits([]);
      setSel(0);
    }
  }, [open]);

  // Debounced engine search.
  useEffect(() => {
    if (!open || !session || q.trim().length < 2) return setHits([]);
    let live = true;
    const t = setTimeout(() => session.search(q, 120).then((h) => live && setHits(h)), 90);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [q, open, session]);

  const items = useMemo<Item[]>(() => {
    const st = useStore.getState();
    const out: Item[] = [];
    const addr = parseAddress(q);
    if (session && addr != null) {
      out.push({ key: "goto", icon: CornerDownLeft, label: `Go to ${fmtAddr(addr, info)}`, hint: "address", run: () => st.goto(addr) });
    }
    for (const h of hits) {
      if (h.kind === "address" && addr != null) continue;
      out.push({
        key: `${h.kind}:${h.address}:${h.label}`,
        icon: KIND_ICON[h.kind],
        label: h.label,
        detail: h.detail,
        hint: fmtAddr(h.address, info),
        run: () => st.goto(h.address),
      });
    }
    const commands: Item[] = [
      { key: "c-open", icon: FolderOpen, label: "Open file…", hint: "Ctrl O", run: async () => { const s = await pickFile(); if (s) st.open(s); } },
    ];
    if (session && info) {
      commands.push(
        { key: "c-entry", icon: Code2, label: "Go to entry point", hint: fmtAddr(info.entry, info), run: () => st.goto(info.entry) },
        { key: "c-funcs", icon: Braces, label: "Show functions", run: () => { st.set("sidebarOpen", true); st.set("sidebarTab", "functions"); } },
        { key: "c-strings", icon: Quote, label: "Show strings", run: () => { st.set("sidebarOpen", true); st.set("sidebarTab", "strings"); } },
        { key: "c-imports", icon: Import, label: "Show imports", run: () => { st.set("sidebarOpen", true); st.set("sidebarTab", "imports"); } },
        { key: "c-bytes", icon: Hash, label: st.showBytes ? "Hide opcode bytes" : "Show opcode bytes", run: () => st.set("showBytes", !st.showBytes) },
      );
    }
    const ql = q.trim().toLowerCase();
    out.push(...commands.filter((c) => !ql || c.label.toLowerCase().includes(ql)));
    return out;
  }, [q, hits, session, info]);

  useEffect(() => setSel(0), [items.length]);
  useEffect(() => {
    list.current?.querySelector(`[data-i="${sel}"]`)?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  if (!open) return null;

  const run = (i: Item | undefined) => {
    if (!i) return;
    close();
    i.run();
  };

  return (
    <div className="modal-veil palette-veil" onMouseDown={close}>
      <div className="palette" onMouseDown={(e) => e.stopPropagation()}>
        <div className="palette-input">
          <Search size={16} />
          <input
            ref={input}
            autoFocus
            value={q}
            placeholder={session ? "Address (hex), function, import, string or command…" : "Type a command…"}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((s) => Math.min(s + 1, items.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((s) => Math.max(s - 1, 0));
              } else if (e.key === "Enter") {
                run(items[sel]);
              } else if (e.key === "Escape") {
                close();
              }
            }}
          />
          <span className="kbd">Esc</span>
        </div>
        <div className="palette-list" ref={list}>
          {items.length === 0 && <div className="palette-empty">No matches</div>}
          {items.map((it, i) => (
            <div
              key={it.key}
              data-i={i}
              className={`palette-item ${i === sel ? "sel" : ""}`}
              onMouseMove={() => setSel(i)}
              onClick={() => run(it)}
            >
              <it.icon size={15} className="palette-icon" />
              <span className="palette-label">{it.label}</span>
              {it.detail && <span className="palette-detail">{it.detail}</span>}
              {it.hint && <span className="palette-hint mono">{it.hint}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
