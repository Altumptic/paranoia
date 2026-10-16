import {
  ArrowRightLeft,
  Binary,
  Bookmark,
  Braces,
  Code2,
  Copy,
  Eraser,
  FileText,
  GitBranch,
  Hash,
  MessageSquare,
  PenLine,
  Shapes,
  Share2,
  SkipForward,
  Type,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { fmtAddr, useStore } from "../store";

interface Entry {
  icon: LucideIcon;
  label: string;
  keys?: string;
  run(): void;
  disabled?: boolean;
}

/** Right-click menu for listing / graph lines — the IDA command set in one place. */
export function ContextMenu() {
  const menu = useStore((s) => s.contextMenu);
  const info = useStore((s) => s.info);
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const st = useStore.getState;

  useEffect(() => {
    if (!menu) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) st().set("contextMenu", null);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    window.addEventListener("blur", () => st().set("contextMenu", null), { once: true });
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", close);
    };
  }, [menu, st]);

  // Keep the menu inside the window.
  useLayoutEffect(() => {
    if (!menu || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    setPos({ x: Math.min(menu.x, window.innerWidth - r.width - 8), y: Math.min(menu.y, window.innerHeight - r.height - 8) });
  }, [menu]);

  if (!menu) return null;
  const { va, ins } = menu;
  const isData = ins != null && ["db", "dw", "dd", "dq", "text", "extrn"].includes(ins.mnemonic);
  const isCond = ins?.flow === "condjump";
  const isCode = ins != null && !isData;

  const groups: Entry[][] = [
    [
      { icon: PenLine, label: "Rename…", keys: "N", run: () => st().set("dialog", { kind: "rename", va, initial: ins?.label ?? "" }) },
      { icon: MessageSquare, label: "Comment…", keys: ";", run: () => st().set("dialog", { kind: "comment", va, initial: ins?.user_comment ?? "" }) },
      { icon: Bookmark, label: "Bookmark…", keys: "Alt M", run: () => st().set("dialog", { kind: "bookmark", va, initial: st().annotations.bookmarks?.[String(va)] ?? "" }) },
      { icon: Share2, label: "Cross references…", keys: "X", run: () => st().set("xrefsFor", va) },
      ...(ins?.target != null ? [{ icon: SkipForward, label: "Follow operand", keys: "Enter", run: () => st().goto(ins.target!) }] : []),
    ],
    [
      { icon: Code2, label: "Code", keys: "C", run: () => st().item("code", va) },
      { icon: Hash, label: "Data (cycle size)", keys: "D", run: () => st().item("data", va) },
      { icon: Type, label: "String", keys: "A", run: () => st().item("string", va) },
      { icon: Shapes, label: "Apply struct…", keys: "Alt Q", run: () => st().set("dialog", { kind: "struct", va, initial: "" }) },
      { icon: Eraser, label: "Undefine", keys: "U", run: () => st().item("undefine", va) },
      { icon: Braces, label: "Create function", keys: "P", run: () => st().makeFunction(va), disabled: isData },
    ],
    [
      { icon: Eraser, label: "Patch: replace with NOPs", run: () => st().patchInsn(va, "nop"), disabled: !isCode },
      { icon: ArrowRightLeft, label: "Patch: invert condition", run: () => st().patchInsn(va, "invert"), disabled: !isCond },
      { icon: SkipForward, label: "Patch: make jump unconditional", run: () => st().patchInsn(va, "jmp"), disabled: !isCond },
    ],
    [
      { icon: GitBranch, label: "Open in graph", keys: "Space", run: () => st().goto(va, { tab: "graph" }), disabled: !isCode },
      { icon: FileText, label: "Open pseudocode", keys: "Tab", run: () => st().goto(va, { tab: "pseudo" }), disabled: !isCode },
      { icon: Binary, label: "Open in hex", run: () => st().goto(va, { tab: "hex" }) },
      {
        icon: Copy,
        label: `Copy address ${fmtAddr(va, info)}`,
        run: () => navigator.clipboard.writeText(`0x${va.toString(16).toUpperCase()}`).catch(() => st().toast("Clipboard is not available", "error")),
      },
    ],
  ];

  return (
    <div ref={ref} className="menu ctx-menu" style={{ left: pos.x || menu.x, top: pos.y || menu.y }} role="menu" onContextMenu={(e) => e.preventDefault()}>
      {groups.map((g, i) => (
        <div key={i} className="menu-group">
          {g.map((e) => (
            <button
              key={e.label}
              role="menuitem"
              className="menu-item"
              disabled={e.disabled}
              onClick={() => {
                st().set("contextMenu", null);
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
  );
}
