import { Code2, Copy, Loader2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { Pseudocode, Token } from "../../engine/types";
import { useStore } from "../../store";

const CLASS: Record<Token["k"], string> = {
  text: "t-text",
  register: "t-reg",
  number: "t-num",
  keyword: "t-kw p-kw",
  symbol: "t-sym",
  address: "t-str",
  punct: "t-punct",
  prefix: "t-kw",
};

export function PseudocodeView() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info)!;
  const cursor = useStore((s) => s.cursor);
  const revision = useStore((s) => s.revision);
  const functions = useStore((s) => s.functions);
  const st = useStore.getState;
  const [code, setCode] = useState<Pseudocode | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "none">("loading");
  const box = useRef<HTMLDivElement>(null);

  const byName = useMemo(() => new Map(functions.map((f) => [f.name, f.address])), [functions]);

  const inside = code && cursor != null && functions.some((f) => f.address === code.address && cursor >= f.address && cursor < f.address + Math.max(1, f.size));
  useEffect(() => {
    if (cursor == null) return;
    if (inside && code) return;
    let live = true;
    setState("loading");
    session.pseudocode(cursor).then((p) => {
      if (!live) return;
      setCode(p);
      setState(p ? "ready" : "none");
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cursor, session]);

  useEffect(() => {
    if (!code) return;
    let live = true;
    session.pseudocode(code.address).then((p) => live && p && setCode(p));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision]);

  // Highlight the line for the current instruction and keep it visible.
  const activeLine = useMemo(() => {
    if (!code || cursor == null) return -1;
    let best = -1;
    let bestAddr = -1;
    code.lines.forEach((l, i) => {
      if (l.address != null && l.address <= cursor && l.address > bestAddr) {
        best = i;
        bestAddr = l.address;
      }
    });
    return best;
  }, [code, cursor]);
  useEffect(() => {
    box.current?.querySelector(".pl.active")?.scrollIntoView({ block: "nearest" });
  }, [activeLine]);

  if (state === "none")
    return (
      <div className="empty">
        <div>
          <p>No function at this address.</p>
          <button className="btn sm" onClick={() => st().set("centerTab", "disasm")}>
            <Code2 size={13} /> Open listing
          </button>
        </div>
      </div>
    );
  if (!code)
    return (
      <div className="empty">
        <Loader2 className="spin" size={18} />
      </div>
    );

  const copy = async () => {
    const text = code.lines.map((l) => "    ".repeat(l.indent) + l.tokens.map((t) => t.t).join("")).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      st().toast("Pseudocode copied", "success");
    } catch {
      st().toast("Clipboard is not available", "error");
    }
  };

  return (
    <div className="pseudo-wrap">
      <div className="pseudo-bar">
        <span className="pseudo-title mono">{code.name}</span>
        <span className="badge">{info.arch === "x86" ? "x86 · cdecl" : info.format === "pe" ? "x64 · Microsoft ABI" : "x64 · System V ABI"}</span>
        <span className="muted small">Lifted pseudocode — verify against the listing</span>
        <span className="flex1" />
        <button className="btn sm" onClick={copy}>
          <Copy size={13} /> Copy
        </button>
      </div>
      {code.note ? (
        <div className="empty">{code.note}</div>
      ) : (
        <div
          ref={box}
          className="pseudo mono selectable"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Tab" || e.key === "F5") {
              e.preventDefault();
              st().set("centerTab", "disasm");
            } else if (e.key === "n" || e.key === "N") {
              e.preventDefault();
              st().set("dialog", { kind: "rename", va: code.address, initial: code.name });
            }
          }}
        >
          {code.lines.map((l, i) => (
            <div key={i} className={`pl ${i === activeLine ? "active" : ""}`} onMouseDown={() => l.address != null && st().setCursor(l.address)}>
              <span className="pl-gutter">{l.address != null ? l.address.toString(16).toUpperCase().slice(-6) : ""}</span>
              <span className="pl-code" style={{ paddingLeft: l.indent * 28 }}>
                {l.tokens.map((t, k) => {
                  const target = t.k === "symbol" ? byName.get(t.t) : undefined;
                  return (
                    <span
                      key={k}
                      className={`${CLASS[t.k]} ${target != null ? "link-tok" : ""}`}
                      onDoubleClick={target != null ? () => st().goto(target, { tab: "pseudo" }) : undefined}
                      onClick={target != null ? (e) => (e.ctrlKey || e.metaKey) && st().goto(target, { tab: "pseudo" }) : undefined}
                      title={target != null ? "Double-click to open" : undefined}
                    >
                      {t.t}
                    </span>
                  );
                })}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
