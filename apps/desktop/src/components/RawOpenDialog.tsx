import { useEffect, useState } from "react";

import { desktop, type RawGuess, type RawOpen } from "../engine/client";
import { useStore } from "../store";

/** CPUs a header-less image can be opened as (the names `paranoia --arch` takes). */
const ARCHES: { id: string; label: string }[] = [
  { id: "thumb", label: "ARM Thumb-2 (Cortex-M)" },
  { id: "arm", label: "ARM 32-bit" },
  { id: "arm64", label: "AArch64" },
  { id: "x86", label: "x86 (32-bit)" },
  { id: "x86-64", label: "x86-64" },
  { id: "mips", label: "MIPS (32-bit)" },
  { id: "mips64", label: "MIPS (64-bit)" },
  { id: "ppc", label: "PowerPC (32-bit)" },
  { id: "ppc64", label: "PowerPC (64-bit)" },
  { id: "riscv32", label: "RISC-V (32-bit)" },
  { id: "riscv64", label: "RISC-V (64-bit)" },
];

/** Parses an address typed as hex (`0x08000000` or `08000000`); null when empty, NaN when invalid. */
function parseAddr(s: string): number | null {
  const t = s.trim().replace(/^0x/i, "");
  if (!t) return null;
  return /^[0-9a-f]+$/i.test(t) && t.length <= 13 ? parseInt(t, 16) : NaN;
}

/**
 * File → Open firmware or raw image…, and what appears when a file has no PE / ELF / Mach-O header:
 * the file cannot say which CPU it is for or where it is loaded, so you do. The fields start from the
 * engine's guess (a Cortex-M vector table, or pointers to strings that agree on a base).
 */
export function RawOpenDialog() {
  const target = useStore((s) => s.rawOpen);
  const [arch, setArch] = useState("thumb");
  const [base, setBase] = useState("");
  const [entry, setEntry] = useState("");
  const [big, setBig] = useState(false);
  const [guess, setGuess] = useState<RawGuess | null>(null);
  const [asked, setAsked] = useState(false);

  const close = () => useStore.getState().set("rawOpen", null);

  useEffect(() => {
    if (!target || !desktop) return;
    setGuess(null);
    setAsked(false);
    setBase("");
    setEntry("");
    desktop
      .engine({ op: "raw_guess", path: target.path })
      .then((g) => {
        const r = g as RawGuess;
        setGuess(r);
        if (r.arch_name) setArch(r.arch_name);
        setBig(r.big_endian);
        if (r.base != null) setBase(`0x${r.base.toString(16)}`);
      })
      .catch(() => setGuess(null))
      .finally(() => setAsked(true));
  }, [target]);

  useEffect(() => {
    if (!target) return;
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [target]);

  if (!target) return null;
  const hasAddresses = guess?.container != null;
  const baseNum = parseAddr(base);
  const entryNum = parseAddr(entry);
  const invalid = Number.isNaN(baseNum) || Number.isNaN(entryNum);

  const open = () => {
    if (invalid) return;
    const raw: RawOpen = { arch };
    if (!hasAddresses && baseNum != null) raw.base = baseNum;
    if (entryNum != null) raw.entry = entryNum;
    if (big) raw.big_endian = true;
    close();
    void useStore.getState().open({ kind: "path", path: target.path, raw });
  };

  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal raw-modal" role="dialog" aria-label="Open firmware or raw image" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">Open firmware or raw image</div>
        <p className="muted small">
          <span className="mono">{target.name}</span> has no PE, ELF or Mach-O header{guess?.container ? `; it is an ${guess.container} file` : ""}. A file like this cannot say which CPU it is for or
          {hasAddresses ? "" : " where it is loaded"}, so tell Paranoia.
        </p>
        <label className="ai-field">
          <span>Architecture</span>
          <select className="input" value={arch} onChange={(e) => setArch(e.target.value)}>
            {ARCHES.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </select>
        </label>
        {!hasAddresses && (
          <label className="ai-field">
            <span>Load address (hex)</span>
            <input className="input mono" value={base} placeholder="0x08000000" spellCheck={false} onChange={(e) => setBase(e.target.value)} />
          </label>
        )}
        <label className="ai-field">
          <span>Entry point (hex, optional)</span>
          <input className="input mono" value={entry} placeholder="from the vector table or the file" spellCheck={false} onChange={(e) => setEntry(e.target.value)} />
        </label>
        <label className="ai-check">
          <input type="checkbox" checked={big} onChange={(e) => setBig(e.target.checked)} />
          <span>Big-endian</span>
        </label>
        {asked && guess && guess.notes.length > 0 && (
          <div className="raw-guess small">
            <strong>Suggested from the file:</strong> {guess.notes.join(" ")} <span className="muted">(a guess, change it if it is wrong)</span>
          </div>
        )}
        {asked && guess && guess.notes.length === 0 && !hasAddresses && <div className="muted small">No suggestion: no Cortex-M vector table, and no base that pointers to strings agree on.</div>}
        {invalid && <div className="update-bad small">An address is hexadecimal digits only, for example 0x08000000.</div>}
        <div className="modal-actions">
          <span className="muted small">Esc to cancel</span>
          <button className="btn sm" onClick={close}>
            Cancel
          </button>
          <button className="btn sm primary" onClick={open} disabled={invalid}>
            Open
          </button>
        </div>
      </div>
    </div>
  );
}
