import { useEffect, useMemo, useState } from "react";

import { kindLabel, memory, type FunctionMatch, type Unmatched } from "../engine/memory";
import type { PseudoLine, Pseudocode, Token } from "../engine/types";
import { useStore } from "../store";

const hex = (v: number) => `0x${v.toString(16)}`;
const pct = (v: number) => (v > 0 && v < 0.01 ? "<1%" : `${(v * 100).toFixed(v >= 0.995 && v < 1 ? 1 : 0)}%`);

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

/** Lowest score at which a match carries its name over. */
const TAKE_NAMES_MIN = 0.75;
/** Rows shown per list; the filter narrows bigger lists. */
const ROWS = 400;

type Tab = "changed" | "removed" | "added" | "identical";

/** Line text with addresses and auto names masked, so layout changes don't count as edits. */
function normal(l: PseudoLine): string {
  const text = l.tokens.map((t) => t.t).join("");
  return text
    .replace(/\b(sub|loc|off|unk|byte|word|dword|qword|stru|asc|a|j)_[0-9A-Fa-f]+\b/g, "$1_#")
    .replace(/\b0x[0-9a-fA-F]{5,}\b/g, "0x#")
    .replace(/\b[0-9A-F]{6,}h\b/g, "#h");
}

/** Marks lines missing on the other side (longest common subsequence on normalised text). */
function lineDiff(a: PseudoLine[], b: PseudoLine[]): [boolean[], boolean[]] {
  const n = a.length;
  const m = b.length;
  const changedA = new Array<boolean>(n).fill(true);
  const changedB = new Array<boolean>(m).fill(true);
  if (n * m > 4_000_000) return [changedA.fill(false), changedB.fill(false)];
  const na = a.map(normal);
  const nb = b.map(normal);
  const dp: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = na[i] === nb[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (na[i] === nb[j]) {
      changedA[i++] = false;
      changedB[j++] = false;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) i++;
    else j++;
  }
  return [changedA, changedB];
}

function Code({ code, marks, side }: { code: Pseudocode | null; marks: boolean[]; side: "a" | "b" }) {
  if (!code) return <div className="muted small cmp-empty">No pseudocode for this function (pseudocode exists for x86, x64 and AArch64).</div>;
  return (
    <div className="cmp-code mono">
      {code.lines.map((l, i) => (
        <div key={i} className={`cmp-line${marks[i] ? ` cmp-${side}` : ""}`}>
          <span style={{ paddingLeft: l.indent * 18 }}>
            {l.tokens.map((t, k) => (
              <span key={k} className={CLASS[t.k]}>
                {t.t}
              </span>
            ))}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Analysis → Compare with another file: which functions changed, appeared or went away,
 *  with the two versions of a function side by side. */
export function CompareDialog() {
  const compare = useStore((s) => s.compare);
  const session = useStore((s) => s.session);
  const info = useStore((s) => s.info);
  const [tab, setTab] = useState<Tab>("changed");
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<FunctionMatch | Unmatched | null>(null);
  const [codes, setCodes] = useState<[Pseudocode | null, Pseudocode | null]>([null, null]);
  const [busy, setBusy] = useState(false);
  const close = () => useStore.getState().closeCompare();

  useEffect(() => {
    if (!compare) return;
    setTab("changed");
    setFilter("");
    setSel(null);
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [compare?.other]);

  const report = compare?.report;
  const lists = useMemo(() => {
    if (!report) return null;
    const changed = report.matches.filter((m) => m.changed).sort((x, y) => x.score - y.score || x.a - y.a);
    const identical = report.matches.filter((m) => !m.changed);
    const bySize = (x: Unmatched, y: Unmatched) => y.instructions - x.instructions || x.address - y.address;
    return { changed, identical, removed: [...report.only_a].sort(bySize), added: [...report.only_b].sort(bySize) };
  }, [report]);

  // Pseudocode of the selected pair.
  useEffect(() => {
    setCodes([null, null]);
    if (!sel || !compare || !session) return;
    let live = true;
    const a = "a" in sel ? sel.a : tab === "removed" ? sel.address : null;
    const b = "b" in sel ? sel.b : tab === "added" ? sel.address : null;
    Promise.all([a != null ? session.pseudocode(a).catch(() => null) : null, b != null ? compare.other.pseudocode(b).catch(() => null) : null]).then(
      ([x, y]) => live && setCodes([x, y]),
    );
    return () => {
      live = false;
    };
  }, [sel]);

  const marks = useMemo(() => {
    const [x, y] = codes;
    if (x && y) return lineDiff(x.lines, y.lines);
    return [x ? x.lines.map(() => false) : [], y ? y.lines.map(() => false) : []];
  }, [codes]);

  if (!compare || !report || !lists || !session || !info) return null;

  const q = filter.trim().toLowerCase();
  const rows: (FunctionMatch | Unmatched)[] = (lists[tab] as (FunctionMatch | Unmatched)[]).filter((r) =>
    !q ? true : "a" in r ? `${r.a_name} ${r.b_name} ${hex(r.a)} ${hex(r.b)}`.toLowerCase().includes(q) : `${r.name} ${hex(r.address)}`.toLowerCase().includes(q),
  );

  const takeable = report.matches.filter((m) => m.b_named && !m.a_named && m.score >= TAKE_NAMES_MIN);
  const takeNames = async () => {
    setBusy(true);
    try {
      const n = await memory.renameMany(
        session,
        takeable.map((m) => ({ va: m.a, text: m.b_name })),
      );
      const st = useStore.getState();
      await st.afterEdit(false);
      useStore.setState({ functions: await session.functions() });
      for (const m of takeable) {
        m.a_name = m.b_name;
        m.a_named = true;
      }
      st.toast(`Took ${n} name${n === 1 ? "" : "s"} from ${compare.name}. Ctrl+Z undoes it.`, "success");
    } catch (e) {
      useStore.getState().toast(`Could not take names: ${e instanceof Error ? e.message : String(e)}`, "error");
    } finally {
      setBusy(false);
    }
  };

  const goto = (va: number) => {
    useStore.getState().goto(va, { tab: "pseudo" });
    close();
  };

  const tabs: [Tab, string, number][] = [
    ["changed", "Changed", lists.changed.length],
    ["removed", `Only in ${info.file_name}`, lists.removed.length],
    ["added", `Only in ${compare.name}`, lists.added.length],
    ["identical", "Identical", lists.identical.length],
  ];
  const selA = sel && ("a" in sel ? sel.a : tab === "removed" ? sel.address : null);

  return (
    <div className="modal-veil cmp-veil" onMouseDown={close}>
      <div className="modal cmp-modal" role="dialog" aria-label="Compare files" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">
          <span className="ellipsis">
            {info.file_name} ↔ {compare.name}
          </span>
          <span className="badge accent">{pct(report.similarity)} shared code</span>
        </div>
        <div className="cmp-summary small muted">
          {report.matches.length} functions matched: {lists.identical.length} identical, {lists.changed.length} changed. {lists.removed.length} only in this
          file, {lists.added.length} only in the other.
        </div>

        <div className="seg cmp-tabs">
          {tabs.map(([id, label, n]) => (
            <button key={id} className={`seg-btn ${tab === id ? "on" : ""}`} onClick={() => (setTab(id), setSel(null))}>
              <span className="ellipsis">{label}</span> <span className="muted">{n}</span>
            </button>
          ))}
        </div>

        <div className="cmp-body">
          <div className="cmp-left">
            <input className="input" placeholder="Filter by name or address" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <div className="cmp-list">
              {rows.slice(0, ROWS).map((r) => {
                const key = "a" in r ? `${r.a}-${r.b}` : String(r.address);
                const on = sel != null && ("a" in sel && "a" in r ? sel.a === r.a : "address" in sel && "address" in r && sel.address === r.address);
                return (
                  <div key={key} className={`cmp-row${on ? " sel" : ""}`} onClick={() => setSel(r)}>
                    {"a" in r ? (
                      <>
                        <span className="cmp-score mono">{r.changed ? pct(r.score) : "="}</span>
                        <span className="ellipsis mono" title={`${r.a_name} ↔ ${r.b_name} · ${kindLabel[r.kind]}`}>
                          {r.a_name === r.b_name ? r.a_name : `${r.a_name} ↔ ${r.b_name}`}
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="cmp-score mono muted">{r.instructions}</span>
                        <span className="ellipsis mono">{r.name}</span>
                      </>
                    )}
                  </div>
                );
              })}
              {rows.length > ROWS && <div className="muted small cmp-more">{rows.length - ROWS} more; use the filter</div>}
              {rows.length === 0 && <div className="muted small cmp-more">Nothing here.</div>}
            </div>
          </div>

          <div className="cmp-right">
            {sel ? (
              <>
                <div className="cmp-pair small">
                  <div className="ellipsis">
                    <b>{info.file_name}</b> {selA != null ? <span className="mono muted">{hex(selA)}</span> : <span className="muted">not in this file</span>}
                  </div>
                  <div className="ellipsis">
                    <b>{compare.name}</b>{" "}
                    {"b" in sel ? <span className="mono muted">{hex(sel.b)}</span> : tab === "added" ? <span className="mono muted">{hex(sel.address)}</span> : <span className="muted">not in that file</span>}
                  </div>
                </div>
                {"kind" in sel && <div className="muted small">Matched by {kindLabel[sel.kind]}{sel.changed ? `, ${pct(sel.score)} similar` : ""}.</div>}
                <div className="cmp-sides">
                  <Code code={codes[0]} marks={marks[0]} side="a" />
                  <Code code={codes[1]} marks={marks[1]} side="b" />
                </div>
              </>
            ) : (
              <div className="muted small cmp-empty">Pick a function to see both versions side by side. Lines that differ are highlighted.</div>
            )}
          </div>
        </div>

        <div className="modal-actions">
          <span className="muted small">
            {takeable.length > 0 ? `${compare.name} has names for ${takeable.length} functions that are unnamed here.` : "Matching is by code only; nothing leaves this computer."}
          </span>
          {takeable.length > 0 && (
            <button className="btn" disabled={busy} onClick={takeNames}>
              Take {takeable.length} names
            </button>
          )}
          {selA != null && (
            <button className="btn" onClick={() => goto(selA)}>
              Go to function
            </button>
          )}
          <button className="btn primary" onClick={close}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
