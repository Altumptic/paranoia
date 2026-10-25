import { ArrowDownAZ, ArrowDownWideNarrow, Bookmark, ChevronDown, ChevronRight, Filter, Link2, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import type { FunctionSummary, NameEntry, StringEntry, Symbol } from "../engine/types";
import { fmtAddr, fmtSize, hex, useStore } from "../store";
import { VirtualList } from "./VirtualList";

function useFilter(): [string, (v: string) => void, (s: string) => boolean] {
  const [q, setQ] = useState("");
  const ql = q.trim().toLowerCase();
  return [q, setQ, (s: string) => !ql || s.toLowerCase().includes(ql)];
}

function Header({ title, count, children }: { title: string; count: number; children?: React.ReactNode }) {
  return (
    <div className="side-head">
      <span className="side-title">{title}</span>
      <span className="count">{count.toLocaleString()}</span>
      <span className="side-head-spacer" />
      {children}
    </div>
  );
}

function FilterBox({ value, onChange, placeholder }: { value: string; onChange(v: string): void; placeholder: string }) {
  return (
    <div className="side-filter">
      <Filter size={13} />
      <input className="input" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} spellCheck={false} />
    </div>
  );
}

export function Sidebar() {
  const tab = useStore((s) => s.sidebarTab);
  return (
    <div className="sidebar">
      {tab === "functions" && <FunctionsPanel />}
      {tab === "names" && <NamesPanel />}
      {tab === "imports" && <ImportsPanel />}
      {tab === "exports" && <ExportsPanel />}
      {tab === "strings" && <StringsPanel />}
      {tab === "sections" && <SectionsPanel />}
      {tab === "symbols" && <SymbolsPanel />}
      {tab === "bookmarks" && <BookmarksPanel />}
      {tab === "types" && <TypesPanel />}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------

type FnSort = "address" | "name" | "size" | "xrefs";

function FunctionsPanel() {
  const functions = useStore((s) => s.functions);
  const info = useStore((s) => s.info);
  const cursor = useStore((s) => s.cursor);
  const goto = useStore((s) => s.goto);
  const [q, setQ, match] = useFilter();
  const [sort, setSort] = useState<FnSort>("address");

  const rows = useMemo(() => {
    const r = functions.filter((f) => match(f.name) || match(hex(f.address)));
    const cmp: Record<FnSort, (a: FunctionSummary, b: FunctionSummary) => number> = {
      address: (a, b) => a.address - b.address,
      name: (a, b) => a.name.localeCompare(b.name),
      size: (a, b) => b.size - a.size,
      xrefs: (a, b) => b.xrefs - a.xrefs,
    };
    return r.sort(cmp[sort]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [functions, q, sort]);

  // The function containing the cursor (functions are contiguous enough for a sorted lookup).
  const current = useMemo(() => {
    if (cursor == null) return -1;
    let best = -1;
    let bestAddr = -1;
    rows.forEach((f, i) => {
      if (f.address <= cursor && cursor < f.address + Math.max(f.size, 1) && f.address > bestAddr) {
        best = i;
        bestAddr = f.address;
      }
    });
    return best;
  }, [rows, cursor]);

  const nextSort: Record<FnSort, FnSort> = { address: "name", name: "size", size: "xrefs", xrefs: "address" };
  return (
    <>
      <Header title="Functions" count={rows.length}>
        <button className="btn sm ghost" onClick={() => setSort(nextSort[sort])} title="Change sort order">
          {sort === "name" ? <ArrowDownAZ size={13} /> : <ArrowDownWideNarrow size={13} />} {sort}
        </button>
      </Header>
      <FilterBox value={q} onChange={setQ} placeholder="Filter functions" />
      {functions.length === 0 ? (
        <div className="empty small">{info?.disassembly_supported ? "No functions found." : "Disassembly isn't available for this architecture yet."}</div>
      ) : (
        <VirtualList
          items={rows}
          activeIndex={current}
          render={(f, i) => (
            <button className={`row fn-row ${i === current ? "active" : ""} ${f.is_import_thunk ? "thunk" : ""} ${f.library ? "lib" : ""}`} onClick={() => goto(f.address)} title={`${f.name}\n${f.instructions} instructions · ${f.blocks} blocks · ${f.xrefs} xrefs`}>
              <span className={`fn-dot src-${f.source}`} />
              <span className="row-main">{f.name}</span>
              {f.xrefs > 0 && <span className="row-xrefs">{f.xrefs}</span>}
              <span className="row-addr mono">{fmtAddr(f.address, info)}</span>
            </button>
          )}
        />
      )}
    </>
  );
}

// ------------------------------------------------------------------------------------------------

function ImportsPanel() {
  const info = useStore((s) => s.info)!;
  const goto = useStore((s) => s.goto);
  const [q, setQ, match] = useFilter();
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  type Row = { kind: "lib"; lib: string; count: number } | { kind: "imp"; name: string; lib: string; address: number; ordinal: number | null };
  const rows = useMemo(() => {
    const groups = new Map<string, typeof info.imports>();
    for (const i of info.imports) {
      if (!match(i.name) && !match(i.library)) continue;
      const k = i.library || "(unknown library)";
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k)!.push(i);
    }
    const out: Row[] = [];
    for (const [lib, items] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      out.push({ kind: "lib", lib, count: items.length });
      if (!collapsed.has(lib)) for (const i of items) out.push({ kind: "imp", name: i.name, lib, address: i.address, ordinal: i.ordinal });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [info, q, collapsed]);

  return (
    <>
      <Header title="Imports" count={info.imports.length} />
      <FilterBox value={q} onChange={setQ} placeholder="Filter imports or libraries" />
      {info.imports.length === 0 ? (
        <div className="empty small">No imports.</div>
      ) : (
        <VirtualList
          items={rows}
          render={(r) =>
            r.kind === "lib" ? (
              <button
                className="row lib-row"
                onClick={() => {
                  const s = new Set(collapsed);
                  if (s.has(r.lib)) s.delete(r.lib);
                  else s.add(r.lib);
                  setCollapsed(s);
                }}
              >
                {collapsed.has(r.lib) ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
                <span className="row-main">{r.lib}</span>
                <span className="count">{r.count}</span>
              </button>
            ) : (
              <button className="row imp-row" onClick={() => r.address && goto(r.address)} title={`${r.lib}!${r.name}\nslot ${fmtAddr(r.address, info)} — shows callers in the inspector`}>
                <span className="row-main">{r.name}</span>
                {r.ordinal != null && <span className="badge">#{r.ordinal}</span>}
                <span className="row-addr mono">{fmtAddr(r.address, info)}</span>
              </button>
            )
          }
        />
      )}
    </>
  );
}

function ExportsPanel() {
  const info = useStore((s) => s.info)!;
  const goto = useStore((s) => s.goto);
  const [q, setQ, match] = useFilter();
  const rows = useMemo(() => info.exports.filter((e) => match(e.name) || (e.forward != null && match(e.forward))), [info, q]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <>
      <Header title="Exports" count={info.exports.length} />
      <FilterBox value={q} onChange={setQ} placeholder="Filter exports" />
      {info.exports.length === 0 ? (
        <div className="empty small">No exports.</div>
      ) : (
        <VirtualList
          items={rows}
          render={(e) => (
            <button className="row" disabled={!e.address} onClick={() => goto(e.address)} title={e.forward ? `Forwarded to ${e.forward}` : e.name}>
              {e.ordinal != null && <span className="row-ord mono">{e.ordinal}</span>}
              <span className="row-main">{e.name}</span>
              {e.forward ? (
                <span className="row-fwd">
                  <Link2 size={11} /> {e.forward}
                </span>
              ) : (
                <span className="row-addr mono">{fmtAddr(e.address, info)}</span>
              )}
            </button>
          )}
        />
      )}
    </>
  );
}

function StringsPanel() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info);
  const st = useStore();
  const [strings, setStrings] = useState<StringEntry[] | null>(null);
  const [q, setQ, match] = useFilter();
  const [refOnly, setRefOnly] = useState(false);

  useEffect(() => {
    let live = true;
    session.strings().then((s) => live && setStrings(s));
    return () => {
      live = false;
    };
  }, [session]);

  const rows = useMemo(() => (strings ?? []).filter((s) => (!refOnly || s.xrefs > 0) && match(s.value)), [strings, q, refOnly]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <Header title="Strings" count={rows.length}>
        <button className={`btn sm ${refOnly ? "" : "ghost"}`} onClick={() => setRefOnly(!refOnly)} title="Only strings referenced from code">
          <Link2 size={12} /> Referenced
        </button>
      </Header>
      <FilterBox value={q} onChange={setQ} placeholder="Filter strings" />
      {strings == null ? (
        <div className="empty">
          <div className="spinner" />
        </div>
      ) : (
        <VirtualList
          items={rows}
          rowHeight={38}
          render={(s) => (
            <button
              className="row str-row"
              onClick={() => {
                if (s.address != null) {
                  st.goto(s.address, { tab: "hex" });
                  st.set("inspectorOpen", true);
                } else st.toast("This string is outside any mapped section.");
              }}
              title={s.value}
            >
              <span className="str-value">
                {s.encoding === "utf16" && <span className="str-enc">L</span>}
                {s.value}
              </span>
              <span className="str-meta">
                <span className="mono">{s.address != null ? fmtAddr(s.address, info) : `+${hex(s.offset)}`}</span>
                {s.section && <span>{s.section}</span>}
                {s.xrefs > 0 && <span className="str-xrefs">{s.xrefs} xref{s.xrefs > 1 ? "s" : ""}</span>}
              </span>
            </button>
          )}
        />
      )}
    </>
  );
}

function entropyColor(e: number) {
  if (e > 7.2) return "var(--danger)";
  if (e > 6.5) return "var(--warn)";
  return "var(--accent)";
}

function SectionsPanel() {
  const info = useStore((s) => s.info)!;
  const goto = useStore((s) => s.goto);
  return (
    <>
      <Header title="Sections" count={info.sections.length} />
      <div className="sections-list">
        {info.sections.map((s, i) => (
          <button
            key={i}
            className="section-card"
            onClick={() => s.vaddr && goto(s.vaddr, { tab: s.perms.x ? "disasm" : "hex" })}
            title={`${s.name}\nentropy ${s.entropy.toFixed(3)}`}
          >
            <div className="section-top">
              <span className="section-name mono">{s.segment ? `${s.segment},${s.name}` : s.name}</span>
              <span className="perms mono">
                <b className={s.perms.r ? "on" : ""}>r</b>
                <b className={s.perms.w ? "on w" : ""}>w</b>
                <b className={s.perms.x ? "on x" : ""}>x</b>
              </span>
            </div>
            <div className="section-meta mono">
              <span>{fmtAddr(s.vaddr, info)}</span>
              <span>{fmtSize(s.vsize)}</span>
            </div>
            <div className="entropy-bar" title={`Entropy ${s.entropy.toFixed(2)} / 8`}>
              <i style={{ width: `${(s.entropy / 8) * 100}%`, background: entropyColor(s.entropy) }} />
            </div>
          </button>
        ))}
      </div>
    </>
  );
}

function SymbolsPanel() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info);
  const goto = useStore((s) => s.goto);
  const [symbols, setSymbols] = useState<Symbol[] | null>(null);
  const [q, setQ, match] = useFilter();
  useEffect(() => {
    let live = true;
    session.symbols().then((s) => live && setSymbols(s.sort((a, b) => a.address - b.address)));
    return () => {
      live = false;
    };
  }, [session]);
  const rows = useMemo(() => (symbols ?? []).filter((s) => match(s.name)), [symbols, q]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <>
      <Header title="Symbols" count={rows.length} />
      <FilterBox value={q} onChange={setQ} placeholder="Filter symbols" />
      {symbols == null ? (
        <div className="empty">
          <div className="spinner" />
        </div>
      ) : symbols.length === 0 ? (
        <div className="empty small">No symbol table (stripped binary).</div>
      ) : (
        <VirtualList
          items={rows}
          render={(s) => (
            <button className="row" onClick={() => goto(s.address)} title={`${s.name}\n${s.kind}${s.size ? ` · ${s.size} bytes` : ""}`}>
              <span className={`sym-kind sym-${s.kind}`}>{s.kind === "function" ? "f" : s.kind === "object" ? "d" : "·"}</span>
              <span className="row-main">{s.name}</span>
              <span className="row-addr mono">{fmtAddr(s.address, info)}</span>
            </button>
          )}
        />
      )}
    </>
  );
}

function BookmarksPanel() {
  const marks = useStore((s) => s.annotations.bookmarks ?? {});
  const info = useStore((s) => s.info);
  const st = useStore();
  const rows = Object.entries(marks)
    .map(([k, v]) => ({ va: Number(k), text: v }))
    .sort((a, b) => a.va - b.va);
  return (
    <>
      <Header title="Bookmarks" count={rows.length} />
      {rows.length === 0 ? (
        <div className="empty small">
          <div>
            <Bookmark size={18} />
            <p>
              Press <span className="kbd">Alt M</span> anywhere to bookmark the current address.
            </p>
          </div>
        </div>
      ) : (
        <div className="bookmarks">
          {rows.map((b) => (
            <div key={b.va} className="bookmark">
              <button className="bookmark-main" onClick={() => st.goto(b.va)}>
                <span className="bookmark-text">{b.text}</span>
                <span className="mono row-addr">{fmtAddr(b.va, info)}</span>
              </button>
              <button className="icon-btn" title="Remove bookmark" onClick={() => st.bookmark(b.va, null)}>
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

const NAME_KIND: Record<NameEntry["kind"], string> = { function: "F", import: "I", export: "E", label: "L", data: "D", string: "A", user: "U" };

function NamesPanel() {
  const session = useStore((s) => s.session)!;
  const info = useStore((s) => s.info);
  const revision = useStore((s) => s.revision);
  const goto = useStore((s) => s.goto);
  const [names, setNames] = useState<NameEntry[] | null>(null);
  const [q, setQ, match] = useFilter();
  useEffect(() => {
    let live = true;
    session.names().then((n) => live && setNames(n));
    return () => {
      live = false;
    };
  }, [session, revision]);
  const rows = useMemo(() => (names ?? []).filter((n) => match(n.name) || match(hex(n.address))), [names, q]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <>
      <Header title="Names" count={rows.length} />
      <FilterBox value={q} onChange={setQ} placeholder="Filter names" />
      {names == null ? (
        <div className="empty">
          <div className="spinner" />
        </div>
      ) : (
        <VirtualList
          items={rows}
          render={(n) => (
            <button className="row" onClick={() => goto(n.address)} title={`${n.name}
${n.kind}`}>
              <span className={`name-kind nk-${n.kind}`}>{NAME_KIND[n.kind]}</span>
              <span className="row-main">{n.name}</span>
              <span className="row-addr mono">{fmtAddr(n.address, info)}</span>
            </button>
          )}
        />
      )}
    </>
  );
}

const TYPE_EXAMPLE = `// Local types: C declarations, like IDA's Local Types window.
typedef struct _POINT {
  LONG x;
  LONG y;
} POINT;

struct Header {
  DWORD magic;
  WORD  version;
  WORD  flags;
  char *name;
  POINT origin;
};

enum Mode { MODE_READ = 1, MODE_WRITE = 2 };
`;

function TypesPanel() {
  const session = useStore((s) => s.session)!;
  const lib = useStore((s) => s.annotations.types);
  const cursor = useStore((s) => s.cursor);
  const [text, setText] = useState(lib?.source || TYPE_EXAMPLE);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const st = useStore.getState;
  const structs = Object.values(lib?.structs ?? {});
  const save = async () => {
    try {
      const n = await session.setTypes(text);
      setErr(null);
      await st().afterEdit(false);
      st().toast(`${n} type${n === 1 ? "" : "s"} defined`, "success");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <>
      <Header title="Local types" count={structs.length} />
      <div className="types-editor">
        <textarea className="mono" value={text} spellCheck={false} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => (e.ctrlKey || e.metaKey) && e.key === "Enter" && save()} />
        {err && <div className="search-error">{err}</div>}
        <button className="btn sm primary" onClick={save}>
          Save types <span className="kbd on-accent">Ctrl Enter</span>
        </button>
      </div>
      <div className="types-list">
        {structs.map((sd) => (
          <div key={sd.name} className="type-card">
            <button className="type-head" onClick={() => setOpen(open === sd.name ? null : sd.name)}>
              {open === sd.name ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              <span className="mono type-name">{sd.name}</span>
              <span className="muted small">{sd.size.toString(16).toUpperCase()}h bytes</span>
              <span className="side-head-spacer" />
              <span
                className="link small"
                onClick={(e) => {
                  e.stopPropagation();
                  if (cursor != null) st().set("dialog", { kind: "struct", va: cursor, initial: sd.name });
                }}
              >
                apply
              </span>
            </button>
            {open === sd.name && (
              <table className="frame-table mono">
                <tbody>
                  {sd.fields.map((f) => (
                    <tr key={f.name}>
                      <td className="fr-off">{f.offset.toString(16).toUpperCase()}</td>
                      <td className="fr-name">{f.name}</td>
                      <td className="fr-size">
                        {f.ty}
                        {f.count > 1 ? `[${f.count}]` : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        ))}
      </div>
    </>
  );
}
