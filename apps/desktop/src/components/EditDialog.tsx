import { useEffect, useRef, useState } from "react";

import { debug } from "../debug";
import { setOperand } from "../operands";
import { fmtAddr, useStore } from "../store";

/** Rename / comment prompt (N and ; in the listing). */
export function EditDialog() {
  const dialog = useStore((s) => s.dialog);
  const info = useStore((s) => s.info);
  const [value, setValue] = useState("");
  const [choices, setChoices] = useState<[string, string][]>([]);
  const [pick, setPick] = useState(0);
  const [found, setFound] = useState<string[]>([]);
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null);

  useEffect(() => {
    if (dialog) {
      setValue(dialog.initial);
      setChoices([]);
      setPick(0);
      if (dialog.kind === "enum" && dialog.value != null) {
        const param = /^([A-Za-z_]\w*)/.exec(dialog.ins?.comment ?? "")?.[1];
        useStore.getState().session?.enumCandidates(dialog.value, param).then(setChoices).catch(() => {});
      }
      setTimeout(() => ref.current?.select(), 0);
    }
  }, [dialog]);

  // Struct names offered while typing: the user's Local Types plus the debug-info (DWARF / PDB) ones.
  const wantsStruct = dialog?.kind === "struct" || dialog?.kind === "vartype";
  useEffect(() => {
    if (!wantsStruct) return;
    const q = value.replace(/\[.*$/, "").replace(/\*/g, "").trim();
    const t = setTimeout(() => {
      useStore.getState().session?.findTypes(q, 30).then((h) => setFound(h.filter((x) => x.kind === "struct").map((x) => x.name))).catch(() => {});
    }, 120);
    return () => clearTimeout(t);
  }, [wantsStruct, value]);

  if (!dialog) return null;
  const close = () => useStore.getState().set("dialog", null);
  const filtered = choices.filter(([e, t]) => !value.trim() || (e + " " + t).toLowerCase().includes(value.trim().toLowerCase()));
  const pickEnum = async (name: string) => {
    close();
    if (dialog.ins) await setOperand(dialog.ins, "enum", name);
  };
  const submit = async () => {
    const st = useStore.getState();
    close();
    if (dialog.kind === "rename") {
      const v = value.trim();
      if (v && !/^[A-Za-z_.$@?][\w.$@?:<>~-]*$/.test(v)) {
        st.toast("Names may contain letters, digits and _ . $ @ ? : < > ~ -", "error");
        return;
      }
      await st.rename(dialog.va, v);
      st.toast(v ? `Renamed to ${v}` : "Name reset", "success");
    } else if (dialog.kind === "struct") {
      const m = /^\s*([A-Za-z_]\w*)\s*(?:\[\s*(\d+)\s*\])?\s*$/.exec(value);
      if (!m) {
        st.toast("Enter a struct name, optionally with a count: POINT or POINT[4]", "error");
        return;
      }
      try {
        await st.session!.applyStruct(dialog.va, m[1], m[2] ? Number(m[2]) : 1);
        await st.afterEdit(false);
        st.toast(`Applied ${m[1]}${m[2] ? `[${m[2]}]` : ""}`, "success");
      } catch (e) {
        st.toast(e instanceof Error ? e.message : String(e), "error");
      }
    } else if (dialog.kind === "vartype") {
      const v = value.trim();
      if (v && !/^(struct\s+)?[A-Za-z_]\w*\s*\*$/.test(v)) {
        st.toast("Enter a pointer type like MY_STRUCT * — declare the struct in Local Types first", "error");
        return;
      }
      try {
        await st.session!.setVarType(dialog.va, dialog.varName ?? "", v);
        await st.afterEdit(false);
        st.toast(v ? `${dialog.varName} is now ${v}` : `Type of ${dialog.varName} reset`, "success");
      } catch (e) {
        st.toast(e instanceof Error ? e.message : String(e), "error");
      }
    } else if (dialog.kind === "gdb") {
      // `host:port [load base in hex]`, e.g. 127.0.0.1:1234 — the main process asks for confirmation.
      const m = /^([A-Za-z0-9._-]+)?:(\d{1,5})(?:\s+(?:base=)?(?:0x)?([0-9a-f]+))?$/i.exec(value.trim());
      if (!m || +m[2] < 1 || +m[2] > 65535) {
        st.toast("Write host:port, for example 127.0.0.1:1234 (optionally followed by the image's load address in hex)", "error");
        return;
      }
      await debug.connect(m[1] || "127.0.0.1", parseInt(m[2], 10), m[3] ? parseInt(m[3], 16) : undefined);
    } else if (dialog.kind === "region") {
      // `NAME START SIZE [kind]`, addresses in hex; `-START` removes the region that starts there.
      const v = value.trim();
      try {
        const rm = /^-\s*(?:0x)?([0-9a-f]+)$/i.exec(v);
        if (rm) {
          await st.session!.removeRegion(parseInt(rm[1], 16));
          await st.afterEdit(false);
          st.toast("Region removed", "success");
          return;
        }
        const m = /^(.+?)\s+(?:0x)?([0-9a-f]+)\s+(?:0x)?([0-9a-f]+)(?:\s+(ram|flash|rom|peripheral|other))?$/i.exec(v);
        if (!m) throw new Error("Write NAME START SIZE [ram|flash|rom|peripheral|other], addresses in hex, e.g. SRAM 20000000 20000 ram");
        await st.session!.setRegion(m[1], parseInt(m[2], 16), parseInt(m[3], 16), (m[4] ?? "other").toLowerCase());
        await st.afterEdit(false);
        st.toast(`Region ${m[1]} set`, "success");
      } catch (e) {
        st.toast(e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : String(e), "error");
      }
    } else if (dialog.kind === "proto") {
      const v = value.trim();
      try {
        await st.session!.setPrototype(dialog.va, v);
        await st.afterEdit(false);
        st.toast(v ? "Prototype set" : "Prototype removed", "success");
      } catch (e) {
        st.toast(e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : String(e), "error");
      }
    } else if (dialog.kind === "varname") {
      const v = value.trim();
      try {
        await st.session!.setVarName(dialog.va, dialog.varName ?? "", v);
        await st.afterEdit(false);
        st.toast(v ? `${dialog.varName} is now ${v}` : `${dialog.varName} restored`, "success");
      } catch (e) {
        st.toast(e instanceof Error ? e.message : String(e), "error");
      }
    } else if (dialog.kind === "enum") {
      const c = filtered[Math.min(pick, filtered.length - 1)];
      if (!c || !dialog.ins) {
        st.toast(choices.length ? "No enum matches the filter" : "No enum has a member with this value — declare one in Local Types", "error");
        return;
      }
      await setOperand(dialog.ins, "enum", c[0]);
    } else if (dialog.kind === "assemble") {
      try {
        const bytes = await st.session!.assemble(dialog.va, value, true);
        await st.afterEdit(false);
        st.toast(`Assembled ${bytes.length / 2} byte${bytes.length === 2 ? "" : "s"}: ${bytes.replace(/(..)/g, "$1 ").trim()}`, "success");
      } catch (e) {
        st.toast(e instanceof Error ? e.message : String(e), "error");
      }
    } else if (dialog.kind === "bookmark") {
      await st.bookmark(dialog.va, value.trim() ? value.trim() : null);
      st.toast(value.trim() ? "Bookmark saved" : "Bookmark removed", "success");
    } else {
      await st.comment(dialog.va, value);
    }
  };

  const isRename = dialog.kind !== "comment";
  const structNames = [...new Set([...Object.keys(useStore.getState().annotations.types?.structs ?? {}), ...found])];
  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">
          {{
            rename: "Rename",
            bookmark: "Bookmark",
            comment: "Comment",
            struct: "Apply struct",
            assemble: "Assemble",
            enum: "Symbolic constant",
            vartype: "Type variable",
            varname: "Rename variable",
            proto: "Function prototype",
            region: "Memory region",
            gdb: "Connect to a GDB server",
          }[dialog.kind]}{" "}
          {dialog.kind === "vartype" || dialog.kind === "varname" ? <span className="mono muted">{dialog.varName}</span> : <span className="mono muted">{fmtAddr(dialog.va, info)}</span>}
        </div>
        {isRename ? (
          <input
            ref={ref}
            className="input mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            list={dialog.kind === "struct" ? "struct-names" : dialog.kind === "vartype" ? "vartype-names" : undefined}
            placeholder={
              dialog.kind === "enum"
                ? `Filter enums for ${dialog.value != null && dialog.value < 0 ? "-0x" + (-dialog.value).toString(16) : "0x" + (dialog.value ?? 0).toString(16)}`
                : dialog.kind === "struct"
                ? structNames.length
                  ? `Struct name, e.g. ${structNames[0]} or ${structNames[0]}[4]`
                  : "Declare structs in Local Types first"
                : dialog.kind === "vartype"
                ? structNames.length
                  ? `Pointer type, e.g. ${structNames[0]} * — empty to reset`
                  : "Declare the struct in Local Types first"
                : dialog.kind === "varname"
                ? "A C identifier — leave empty to restore the generated name"
                : dialog.kind === "proto"
                ? "e.g. int __stdcall f(HANDLE h, const char *buf, DWORD n) — empty removes it"
                : dialog.kind === "gdb"
                ? "host:port of a gdbserver or QEMU gdbstub, e.g. 127.0.0.1:1234 — add the load address in hex if the program is relocated"
                : dialog.kind === "region"
                ? "NAME START SIZE [ram|flash|rom|peripheral|other] in hex, e.g. SRAM 20000000 20000 ram — or -START to remove"
                : dialog.kind === "assemble"
                ? "e.g. mov eax, 1  ·  jz 0x401020  ·  nop  ·  db 0x90, 0xcc"
                : dialog.kind === "bookmark"
                  ? "Describe this location — leave empty to remove"
                  : "Leave empty to restore the automatic name"
            }
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
              if (e.key === "Escape") close();
              if (dialog.kind === "enum" && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
                e.preventDefault();
                setPick((p) => Math.max(0, Math.min(filtered.length - 1, p + (e.key === "ArrowDown" ? 1 : -1))));
              }
            }}
          />
        ) : null}
        {dialog.kind === "enum" && (
          <div className="enum-list mono">
            {filtered.map(([e, t], i) => (
              <button key={e} className={`enum-row ${i === Math.min(pick, filtered.length - 1) ? "sel" : ""}`} onMouseEnter={() => setPick(i)} onClick={() => pickEnum(e)}>
                <span className="enum-text">{t}</span>
                <span className="muted small">{e}</span>
              </button>
            ))}
            {filtered.length === 0 && <div className="muted small">{choices.length ? "Nothing matches the filter." : "No known enum has a member with this value."}</div>}
          </div>
        )}
        {dialog.kind === "struct" && (
          <datalist id="struct-names">
            {structNames.map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
        )}
        {dialog.kind === "vartype" && (
          <datalist id="vartype-names">
            {structNames.map((n) => (
              <option key={n} value={`${n} *`} />
            ))}
          </datalist>
        )}
        {dialog.kind === "comment" && (
          <textarea
            ref={ref}
            className="input mono textarea"
            value={value}
            rows={4}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Comment shown next to the instruction"
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) submit();
              if (e.key === "Escape") close();
            }}
          />
        )}
        <div className="modal-actions">
          <span className="muted small">{isRename ? "Enter to save" : "Ctrl+Enter to save"} · Esc to cancel</span>
          <button className="btn sm" onClick={close}>
            Cancel
          </button>
          <button className="btn sm primary" onClick={submit}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
