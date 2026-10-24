import { useEffect, useRef, useState } from "react";

import { setOperand } from "../operands";
import { fmtAddr, useStore } from "../store";

/** Rename / comment prompt (N and ; in the listing). */
export function EditDialog() {
  const dialog = useStore((s) => s.dialog);
  const info = useStore((s) => s.info);
  const [value, setValue] = useState("");
  const [choices, setChoices] = useState<[string, string][]>([]);
  const [pick, setPick] = useState(0);
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
    } else if (dialog.kind === "enum") {
      const c = filtered[Math.min(pick, filtered.length - 1)];
      if (!c || !dialog.ins) {
        st.toast(choices.length ? "No enum matches the filter" : "No enum has a member with this value — declare one in Local Types", "error");
        return;
      }
      await setOperand(dialog.ins, "enum", c[0]);
    } else if (dialog.kind === "bookmark") {
      await st.bookmark(dialog.va, value.trim() ? value.trim() : null);
      st.toast(value.trim() ? "Bookmark saved" : "Bookmark removed", "success");
    } else {
      await st.comment(dialog.va, value);
    }
  };

  const isRename = dialog.kind !== "comment";
  const structNames = Object.keys(useStore.getState().annotations.types?.structs ?? {});
  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">
          {{ rename: "Rename", bookmark: "Bookmark", comment: "Comment", struct: "Apply struct", enum: "Symbolic constant" }[dialog.kind]} <span className="mono muted">{fmtAddr(dialog.va, info)}</span>
        </div>
        {isRename ? (
          <input
            ref={ref}
            className="input mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            list={dialog.kind === "struct" ? "struct-names" : undefined}
            placeholder={
              dialog.kind === "enum"
                ? `Filter enums for ${dialog.value != null && dialog.value < 0 ? "-0x" + (-dialog.value).toString(16) : "0x" + (dialog.value ?? 0).toString(16)}`
                : dialog.kind === "struct"
                ? structNames.length
                  ? `Struct name, e.g. ${structNames[0]} or ${structNames[0]}[4]`
                  : "Declare structs in Local Types first"
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
