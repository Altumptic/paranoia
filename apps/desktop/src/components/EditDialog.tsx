import { useEffect, useRef, useState } from "react";

import { fmtAddr, useStore } from "../store";

/** Rename / comment prompt (N and ; in the listing). */
export function EditDialog() {
  const dialog = useStore((s) => s.dialog);
  const info = useStore((s) => s.info);
  const [value, setValue] = useState("");
  const ref = useRef<HTMLInputElement & HTMLTextAreaElement>(null);

  useEffect(() => {
    if (dialog) {
      setValue(dialog.initial);
      setTimeout(() => ref.current?.select(), 0);
    }
  }, [dialog]);

  if (!dialog) return null;
  const close = () => useStore.getState().set("dialog", null);
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
          {{ rename: "Rename", bookmark: "Bookmark", comment: "Comment", struct: "Apply struct" }[dialog.kind]} <span className="mono muted">{fmtAddr(dialog.va, info)}</span>
        </div>
        {isRename ? (
          <input
            ref={ref}
            className="input mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            list={dialog.kind === "struct" ? "struct-names" : undefined}
            placeholder={
              dialog.kind === "struct"
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
            }}
          />
        ) : null}
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
