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
    } else {
      await st.comment(dialog.va, value);
    }
  };

  const isRename = dialog.kind === "rename";
  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">
          {isRename ? "Rename" : "Comment"} <span className="mono muted">{fmtAddr(dialog.va, info)}</span>
        </div>
        {isRename ? (
          <input
            ref={ref}
            className="input mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Leave empty to restore the automatic name"
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
              if (e.key === "Escape") close();
            }}
          />
        ) : (
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
