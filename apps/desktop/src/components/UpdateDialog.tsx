import { useEffect, useState } from "react";

import { desktop, type UpdateResult } from "../engine/client";
import { useStore } from "../store";

/**
 * Help → Check for updates. Nothing leaves the machine until "Check now" is pressed; then the app
 * asks GitHub's public release list once and shows the answer. It never downloads or installs:
 * the release page opens in the browser, and the download is verified like any other (VERIFY.md).
 */
export function UpdateDialog() {
  const open = useStore((s) => s.updateOpen);
  const [state, setState] = useState<{ kind: "idle" } | { kind: "busy" } | { kind: "done"; r: UpdateResult } | { kind: "error"; message: string }>({ kind: "idle" });

  useEffect(() => {
    if (!open) return;
    setState({ kind: "idle" });
    const key = (e: KeyboardEvent) => e.key === "Escape" && useStore.getState().set("updateOpen", false);
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [open]);

  if (!open || !desktop) return null;
  const close = () => useStore.getState().set("updateOpen", false);
  const check = () => {
    setState({ kind: "busy" });
    desktop!
      .checkForUpdates()
      .then((r) => setState({ kind: "done", r }))
      .catch((e: unknown) => setState({ kind: "error", message: String((e as Error)?.message ?? e).replace(/^Error invoking remote method '[^']+': (Error: )?/, "") }));
  };

  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal update" role="dialog" aria-label="Check for updates" onMouseDown={(e) => e.stopPropagation()}>
        <h2 className="modal-title">Check for updates</h2>
        <p className="muted small">
          You have version <span className="mono">{__APP_VERSION__}</span>. Pressing the button sends one request to <span className="mono">api.github.com</span> (GitHub's public list of releases). Nothing about you or your files is sent, and nothing is downloaded or
          installed.
        </p>
        <div className="update-result" aria-live="polite">
          {state.kind === "busy" && <span className="muted">Asking GitHub…</span>}
          {state.kind === "error" && <span className="update-bad">{state.message}</span>}
          {state.kind === "done" && state.r.status === "newer" && (
            <>
              <strong>
                Version <span className="mono">{state.r.version}</span> is available
              </strong>
              {state.r.published && <span className="muted small"> (published {state.r.published})</span>}
              <div>
                <a href={state.r.url} target="_blank" rel="noreferrer">
                  Open the release page
                </a>
                <span className="muted small"> — check the download against the signed checksums before you run it (docs/VERIFY.md).</span>
              </div>
            </>
          )}
          {state.kind === "done" && state.r.status === "current" && (
            <strong>
              You have the latest release (<span className="mono">{state.r.version}</span>).
            </strong>
          )}
          {state.kind === "done" && state.r.status === "ahead" && (
            <span>
              This build (<span className="mono">{state.r.current}</span>) is newer than the latest release (<span className="mono">{state.r.version}</span>): a release candidate or a development build.
            </span>
          )}
        </div>
        <div className="modal-actions">
          <span className="muted small">Esc to close</span>
          <button className="btn sm" onClick={close}>
            Close
          </button>
          <button className="btn sm primary" onClick={check} disabled={state.kind === "busy"}>
            {state.kind === "done" || state.kind === "error" ? "Check again" : "Check now"}
          </button>
        </div>
      </div>
    </div>
  );
}
