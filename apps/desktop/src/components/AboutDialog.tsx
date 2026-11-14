import { useEffect, useState } from "react";

import { desktop } from "../engine/client";
import { useStore } from "../store";
import { AppIcon } from "./Logo";

/** Help → About: version, what runs where, and the licence. */
export function AboutDialog() {
  const open = useStore((s) => s.aboutOpen);
  const [electron, setElectron] = useState<string | null>(null);

  useEffect(() => {
    if (open && desktop) desktop.info().then((i) => setElectron(i.electron)).catch(() => setElectron(null));
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const key = (e: KeyboardEvent) => e.key === "Escape" && useStore.getState().set("aboutOpen", false);
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [open]);

  if (!open) return null;
  const close = () => useStore.getState().set("aboutOpen", false);
  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal about" role="dialog" aria-label="About Paranoia" onMouseDown={(e) => e.stopPropagation()}>
        <AppIcon size={72} />
        <h2 className="about-name">Paranoia</h2>
        <div className="about-version mono">Version {__APP_VERSION__}</div>
        <p className="about-text">An open, local-first reverse-engineering platform.</p>
        <dl className="about-kv">
          <dt>Engine</dt>
          <dd>{desktop ? "native (Rust)" : "WebAssembly in this browser"}</dd>
          {electron && (
            <>
              <dt>Electron</dt>
              <dd className="mono">{electron}</dd>
            </>
          )}
          <dt>Network</dt>
          <dd>none by default, no telemetry. Only when you ask: Help → Check for updates (GitHub) and the AI assistant (the server you set)</dd>
          <dt>Licence</dt>
          <dd>Apache-2.0</dd>
          <dt>Source</dt>
          <dd className="mono">github.com/Altumptic/paranoia</dd>
        </dl>
        <div className="modal-actions">
          <span className="muted small">Esc to close</span>
          <button className="btn sm primary" onClick={close}>
            OK
          </button>
        </div>
      </div>
    </div>
  );
}
