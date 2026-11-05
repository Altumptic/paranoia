import { useEffect, useState } from "react";

import { desktop, type AiSettings } from "../engine/client";
import { useStore } from "../store";

/** Model servers. Local ones keep everything on this computer; hosted ones need an API key and send
 *  the function's decompiled text to that company. Model names other than Claude's are left for the
 *  user to fill in from the provider's model list, since they change often. */
const PRESETS: { label: string; endpoint: string; model: string; local?: boolean }[] = [
  { label: "Ollama", endpoint: "http://127.0.0.1:11434/v1", model: "llama3.1", local: true },
  { label: "LM Studio", endpoint: "http://127.0.0.1:1234/v1", model: "", local: true },
  { label: "Claude", endpoint: "https://api.anthropic.com/v1", model: "claude-opus-5-5" },
  { label: "OpenAI / Codex", endpoint: "https://api.openai.com/v1", model: "" },
  { label: "DeepSeek", endpoint: "https://api.deepseek.com/v1", model: "deepseek-chat" },
  { label: "Kimi", endpoint: "https://api.moonshot.ai/v1", model: "" },
  { label: "Gemini", endpoint: "https://generativelanguage.googleapis.com/v1beta/openai", model: "" },
  { label: "Mistral", endpoint: "https://api.mistral.ai/v1", model: "" },
  { label: "OpenRouter", endpoint: "https://openrouter.ai/api/v1", model: "" },
];

function useEsc(open: boolean, close: () => void) {
  useEffect(() => {
    if (!open) return;
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  });
}

/** Assistant → Settings: which model server to use. Off until an endpoint is set. */
export function AiSettingsDialog() {
  const open = useStore((s) => s.aiSettingsOpen);
  const [cur, setCur] = useState<AiSettings | null>(null);
  const [endpoint, setEndpoint] = useState("");
  const [model, setModel] = useState("");
  const [key, setKey] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const close = () => useStore.getState().set("aiSettingsOpen", false);
  useEsc(open, close);

  useEffect(() => {
    if (!open || !desktop) return;
    setErr(null);
    setKey("");
    desktop.ai
      .get()
      .then((s) => {
        setCur(s);
        setEndpoint(s.endpoint);
        setModel(s.model);
      })
      .catch((e) => setErr(String(e)));
  }, [open]);

  if (!open || !desktop) return null;
  const remote = endpoint.trim() !== "" && !/^https?:\/\/(localhost|127(\.\d+){3}|\[::1\])(:|\/|$)/i.test(endpoint.trim());
  const save = async (clearKey = false) => {
    setBusy(true);
    setErr(null);
    try {
      const s = await desktop!.ai.set({ endpoint, model, key: clearKey ? "" : key ? key : undefined });
      setCur(s);
      useStore.getState().toast(s.endpoint ? `Assistant uses ${s.host}${s.local ? " (this computer)" : ""}` : "Assistant turned off", "success");
      close();
    } catch (e) {
      setErr(e instanceof Error ? e.message.replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal ai-modal" role="dialog" aria-label="Assistant settings" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">Assistant settings</div>
        <p className="muted small">
          Optional. Point Paranoia at a model server that speaks the OpenAI chat API — a local one keeps everything on this computer. Leave the endpoint empty to
          turn the assistant off; nothing is sent anywhere until you choose an Assistant command.
        </p>
        <div className="ai-presets-head muted small">On this computer</div>
        <div className="ai-presets">
          {PRESETS.filter((p) => p.local).map((p) => (
            <button key={p.label} className={`btn sm${endpoint === p.endpoint ? " primary" : ""}`} onClick={() => (setEndpoint(p.endpoint), setModel(p.model))}>
              {p.label}
            </button>
          ))}
        </div>
        <div className="ai-presets-head muted small">Cloud — needs an API key, sends the function you ask about</div>
        <div className="ai-presets">
          {PRESETS.filter((p) => !p.local).map((p) => (
            <button key={p.label} className={`btn sm${endpoint === p.endpoint ? " primary" : ""}`} onClick={() => (setEndpoint(p.endpoint), setModel(p.model))}>
              {p.label}
            </button>
          ))}
        </div>
        <label className="ai-field">
          <span>Endpoint</span>
          <input className="input mono" value={endpoint} placeholder="http://127.0.0.1:11434/v1" spellCheck={false} onChange={(e) => setEndpoint(e.target.value)} />
        </label>
        <label className="ai-field">
          <span>Model</span>
          <input className="input mono" value={model} placeholder="model id from the provider, e.g. llama3.1" spellCheck={false} onChange={(e) => setModel(e.target.value)} />
        </label>
        <label className="ai-field">
          <span>API key {cur?.hasKey && <em className="muted">(saved)</em>}</span>
          <input
            className="input mono"
            type="password"
            value={key}
            placeholder={cur?.hasKey ? "leave empty to keep" : "optional — local servers need none"}
            autoComplete="off"
            onChange={(e) => setKey(e.target.value)}
          />
        </label>
        {cur && !cur.encryption && <div className="muted small">This system cannot encrypt secrets, so the key is kept in memory for this session only.</div>}
        {remote && (
          <div className="ai-warn">
            This is not a local address. Function code you ask about would be sent to that service; Paranoia will ask you to confirm the host.
          </div>
        )}
        {err && <div className="search-error">{err}</div>}
        <div className="modal-actions">
          {cur?.hasKey ? (
            <button className="btn sm" disabled={busy} onClick={() => save(true)}>
              Remove key
            </button>
          ) : (
            <span className="muted small">Esc to close</span>
          )}
          <button className="btn sm primary" disabled={busy} onClick={() => save()}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

/** The assistant's answer for the function under the cursor. */
export function AssistantDialog() {
  const a = useStore((s) => s.assistant);
  const close = () => {
    desktop?.ai.cancel().catch(() => {});
    useStore.getState().set("assistant", null);
  };
  useEsc(a != null, close);
  if (!a) return null;
  const st = useStore.getState;
  return (
    <div className="modal-veil" onMouseDown={close}>
      <div className="modal ai-modal" role="dialog" aria-label={a.title} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-title">
          {a.title} <span className="mono muted">{a.fn}</span>
        </div>
        {a.state === "busy" && <div className="muted">Asking the model…</div>}
        {a.state === "error" && <div className="search-error">{a.text}</div>}
        {a.state === "done" && (
          <>
            {a.name ? (
              <div className="ai-name">
                <span className="mono">{a.name.name}</span>
                <span className="muted small">{a.name.reason}</span>
              </div>
            ) : (
              <div className="ai-answer">{a.text}</div>
            )}
            <div className="muted small ai-foot">
              Generated by {a.local ? "a model on this computer" : a.host} — it can be wrong; check it against the code.
            </div>
          </>
        )}
        <div className="modal-actions">
          <span className="muted small">Esc to close</span>
          {a.state === "done" && a.name && a.va != null && (
            <button
              className="btn sm primary"
              onClick={async () => {
                await st().rename(a.va!, a.name!.name);
                st().set("assistant", null);
              }}
            >
              Apply name
            </button>
          )}
          <button className="btn sm" onClick={close}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
