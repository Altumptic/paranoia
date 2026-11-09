// AI assistant: optional, off until the user points it at a model server.
//
// It speaks the OpenAI-compatible `/chat/completions` protocol, which Ollama
// (http://127.0.0.1:11434/v1), LM Studio (http://127.0.0.1:1234/v1) and most hosted services
// accept. Requests are made from the main process (the page has no network access), and only
// the text of the function the user asked about is sent. Pure functions here; the network call
// takes an injectable `fetch` so it is testable without a server.

const MAX_CODE_CHARS = 12000;
const MAX_REPLY_BYTES = 256 * 1024;
// Hosted models that think before answering can take minutes on a large function.
const TIMEOUT_MS = 300000;

const TASKS = {
  explain: {
    title: "Explain function",
    system:
      "You are a reverse engineer's assistant. Explain what the given decompiled function does in plain language: purpose, inputs, outputs, notable API calls and control flow. " +
      "Be concrete and concise (under 250 words). The code is automatically generated, so variable names are meaningless; say when you are unsure.",
  },
  name: {
    title: "Suggest a name",
    system:
      "You name functions in reverse-engineered binaries. Reply with ONLY a JSON object {\"name\": string, \"reason\": string}. " +
      "`name` is a lowercase snake_case C identifier of at most 40 characters describing what the function does (no `sub_` prefix). `reason` is one sentence.",
  },
  suspicious: {
    title: "Flag suspicious behaviour",
    system:
      "You are a malware analyst's assistant. Review the decompiled function and list behaviours that look suspicious or security-relevant " +
      "(process injection, persistence, anti-debugging, crypto, network, credential access, self-modifying code, unsafe memory handling). " +
      "For each, quote the line or call that shows it. If nothing stands out, say so plainly. Do not speculate beyond the code.",
  },
};

/**
 * Hosts that never leave this machine. Names under `.localhost` are not included: the OS may
 * resolve them through DNS, so they could point anywhere.
 */
function isLoopbackHost(host) {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}

/**
 * Normalises a base URL ("http://127.0.0.1:11434/v1") and says whether it stays on this machine.
 * @returns {{ url: string, host: string, local: boolean }}
 */
function parseEndpoint(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    throw new Error("The endpoint is not a valid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("The endpoint must start with http:// or https://");
  if (u.username || u.password) throw new Error("Do not put credentials in the URL; use the API key field");
  const local = isLoopbackHost(u.hostname);
  if (!local && u.protocol !== "https:") throw new Error("A remote endpoint must use https://");
  u.hash = "";
  u.search = "";
  return { url: u.toString().replace(/\/+$/, ""), host: u.host, local };
}

/** Messages for `task`; the code is truncated so a huge function cannot blow up the request. */
function buildMessages(task, info) {
  // Own keys only: `constructor` / `__proto__` are not tasks.
  const t = typeof task === "string" && Object.hasOwn(TASKS, task) ? TASKS[task] : null;
  if (!t) throw new Error(`unknown assistant task ${JSON.stringify(task)}`);
  const code = String(info.code ?? "");
  const clipped = code.length > MAX_CODE_CHARS ? `${code.slice(0, MAX_CODE_CHARS)}\n/* … ${code.length - MAX_CODE_CHARS} more characters omitted … */` : code;
  const head = `Function: ${String(info.name ?? "?").slice(0, 200)} at ${String(info.address ?? "?").slice(0, 32)} (${String(info.arch ?? "unknown").slice(0, 40)}, ${String(info.format ?? "unknown").slice(0, 20)})`;
  return [
    { role: "system", content: t.system },
    { role: "user", content: `${head}\n\n\`\`\`c\n${clipped}\n\`\`\`` },
  ];
}

/** The wire protocol an endpoint speaks: Anthropic's Messages API for api.anthropic.com, the
 *  OpenAI chat-completions API for everything else (OpenAI, DeepSeek, Kimi, Gemini, OpenRouter,
 *  Mistral, Ollama, LM Studio, …). */
function protocolFor(ep) {
  return ep.host === "api.anthropic.com" ? "anthropic" : "openai";
}

/** Anthropic API version sent with every request. */
const ANTHROPIC_VERSION = "2026-10-21";

/** The HTTP request for one chat turn; `messages` is `[system, user]` from buildMessages. */
function buildRequest(ep, key, model, messages) {
  const system = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
  const turns = messages.filter((m) => m.role !== "system");
  if (protocolFor(ep) === "anthropic") {
    return {
      url: `${ep.url}/messages`,
      headers: { "Content-Type": "application/json", "anthropic-version": ANTHROPIC_VERSION, ...(key ? { "x-api-key": key } : {}) },
      body: { model, max_tokens: 16000, ...(system ? { system } : {}), messages: turns },
    };
  }
  // No sampling parameters: several hosted reasoning models reject a non-default temperature.
  return {
    url: `${ep.url}/chat/completions`,
    headers: { "Content-Type": "application/json", ...(key ? { Authorization: `Bearer ${key}` } : {}) },
    body: { model, messages, stream: false },
  };
}

/** The answer text of a successful reply. */
function readAnswer(protocol, j) {
  if (protocol === "anthropic") {
    if (j?.stop_reason === "refusal") {
      const why = j?.stop_details?.explanation || j?.stop_details?.category || "";
      throw new Error(`The model declined this request${why ? ` (${String(why).slice(0, 200)})` : ""}`);
    }
    const blocks = Array.isArray(j?.content) ? j.content : [];
    // Thinking blocks and others are skipped; only the text answer is shown.
    return blocks.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text).join("\n");
  }
  return j?.choices?.[0]?.message?.content;
}

/** Calls the model. `fetchImpl` defaults to the global fetch. */
async function chat({ endpoint, key, model, messages, fetchImpl, signal }) {
  const f = fetchImpl ?? globalThis.fetch;
  const ep = parseEndpoint(endpoint);
  if (typeof model !== "string" || !model.trim()) throw new Error("No model name is set");
  const protocol = protocolFor(ep);
  if (protocol === "anthropic" && !key) throw new Error("Claude needs an API key — add it in Assistant → Settings");
  const req = buildRequest(ep, key, model.trim(), messages);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  signal?.addEventListener("abort", () => ctl.abort(), { once: true });
  let res;
  let text;
  try {
    res = await f(req.url, { method: "POST", headers: req.headers, body: JSON.stringify(req.body), signal: ctl.signal, redirect: "error" });
    text = await res.text();
  } catch (e) {
    if (ctl.signal.aborted) throw new Error("The model did not answer in time (or the request was cancelled)");
    throw new Error(`Cannot reach ${ep.host}: ${e instanceof Error ? e.message : e}`);
  } finally {
    clearTimeout(timer);
  }
  if (text.length > MAX_REPLY_BYTES) throw new Error("The reply is unexpectedly large");
  if (!res.ok) {
    let detail = "";
    try {
      const j = JSON.parse(text);
      detail = j?.error?.message ?? j?.error ?? "";
    } catch {
      /* not JSON */
    }
    throw new Error(`${ep.host} answered ${res.status}${detail ? `: ${String(detail).slice(0, 300)}` : ""}`);
  }
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error(
      protocol === "anthropic" ? "The server did not return JSON" : "The server did not return JSON — is this an OpenAI-compatible /v1 endpoint?",
    );
  }
  const content = readAnswer(protocol, j);
  if (typeof content !== "string" || !content.trim()) throw new Error("The model returned an empty answer");
  return content.trim();
}

const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** Reads the `{name, reason}` answer, tolerating code fences and chatter around the JSON. */
function parseName(text) {
  const m = /\{[\s\S]*\}/.exec(text);
  if (!m) throw new Error("The model did not return a name");
  let j;
  try {
    j = JSON.parse(m[0]);
  } catch {
    throw new Error("The model's answer was not valid JSON");
  }
  const name = typeof j.name === "string" ? j.name.trim() : "";
  if (!NAME.test(name)) throw new Error(`“${String(j.name).slice(0, 40)}” is not a usable function name`);
  return { name, reason: typeof j.reason === "string" ? j.reason.slice(0, 300) : "" };
}

/** Stored settings, with what is safe to show the page. */
function publicSettings(s) {
  let ep = null;
  try {
    ep = s.endpoint ? parseEndpoint(s.endpoint) : null;
  } catch {
    ep = null;
  }
  return { endpoint: ep?.url ?? "", model: s.model ?? "", hasKey: Boolean(s.keyEnc), local: ep?.local ?? true, host: ep?.host ?? "" };
}

module.exports = { TASKS, protocolFor, buildRequest, parseEndpoint, isLoopbackHost, buildMessages, chat, parseName, publicSettings, MAX_CODE_CHARS };
