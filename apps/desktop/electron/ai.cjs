// AI assistant: optional, off until the user points it at a model server.
//
// It speaks the OpenAI-compatible `/chat/completions` protocol, which Ollama
// (http://127.0.0.1:11434/v1), LM Studio (http://127.0.0.1:1234/v1) and most hosted services
// accept. Requests are made from the main process (the page has no network access), and only
// the text of the function the user asked about is sent. Redaction and the disclosure ledger
// mirror `paranoia mcp` (crates/paranoia-cli/src/disclosure.rs). Pure functions here; the
// network call takes an injectable `fetch` so it is testable without a server.

const crypto = require("node:crypto");

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

const MAX_MODELS_BYTES = 2 * 1024 * 1024;
const MODELS_TIMEOUT_MS = 20000;

/**
 * The model ids a server offers (`GET {endpoint}/models`). Ollama, LM Studio, llama.cpp, vLLM,
 * OpenAI-compatible clouds and Anthropic all answer with `{ data: [{ id }] }`. Only the API key
 * is sent; no code.
 */
async function listModels({ endpoint, key, fetchImpl, signal }) {
  const f = fetchImpl ?? globalThis.fetch;
  const ep = parseEndpoint(endpoint);
  const headers =
    protocolFor(ep) === "anthropic"
      ? { "anthropic-version": ANTHROPIC_VERSION, ...(key ? { "x-api-key": key } : {}) }
      : key
        ? { Authorization: `Bearer ${key}` }
        : {};
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), MODELS_TIMEOUT_MS);
  signal?.addEventListener("abort", () => ctl.abort(), { once: true });
  let res;
  let text;
  try {
    res = await f(`${ep.url}/models`, { method: "GET", headers, signal: ctl.signal, redirect: "error" });
    text = await res.text();
  } catch (e) {
    if (ctl.signal.aborted) throw new Error(`${ep.host} did not answer in time`);
    throw new Error(`Cannot reach ${ep.host}: ${e instanceof Error ? e.message : e}`);
  } finally {
    clearTimeout(timer);
  }
  if (text.length > MAX_MODELS_BYTES) throw new Error("The model list is unexpectedly large");
  if (!res.ok) throw new Error(`${ep.host} answered ${res.status} to the model list request`);
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error(`${ep.host} did not return a model list (is this an OpenAI-compatible /v1 endpoint?)`);
  }
  const rows = Array.isArray(j?.data) ? j.data : Array.isArray(j?.models) ? j.models : [];
  const ids = rows.map((m) => (typeof m === "string" ? m : m?.id ?? m?.name)).filter((id) => typeof id === "string" && id.trim() && id.length <= 200);
  return [...new Set(ids.map((id) => id.trim()))].sort((a, b) => a.localeCompare(b)).slice(0, 500);
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

// ---- Redaction and the disclosure ledger ------------------------------------------------------
// The same placeholders as `paranoia mcp --redact-strings/--redact-ips`: quoted literals become
// `"<str#N len=L>"`, names derived from them `aRedactedN`, and IP-like constants `<ip#N>`.
// Numbering follows the file's string order, so a string keeps its number for the whole request.

/** Shorter strings are too common ("%s", "true") to identify anything (disclosure.rs). */
const MIN_NAMED = 4;

/** A string as the engine prints it inside a literal: `Hello\n` → `Hello\\n` (Rust's escape_debug). */
function escapeDebug(s) {
  let out = "";
  for (const ch of String(s)) {
    const code = ch.codePointAt(0);
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code === 0x7f) out += `\\u{${code.toString(16)}}`;
    else out += ch;
  }
  return out;
}

/** `Hello, world!` → `aHelloWorld`, the engine's name for a string (paranoia_core::string_name). */
function stringName(s) {
  let out = "a";
  let upper = true;
  for (const ch of String(s)) {
    if (out.length >= 26) break;
    if (/^[A-Za-z0-9]$/.test(ch)) {
      out += upper ? ch.toUpperCase() : ch;
      upper = false;
    } else {
      upper = true;
    }
  }
  return out.length === 1 ? `${out}Str` : out;
}

const isDigit = (c) => typeof c === "string" && c >= "0" && c <= "9";
const isHex = (c) => isDigit(c) || (typeof c === "string" && /^[A-Fa-f]$/.test(c));
const isAlphaNum = (c) => typeof c === "string" && /^[A-Za-z0-9]$/.test(c);

/**
 * Builds a redactor for one assistant request. `strings` is the analysed file's string list
 * (`StringEntry.value`), used to number literals in the file's order and to know the engine's
 * auto names for them. `apply(text)` returns `{ text, strings, ips }`: the redacted text and
 * how many replacements of each kind were made.
 */
function createRedactor({ strings = [], redactStrings = false, redactIps = false } = {}) {
  const literalIds = new Map();
  const nameIds = new Map();
  const ipIds = new Map();
  let next = 0;
  const idFor = (key) => {
    let id = literalIds.get(key);
    if (id === undefined) {
      id = ++next;
      literalIds.set(key, id);
    }
    return id;
  };
  if (redactStrings) {
    for (const value of Array.isArray(strings) ? strings : []) {
      if (typeof value !== "string") continue;
      const id = idFor(escapeDebug(value));
      if ([...value].length < MIN_NAMED) continue;
      const name = stringName(value);
      // A string like "1   " is named `a1`, the same as the first parameter in pseudocode.
      if (/^a\d+$/.test(name)) continue;
      if (!nameIds.has(name)) nameIds.set(name, id);
    }
  }
  return {
    apply(text) {
      let out = String(text);
      let stringCount = 0;
      let ipCount = 0;
      if (redactStrings) {
        const r = redactStringLiterals(out, literalIds, nameIds);
        out = r.text;
        stringCount = r.count;
      }
      if (redactIps) {
        const r = redactIpConstants(out, ipIds);
        out = r.text;
        ipCount = r.count;
      }
      return { text: out, strings: stringCount, ips: ipCount };
    },
  };
}

/** Replaces quoted literals and string-derived names in `text`. */
function redactStringLiterals(text, literalIds, nameIds) {
  const chars = [...text];
  let out = "";
  let count = 0;
  let i = 0;
  while (i < chars.length) {
    const c = chars[i];
    if (c === '"' || c === "'") {
      const end = closingQuote(chars, i);
      if (end !== null) {
        const inner = chars.slice(i + 1, end).join("");
        let id = literalIds.get(inner);
        if (id === undefined) {
          id = literalIds.size + 1;
          literalIds.set(inner, id);
        }
        out += `${c}<str#${id} len=${[...inner].length}>${c}`;
        count += 1;
        i = end + 1;
        continue;
      }
    }
    if (c === "_" || /^[A-Za-z]$/.test(c)) {
      const start = i;
      while (i < chars.length && (isAlphaNum(chars[i]) || chars[i] === "_")) i += 1;
      const word = chars.slice(start, i).join("");
      // Only whole identifiers: `aHelloWorld`, not the tail of `xaHelloWorld`.
      const whole = start === 0 || !(isAlphaNum(chars[start - 1]) || chars[start - 1] === "_");
      const id = nameIds.get(word);
      if (whole && id !== undefined) {
        out += `aRedacted${id}`;
        count += 1;
      } else {
        out += word;
      }
      continue;
    }
    out += c;
    i += 1;
  }
  return { text: out, count };
}

/** Index of the quote closing the literal opened at `open`, on the same line. */
function closingQuote(chars, open) {
  const q = chars[open];
  let i = open + 1;
  while (i < chars.length) {
    if (chars[i] === "\\") i += 2;
    else if (chars[i] === "\n") return null;
    else if (chars[i] === q) return i;
    else i += 1;
  }
  return null;
}

/**
 * Replaces IP-like constants: the same rule as `IpRedactor` in disclosure.rs — IPv4 dotted
 * quads with octets 0–255 (optionally /0–/32) and IPv6 literals (all eight groups or a `::`
 * form). Plain numbers, floats, times such as `12:34:56`, MAC addresses, identifiers and
 * version numbers that do not fit those shapes are left alone.
 */
function redactIpConstants(text, ipIds) {
  const chars = [...text];
  let out = "";
  let count = 0;
  let i = 0;
  while (i < chars.length) {
    const hit = ipAt(chars, i);
    if (hit) {
      const [end, address] = hit;
      let id = ipIds.get(address);
      if (id === undefined) {
        id = ipIds.size + 1;
        ipIds.set(address, id);
      }
      out += `<ip#${id}>`;
      count += 1;
      i = end;
    } else {
      out += chars[i];
      i += 1;
    }
  }
  return { text: out, count };
}

/** `[end, address]` if an IP-like constant starts at `chars[i]`, else `null`. */
function ipAt(chars, i) {
  const c = chars[i];
  if (!isDigit(c) && c !== ":" && !isHex(c)) return null;
  if (i > 0) {
    const p = chars[i - 1];
    if (isAlphaNum(p) || p === "_" || p === "." || p === ":") return null;
  }
  if (isDigit(c)) {
    const end = v4End(chars, i);
    if (end !== null) {
      const stop = chars[end] === "/" ? (prefixEnd(chars, end + 1) ?? end) : end;
      return [stop, chars.slice(i, end).join("")];
    }
  }
  const run = hexRunEnd(chars, i);
  let token = chars.slice(i, run).join("");
  if (token.endsWith(".")) token = token.slice(0, -1);
  return token.includes(":") && ipv6Like(token) ? [i + [...token].length, token] : null;
}

/** End (exclusive) of a dotted quad starting at `start`: four octets, each 0–255. */
function v4End(chars, start) {
  let i = start;
  for (let part = 0; part < 4; part += 1) {
    const begin = i;
    let octet = 0;
    while (i < chars.length && isDigit(chars[i])) {
      if (i - begin === 3) return null;
      octet = octet * 10 + Number(chars[i]);
      i += 1;
    }
    if (i === begin || octet > 255) return null;
    if (part < 3) {
      if (chars[i] !== ".") return null;
      i += 1;
    }
  }
  // A fifth component (`1.2.3.4.5`) is a version, not an address; `1.2.3.4x` is a name.
  if (chars[i] === "." && isDigit(chars[i + 1])) return null;
  if (isAlphaNum(chars[i]) || chars[i] === "_") return null;
  return i;
}

/** End (exclusive) of a `/0`–`/32` IPv4 prefix whose digits start at `start`. */
function prefixEnd(chars, start) {
  let i = start;
  let value = 0;
  while (i < chars.length && isDigit(chars[i])) {
    value = value * 10 + Number(chars[i]);
    i += 1;
  }
  const digits = i - start;
  return digits >= 1 && digits <= 2 && value <= 32 ? i : null;
}

/** End (exclusive) of the run of hex digits, colons and dots an IPv6 literal may consist of. */
function hexRunEnd(chars, start) {
  let i = start;
  while (i < chars.length && (isHex(chars[i]) || chars[i] === ":" || chars[i] === ".")) i += 1;
  return i;
}

/** True when `token` looks like all eight groups of an IPv6 address, or a `::`-compressed form. */
function ipv6Like(token) {
  const at = token.indexOf("::");
  if (at < 0) {
    const groups = token.split(":");
    return groups.length === 8 && groups.every((g, k) => v6Group(g, k === 7));
  }
  const left = splitV6Groups(token.slice(0, at));
  const right = splitV6Groups(token.slice(at + 2));
  if (!left || !right || token.slice(at + 2).includes("::")) return false;
  const groups = [...left, ...right];
  // The compressed part stands for at least one omitted group; at most seven can be written.
  return groups.length >= 1 && groups.length <= 7 && groups.every((g, k) => v6Group(g, k === groups.length - 1));
}

/** The non-empty colon-separated groups of one side of an IPv6 `::`, or `null`. */
function splitV6Groups(s) {
  if (s === "") return [];
  const groups = s.split(":");
  return groups.every((g) => g !== "") ? groups : null;
}

/** One group of an IPv6 address: 1–4 hex digits, or an embedded IPv4 address in the last group. */
function v6Group(group, last) {
  if (last && group.includes(".")) return v4Literal(group);
  return /^[0-9a-fA-F]{1,4}$/.test(group);
}

/** Exactly four octets, each 0–255 (no prefix, no surrounding text). */
function v4Literal(s) {
  const parts = s.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** What leaves the machine with this request, in one sentence for the consent dialogs. */
function redactionSummary(redactStrings, redactIps) {
  const parts = [];
  if (redactStrings) parts.push("the file's strings are replaced with <str#N len=L> placeholders (names derived from them with aRedactedN)");
  if (redactIps) parts.push("numbers that look like IPv4 or IPv6 addresses are replaced with <ip#N>");
  if (!parts.length) {
    return "Redaction is off: string literals and constants from the file are sent as they are. You can turn it on in Assistant → Settings.";
  }
  return `Redaction is on: ${parts.join("; ")} before sending.`;
}

/** SHA-256 of a text, lowercase hex. */
function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text), "utf8").digest("hex");
}

/** One line of the hash-chained disclosure ledger: the entry plus `time` and `prev` (the hash
 *  of the line before it, or null for the first line). */
function ledgerLine(prev, entry, time = Math.floor(Date.now() / 1000)) {
  return JSON.stringify({ ...entry, time, prev: prev ?? null });
}

/** Stored settings, with what is safe to show the page. */
function publicSettings(s) {
  let ep = null;
  try {
    ep = s.endpoint ? parseEndpoint(s.endpoint) : null;
  } catch {
    ep = null;
  }
  return {
    endpoint: ep?.url ?? "",
    model: s.model ?? "",
    hasKey: Boolean(s.keyEnc),
    local: ep?.local ?? true,
    host: ep?.host ?? "",
    redactStrings: s.redactStrings === true,
    redactIps: s.redactIps === true,
  };
}

/** A fixed prompt for "Test": proves the endpoint, key and model work without sending any code. */
const TEST_MESSAGES = [
  { role: "system", content: "You are a connection test. Answer with one short sentence." },
  { role: "user", content: "Reply with the word OK and the name of your model if you know it." },
];

module.exports = {
  TASKS,
  TEST_MESSAGES,
  protocolFor,
  buildRequest,
  parseEndpoint,
  isLoopbackHost,
  buildMessages,
  chat,
  listModels,
  parseName,
  createRedactor,
  redactionSummary,
  sha256Hex,
  ledgerLine,
  publicSettings,
  MAX_CODE_CHARS,
};
