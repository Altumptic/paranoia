const test = require("node:test");
const assert = require("node:assert/strict");

const A = require("./ai.cjs");

const reply = (status, body) => async () => ({ ok: status < 300, status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
const ok = (content) => reply(200, { choices: [{ message: { content } }] });

test("loopback endpoints are local, everything else is remote", () => {
  for (const u of ["http://127.0.0.1:11434/v1", "http://localhost:1234/v1", "http://[::1]:8080/v1", "http://127.1.2.3/v1"]) {
    assert.equal(A.parseEndpoint(u).local, true, u);
  }
  for (const u of ["https://api.example.com/v1", "https://10.0.0.5/v1", "https://localhost.evil.com/v1", "https://127.0.0.1.evil.com/v1", "https://ai.localhost/v1"]) {
    assert.equal(A.parseEndpoint(u).local, false, u);
  }
  // A `.localhost` name may resolve anywhere, so plain http to it is refused like any remote host.
  assert.throws(() => A.parseEndpoint("http://ai.localhost/v1"), /https/);
});

test("endpoints are validated", () => {
  assert.equal(A.parseEndpoint("http://127.0.0.1:11434/v1/").url, "http://127.0.0.1:11434/v1");
  assert.equal(A.parseEndpoint("https://api.example.com/v1?x=1#y").url, "https://api.example.com/v1");
  assert.throws(() => A.parseEndpoint("not a url"), /valid URL/);
  assert.throws(() => A.parseEndpoint("ftp://x/v1"), /http/);
  assert.throws(() => A.parseEndpoint("http://api.example.com/v1"), /https/);
  assert.throws(() => A.parseEndpoint("https://user:pw@api.example.com/v1"), /credentials/);
});

test("messages name the task, carry the code and clip huge functions", () => {
  const m = A.buildMessages("explain", { name: "sub_401000", address: "0x401000", arch: "x86", format: "pe", code: "int f() { return 1; }" });
  assert.equal(m[0].role, "system");
  assert.match(m[1].content, /sub_401000 at 0x401000/);
  assert.match(m[1].content, /return 1;/);
  const big = A.buildMessages("suspicious", { name: "f", code: "x".repeat(A.MAX_CODE_CHARS + 500) });
  assert.match(big[1].content, /500 more characters omitted/);
  assert.ok(big[1].content.length < A.MAX_CODE_CHARS + 400);
  assert.throws(() => A.buildMessages("nope", {}), /unknown assistant task/);
  for (const t of ["constructor", "__proto__", "toString", 1, null]) assert.throws(() => A.buildMessages(t, {}), /unknown assistant task/);
});

test("chat posts to /chat/completions with the key and returns the answer", async () => {
  let seen;
  const f = async (url, init) => {
    seen = { url, init };
    return ok("  Hello  ")();
  };
  const out = await A.chat({ endpoint: "http://127.0.0.1:11434/v1", key: "sk-test", model: " llama3 ", messages: [{ role: "user", content: "hi" }], fetchImpl: f });
  assert.equal(out, "Hello");
  assert.equal(seen.url, "http://127.0.0.1:11434/v1/chat/completions");
  assert.equal(seen.init.headers.Authorization, "Bearer sk-test");
  assert.equal(seen.init.redirect, "error");
  const body = JSON.parse(seen.init.body);
  assert.equal(body.model, "llama3");
  assert.equal(body.stream, false);
  // No key, no Authorization header.
  await A.chat({ endpoint: "http://127.0.0.1:11434/v1", model: "m", messages: [], fetchImpl: async (u, i) => ((seen = { u, i }), ok("x")()) });
  assert.equal("Authorization" in seen.i.headers, false);
});

test("api.anthropic.com speaks the Messages API", async () => {
  let seen;
  const reply = { content: [{ type: "thinking", thinking: "" }, { type: "text", text: "It parses a header." }], stop_reason: "end_turn" };
  const f = async (url, init) => ((seen = { url, init }), { ok: true, status: 200, text: async () => JSON.stringify(reply) });
  const messages = A.buildMessages("explain", { name: "f", code: "int f();" });
  const out = await A.chat({ endpoint: "https://api.anthropic.com/v1", key: "sk-ant-test", model: "claude-opus-5-5", messages, fetchImpl: f });
  assert.equal(out, "It parses a header.");
  assert.equal(seen.url, "https://api.anthropic.com/v1/messages");
  assert.equal(seen.init.headers["x-api-key"], "sk-ant-test");
  assert.equal(seen.init.headers["anthropic-version"], "2026-10-21");
  assert.equal("Authorization" in seen.init.headers, false);
  const body = JSON.parse(seen.init.body);
  assert.equal(body.model, "claude-opus-5-5");
  assert.equal(typeof body.system, "string");
  assert.deepEqual(body.messages.map((m) => m.role), ["user"]);
  assert.ok(body.max_tokens > 0);
  for (const k of ["temperature", "top_p", "top_k", "stream"]) assert.equal(k in body, false, k);
});

test("a Claude refusal and a missing key are reported", async () => {
  const f = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ content: [], stop_reason: "refusal", stop_details: { category: "cyber" } }) });
  await assert.rejects(A.chat({ endpoint: "https://api.anthropic.com/v1", key: "k", model: "m", messages: [], fetchImpl: f }), /declined.*cyber/);
  await assert.rejects(A.chat({ endpoint: "https://api.anthropic.com/v1", model: "m", messages: [], fetchImpl: f }), /API key/);
});

test("other hosted providers use the OpenAI protocol without sampling parameters", () => {
  for (const u of ["https://api.openai.com/v1", "https://api.deepseek.com/v1", "https://api.moonshot.ai/v1", "https://openrouter.ai/api/v1", "https://generativelanguage.googleapis.com/v1beta/openai"]) {
    const ep = A.parseEndpoint(u);
    assert.equal(A.protocolFor(ep), "openai", u);
    const r = A.buildRequest(ep, "k", "m", [{ role: "user", content: "x" }]);
    assert.equal(r.url, `${ep.url}/chat/completions`);
    assert.equal("temperature" in r.body, false);
  }
  assert.equal(A.protocolFor(A.parseEndpoint("https://api.anthropic.com.evil.com/v1")), "openai");
});

test("chat reports failures in words", async () => {
  const run = (fetchImpl, extra = {}) => A.chat({ endpoint: "http://127.0.0.1:11434/v1", model: "m", messages: [], fetchImpl, ...extra });
  await assert.rejects(run(reply(401, { error: { message: "bad key" } })), /answered 401: bad key/);
  await assert.rejects(run(reply(500, "oops")), /answered 500/);
  await assert.rejects(run(reply(200, "<html>")), /OpenAI-compatible/);
  await assert.rejects(run(ok("   ")), /empty answer/);
  await assert.rejects(run(reply(200, { choices: [] })), /empty answer/);
  await assert.rejects(run(async () => { throw new Error("ECONNREFUSED"); }), /Cannot reach 127.0.0.1:11434: ECONNREFUSED/);
  await assert.rejects(run(ok("x"), { model: "" }), /No model/);
  await assert.rejects(A.chat({ endpoint: "http://api.example.com/v1", model: "m", messages: [], fetchImpl: ok("x") }), /https/);
  await assert.rejects(run(reply(200, "x".repeat(300 * 1024))), /unexpectedly large/);
});

test("a cancelled request says so", async () => {
  const ctl = new AbortController();
  const f = (_u, init) => new Promise((_res, rej) => init.signal.addEventListener("abort", () => rej(new Error("aborted"))));
  const p = A.chat({ endpoint: "http://127.0.0.1:1/v1", model: "m", messages: [], fetchImpl: f, signal: ctl.signal });
  ctl.abort();
  await assert.rejects(p, /cancelled/);
});

test("name answers are parsed from JSON wrapped in chatter and validated", () => {
  assert.deepEqual(A.parseName('Sure!\n```json\n{"name": "parse_config", "reason": "reads keys"}\n```'), { name: "parse_config", reason: "reads keys" });
  assert.deepEqual(A.parseName('{"name":"init_table"}'), { name: "init_table", reason: "" });
  assert.throws(() => A.parseName("no idea"), /did not return a name/);
  assert.throws(() => A.parseName("{nope}"), /not valid JSON/);
  assert.throws(() => A.parseName('{"name": "has space"}'), /not a usable/);
  assert.throws(() => A.parseName('{"name": "1abc"}'), /not a usable/);
  assert.throws(() => A.parseName('{"name": "a;system(\\"x\\")"}'), /not a usable/);
});

test("public settings never include the key", () => {
  const p = A.publicSettings({ endpoint: "https://api.example.com/v1", model: "m", keyEnc: "SECRET" });
  assert.deepEqual(p, { endpoint: "https://api.example.com/v1", model: "m", hasKey: true, local: false, host: "api.example.com" });
  assert.equal(JSON.stringify(p).includes("SECRET"), false);
  assert.deepEqual(A.publicSettings({}), { endpoint: "", model: "", hasKey: false, local: true, host: "" });
});
