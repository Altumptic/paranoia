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

test("model lists come from GET /models, for OpenAI-style and Anthropic servers", async () => {
  let seen;
  const list = (body) => async (url, init) => ((seen = { url, init }), { ok: true, status: 200, text: async () => JSON.stringify(body) });
  const ids = await A.listModels({ endpoint: "http://127.0.0.1:11434/v1", fetchImpl: list({ data: [{ id: "qwen2.5:0.5b" }, { id: "llama3.1" }, { id: "llama3.1" }, { id: 7 }] }) });
  assert.deepEqual(ids, ["llama3.1", "qwen2.5:0.5b"]);
  assert.equal(seen.url, "http://127.0.0.1:11434/v1/models");
  assert.equal(seen.init.method, "GET");
  assert.equal(seen.init.redirect, "error");
  assert.equal("Authorization" in seen.init.headers, false);
  await A.listModels({ endpoint: "https://api.openai.com/v1", key: "sk", fetchImpl: list({ data: [] }) });
  assert.equal(seen.init.headers.Authorization, "Bearer sk");
  await A.listModels({ endpoint: "https://api.anthropic.com/v1", key: "sk-ant", fetchImpl: list({ data: [{ id: "claude-opus-5-5" }] }) });
  assert.equal(seen.init.headers["x-api-key"], "sk-ant");
  assert.equal(seen.init.headers["anthropic-version"], "2026-10-21");
  await assert.rejects(A.listModels({ endpoint: "http://127.0.0.1:1/v1", fetchImpl: reply(404, "nope") }), /404/);
  await assert.rejects(A.listModels({ endpoint: "http://127.0.0.1:1/v1", fetchImpl: reply(200, "<html>") }), /model list/);
  await assert.rejects(A.listModels({ endpoint: "http://127.0.0.1:1/v1", fetchImpl: reply(200, "x".repeat(3 * 1024 * 1024)) }), /unexpectedly large/);
});

test("string redaction uses the engine's placeholders and numbering", () => {
  const strings = ["Hello, world!\n", "db.internal.corp", "%s", "1   "];
  const r = A.createRedactor({ strings, redactStrings: true });
  const out = r.apply('v1 = puts("Hello, world!\\n"); // see aHelloWorld\nlea rax, [aDbInternalCorp] ; "db.internal.corp"');
  assert.deepEqual(out, {
    text: 'v1 = puts("<str#1 len=15>"); // see aRedacted1\nlea rax, [aRedacted2] ; "<str#2 len=16>"',
    strings: 4,
    ips: 0,
  });
  // The same literal keeps its number; an unknown one gets the next; a quoted pair is one hit.
  assert.deepEqual(r.apply(`x("db.internal.corp", 'k')`), { text: `x("<str#2 len=16>", '<str#5 len=1>')`, strings: 2, ips: 0 });
  // Parts of longer identifiers, parameters named a1 and unclosed quotes are left alone.
  assert.deepEqual(r.apply("xaHelloWorld don't a1"), { text: "xaHelloWorld don't a1", strings: 0, ips: 0 });
  assert.deepEqual(r.apply("f('open"), { text: "f('open", strings: 0, ips: 0 });
  // Nothing changes when the option is off, even with strings available.
  assert.deepEqual(A.createRedactor({ strings }).apply('f("Hello, world!")'), { text: 'f("Hello, world!")', strings: 0, ips: 0 });
});

test("IP-like constants are redacted and keep their number", () => {
  const r = A.createRedactor({ redactIps: true });
  assert.deepEqual(r.apply("beacon 192.168.13.37:443, gw 10.0.0.0/8, v6 fe80::1 and 2001:db8:85a3::8a2e:370:7334"), {
    text: "beacon <ip#1>:443, gw <ip#2>, v6 <ip#3> and <ip#4>",
    strings: 0,
    ips: 4,
  });
  // The same address keeps its number, a prefix is not part of its identity.
  assert.deepEqual(r.apply("192.168.13.37 and 10.0.0.0/16 and ::ffff:10.0.0.0"), {
    text: "<ip#1> and <ip#2> and <ip#5>",
    strings: 0,
    ips: 3,
  });
  assert.deepEqual(A.createRedactor({}).apply("see 192.168.13.37"), { text: "see 192.168.13.37", strings: 0, ips: 0 });
});

test("numbers, floats, times, MACs and names are not IPs", () => {
  const r = A.createRedactor({ redactIps: true });
  const text = "1.2.3  999.1.1.1  10.0.19041.1  3.14  0x401000  1.2.3.4.5  v1.2.3.4  12:34:56  std::vector  a:b  sub_401000  00:1A:2B:3C:4D:5E";
  assert.deepEqual(r.apply(text), { text, strings: 0, ips: 0 });
});

test("the consent wording says what leaves the machine", () => {
  const off = A.redactionSummary(false, false);
  assert.match(off, /Redaction is off/);
  assert.match(A.redactionSummary(true, false), /strings.*<str#N len=L>/);
  assert.match(A.redactionSummary(false, true), /<ip#N>/);
  const both = A.redactionSummary(true, true);
  assert.match(both, /<str#N len=L>/);
  assert.match(both, /<ip#N>/);
});

test("disclosure ledger lines are chained by SHA-256", () => {
  assert.equal(A.sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const first = A.ledgerLine(null, { event: "request", host: "api.example.com", task: "explain", redactions: { strings: 2, ips: 1 } }, 1762610400);
  const e1 = JSON.parse(first);
  assert.equal(e1.time, 1762610400);
  assert.equal(e1.prev, null);
  assert.equal(e1.redactions.ips, 1);
  const second = A.ledgerLine(A.sha256Hex(first), { event: "answer", response_sha256: "def" }, 1762610401);
  assert.equal(JSON.parse(second).prev, A.sha256Hex(first));
});

test("the connection test sends no code", () => {
  assert.ok(A.TEST_MESSAGES.every((m) => !/```/.test(m.content)));
});

test("public settings never include the key", () => {
  const p = A.publicSettings({ endpoint: "https://api.example.com/v1", model: "m", keyEnc: "SECRET", redactStrings: true });
  assert.deepEqual(p, {
    endpoint: "https://api.example.com/v1",
    model: "m",
    hasKey: true,
    local: false,
    host: "api.example.com",
    redactStrings: true,
    redactIps: false,
  });
  assert.equal(JSON.stringify(p).includes("SECRET"), false);
  assert.deepEqual(A.publicSettings({}), { endpoint: "", model: "", hasKey: false, local: true, host: "", redactStrings: false, redactIps: false });
});
