const test = require("node:test");
const assert = require("node:assert/strict");
const { LATEST_URL, compareVersions, parseLatest, outcome, check } = require("./update.cjs");

const answer = (status, body) => async () => ({ status, ok: status >= 200 && status < 300, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
const release = (tag, extra = {}) => ({ tag_name: tag, html_url: `https://github.com/Altumptic/paranoia/releases/tag/${tag}`, published_at: "2026-11-20T10:00:00Z", ...extra });

test("versions compare numerically, not as text", () => {
  assert.ok(compareVersions("0.9.0", "0.10.0") < 0);
  assert.ok(compareVersions("0.10.0", "0.9.9") > 0);
  assert.equal(compareVersions("1.2.3", "1.2.3"), 0);
  assert.ok(compareVersions("0.9.0", "0.9.1") < 0);
});

test("the answer is reduced to version, tag, link and date", () => {
  const r = parseLatest(release("v0.10.0", { body: "ignored", assets: [{ browser_download_url: "https://evil.example/x.exe" }] }));
  assert.deepEqual(r, { tag: "v0.10.0", version: "0.10.0", url: "https://github.com/Altumptic/paranoia/releases/tag/v0.10.0", published: "2026-11-20" });
  assert.ok(!JSON.stringify(r).includes("evil"));
});

test("a tag we do not understand, or a page elsewhere, is refused", () => {
  assert.throws(() => parseLatest(release("v0.10.0-rc.1")), /tag/);
  assert.throws(() => parseLatest(release("latest")), /tag/);
  assert.throws(() => parseLatest(release("v0.10.0", { html_url: "https://evil.example/releases/tag/v0.10.0" })), /github\.com/);
  assert.throws(() => parseLatest(null), /Unexpected/);
  assert.throws(() => parseLatest([]), /tag/);
});

test("outcomes", () => {
  assert.equal(outcome("0.9.0", "0.10.0"), "newer");
  assert.equal(outcome("0.10.0", "0.10.0"), "current");
  assert.equal(outcome("0.11.0", "0.10.0"), "ahead");
});

test("check: asks only the releases address, without cookies or the app version", async () => {
  let seen;
  const fetchFn = async (url, init) => {
    seen = { url, init };
    return answer(200, release("v0.10.0"))();
  };
  const r = await check(fetchFn, "0.9.0");
  assert.equal(seen.url, LATEST_URL);
  assert.equal(seen.init.credentials, "omit");
  assert.ok(!JSON.stringify(seen.init.headers).includes("0.9.0"));
  assert.equal(r.status, "newer");
  assert.equal(r.current, "0.9.0");
  assert.equal(r.version, "0.10.0");
});

test("check: errors say what happened", async () => {
  await assert.rejects(check(answer(404, {}), "0.9.0"), /No release/);
  await assert.rejects(check(answer(403, {}), "0.9.0"), /limiting/);
  await assert.rejects(check(answer(500, {}), "0.9.0"), /500/);
  await assert.rejects(check(answer(200, "not json"), "0.9.0"), /Unexpected/);
  await assert.rejects(check(answer(200, "x".repeat(1_000_001)), "0.9.0"), /too large/);
  await assert.rejects(
    check(async () => {
      throw Object.assign(new Error("fetch failed"), { cause: { code: "ENOTFOUND" } });
    }, "0.9.0"),
    /Could not reach GitHub \(ENOTFOUND\)/,
  );
});
