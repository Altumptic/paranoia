const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const policy = require("./policy.cjs");

const index = path.resolve("/app/dist/index.html");
const app = policy.appUrl(index);

test("only the app's own page is trusted", () => {
  assert.ok(policy.isAppPage(app, app));
  assert.ok(policy.isAppPage(`${app}#/overview`, app));
  assert.ok(policy.isAppPage(`${app}?x=1`, app));
  // Another HTML file on disk, even next to the app, is not the app.
  assert.ok(!policy.isAppPage(policy.appUrl(path.resolve("/app/dist/other.html")), app));
  assert.ok(!policy.isAppPage(policy.appUrl(path.resolve("/samples/evil.html")), app));
  assert.ok(!policy.isAppPage("https://example.com/", app));
  assert.ok(!policy.isAppPage(undefined, app));
});

test("external links are limited to a few https hosts", () => {
  assert.ok(policy.externalAllowed("https://github.com/Altumptic/paranoia"));
  assert.ok(policy.externalAllowed("https://altumptic.com/security"));
  for (const u of [
    "http://github.com/",
    "https://github.com.evil.com/",
    "https://user:pw@github.com/",
    "file:///C:/Windows/System32/calc.exe",
    "ms-settings:",
    "javascript:alert(1)",
    "not a url",
  ]) {
    assert.ok(!policy.externalAllowed(u), u);
  }
});

test("the page may use a fixed set of store methods", () => {
  for (const m of ["annotations_get", "annotations_set", "recent_list", "recent_add", "recent_remove"]) assert.ok(policy.storeMethodAllowed(m));
  for (const m of ["", "drop_all", "__proto__", undefined, 42]) assert.ok(!policy.storeMethodAllowed(m));
});

test("recent_add cannot smuggle a path into the allow-list", () => {
  const opened = new Set(["c:\\samples\\a.exe"]);
  const isAllowed = (p) => opened.has(p.toLowerCase());
  assert.ok(policy.recentAddAllowed({ entry: { path: "C:\\Samples\\a.exe" } }, isAllowed));
  assert.ok(!policy.recentAddAllowed({ entry: { path: "C:\\Users\\me\\.ssh\\id_rsa" } }, isAllowed));
  assert.ok(!policy.recentAddAllowed({ entry: { path: 42 } }, isAllowed));
  // Browser-style entries without a path add nothing.
  assert.ok(policy.recentAddAllowed({ entry: { name: "x" } }, isAllowed));
});

test("the debug confirmation names the program and its arguments", () => {
  const d = policy.debugDetail("C:\\samples\\a.exe", "--wipe C:\\");
  assert.match(d, /Program: C:\\samples\\a\.exe/);
  assert.match(d, /Arguments: --wipe C:\\/);
  assert.match(policy.debugDetail(null, ""), /Arguments: \(none\)/);
});
