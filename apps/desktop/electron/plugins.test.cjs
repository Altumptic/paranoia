const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const P = require("./plugins.cjs");

const manifest = (over = {}) => ({
  id: "demo",
  name: "Demo",
  version: "1.0.0",
  language: "js",
  entry: "main.js",
  commands: [{ id: "go", title: "Go", run: "main" }],
  ...over,
});

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "pn-plugins-"));
}

function write(root, id, m, code = "async function main() { print(1); }") {
  const dir = path.join(root, id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "plugin.json"), JSON.stringify(m));
  if (m && typeof m.entry === "string") fs.writeFileSync(path.join(dir, m.entry), code);
}

const hookManifest = (extra) => ({ id: "p", name: "P", version: "1", language: "js", entry: "main.js", commands: [{ id: "a", title: "A", key: "ctrl+alt+h" }], ...extra });

test("hotkeys need Ctrl or Alt, a single key, and not one the app uses", () => {
  assert.equal(P.normalizeKey("ctrl+alt+h"), "Ctrl+Alt+H");
  assert.equal(P.normalizeKey("Alt+F6"), "Alt+F6");
  assert.equal(P.normalizeKey("Ctrl+Shift+7"), "Ctrl+Shift+7");
  for (const bad of ["H", "Shift+H", "Ctrl+", "Ctrl+Alt", "Ctrl+Enter", "Ctrl+Ctrl+H", "Win+H", "Ctrl+O", "ctrl+k", "F7", "Alt+Q", "Ctrl+HH", "Ctrl+F13", 5, null, "Ctrl+" + "x".repeat(30)]) {
    assert.equal(P.normalizeKey(bad), null, String(bad));
  }
  const v = P.validate(hookManifest({}), "p");
  assert.ok(v.ok);
  assert.equal(v.plugin.commands[0].key, "Ctrl+Alt+H");
  assert.match(P.validate(hookManifest({ commands: [{ id: "a", title: "A", key: "H" }] }), "p").error, /key/);
  assert.match(P.validate(hookManifest({ commands: [{ id: "a", title: "A", key: "Ctrl+Alt+H" }, { id: "b", title: "B", key: "alt+ctrl+h" }] }), "p").error, /already used/);
});

test("hooks: known events only, bounded, and the script gets the event as plain data", () => {
  const ok = P.validate(hookManifest({ hooks: [{ event: "open", run: "onOpen" }, { event: "rename" }] }), "p");
  assert.ok(ok.ok);
  assert.deepEqual(ok.plugin.hooks, [{ event: "open", run: "onOpen" }, { event: "rename", run: null }]);
  assert.equal(P.validate(hookManifest({}), "p").plugin.hooks.length, 0);
  for (const hooks of [[{ event: "keypress" }], [{ event: "open", run: "a b" }], [{ event: "open", run: 5 }], "open", Array.from({ length: 9 }, () => ({ event: "open" })), [null]]) {
    assert.equal(P.validate(hookManifest({ hooks }), "p").ok, false, JSON.stringify(hooks));
  }
  const js = P.hookInvocation(ok.plugin, "open", { file: "a\"b'; process.exit()//", sha256: "x" }, "// code");
  assert.match(js, /^globalThis\.event = JSON\.parse\(/);
  assert.match(js, /;await onOpen\(event\);/);
  // The data is a JSON string inside a JSON string: it cannot break out into code.
  const arg = js.split("JSON.parse(")[1].split(");\n")[0];
  assert.equal(JSON.parse(JSON.parse(arg)).file, "a\"b'; process.exit()//");
  const py = P.hookInvocation({ ...ok.plugin, language: "py" }, "open", { file: "x" }, "# code");
  assert.match(py, /^import json\nevent = json\.loads\(/);
  assert.throws(() => P.hookInvocation(ok.plugin, "save", {}, ""), /does not hook/);
});

test("a valid manifest is accepted and normalised", () => {
  const v = P.validate(manifest({ description: "  hi  " }), "demo");
  assert.equal(v.ok, true);
  assert.equal(v.plugin.description, "hi");
  assert.deepEqual(v.plugin.commands, [{ id: "go", title: "Go", run: "main", key: null }]);
  assert.deepEqual(v.plugin.hooks, []);
});

test("bad manifests are refused with a reason", () => {
  const bad = (over, dir = "demo") => P.validate(manifest(over), dir);
  assert.match(bad({ id: "Demo" }, "Demo").error, /id/);
  assert.match(bad({}, "other").error, /folder name/);
  assert.match(bad({ name: "" }).error, /name/);
  assert.match(bad({ language: "lua" }).error, /language/);
  assert.match(bad({ entry: "../evil.js" }).error, /entry/);
  assert.match(bad({ entry: "sub/main.js" }).error, /entry/);
  assert.match(bad({ entry: "main.py" }).error, /does not match/);
  assert.match(bad({ commands: [] }).error, /commands/);
  assert.match(bad({ commands: [{ id: "a", title: "A", run: "x; evil()" }] }).error, /function name/);
  assert.match(bad({ commands: [{ id: "a", title: "A" }, { id: "a", title: "B" }] }).error, /duplicate/);
  assert.equal(P.validate(null, "demo").ok, false);
  assert.equal(P.validate([], "demo").ok, false);
});

test("scan lists good plugins and reports broken ones", () => {
  const root = tmp();
  write(root, "demo", manifest());
  write(root, "broken", manifest({ id: "broken", language: "rb" }));
  fs.mkdirSync(path.join(root, "empty"));
  const { plugins, errors } = P.scan(root);
  assert.deepEqual(plugins.map((p) => p.id), ["demo"]);
  assert.match(plugins[0].hash, /^[0-9a-f]{64}$/);
  assert.deepEqual(errors.map((e) => e.id).sort(), ["broken", "empty"]);
  assert.deepEqual(P.scan(path.join(root, "missing")), { plugins: [], errors: [] });
});

test("the fingerprint changes when the script or the manifest changes", () => {
  const root = tmp();
  write(root, "demo", manifest(), "a");
  const h1 = P.load(root, "demo").hash;
  write(root, "demo", manifest(), "b");
  const h2 = P.load(root, "demo").hash;
  write(root, "demo", manifest({ version: "1.0.1" }), "b");
  const h3 = P.load(root, "demo").hash;
  assert.equal(new Set([h1, h2, h3]).size, 3);
  assert.equal(P.load(root, "demo").hash, h3, "same files, same fingerprint");
});

test("load refuses ids that could escape the plugin folder and oversized scripts", () => {
  const root = tmp();
  assert.throws(() => P.load(root, "../x"), /invalid plugin id/);
  assert.throws(() => P.load(root, "a/b"), /invalid plugin id/);
  write(root, "big", manifest({ id: "big" }), "x".repeat(P.MAX_SOURCE + 1));
  assert.throws(() => P.load(root, "big"), /larger than/);
});

test("load does not follow a script link out of the folder", (t) => {
  const root = tmp();
  const outside = path.join(tmp(), "secret.js");
  fs.writeFileSync(outside, "steal()");
  const dir = path.join(root, "demo");
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, "plugin.json"), JSON.stringify(manifest()));
  try {
    fs.symlinkSync(outside, path.join(dir, "main.js"));
  } catch {
    return t.skip("symlinks are not permitted here");
  }
  assert.throws(() => P.load(root, "demo"), /not a regular file/);
});

test("invocation appends the command's function call", () => {
  const js = P.validate(manifest(), "demo").plugin;
  assert.equal(P.invocation(js, "go", "CODE"), "CODE\n;await main();\n");
  const noRun = P.validate(manifest({ commands: [{ id: "go", title: "Go" }] }), "demo").plugin;
  assert.equal(P.invocation(noRun, "go", "CODE"), "CODE");
  const py = P.validate(manifest({ language: "py", entry: "main.py" }), "demo").plugin;
  assert.equal(P.invocation(py, "go", "CODE"), "CODE\nmain()\n");
  assert.throws(() => P.invocation(js, "nope", "CODE"), /no command/);
});

test("trust is persisted and tolerates a damaged file", () => {
  const file = path.join(tmp(), "trust.json");
  assert.equal(P.readTrust(file).size, 0);
  const h = "a".repeat(64);
  P.writeTrust(file, new Set([h]));
  assert.deepEqual([...P.readTrust(file)], [h]);
  fs.writeFileSync(file, "not json");
  assert.equal(P.readTrust(file).size, 0);
  fs.writeFileSync(file, JSON.stringify([h, "short", 5]));
  assert.deepEqual([...P.readTrust(file)], [h]);
});
