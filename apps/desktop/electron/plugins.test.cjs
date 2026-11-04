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

test("a valid manifest is accepted and normalised", () => {
  const v = P.validate(manifest({ description: "  hi  " }), "demo");
  assert.equal(v.ok, true);
  assert.equal(v.plugin.description, "hi");
  assert.deepEqual(v.plugin.commands, [{ id: "go", title: "Go", run: "main" }]);
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
