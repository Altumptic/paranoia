// Plugins: folders in <userData>/plugins, each a `plugin.json` manifest plus one script.
// This module only reads and validates; it never runs anything. The main process asks the
// user before a plugin's code runs (see `plugins:run` in main.cjs), and the renderer executes
// it through the same sandboxed JavaScript worker / Python bridge as the console.

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const ENTRY = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\.(js|py)$/;
const MAX_MANIFEST = 32 * 1024;
const MAX_SOURCE = 256 * 1024;
const MAX_PLUGINS = 64;
const MAX_COMMANDS = 32;

const str = (v, max) => (typeof v === "string" && v.trim() && v.length <= max ? v.trim() : null);

/**
 * Checks a parsed manifest. `dirName` must equal the plugin id so two folders cannot claim one id.
 * @returns {{ ok: true, plugin: object } | { ok: false, error: string }}
 */
function validate(manifest, dirName) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return { ok: false, error: "plugin.json must be an object" };
  const id = manifest.id;
  if (typeof id !== "string" || !ID.test(id)) return { ok: false, error: "`id` must be lowercase letters, digits, . _ - (1-64 characters)" };
  if (id !== dirName) return { ok: false, error: `\`id\` (${id}) must match the folder name (${dirName})` };
  const name = str(manifest.name, 80);
  if (!name) return { ok: false, error: "`name` is required (up to 80 characters)" };
  const version = str(manifest.version, 32);
  if (!version) return { ok: false, error: "`version` is required" };
  const language = manifest.language;
  if (language !== "js" && language !== "py") return { ok: false, error: "`language` must be \"js\" or \"py\"" };
  const entry = manifest.entry;
  if (typeof entry !== "string" || !ENTRY.test(entry)) return { ok: false, error: "`entry` must be a file name in the plugin folder ending in .js or .py" };
  if (!entry.endsWith(language === "js" ? ".js" : ".py")) return { ok: false, error: "`entry` does not match `language`" };
  const description = manifest.description == null ? "" : str(manifest.description, 300);
  if (description === null) return { ok: false, error: "`description` must be a short string" };
  const list = manifest.commands;
  if (!Array.isArray(list) || list.length === 0 || list.length > MAX_COMMANDS) return { ok: false, error: `\`commands\` needs 1-${MAX_COMMANDS} entries` };
  const commands = [];
  const seen = new Set();
  for (const c of list) {
    if (!c || typeof c !== "object") return { ok: false, error: "every command must be an object" };
    const cid = c.id;
    if (typeof cid !== "string" || !ID.test(cid) || seen.has(cid)) return { ok: false, error: `bad or duplicate command id ${JSON.stringify(cid)}` };
    seen.add(cid);
    const title = str(c.title, 80);
    if (!title) return { ok: false, error: `command ${cid} needs a \`title\`` };
    if (c.run != null && (typeof c.run !== "string" || !IDENT.test(c.run))) return { ok: false, error: `command ${cid}: \`run\` must be a function name` };
    commands.push({ id: cid, title, run: c.run ?? null });
  }
  return { ok: true, plugin: { id, name, version, description: description || "", language, entry, commands } };
}

/** Reads a plugin's script without following links out of its folder. */
function readEntry(dir, entry) {
  const file = path.join(dir, entry);
  const st = fs.lstatSync(file);
  if (!st.isFile()) throw new Error(`${entry} is not a regular file`);
  if (st.size > MAX_SOURCE) throw new Error(`${entry} is larger than ${MAX_SOURCE / 1024} KB`);
  const real = fs.realpathSync(file);
  const root = fs.realpathSync(dir);
  if (path.dirname(real) !== root) throw new Error(`${entry} resolves outside the plugin folder`);
  return fs.readFileSync(real, "utf8");
}

/** Identity of what would run: the manifest and the script. Any edit changes it, so trust is re-asked. */
function fingerprint(manifestText, code) {
  return crypto.createHash("sha256").update(manifestText).update("\0").update(code).digest("hex");
}

/** Loads one plugin from disk, fresh. @returns {{ plugin, code, hash }} */
function load(root, id) {
  if (typeof id !== "string" || !ID.test(id)) throw new Error("invalid plugin id");
  const dir = path.join(root, id);
  const manifestPath = path.join(dir, "plugin.json");
  const st = fs.lstatSync(manifestPath);
  if (!st.isFile() || st.size > MAX_MANIFEST) throw new Error("plugin.json is missing or too large");
  const text = fs.readFileSync(manifestPath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`plugin.json is not valid JSON: ${e.message}`);
  }
  const v = validate(parsed, id);
  if (!v.ok) throw new Error(v.error);
  const code = readEntry(dir, v.plugin.entry);
  return { plugin: v.plugin, code, hash: fingerprint(text, code) };
}

/** Lists the plugins under `root` (without their code); problems are reported, not thrown. */
function scan(root) {
  const plugins = [];
  const errors = [];
  let names = [];
  try {
    names = fs.readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
  } catch {
    return { plugins, errors };
  }
  for (const name of names.slice(0, MAX_PLUGINS)) {
    try {
      const { plugin, hash } = load(root, name);
      plugins.push({ ...plugin, hash });
    } catch (e) {
      errors.push({ id: name, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return { plugins, errors };
}

/** The script text to execute for `command`: the entry plus a call of its function, if it names one. */
function invocation(plugin, commandId, code) {
  const cmd = plugin.commands.find((c) => c.id === commandId);
  if (!cmd) throw new Error(`plugin ${plugin.id} has no command ${commandId}`);
  if (!cmd.run) return code;
  return plugin.language === "js" ? `${code}\n;await ${cmd.run}();\n` : `${code}\n${cmd.run}()\n`;
}

/** Trusted fingerprints, remembered across sessions. */
function readTrust(file) {
  try {
    const v = JSON.parse(fs.readFileSync(file, "utf8"));
    return new Set(Array.isArray(v) ? v.filter((h) => typeof h === "string" && /^[0-9a-f]{64}$/.test(h)) : []);
  } catch {
    return new Set();
  }
}

function writeTrust(file, set) {
  fs.writeFileSync(file, JSON.stringify([...set].slice(-500)), "utf8");
}

module.exports = { validate, load, scan, invocation, fingerprint, readTrust, writeTrust, MAX_SOURCE };
