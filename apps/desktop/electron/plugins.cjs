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
const MAX_HOOKS = 8;
/** Events a plugin can hook. `open`: a file was opened and analysed. `rename`: a name was changed. */
const EVENTS = ["open", "rename"];
/** Keys the app itself uses; a plugin cannot take them. */
const RESERVED_KEYS = new Set(["Ctrl+O", "Ctrl+K", "Ctrl+P", "Ctrl+Z", "Ctrl+Y", "Ctrl+S", "Ctrl+C", "Ctrl+V", "Ctrl+X", "Ctrl+A", "Ctrl+F", "Ctrl+W", "Ctrl+Q", "Ctrl+N", "Ctrl+R", "Ctrl+T", "Ctrl+L", "Ctrl+Shift+Z", "Alt+F4", "F5", "F7", "F8", "F9", "F10", "F11", "F12", "Alt+Q", "Alt+B", "Alt+T", "Alt+I", "Alt+M"]);

/**
 * A hotkey as written in the manifest, normalised (`ctrl+alt+h` → `Ctrl+Alt+H`), or null when it is not
 * allowed: it needs Ctrl or Alt (a plain letter would steal typing), a single letter, digit or F-key,
 * and must not be one the app uses.
 */
function normalizeKey(key) {
  if (typeof key !== "string" || key.length > 24) return null;
  const parts = key.split("+").map((p) => p.trim());
  const last = parts.pop();
  if (!last || !/^([A-Za-z0-9]|F([1-9]|1[0-2]))$/.test(last)) return null;
  const mods = new Set(parts.map((p) => p.toLowerCase()));
  if (mods.size !== parts.length || [...mods].some((m) => !["ctrl", "alt", "shift"].includes(m))) return null;
  if (!mods.has("ctrl") && !mods.has("alt")) return null;
  const norm = [mods.has("ctrl") ? "Ctrl" : null, mods.has("alt") ? "Alt" : null, mods.has("shift") ? "Shift" : null, last.length === 1 ? last.toUpperCase() : last.toUpperCase()].filter(Boolean).join("+");
  return RESERVED_KEYS.has(norm) ? null : norm;
}

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
    let key = null;
    if (c.key != null) {
      key = normalizeKey(c.key);
      if (!key) return { ok: false, error: `command ${cid}: \`key\` must be Ctrl or Alt plus a letter, digit or F-key, and not one the app uses (${String(c.key).slice(0, 24)})` };
      if (commands.some((o) => o.key === key)) return { ok: false, error: `command ${cid}: the key ${key} is already used by another command` };
    }
    commands.push({ id: cid, title, run: c.run ?? null, key });
  }
  const hooks = [];
  if (manifest.hooks != null) {
    if (!Array.isArray(manifest.hooks) || manifest.hooks.length > MAX_HOOKS) return { ok: false, error: `\`hooks\` needs at most ${MAX_HOOKS} entries` };
    for (const h of manifest.hooks) {
      if (!h || typeof h !== "object" || !EVENTS.includes(h.event)) return { ok: false, error: `a hook needs an \`event\`: ${EVENTS.join(" or ")}` };
      if (h.run != null && (typeof h.run !== "string" || !IDENT.test(h.run))) return { ok: false, error: `hook ${h.event}: \`run\` must be a function name` };
      hooks.push({ event: h.event, run: h.run ?? null });
    }
  }
  return { ok: true, plugin: { id, name, version, description: description || "", language, entry, commands, hooks } };
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

/**
 * The script for an event hook: the entry, an `event` object describing what happened (plain data, as
 * JSON), and a call of the hook's function if it names one.
 */
function hookInvocation(plugin, event, data, code) {
  const hooks = plugin.hooks.filter((h) => h.event === event);
  if (hooks.length === 0) throw new Error(`plugin ${plugin.id} does not hook ${event}`);
  const payload = JSON.stringify(JSON.stringify({ name: event, ...data }));
  const head = plugin.language === "js" ? `globalThis.event = JSON.parse(${payload});\n` : `import json\nevent = json.loads(${payload})\n`;
  const calls = hooks.filter((h) => h.run).map((h) => (plugin.language === "js" ? `;await ${h.run}(event);\n` : `${h.run}(event)\n`));
  return `${head}${code}\n${calls.join("")}`;
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

module.exports = { validate, load, scan, invocation, hookInvocation, normalizeKey, fingerprint, readTrust, writeTrust, EVENTS, MAX_SOURCE };
