// Security rules for the main process, kept free of Electron so they can be unit-tested
// (policy.test.cjs). main.cjs applies them to every IPC request.

const { pathToFileURL } = require("node:url");

/** The URL of the packaged page, without hash or query. */
function appUrl(indexHtml) {
  return pathToFileURL(indexHtml).href;
}

/** Whether `url` is the app's own page (any hash or query), and nothing else on disk. */
function isAppPage(url, app) {
  if (typeof url !== "string") return false;
  const bare = url.split("#")[0].split("?")[0];
  return bare === app;
}

/** Links the app may hand to the system browser. Everything else is dropped. */
const EXTERNAL_HOSTS = new Set(["github.com", "altumptic.com", "www.altumptic.com"]);

function externalAllowed(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return u.protocol === "https:" && !u.username && !u.password && EXTERNAL_HOSTS.has(u.hostname);
}

/** Store methods the page may call. `recent_add` is checked separately (see recentAddAllowed). */
const STORE_METHODS = new Set(["annotations_get", "annotations_set", "recent_list", "recent_add", "recent_remove"]);

// Function knowledge base. Export and import take file paths and stay in the CLI.
const MEMORY_METHODS = new Set(["stats", "learn", "recall", "forget"]);

function memoryMethodAllowed(method) {
  return typeof method === "string" && MEMORY_METHODS.has(method);
}

function storeMethodAllowed(method) {
  return typeof method === "string" && STORE_METHODS.has(method);
}

/**
 * The recent-files list also works as an allow-list (files opened before can be opened again),
 * so the page may only add a path the user really opened in this session.
 */
function recentAddAllowed(args, isAllowed) {
  const p = args && typeof args === "object" && args.entry && typeof args.entry === "object" ? args.entry.path : undefined;
  // Entries without a path (files opened from bytes in the browser build) add nothing to the allow-list.
  if (p === undefined || p === null || p === "") return true;
  return typeof p === "string" && isAllowed(p);
}

/** Text shown in the native confirmation before a debuggee starts. */
function debugDetail(file, cmdline) {
  const args = typeof cmdline === "string" && cmdline.trim() ? cmdline.trim().slice(0, 500) : "(none)";
  return (
    `Program: ${file ?? "unknown"}\nArguments: ${args}\n\n` +
    "Only debug files you trust, or do it inside a virtual machine. Malware will run with your user's permissions."
  );
}

module.exports = { appUrl, isAppPage, externalAllowed, storeMethodAllowed, memoryMethodAllowed, recentAddAllowed, debugDetail };
