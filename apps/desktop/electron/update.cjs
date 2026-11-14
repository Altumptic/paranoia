// "Check for updates": one explicit request, started by the user, to the public list of
// releases. It reads a small JSON answer and never downloads or installs anything.
// Free of Electron so the logic can be tested (update.test.cjs); main.cjs passes net.fetch in.

const REPO = "Altumptic/paranoia";
/** The only address this feature contacts. GitHub's "latest" skips pre-releases and drafts. */
const LATEST_URL = `https://api.github.com/repos/${REPO}/releases/latest`;
const MAX_BYTES = 1_000_000;
const TIMEOUT_MS = 10_000;

const TAG = /^v(\d+)\.(\d+)\.(\d+)$/;

/** Orders two plain `MAJOR.MINOR.PATCH` versions: negative when a < b. */
function compareVersions(a, b) {
  const x = String(a).split(".").map(Number);
  const y = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

/**
 * Reads GitHub's answer and keeps only what is shown: the version, the release name and a
 * link on github.com. A page that does not look like this repository's release is refused,
 * so a changed or hostile answer cannot put another link in front of the user.
 */
function parseLatest(json) {
  if (!json || typeof json !== "object") throw new Error("Unexpected answer from GitHub");
  const tag = typeof json.tag_name === "string" ? json.tag_name : "";
  const m = TAG.exec(tag);
  if (!m) throw new Error("The latest release has a tag this version does not understand");
  const url = `https://github.com/${REPO}/releases/tag/${tag}`;
  if (json.html_url !== undefined && json.html_url !== url) throw new Error("The release page is not on github.com/" + REPO);
  const published = typeof json.published_at === "string" && /^\d{4}-\d{2}-\d{2}/.test(json.published_at) ? json.published_at.slice(0, 10) : null;
  return { tag, version: `${m[1]}.${m[2]}.${m[3]}`, url, published };
}

/** "newer": a release newer than this one exists. "current": this is the latest. "ahead": this build is newer than the latest release. */
function outcome(current, latest) {
  const c = compareVersions(current, latest);
  return c < 0 ? "newer" : c > 0 ? "ahead" : "current";
}

/**
 * @param {typeof fetch} fetchFn  net.fetch from Electron (honours the system proxy)
 * @param {string} current        this app's version
 */
async function check(fetchFn, current) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  let res;
  try {
    // No cookies, no identifying headers: not even the app's version leaves the machine.
    res = await fetchFn(LATEST_URL, {
      signal: ctl.signal,
      credentials: "omit",
      headers: { Accept: "application/vnd.github+json", "User-Agent": "Paranoia-update-check" },
    });
  } catch (e) {
    throw new Error(ctl.signal.aborted ? "GitHub did not answer in time" : `Could not reach GitHub (${e?.cause?.code ?? e?.message ?? "network error"})`);
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 403 || res.status === 429) throw new Error("GitHub is limiting requests from this address; try again later");
  if (res.status === 404) throw new Error("No release has been published yet");
  if (!res.ok) throw new Error(`GitHub answered ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error("The answer from GitHub is too large");
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error("Unexpected answer from GitHub");
  }
  const latest = parseLatest(json);
  return { current, ...latest, status: outcome(current, latest.version), checkedAt: new Date().toISOString() };
}

module.exports = { LATEST_URL, REPO, compareVersions, parseLatest, outcome, check };
