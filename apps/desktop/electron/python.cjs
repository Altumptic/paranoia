// Python scripting: runs the user's script in their own CPython with the `paranoia`
// module (electron/paranoia.py) on the path. The script talks to the engine through
// this process: lines starting with \x1e on its stdout are JSON requests, replies go
// to its stdin. Everything else it prints is shown in the console.

const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");

/** Finds a Python 3 interpreter: $PARANOIA_PYTHON, then python, python3, py -3. */
function findPython() {
  const candidates = [];
  if (process.env.PARANOIA_PYTHON) candidates.push([process.env.PARANOIA_PYTHON, []]);
  candidates.push(["python", []], ["python3", []], ["py", ["-3"]]);
  for (const [exe, pre] of candidates) {
    try {
      const r = spawnSync(exe, [...pre, "-c", "import sys; print(sys.version_info[0], sys.version.split()[0])"], { encoding: "utf8", windowsHide: true, timeout: 8000 });
      const out = (r.stdout || "").trim();
      if (r.status === 0 && out.startsWith("3 ")) return { exe, pre, version: out.slice(2) };
    } catch {
      /* try the next one */
    }
  }
  return null;
}

class PythonRunner {
  /**
   * @param {{ request(req: object): Promise<unknown> }} engine
   * @param {(channel: string, payload: unknown) => void} send events to the renderer
   * @param {string} moduleSource path of paranoia.py
   */
  constructor(engine, send, moduleSource) {
    this.engine = engine;
    this.send = send;
    this.moduleSource = moduleSource;
    this.child = null;
    this.python = undefined;
  }

  status() {
    if (this.python === undefined) this.python = findPython();
    return this.python ? { available: true, version: this.python.version, exe: this.python.exe } : { available: false };
  }

  stop() {
    if (this.child) {
      this.child.kill();
      this.child = null;
    }
  }

  /** @param {string} code @param {number} handle engine session @param {number} cursor */
  run(code, handle, cursor) {
    const st = this.status();
    if (!st.available) throw new Error("Python 3 was not found. Install it from python.org or set PARANOIA_PYTHON to python.exe.");
    this.stop();
    const dir = path.join(os.tmpdir(), "paranoia-python");
    fs.mkdirSync(dir, { recursive: true });
    fs.copyFileSync(this.moduleSource, path.join(dir, "paranoia.py"));
    const script = path.join(dir, `script-${process.pid}.py`);
    fs.writeFileSync(script, code, "utf8");

    const boot = "import paranoia, sys; paranoia._main(sys.argv[1])";
    const child = spawn(this.python.exe, [...this.python.pre, "-u", "-X", "utf8", "-c", boot, script], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      env: { ...process.env, PYTHONPATH: dir + path.delimiter + (process.env.PYTHONPATH || ""), PYTHONIOENCODING: "utf-8", PN_CURSOR: String(cursor || 0) },
    });
    this.child = child;
    const started = Date.now();

    readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", async (line) => {
      if (!line.startsWith("\x1e")) {
        this.send("python:output", { stream: "out", text: line });
        return;
      }
      let msg;
      try {
        msg = JSON.parse(line.slice(1));
      } catch {
        return;
      }
      const reply = (ok, value) => {
        if (child.exitCode === null) child.stdin.write(JSON.stringify(ok ? { id: msg.id, ok, value } : { id: msg.id, ok, error: value }) + "\n");
      };
      try {
        if (msg.op === "call" && typeof msg.method === "string") {
          reply(true, await this.engine.request({ op: "call", handle, method: msg.method, args: msg.args ?? null }));
        } else if (msg.op === "goto") {
          this.send("python:goto", Number(msg.va));
          reply(true, null);
        } else if (msg.op === "refresh") {
          this.send("python:refresh", null);
          reply(true, null);
        } else {
          reply(false, `unknown request ${msg.op}`);
        }
      } catch (e) {
        reply(false, e instanceof Error ? e.message : String(e));
      }
    });
    readline.createInterface({ input: child.stderr, crlfDelay: Infinity }).on("line", (line) => this.send("python:output", { stream: "err", text: line }));
    child.on("exit", (code) => {
      if (this.child === child) this.child = null;
      fs.rm(script, () => {});
      this.send("python:exit", { code, millis: Date.now() - started });
    });
    child.on("error", (e) => this.send("python:output", { stream: "err", text: e.message }));
    return { started: true, version: st.version };
  }
}

module.exports = { PythonRunner, findPython };
