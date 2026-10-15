// Supervises the native `paranoia-engine` process and multiplexes requests
// over its line-delimited JSON protocol (see crates/paranoia-engine).

const { spawn } = require("node:child_process");
const readline = require("node:readline");

class EngineProcess {
  /** @param {string} exe @param {string[]} args @param {(reason: string) => void} onRestart */
  constructor(exe, args, onRestart) {
    this.exe = exe;
    this.args = args;
    this.onRestart = onRestart;
    this.child = null;
    this.seq = 0;
    this.pending = new Map();
    this.stderr = "";
  }

  start() {
    const child = spawn(this.exe, this.args, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    this.child = child;
    readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      if (msg.ok) p.resolve(msg.value);
      else p.reject(new Error(msg.error));
    });
    child.stderr.on("data", (d) => {
      this.stderr = (this.stderr + d.toString()).slice(-4000);
    });
    child.on("exit", (code, signal) => {
      if (this.child !== child) return;
      this.child = null;
      const reason = `engine exited (${signal ?? code})${this.stderr ? `: ${this.stderr.trim().split("\n").pop()}` : ""}`;
      for (const p of this.pending.values()) p.reject(new Error(`The analysis engine stopped unexpectedly — ${reason}`));
      this.pending.clear();
      this.onRestart(reason);
    });
    child.on("error", (err) => {
      for (const p of this.pending.values()) p.reject(new Error(`Could not start the analysis engine: ${err.message}`));
      this.pending.clear();
    });
  }

  /** @param {Record<string, unknown>} req */
  request(req) {
    if (!this.child) this.start();
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin.write(JSON.stringify({ ...req, id }) + "\n", (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  stop() {
    const c = this.child;
    this.child = null;
    if (c) {
      c.stdin.end();
      setTimeout(() => c.kill(), 500);
    }
  }
}

module.exports = { EngineProcess };
