// Small async child-process helper (the benchmark runs tool adapters in
// parallel, so the synchronous spawnSync variants in the Node stdlib would
// serialize everything on the event loop).
import { spawn } from 'node:child_process';

export function runAsync(cmd, args, opts = {}) {
    const { timeoutMs = 0, ...spawnOpts } = opts;
    let exe = cmd;
    let argv = args;
    let extra = {};
    // Windows: Node cannot CreateProcess a .bat/.cmd directly (EINVAL), and
    // cmd.exe needs the whole command line pre-quoted. Spawn cmd.exe and pass a
    // verbatim, double-quoted command line instead.
    if (process.platform === 'win32' && /\.(bat|cmd)$/i.test(cmd)) {
        const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';
        exe = process.env.ComSpec || 'cmd.exe';
        argv = ['/d', '/s', '/c', '"' + [q(cmd), ...args.map(q)].join(' ') + '"'];
        extra = { windowsVerbatimArguments: true };
    }
    return new Promise((resolve, reject) => {
        const t0 = process.hrtime.bigint();
        let stdout = '';
        let stderr = '';
        let timedOut = false;
        const child = spawn(exe, argv, { ...spawnOpts, ...extra, stdio: ['ignore', 'pipe', 'pipe'] });
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (d) => (stdout += d));
        child.stderr.on('data', (d) => (stderr += d));
        let timer = null;
        if (timeoutMs > 0) {
            timer = setTimeout(() => {
                timedOut = true;
                child.kill();
            }, timeoutMs);
        }
        child.on('error', (e) => {
            if (timer) clearTimeout(timer);
            reject(e);
        });
        child.on('close', (code) => {
            if (timer) clearTimeout(timer);
            const wallMs = Number(process.hrtime.bigint() - t0) / 1e6;
            if (timedOut) {
                reject(new Error(`${cmd} timed out after ${timeoutMs} ms`));
                return;
            }
            resolve({ code, wallMs, stdout, stderr });
        });
    });
}

// Runs up to `jobs` async tasks at once, preserving the input order of results.
export async function pool(items, jobs, fn) {
    const results = new Array(items.length);
    let next = 0;
    const workers = Array.from({ length: Math.max(1, Math.min(jobs, items.length)) }, async () => {
        for (;;) {
            const i = next++;
            if (i >= items.length) return;
            results[i] = await fn(items[i], i);
        }
    });
    await Promise.all(workers);
    return results;
}
