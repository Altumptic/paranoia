// Metric computation for one (tool, binary) pair. Pure: takes the tool's dump
// (produced by the adapters) and the ground truth, returns a JSON object.
import { canon, callIdentifiers, cSize, isFailedC } from './names.mjs';
import { gtNameAt } from './gt.mjs';

const MAX_FAILURES_LISTED = 25;

function addrKey(a) {
    if (a === null || a === undefined) return null;
    const s = String(a).toLowerCase();
    if (!s.startsWith('0x')) return '0x' + BigInt(s).toString(16);
    return '0x' + BigInt(s).toString(16);
}

function pct(n, d) {
    return d === 0 ? null : Number(((100 * n) / d).toFixed(2));
}

// Expected callee name for one recorded call target: an address is resolved
// through the ground-truth symbol/import maps first; a recorded name is used
// when the tool itself spelled the callee (e.g. Ghidra EXTERNAL references)
// and that name is ground-truth-consistent.
function expectedNameForTarget(gt, t) {
    if (!t) return null;
    if (t.addr) {
        const n = gtNameAt(gt, t.addr);
        if (n) return n;
    }
    if (t.name) {
        const c = canon(t.name);
        if (c && c.length >= 2 && gt.nameCanons.has(c)) return t.name;
    }
    return null;
}

/**
 * @param {object} p
 * @param {string} p.tool
 * @param {string} p.id
 * @param {string} p.category
 * @param {object} p.functions  [{entry,name,thunk,external,c,error,note,decompMs,sampled}]
 * @param {Map<string,string[]>} p.callsByAddr  function entry -> call target addresses
 * @param {object} p.gt  buildGroundTruth() result
 * @param {object} p.timing {analysisMs, decompileMs, wallMs, toolVersion}
 * @param {number} p.maxFunctions  decompile sample size (first N non-thunk by address; 0 = all)
 */
export function computeMetrics(p) {
    const { tool, id, category, functions, callsByAddr, gt, timing, maxFunctions = 0 } = p;

    const cmpAddr = (a, b) => {
        const x = BigInt(a.entry ?? '0x0');
        const y = BigInt(b.entry ?? '0x0');
        return x < y ? -1 : x > y ? 1 : 0;
    };
    const nonThunk = functions.filter((f) => !f.thunk && !f.external).sort(cmpAddr);
    const thunks = functions.filter((f) => f.thunk && !f.external);
    const external = functions.filter((f) => f.external);
    // Functions whose C generation is measured: the sampled prefix (first N
    // non-thunk functions by address), or everything when sampling is disabled.
    const measured = maxFunctions > 0 ? nonThunk.filter((f) => f.sampled !== false).slice(0, maxFunctions) : nonThunk;

    // --- function discovery and naming against ground-truth entries -----------
    // Uses the *full* listing: discovery is cheap and should not depend on the
    // decompile sample.
    const byEntry = new Map();
    for (const f of functions) {
        const a = addrKey(f.entry);
        if (a) byEntry.set(a, f);
    }
    let gtFound = 0;
    let gtNamed = 0;
    for (const [addr, names] of gt.byAddr) {
        const f = byEntry.get(addr);
        if (!f) continue;
        gtFound++;
        const fc = canon(f.name);
        if (!fc) continue;
        if (names.some((n) => canon(n) === fc)) gtNamed++;
    }

    // --- decompilation coverage -------------------------------------------------
    const failed = [];
    let decompiled = 0;
    let cLines = 0;
    let cNonEmptyLines = 0;
    let cChars = 0;
    let decompMsSum = 0;
    for (const f of measured) {
        const dt = typeof f.decompMs === 'number' ? f.decompMs : 0;
        decompMsSum += dt;
        if (isFailedC(f.c, f.error)) {
            if (failed.length < MAX_FAILURES_LISTED) {
                failed.push({
                    entry: addrKey(f.entry),
                    name: f.name,
                    reason: f.error ?? f.note ?? 'empty output',
                });
            }
            continue;
        }
        decompiled++;
        const size = cSize(f.c);
        cLines += size.lines;
        cNonEmptyLines += size.nonEmptyLines;
        cChars += size.chars;
    }
    const failedTotal = measured.length - decompiled;

    // --- call-edge agreement ----------------------------------------------------
    let expectedTotal = 0;
    let observedTotal = 0;
    let tp = 0;
    let fn = 0;
    let fp = 0;
    let functionsWithExpected = 0;
    let functionsWithAnyMatch = 0;
    const perFunctionMissing = [];
    for (const f of measured) {
        const entry = addrKey(f.entry);
        if (!entry) continue;
        const targets = callsByAddr.get(entry) ?? [];
        const expected = new Set();
        const self = canon(f.name);
        for (const t of targets) {
            const name = expectedNameForTarget(gt, t);
            if (!name) continue;
            const c = canon(name);
            if (!c || c.length < 2 || c === self) continue;
            expected.add(c);
        }
        if (!expected.size) continue;
        functionsWithExpected++;
        const observedAll = callIdentifiers(f.c, self);
        const observed = new Set();
        for (const c of observedAll) {
            if (gt.nameCanons.has(c)) observed.add(c);
        }
        expectedTotal += expected.size;
        observedTotal += observed.size;
        let matched = 0;
        for (const e of expected) {
            if (observed.has(e)) matched++;
            else fn++;
        }
        tp += matched;
        for (const o of observed) if (!expected.has(o)) fp++;
        if (matched > 0) functionsWithAnyMatch++;
        if (matched < expected.size && perFunctionMissing.length < MAX_FAILURES_LISTED) {
            perFunctionMissing.push({ entry, name: f.name, expected: expected.size, matched });
        }
    }
    const precision = tp + fp === 0 ? null : tp / (tp + fp);
    const recall = tp + fn === 0 ? null : tp / (tp + fn);
    const f1 = precision === null || recall === null || precision + recall === 0 ? null : (2 * precision * recall) / (precision + recall);

    const gtFunctions = gt.byAddr.size;
    const toolFunctions = nonThunk.length;

    return {
        tool,
        id,
        category,
        sha256: p.sha256,
        gt: {
            gtSource: gt.gtSource,
            functionSymbols: gt.functionSymbols,
            exports: gt.exportCount,
            imports: gt.importCount,
            canonNames: gt.nameCanons.size,
        },
        functions: {
            total: functions.length,
            nonThunk: toolFunctions,
            sampled: measured.length,
            thunks: thunks.length,
            external: external.length,
            gtEntries: gtFunctions,
            gtFound,
            gtFoundPct: pct(gtFound, gtFunctions),
            gtNamed,
            gtNamedPct: pct(gtNamed, gtFunctions),
            unnamed: gtFound - gtNamed,
        },
        decompilation: {
            attempted: measured.length,
            decompiled,
            failed: failedTotal,
            coveragePct: pct(decompiled, measured.length),
            cLines,
            cNonEmptyLines,
            cChars,
            avgLinesPerFunction: decompiled === 0 ? null : Number((cLines / decompiled).toFixed(1)),
            avgCharsPerFunction: decompiled === 0 ? null : Number((cChars / decompiled).toFixed(0)),
            failedFunctions: failed,
        },
        calls: {
            functionsWithExpected,
            functionsWithAnyMatch,
            expected: expectedTotal,
            observed: observedTotal,
            matched: tp,
            missing: fn,
            extra: fp,
            recallPct: recall === null ? null : Number((100 * recall).toFixed(2)),
            precisionPct: precision === null ? null : Number((100 * precision).toFixed(2)),
            f1Pct: f1 === null ? null : Number((100 * f1).toFixed(2)),
            functionsWithMissing: perFunctionMissing,
        },
        timing: {
            analysisMs: timing.analysisMs ?? null,
            decompileMs: timing.decompileMs ?? decompMsSum,
            wallMs: timing.wallMs ?? null,
            toolVersion: timing.toolVersion ?? null,
        },
    };
}

// Aggregate per-binary metrics into corpus-level and per-category summaries.
export function aggregate(metricsList) {
    const groups = new Map();
    const push = (key, m) => {
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(m);
    };
    for (const m of metricsList) {
        push('all', m);
        push(m.category, m);
        push(`tool:${m.tool}`, m);
        push(`tool:${m.tool}:${m.category}`, m);
    }
    const out = {};
    for (const [key, rows] of groups) {
        const sum = (fn) => rows.reduce((a, m) => a + (fn(m) ?? 0), 0);
        const toolFunctions = sum((m) => m.functions.nonThunk);
        const sampled = sum((m) => m.decompilation.attempted);
        const decompiled = sum((m) => m.decompilation.decompiled);
        const gtEntries = sum((m) => m.functions.gtEntries);
        const gtFound = sum((m) => m.functions.gtFound);
        const gtNamed = sum((m) => m.functions.gtNamed);
        const expected = sum((m) => m.calls.expected);
        const matched = sum((m) => m.calls.matched);
        const extra = sum((m) => m.calls.extra);
        const missing = sum((m) => m.calls.missing);
        const precision = matched + extra === 0 ? null : matched / (matched + extra);
        const recall = matched + missing === 0 ? null : matched / (matched + missing);
        out[key] = {
            binaries: rows.length,
            functions: {
                nonThunk: toolFunctions,
                sampled,
                decompiled,
                failed: sampled - decompiled,
                coveragePct: pct(decompiled, sampled),
            },
            discovery: {
                gtEntries,
                gtFound,
                gtFoundPct: pct(gtFound, gtEntries),
                gtNamed,
                gtNamedPct: pct(gtNamed, gtEntries),
            },
            calls: {
                expected,
                matched,
                missing,
                extra,
                recallPct: recall === null ? null : Number((100 * recall).toFixed(2)),
                precisionPct: precision === null ? null : Number((100 * precision).toFixed(2)),
                f1Pct:
                    precision === null || recall === null || precision + recall === 0
                        ? null
                        : Number(((100 * 2 * precision * recall) / (precision + recall)).toFixed(2)),
            },
            output: {
                cLines: sum((m) => m.decompilation.cLines),
                cChars: sum((m) => m.decompilation.cChars),
            },
            timing: {
                analysisMs: sum((m) => m.timing.analysisMs),
                decompileMs: sum((m) => m.timing.decompileMs),
                wallMs: sum((m) => m.timing.wallMs),
            },
        };
    }
    // Sort keys: tool group order is stable because insertion follows metrics order.
    return out;
}
