"""Benchmark adapter: decompile every function through paranoia's Python module.

Run through the CLI (not directly):

    paranoia script <binary> bench/tools/paranoia-dump.py

Environment:
    PARANOIA_BENCH_OUT   output directory (required)

Writes <sha256>.paranoia.jsonl (one JSON object per function) and
<sha256>.paranoia.summary (timings) for bench/run.mjs.
"""
import json
import os
import sys
import time

import paranoia

out_dir = os.environ.get("PARANOIA_BENCH_OUT")
if not out_dir:
    raise SystemExit("PARANOIA_BENCH_OUT is not set")

wall_start = time.perf_counter()

# "stats" runs auto-analysis and returns its timing; "functions"/"info" then
# answer from the analysed binary.
stats = paranoia.call("stats")
info = paranoia.info()
sha = info["hashes"]["sha256"]
functions = paranoia.functions()
# Deterministic order (the listing is address-ordered in practice; sort anyway).
functions.sort(key=lambda f: int(f["address"]))
# Sampling: decompile at most MAX non-thunk functions (first N by address) and
# record the whole listing without C so function-discovery metrics stay
# complete. 0 = decompile everything (slow; the published run samples).
max_funcs = int(os.environ.get("PARANOIA_BENCH_MAX_FUNCS", "0") or "0")

jsonl_path = os.path.join(out_dir, sha + ".paranoia.jsonl")
summary_path = os.path.join(out_dir, sha + ".paranoia.summary")

decompiled = 0
failed = 0
sampled_count = 0
total_decomp_ms = 0.0
total_chars = 0
total_lines = 0

with open(jsonl_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(
        json.dumps(
            {
                "kind": "header",
                "tool": "paranoia",
                "formatVersion": 1,
                "sha256": sha,
                "name": info["file_name"],
                "format": info["format"],
                "arch": info["arch"],
                "bits": info["bits"],
                "entry": "0x%x" % info["entry"],
                "imageBase": "0x%x" % info["image_base"],
                "analysisMs": stats["millis"],
            }
        )
        + "\n"
    )
    for i, fn in enumerate(functions):
        ea = int(fn["address"])
        is_thunk = bool(fn.get("is_import_thunk"))
        sampled = True
        if max_funcs > 0:
            sampled = (not is_thunk) and sampled_count < max_funcs
        if sampled and not is_thunk:
            sampled_count += 1
        t0 = time.perf_counter()
        error = None
        note = None
        text = None
        try:
            if sampled:
                p = paranoia.call("pseudocode", va=ea)
                if p:
                    note = p.get("note")
                    lines = []
                    for line in p["lines"]:
                        lines.append("    " * line["indent"] + "".join(tok["t"] for tok in line["tokens"]))
                    text = "\n".join(lines)
        except Exception as exc:  # noqa: BLE001 - record, never abort the corpus
            error = type(exc).__name__ + ": " + str(exc)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        total_decomp_ms += dt_ms
        if not sampled:
            pass
        elif text is None or not text.strip():
            failed += 1
        else:
            decompiled += 1
            total_chars += len(text)
            total_lines += text.count("\n") + 1
        rec = {
            "kind": "function",
            "entry": "0x%x" % ea,
            "name": fn["name"],
            "size": fn["size"],
            "blocks": fn["blocks"],
            "instructions": fn["instructions"],
            "source": fn["source"],
            "thunk": is_thunk,
            "library": bool(fn.get("library")),
            "sampled": sampled,
            "decompMs": round(dt_ms, 3),
            "c": text,
            "note": note,
            "error": error,
        }
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if (i + 1) % 250 == 0:
            print(
                "paranoia-dump: %d/%d functions, %.1f s, %.1f ms/func"
                % (i + 1, len(functions), time.perf_counter() - wall_start, (time.perf_counter() - wall_start) * 1000 / (i + 1)),
                file=sys.stderr,
            )

wall_ms = (time.perf_counter() - wall_start) * 1000.0
summary = {
    "kind": "summary",
    "tool": "paranoia",
    "sha256": sha,
    "functions": len(functions),
    "sampled": sampled_count,
    "decompiled": decompiled,
    "failed": failed,
    "analysisMs": stats["millis"],
    "decompileMs": round(total_decomp_ms, 3),
    "cChars": total_chars,
    "cLines": total_lines,
    "wallMs": round(wall_ms, 3),
}
with open(summary_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(json.dumps(summary) + "\n")
print("PARANOIA_BENCH_DONE " + json.dumps(summary), file=sys.stdout)
