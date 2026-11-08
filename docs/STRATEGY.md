# Product strategy

What Paranoia is for, the one capability it is built around, and how work is prioritised. The [roadmap](ROADMAP.md) turns this into milestones. Every claim here is either measured (with how) or marked as a goal.

Last reviewed: 2026-11-08 · v0.7.0

## In one sentence

Paranoia is a reverse-engineering engine for files you cannot send anywhere: it runs on your machine, it is fast enough to be interactive, its releases can be verified, and when an AI agent works on a sample, Paranoia decides what the agent may see and keeps a record of everything it saw.

## Who it is for

| | Who | What they need from us |
| --- | --- | --- |
| **Primary** | Incident responders and malware analysts triaging samples on machines that must stay offline, or under an NDA that forbids uploading | Open a file and see functions, imports, strings and readable pseudocode in seconds; no network; evidence they can show to whoever audits their tools |
| **Primary** | Security engineers who want AI help on binaries without uploading them | An agent interface that is local, read-only by default and confined to the folders they choose |
| Secondary | Students and CTF players | Free, quick to install, familiar IDA keys and IDA-style scripting |
| Secondary | Developers who embed analysis in their own tools | The same engine as a CLI, a WebAssembly module and an MCP server, all behind one JSON contract |
| Not now | Analysts of large C++ applications, or of architectures beyond the ones listed in the README | IDA Pro with Hex-Rays and Ghidra are far ahead on C++ decompilation and on architecture count; we say so instead of competing there |

## The key feature: private, agent-ready analysis

### What is unique: controlled disclosure

Connecting a disassembler to an AI agent is no longer rare — IDA, Ghidra, Binary Ninja and radare2 all have MCP integrations. What those integrations do not address is the analyst's real constraint: the sample may contain a customer's hostnames, keys or personal data, and once the agent's model has read it, there is no taking it back and no record of what was read. Paranoia's MCP server handles that itself:

| | What it does | Evidence |
| --- | --- | --- |
| **Redaction** (`--redact-strings`) | The file's string contents never reach the agent. Quoted literals in pseudocode, listings, comments, string lists and search results become `"<str#12 len=23>"`; auto names derived from strings (`aDbInternalCorp`) become `aRedacted12`. The same string keeps its number for the whole session, so the agent can still reason about "the function that uses str#12" and the analyst can look it up locally | `redaction_and_ledger` in `crates/paranoia-cli/src/mcp.rs`; `disclosure.rs` unit tests |
| **Disclosure ledger** (`--ledger FILE`) | Every answer the agent receives is appended to a local JSON-lines file first: time, tool, arguments, the analysed file's SHA-256, the exact text and its SHA-256, and how many strings were redacted. If the line cannot be written, the answer is withheld | `unwritable_ledger_withholds_results`; the ledger format in [MCP.md](MCP.md#disclosure-ledger) |
| **Boundaries** | stdio only, files only under `--root`, read-only by default | [MCP.md § Security](MCP.md#security) |

So an analyst under an NDA can use a hosted model and later show exactly what it was given — or run it with redaction and show that no string from the sample was disclosed. We know of no other reverse-engineering tool that does this (checked on the review date; tell us if one does).

**What redaction does not cover**, stated so it is not over-trusted: function, import and export names, section names, numeric constants (an IP address stored as a number), code structure, and the arguments the agent itself sends (a `search` for a word reveals whether the file contains it). Redaction lowers what leaks; it does not make a hosted model safe for every sample.

### The ground it stands on

Three properties make the feature possible. Each one exists today and has evidence.

| Property | What it means | Evidence |
| --- | --- | --- |
| **One engine everywhere** | The same Rust core runs the desktop app, the browser build (WebAssembly, no server), the `paranoia` CLI and the MCP server. A fix or a feature reaches all four at once | One contract, `Session::call` in `crates/paranoia-core/src/api.rs`; the core has no I/O so it compiles to `wasm32` (AGENTS.md, invariant 2) |
| **Nothing leaves the machine** | The engine makes no network connections. The MCP server talks over stdio only, opens files only under the folders given with `--root`, and is read-only unless started with `--allow-writes`. Releases ship signed checksums, provenance attestations and SBOMs | [SECURITY-DESIGN.md](SECURITY-DESIGN.md), [PSB.md](PSB.md), [VERIFY.md](VERIFY.md), [MCP.md](MCP.md) |
| **Fast enough for a conversation** | Auto-analysis finishes before an agent's next turn, so it can open a file and start asking questions right away | Release build, Intel Core i5-12450H, `paranoia functions <file>` (analysis time as the engine reports it, best of 3): notepad.exe (0.3 MB) 459 functions in 45 ms; kernel32.dll (0.8 MB) 2 604 functions in 108 ms; shell32.dll (7.7 MB) 24 449 functions, 1.47 M instructions in 1.02 s |

**What we do not claim.** We have not run a controlled speed comparison with IDA, Ghidra or Binary Ninja, so the README gives our numbers only. "Nothing leaves the machine" covers Paranoia itself: when your MCP client uses a hosted model, the pseudocode and listings you ask for go to that model's provider through your client. For no egress at all, use a client with a local model.

### Why this, and not "IDA, but free"

| | IDA Pro | Ghidra | Binary Ninja | radare2 / rizin | Paranoia |
| --- | --- | --- | --- | --- | --- |
| Licence | Commercial | Free, Apache-2.0 | Commercial, free tier | Free, LGPL | Free, Apache-2.0 |
| Decompiler | Hex-Rays, many architectures, best C++ | Many architectures | Several architectures (IL based) | Through plugins (e.g. rz-ghidra) | x86 / x64 today; AArch64 next |
| Agent interface (MCP) | Community plugins inside IDA | Community plugins inside Ghidra | Plugins | r2mcp | Built into the engine binary: `paranoia mcp`, no host application, no Python bridge |
| Redaction of sample content and a ledger of what the agent saw | Not known to us | Not known to us | Not known to us | Not known to us | Yes (`--redact-strings`, `--ledger`) |
| Runs in a browser with no server | No | No | No | No | Yes (WebAssembly) |
| Release verification | Vendor download | Published checksums | Vendor download | Varies | Sigstore-signed checksums, provenance attestations, SBOM per release |

The competitor columns describe the projects as we understand them on the review date; check before quoting them.

A free copy of IDA loses to Ghidra on breadth and to IDA on depth. The place where we can be clearly better is narrower: a small, fast, verifiable engine that a human and an agent can use on a confidential sample, on x86/x64 and AArch64 — the two architectures that cover Windows, Linux servers, Apple silicon and Android.

## What we will not do

- No cloud analysis service, accounts or telemetry — not in a paid edition either.
- No new architecture or format without tests on real binaries (decoder tests alone do not count as support).
- No "parity" claim without a test that shows it; the parity table in the roadmap marks partial work as partial.
- No feature that opens a network connection without the user starting it, a native confirmation for non-loopback targets, and an update of the security design first.
- No paid feature that takes away from the open core ([roadmap § Editions](ROADMAP.md#editions)).

## How work is prioritised

When two pieces of work compete, the earlier line wins:

1. **Robustness on hostile input** — a crash or hang on a crafted file is a bug before anything else ([AGENTS.md](../AGENTS.md), invariant 1).
2. **Readable pseudocode on x86/x64 and AArch64** — the decompiler is what most users judge the tool by.
3. **The agent interface and automation** — MCP, CLI, scripting.
4. **Reach** — Linux and macOS packages.
5. **Breadth** — firmware and raw images, remote debugging, more architectures.

Every feature ships with tests on real binaries, a line in the roadmap's parity table and its limits stated where users read them.

## What we measure

| Measure | How | Today |
| --- | --- | --- |
| Time to first analysis | `paranoia functions` on fixed system binaries, release build | See the table above |
| Robustness | Mutation suite on real PE / ELF / Mach-O (`tests/real_binaries.rs`) | 500 mutants per OS in CI, 18 000 before a release, no crash |
| Decompiler agreement | C·SSA view against the C view on real functions (`c_from_ssa_on_real_code`) | Same callees in 598 of 600 functions |
| Agent interface | End-to-end MCP tests (`crates/paranoia-cli/src/mcp.rs`) and a stdio session against system binaries | 15 read-only tools, 3 write tools; `triage` over all 2 604 functions of kernel32.dll, including opening the file, in 1.2 s |
| Disclosure control | Redaction and ledger tests; live run on notepad.exe | Every string literal in the output replaced; every answer in the ledger with its SHA-256 |
| Decompiler readability | — | Not measured yet. Goal: a public corpus (open-source binaries with their sources) and a published score per release |

## Risks

| Risk | What we do about it |
| --- | --- |
| The decompiler stays behind Hex-Rays and Ghidra | Two architectures only, measured on a corpus; no breadth work while AArch64 pseudocode is missing |
| Prompt injection: strings in a sample address the agent | The MCP server tells clients that file content is data; writes are off by default and stay in memory; with `--redact-strings` the strings never reach the model at all; see [MCP.md § Security](MCP.md#security) |
| Redaction is trusted beyond what it covers | Its limits are listed next to the feature, in [MCP.md](MCP.md) and here |
| One maintainer | Recorded in [PSB.md](PSB.md); CI enforces the checks a reviewer would make |
| macOS distribution needs an Apple Developer ID for notarisation (paid, tied to the maintainer) | Unsigned builds first, the requirement stated in the roadmap; notarisation when the account exists |
