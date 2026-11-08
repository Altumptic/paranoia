# MCP server: Paranoia for AI agents

`paranoia mcp` serves the analysis engine over the [Model Context Protocol](https://modelcontextprotocol.io), so an agent (Claude Code, Claude Desktop, Cursor or any MCP client) can open a binary, list its functions, read pseudocode and disassembly and follow cross references. It is part of the `paranoia` command-line tool: there is no plugin to install, no other application to keep running and no Python bridge.

## Get the tool

- **Windows:** download `paranoia-cli-vX.Y.Z-windows-x64.exe` from [Releases](https://github.com/Altumptic/paranoia/releases/latest) (first release after v0.7.0), check it ([VERIFY.md](VERIFY.md)), and rename it to `paranoia.exe` if you like.
- **Any OS, from source:** `cargo install --path crates/paranoia-cli` (Rust 1.82 or newer). Linux and macOS binaries are not published yet ([roadmap](ROADMAP.md)).

## Connect a client

Replace the paths with yours. `--root` is the folder the agent may open files from; repeat it for more folders.

**Claude Code**

```bash
claude mcp add paranoia -- paranoia mcp --root /path/to/samples
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor** (`~/.cursor/mcp.json`) and other clients that use the same format:

```json
{
  "mcpServers": {
    "paranoia": {
      "command": "C:\\Tools\\paranoia.exe",
      "args": ["mcp", "--root", "D:\\samples"]
    }
  }
}
```

Then ask, for example: *"Open D:\samples\invoice_update.exe, find the functions that call CreateFileW and explain what they write."*

## Options

| Option | Effect |
| --- | --- |
| `--root DIR` | Folder files may be opened from (repeatable). Without it, the current working directory |
| `--allow-writes` | Also offer `rename`, `set_comment` and `rename_variable`. Changes stay in the server's memory for this session; `export_idc` gives them back as an IDC script |
| `--redact-strings` | The file's string contents never reach the agent ([below](#redaction)) |
| `--ledger FILE` | Append every answer to `FILE` before sending it; if that fails, the answer is withheld ([below](#disclosure-ledger)) |
| `--workspace [FILE]` | Share names with the desktop app. On `open_binary` the analyst's names, comments, types and patches are loaded from the app's workspace (without a value: the app's own, `%APPDATA%\Paranoia\workspace.redb` on Windows, `~/.config/Paranoia/` on Linux, `~/Library/Application Support/Paranoia/` on macOS). With `--allow-writes`, every rename or comment is saved there at once. The app locks its workspace while it runs: then nothing is loaded, and a change is refused and undone — close the app, or work without `--workspace` |

For a confidential sample with a hosted model, the recommended start is:

```bash
paranoia mcp --root D:\cases\0412 --redact-strings --ledger D:\cases\0412\agent-ledger.jsonl
```

## Tools

All tools take an optional `binary` (an id returned by `open_binary`; default: the last opened file). Addresses are hex (`0x401c04` or `401c04`) or a function, export or import name; a name wins over a hex reading (`add` is the function, not `0xadd`).

| Tool | Returns |
| --- | --- |
| `open_binary` | Loads and analyses a file under a root; id, format, architecture, entry and counts |
| `list_binaries` | Files opened in this session |
| `binary_info` | Format, architecture, entry, hashes, sections, mitigations, warnings |
| `list_functions` | Functions with instruction, block and reference counts (`filter`, `offset`, `limit`) |
| `decompile` | C-like pseudocode of the function containing the address (x86 / x64) |
| `disassemble` | Instructions from an address (`count` up to 500) |
| `function_graph` | Basic blocks and their edges |
| `xrefs_to` | Code and data references to an address |
| `callees` | Functions and imports the function calls |
| `list_strings`, `list_imports`, `list_exports` | Filterable, paged lists |
| `search` | Functions, names and strings matching a query |
| `triage` | One line per function: what it calls (imports first) and which strings it references; library functions and thunks left out unless `include_library`. The quickest way to pick functions to decompile (kernel32.dll: all 2 604 functions, opening included, in 1.2 s) |
| `export_idc` | An IDC script with the session's names, comments and functions |
| `rename`, `set_comment`, `rename_variable` | Only with `--allow-writes`; saved to the workspace with `--workspace` |

Each result is plain text, at most 60 000 characters; longer output is cut with a note that says how to narrow the request. Lists say how many items exist and which `offset` gives the next page.

## Controlled disclosure

### Redaction

With `--redact-strings`, every answer is filtered before it is sent:

- quoted literals — in pseudocode, listings, comments, `list_strings`, `search`, `triage` and `xrefs_to` — become `"<str#N len=L>"`;
- auto names made from strings (`aHelloWorld`) become `aRedactedN`, with the same `N` as the literal.

Numbers are given in the file's string order when it is opened, so they do not depend on what the agent asks first and stay the same for the session. The agent is told about the placeholders in the server's instructions. To see what `str#N` is, look it up in the app or in a run without redaction.

Not redacted: function, import, export and section names; numbers in code (an IP address stored as a constant); the arguments the agent sends — a `search` for a word reveals whether the file contains it; `export_idc` output is redacted like everything else, so it is not usable as an IDC script in this mode.

### Disclosure ledger

With `--ledger FILE`, the server appends one JSON line per event to `FILE` (created if missing, never truncated) and syncs it to disk before answering:

```json
{"event":"session","version":"0.7.0","roots":["D:\\cases\\0412"],"allow_writes":false,"redact_strings":true,"time":1762610400,"prev":null}
{"event":"tool","tool":"decompile","arguments":{"address":"sub_401C04"},"file_sha256":"1e47…","is_error":false,"redactions":2,"chars":2068,"sha256":"45ee…","text":"// sub_401C04 at 0x401c04\n…","time":1762610412,"prev":"9c1f…"}
```

`text` is exactly what the agent received and `sha256` is its hash, so the record can be checked against a client's transcript. `prev` is the SHA-256 of the line before (also across sessions appended to the same file), so the lines form a chain. If a line cannot be written (disk full, file removed), the agent gets an error instead of the answer. The ledger contains the disclosed text itself — keep it with the case files.

Check a ledger:

```bash
paranoia ledger D:\cases\0412\agent-ledger.jsonl
```

It prints how many answers, characters and redactions each tool produced and which files they concerned, and exits with status 2 if any text no longer matches its hash or the chain is broken (a line removed, inserted or changed). What it cannot prove: that nobody rewrote the whole file from some line onward with fresh hashes — for that, keep a copy of the last line's hash elsewhere (for example in the case notes) or sign the file.

## Security

The server follows the same rules as the rest of Paranoia ([SECURITY-DESIGN.md](SECURITY-DESIGN.md)).

- **No network.** It reads requests on stdin and writes answers on stdout. It opens no sockets.
- **Confined files.** `open_binary` resolves the path (symbolic links included) and refuses anything outside the `--root` folders. Files larger than 1 GiB are refused.
- **Read-only by default.** Write tools are not even listed unless `--allow-writes` is given. They never touch the analysed file, and they touch the desktop app's workspace only with `--workspace`.
- **The sample is hostile.** Strings, symbol names and comments come from the file's author. A string such as "ignore previous instructions and …" is data. The server's `instructions` tell the client so, but whether a model obeys text it reads is up to the model and the client: keep write tools off for untrusted samples, review what an agent proposes, and use `--redact-strings` so string contents never reach the model.
- **Where the text goes.** Paranoia sends nothing. Your MCP client sends what the tools return to the model it uses. With a hosted model (Claude, GPT, …) that includes the pseudocode, listings and strings the agent asked for — minus what `--redact-strings` removes, and all of it recorded if you use `--ledger`. For no egress at all, use a client with a local model.
- **Crashes.** A panic while answering a tool call is caught and reported as a tool error; the server keeps running.

## Limits

- Pseudocode for x86 / x64 only; for other architectures use `disassemble` and `function_graph`.
- Names are shared with the desktop app only through `--workspace`, and only while the app is closed (its workspace is locked while it runs). The app reads the names when it next opens the file.
- No MCP resources or prompts yet; tools only. No progress notifications for long analyses (a 7.7 MB DLL takes about a second).
- Protocol revisions 2025-06-18, 2025-03-26 and 2024-11-05.
