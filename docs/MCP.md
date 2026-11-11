# MCP server

`paranoia mcp` lets an AI agent (Claude Code, Claude Desktop, Cursor or any other MCP client) use the engine: open a binary, list functions, read pseudocode and disassembly, follow cross references. It's part of the `paranoia` command-line tool, so there's nothing else to install or keep running.

## Getting it

Download it from [Releases](https://github.com/Altumptic/paranoia/releases/latest): `paranoia-cli-vX.Y.Z-windows-x64.exe` (rename it to `paranoia.exe` if you like), or `paranoia-cli-vX.Y.Z-<linux|macos>-<arch>.tar.gz` for Linux (x64, ARM64) and macOS (ARM64, x64) from v0.8.0 on. You can also build it with `cargo install --path crates/paranoia-cli`.

## Connecting a client

`--root` is the folder the agent may open files from. You can give it more than once.

Claude Code:

```bash
claude mcp add paranoia -- paranoia mcp --root /path/to/samples
```

Claude Desktop (`claude_desktop_config.json`), Cursor (`~/.cursor/mcp.json`) and clients with the same format:

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

Gemini CLI (`~/.gemini/settings.json`) uses the same `mcpServers` format.

OpenCode (`opencode.json`, or `~/.config/opencode/opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "paranoia": { "type": "local", "command": ["paranoia", "mcp", "--root", "/path/to/samples"] }
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.paranoia]
command = "paranoia"
args = ["mcp", "--root", "/path/to/samples"]
```

Then ask something like "open D:\samples\invoice_update.exe, find the functions that call CreateFileW and explain what they write".

The model behind the agent is the agent's business: any model your client supports, hosted or local, can use these tools. For the AI assistant built into the desktop app, see [ASSISTANT.md](ASSISTANT.md).

## Options

- `--root DIR`: a folder files may be opened from. Without it, the current directory.
- `--allow-writes`: also offer `rename`, `set_comment` and `rename_variable`. Changes are kept in memory for the session; `export_idc` returns them as an IDC script.
- `--redact-strings`: the file's string contents never reach the agent (see below).
- `--ledger FILE`: write every answer to `FILE` before sending it. If that fails, the answer isn't sent.
- `--memory [FILE]`: offer `recognize_functions`, which looks the open file up in the function knowledge base ([FUNCTION-MEMORY.md](FUNCTION-MEMORY.md)). Without a path it uses the app's own `memory.redb`. With `--allow-writes` the tool can also apply the names it finds.
- `--workspace [FILE]`: share names with the desktop app. Names, comments and types are loaded from the app's workspace when a file is opened, and with `--allow-writes` each change is saved back. Without a path it uses the app's own workspace (`%APPDATA%\Paranoia\workspace.redb` on Windows, `~/.config/Paranoia/` on Linux, `~/Library/Application Support/Paranoia/` on macOS). The app locks the workspace while it's open, so close it first.

For a confidential sample and a hosted model:

```bash
paranoia mcp --root D:\cases\0412 --redact-strings --ledger D:\cases\0412\agent-ledger.jsonl
```

## Tools

Every tool takes an optional `binary`, the id `open_binary` returned (default: the last file opened). Addresses can be hex (`0x401c04` or `401c04`) or a function, export or import name. Names are tried first, so `add` means the function `add`, not `0xadd`.

| Tool | What it returns |
| --- | --- |
| `open_binary` | Loads and analyses a file: id, format, architecture, entry point, counts |
| `list_binaries` | Files opened in this session |
| `binary_info` | Format, hashes, sections, mitigations, warnings |
| `list_functions` | Functions with their size and reference counts |
| `triage` | One line per function with what it calls and which strings it uses. A good first step |
| `decompile` | Pseudocode of the function at an address |
| `disassemble` | Instructions from an address |
| `function_graph` | Basic blocks and edges |
| `xrefs_to` | References to an address |
| `callees` | What a function calls |
| `list_strings`, `list_imports`, `list_exports` | Lists, with `filter`, `offset` and `limit` |
| `search` | Functions, names and strings matching a query |
| `compare_binaries` | Matches the functions of two open binaries: shared code, changed functions (least similar first), functions in only one of them |
| `recognize_functions` | Only with `--memory`: functions the knowledge base knows from other files, with the remembered name and how similar the code is |
| `export_idc` | The session's names and comments as an IDC script |
| `rename`, `set_comment`, `rename_variable` | Only with `--allow-writes` |

Results are plain text and capped at 60 000 characters. Long lists say how many items there are and which `offset` to use for the next page.

## Redaction

With `--redact-strings`, every answer is filtered before it goes out. Quoted strings in pseudocode, listings, comments and lists become `"<str#N len=L>"`, and auto names made from strings (`aHelloWorld`) become `aRedactedN` with the same `N`. The numbers follow the file's string order, so the same string has the same number for the whole session. To find out what `str#N` is, look at the file in the app.

For example, the same function from `notepad.exe` as the agent sees it, first as is and then with `--redact-strings`:

```c
v6 = GetModuleHandleW(L"ntdll.dll");
v6 = GetProcAddress(v6, "RtlDisownModuleHeapAllocation");
```

```c
v6 = GetModuleHandleW(L"<str#35 len=9>");
v6 = GetProcAddress(v6, "<str#36 len=29>");
```

The agent can still see that two strings are passed to these calls and how long they are, but not what they say.

It doesn't hide function, import, export or section names, numbers in the code (an IP address stored as an integer, for example), or what the agent itself searches for: a `search` for a word tells the agent whether the file contains it. `export_idc` output is redacted too, so it isn't a usable IDC script in this mode.

## Ledger

With `--ledger FILE`, the server appends one JSON line per answer and syncs it to disk before replying:

```json
{"event":"session","version":"0.7.0","roots":["D:\\cases\\0412"],"allow_writes":false,"redact_strings":true,"time":1762610400,"prev":null}
{"event":"tool","tool":"decompile","arguments":{"address":"sub_401C04"},"file_sha256":"1e47…","is_error":false,"redactions":2,"chars":2068,"sha256":"45ee…","text":"// sub_401C04 at 0x401c04\n…","time":1762610412,"prev":"9c1f…"}
```

`text` is exactly what the agent got, `sha256` is its hash, and `prev` is the hash of the previous line, so the lines form a chain. The file contains the disclosed text itself, so keep it with the case notes.

To check a ledger:

```bash
paranoia ledger D:\cases\0412\agent-ledger.jsonl
```

This prints what each tool returned and for which files, and exits with status 2 if a text doesn't match its hash or a line was removed, added or edited. It can't detect someone rewriting everything from some point on with new hashes. If that matters, write down the hash of the last line somewhere else, or sign the file.

## Security

- The server talks over stdin and stdout and never opens a socket.
- `open_binary` resolves the path, including symlinks, and refuses anything outside `--root`. Files over 1 GiB are refused.
- Write tools only exist with `--allow-writes`. They never change the analysed file, and only touch the app's workspace with `--workspace`.
- Strings and names come from whoever made the file. A string like "ignore previous instructions" is just data, and the server tells the client so, but whether the model listens is up to the model. Keep write tools off for untrusted files and check what the agent suggests. `--redact-strings` keeps the strings away from the model entirely.
- Paranoia itself sends nothing anywhere. Your MCP client sends the tool results to its model, so with a hosted model the pseudocode and strings the agent reads leave your machine. Use a local model if nothing may leave.
- If something panics while answering, the agent gets an error and the server keeps running.

## Limits

- Pseudocode for x86/x64, and AArch64 experimentally. For other architectures use `disassemble` and `function_graph`.
- Sharing names with the app only works while the app is closed.
- No MCP resources or prompts, no progress notifications.
- Supported protocol versions: 2025-06-18, 2025-03-26, 2024-11-05.
