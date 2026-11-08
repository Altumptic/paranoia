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
| `export_idc` | An IDC script with the session's names, comments and functions |
| `rename`, `set_comment`, `rename_variable` | Only with `--allow-writes` |

Each result is plain text, at most 60 000 characters; longer output is cut with a note that says how to narrow the request. Lists say how many items exist and which `offset` gives the next page.

## Security

The server follows the same rules as the rest of Paranoia ([SECURITY-DESIGN.md](SECURITY-DESIGN.md)).

- **No network.** It reads requests on stdin and writes answers on stdout. It opens no sockets.
- **Confined files.** `open_binary` resolves the path (symbolic links included) and refuses anything outside the `--root` folders. Files larger than 1 GiB are refused.
- **Read-only by default.** Write tools are not even listed unless `--allow-writes` is given, and they never touch the analysed file or the desktop app's workspace.
- **The sample is hostile.** Strings, symbol names and comments come from the file's author. A string such as "ignore previous instructions and …" is data. The server's `instructions` tell the client so, but whether a model obeys text it reads is up to the model and the client: keep write tools off for untrusted samples and review what an agent proposes.
- **Where the text goes.** Paranoia sends nothing. Your MCP client sends what the tools return to the model it uses. With a hosted model (Claude, GPT, …) that includes the pseudocode, listings and strings the agent asked for. For no egress at all, use a client with a local model.
- **Crashes.** A panic while answering a tool call is caught and reported as a tool error; the server keeps running.

## Limits

- Pseudocode for x86 / x64 only; for other architectures use `disassemble` and `function_graph`.
- Names and comments made through MCP are not shared with the desktop app (planned: an opt-in link to the app's workspace, see the roadmap).
- No MCP resources or prompts yet; tools only. No progress notifications for long analyses (a 7.7 MB DLL takes about a second).
- Protocol revisions 2025-06-18, 2025-03-26 and 2024-11-05.
