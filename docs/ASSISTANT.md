# AI assistant

The desktop app can ask a language model about the function under the cursor: explain it, suggest a name, or point out suspicious behaviour. It is off until you choose a model server in **Assistant → Settings**. For agents that drive Paranoia themselves (Claude Code, Codex, Cursor, OpenCode and others), see [MCP.md](MCP.md).

## Choosing a server

The settings dialog has presets. Pick one, press **Load models** to see what the server offers, choose a model, then **Test** to check that the endpoint, key and model answer. Test sends a fixed one-line prompt, never your code.

| Server | Endpoint | Notes |
| --- | --- | --- |
| Ollama | `http://127.0.0.1:11434/v1` | `ollama pull <model>` first |
| LM Studio | `http://127.0.0.1:1234/v1` | Start the server in LM Studio's Developer tab |
| llama.cpp | `http://127.0.0.1:8080/v1` | `llama-server -m model.gguf` (pass `--port` if 8080 is taken) |
| Jan | `http://127.0.0.1:1337/v1` | Enable the local API server |
| vLLM | `http://127.0.0.1:8000/v1` | `vllm serve <model>` |
| Claude | `https://api.anthropic.com/v1` | Anthropic API key; uses the Messages API |
| OpenAI / Codex | `https://api.openai.com/v1` | |
| OpenCode | `https://opencode.ai/inference/openai/v1` | OpenCode console API key |
| DeepSeek, Kimi, Gemini, Mistral, Grok, Groq, Together, OpenRouter | see the presets | OpenAI-compatible APIs |

Any other server that speaks the OpenAI `/v1/chat/completions` API works too: type its base URL.

Local servers keep everything on your machine. With a hosted one, the decompiled text of the function you ask about goes to that company. Paranoia asks you to confirm the host when you save it and again before the first request of each session. Only `localhost`, `127.x.x.x` and `::1` count as local. What that text contains is up to the privacy options below, and every request is recorded in a local disclosure ledger. Details are in [SECURITY-DESIGN.md](SECURITY-DESIGN.md#ai-assistant).

## Privacy: redaction and the disclosure ledger

Two opt-in checkboxes in **Assistant → Settings** decide what a request contains; both are off until you tick them.

- **Hide the file's strings** — every quoted literal becomes `"<str#N len=L>"`, and auto names made from strings (`aHelloWorld`) become `aRedactedN` with the same `N`. The numbers follow the file's string order, so a string keeps its number from one request to the next. This is the same rule as `paranoia mcp --redact-strings` ([MCP.md](MCP.md#redaction)).
- **Hide numbers that look like IP addresses** — dotted-quad IPv4 (`192.168.13.37`, `10.0.0.0/8`) and IPv6 literals (`fe80::1`, `2001:db8::1`, `::1`, `::ffff:192.168.1.1`) become `<ip#N>`, numbered in the order they appear in the request. Ordinary numbers, floats, times such as `12:34:56`, MAC addresses, identifiers like `std::vector` and version numbers that don't fit those shapes are left alone; a four-part number whose parts are all ≤255 is indistinguishable from an IPv4 address, so it is redacted too. This is the same rule as `paranoia mcp --redact-ips`.

The native consent dialog for a hosted model says which of the two is on before the first request of each session. Redaction is textual: an address stored as an integer (`0xC0A80D25`) or as encrypted data is not recognised, and function, import and export names are always sent.

Every request about a file is recorded before it is sent, in `assistant-ledger.jsonl` in the app's data folder. It is a JSON-lines file chained by SHA-256 — each line carries `prev`, the hash of the line before it: a `request` line with the time, host, task, which redactions were on, how many replacements were made and the SHA-256 of the exact messages, then an `answer` line with the SHA-256 and length of the reply. The code and the answer themselves are not written. If the request cannot be recorded, it is not sent; if the answer cannot be recorded, it is not shown. Delete the file to clear the history.

```json
{"event":"request","host":"api.example.com","local":false,"task":"explain","model":"…","redact_strings":true,"redact_ips":true,"redactions":{"strings":4,"ips":2},"request_sha256":"…","time":1762610400,"prev":null}
{"event":"answer","host":"api.example.com","task":"explain","response_sha256":"…","response_chars":1712,"time":1762610409,"prev":"…"}
```

## What has been tested

On 2026-11-11, against llama.cpp b12283 serving Qwen2.5-0.5B-Instruct (Q4_K_M) on Windows:

- model list, connection test and all three tasks went through the real HTTP path;
- **Explain** gave a correct summary of a `notepad.exe` function (heap allocation, `GetModuleHandleW("ntdll.dll")`, `GetProcAddress`);
- **Suggest a name** returned valid JSON, but the name was poor ("disassembly");
- **Flag suspicious behaviour** claimed process injection that isn't there.

So the plumbing works, and a model this small isn't good enough for naming or triage. Use a 7B or larger model locally (for example a Qwen2.5-Coder or Llama 3.1 build in Ollama), or a hosted model. The hosted presets were tested against recorded replies, not live accounts.

## Limits

- One function per request, up to 12 000 characters of pseudocode. No chat, no streaming yet.
- A suggested name is only applied when you click it.
- Requests time out after 300 seconds.
- Redaction covers the text form of the strings and addresses in the pseudocode. A string is hidden as a literal and as an auto name; an address stored as an integer, and anything encrypted or compressed, is not recognised.
