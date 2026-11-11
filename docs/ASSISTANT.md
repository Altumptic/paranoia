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

Local servers keep everything on your machine. With a hosted one, the decompiled text of the function you ask about goes to that company. Paranoia asks you to confirm the host when you save it and again before the first request of each session. Only `localhost`, `127.x.x.x` and `::1` count as local. Details are in [SECURITY-DESIGN.md](SECURITY-DESIGN.md#ai-assistant).

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
