# Sentinel AI — local-model diagnostic assistant

Sentinel AI makes a **real**, opt-in request to a local OpenAI-compatible
chat-completions endpoint, such as the Ollama local API. It does **not** have
access to Sentinel commands, SSH sessions, credentials, tools, the terminal
buffer, files, system prompts from other users, or an operating-system shell.

```text
sentinel-ai ask question="How should I investigate a 502 reverse-proxy error?"
sentinel-ai explain diagnostic="Service returns HTTP 503 after deployment"
```

Only the explicit `question` or `diagnostic` argument is sent to the model.
Do **not** paste secrets, access tokens, passwords or private customer logs.
Output is advisory and untrusted. The AI cannot execute or approve changes.

## Setup and limitations

Default: `http://127.0.0.1:11434/v1/chat/completions`
Default model: `qwen2.5:7b`.

Operators may provision `SENTINEL_AI_MODEL` and
`SENTINEL_AI_ENDPOINT` in the trusted Sentinel **host environment**. Endpoint
policy permits only a literal loopback IP, HTTP, an explicit port and exactly
`/v1/chat/completions`. Hostnames, remote HTTPS, authentication in URLs,
redirects, query parameters, proxy settings and arbitrary URLs are rejected.
There are no API keys in plugin arguments or manifests.

The current marketplace Linux bubblewrap isolation disables networking,
including loopback access to the host model. Consequently **this source
is not yet compatible with the managed signed marketplace** and must not be
advertised as installable through `plugins install sentinel-ai`.
A future scoped host-side `ai.generate` broker or a properly secured
model bridge is required. Do not bypass the sandbox or run Sentinel as root.

No automatic command actions, orchestration, auto-fixing or remote tools exist.
The endpoint must be operated locally and authenticated/isolation-protected
by its owner; do not expose a local Ollama model to the public Internet.
