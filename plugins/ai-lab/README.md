# Sentinel AI Lab — Go plugin (developer preview)

AI Lab is an opt-in, **admin-only** persistent Go plugin that benchmarks a
locally operated OpenAI-compatible language model. The first milestone offers
reproducible instruction-following, arithmetic, and *code comprehension* smoke
tests with scores, latency and reported completion-token counts. It does **not**
execute model-produced code and is **not** a SWE-bench or GPU throughput suite.

**Status: source-only / NOT released / NOT marketplace-compatible.** Current
marketplace isolation blocks loopback networking and `exec-rpc` package layouts;
installing through `plugins install ai-lab` is not supported. Running a trusted
plugin outside the managed sandbox is an administrator-only developer workflow,
not a security substitute. The daemon should not run as root.

## Developer setup (controlled local host only)

1. Provision an **operator-managed** Ollama/OpenAI-compatible
   `/v1/chat/completions` service listening only on `127.0.0.1` (or `::1`).
   Install/pull the desired model separately. Do not expose Ollama publicly.
2. Build with `go build -o ai-lab ./plugins/ai-lab` from the community repo.
   On a disposable Sentinel dev host, place reviewed source-derived executable
   at `assets/plugins/ai-lab/bin/ai-lab` (`ai-lab.exe` on Windows) and this
   `plugin.yaml` + `views/bench.sml` in the plugin directory.
3. Configure host-approved `plugins.trusted_code=true`, and if necessary set
   `SENTINEL_AI_LAB_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions`
   **in the Sentinel server process environment**, not a user command.
   Confirm endpoint isolation separately; don't weaken the managed marketplace
   worker sandbox to make networking function.
4. As an administrator, enable the manually installed plugin and use:

```text
plugins enable ai-lab
ai-lab suites
ai-lab run model=qwen2.5-coder:7b suite=code-v1
ai-lab results
ai-lab status id=<16-char-run-id>
ai-lab cancel id=<16-char-run-id>
```

Commands are explicitly denied to non-admins by the manifest. The model name
is an allowlisted identifier, **not a shell command or URL**. The endpoint
only accepts a literal loopback HTTP IP, valid explicit port and exact
`/v1/chat/completions` path. No request proxy or redirects are used.

## Behavior and limits

- Fixed, versioned 3-question suites (`sanity-v1`, `code-v1`). Input prompts
  never use user-provided files, secrets, shell commands or network targets.
- One active run per plugin worker, max 20 in-memory result records.
- Each model request has a 35-second deadline, each run a 120-second deadline.
- Cancellation is cooperative through Go request contexts.
- Background model execution immediately returns a run ID so Sentinel's
  short RPC command timeout is not held up by model inference.
- `status` shows correctness counts, test progress, mean *whole-request*
  latency and completion tokens **only when reported by the model endpoint**.
  Missing token usage is shown as zero; no token/sec or TTFT is claimed.
- Scores are strict against known short answers, so variance and prompt
  sensitivity can reduce scores; results are a smoke test, not a comprehensive
  quality ranking. No AI-written program is run in this milestone.
- State is process-local and lost on plugin restart/reload. Plugin crash and
  host shutdown may interrupt jobs without persistence.
- Nothing charges a fee; optional licensing and commercial packaging can be
  added later without restricting local baseline checks.

## Development checks

```sh
go test -race ./plugins/ai-lab
python scripts/validate_plugins.py
```

## Next milestone — actual isolated agent benchmarks

Implement a dedicated Linux worker with namespace/microVM isolation, no
host-secret mounts, resource quotas, egress deny-by-default, image pinning,
per-job ephemeral workspaces, timeout/kill support and audited policy checks.
Only then execute generated code/test suites, with signed fixtures and
repeatability controls. Extend marketplace packaging and brokered local-model
access rather than loosening the current plugin sandbox. Add durable
per-tenant results and fine-grained permissions before a production launch.
