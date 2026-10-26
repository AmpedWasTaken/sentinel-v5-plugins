# Sentinel Sandbox — source-only foundation (v0.1)

**Not an operational sandbox.** This is the first source milestone for a reusable sandbox plugin for Sentinel V5. It does not run programs, create Docker containers, access KVM, expose a control socket, or make host changes. The intended backend is a separate, reviewed Linux worker accessible only through a new authenticated core capability broker.

The checked-in plugin demonstrates **read-only** commands and SML v3 views against Sentinel's existing one-shot Go plugin SDK.

## Commands (manual development install only)

```text
sentinel-sandbox status
sentinel-sandbox profiles
sentinel-sandbox plan profile=python-safe-v1
sentinel-sandbox plan profile=agent-code-v1
sentinel-sandbox doctor
```

`status` and `plan` use SML presentation assets; `doctor` and `profiles` return text. None of these commands performs sandbox execution. The two example profiles use an all-zero SHA-256 image **placeholder**; a future scheduler rejects it and must require a verified image and fixture digest.

The plugin is **disabled by default** and **admin-only**. No `sandbox run` command exists yet. A manifest role is not a substitute for the planned broker's authorization checks.

## Build and test from the community repository

```sh
go test ./pkg/sandboxpolicy ./pkg/sandboxcore ./plugins/sentinel-sandbox ./cmd/sentinel-sandboxd
go test -race ./pkg/sandboxpolicy ./pkg/sandboxcore ./plugins/sentinel-sandbox ./cmd/sentinel-sandboxd
go vet ./pkg/sandboxpolicy ./pkg/sandboxcore ./plugins/sentinel-sandbox ./cmd/sentinel-sandboxd
go build -o sentinel-sandbox ./plugins/sentinel-sandbox
go run ./cmd/sentinel-sandboxd doctor
python scripts/validate_plugins.py
```

For a disposable, manually reviewed development host, copy the compiled binary to `assets/plugins/sentinel-sandbox/bin/sentinel-sandbox`, alongside `plugin.yaml` and `views/*.sml`; use the existing opt-in trusted-code feature and only enable as an administrator. **Do not** bypass the managed plugin sandbox to run untrusted executable plugins. Current signed installer packaging accepts only strict native two-file archives and does not support SML assets.

The module packages are shared foundations:

- `pkg/sandboxpolicy` — schema, fixed resource ceilings, deny-by-default flags and canonical policy hash.
- `pkg/sandboxcore` — admission, optional verified backend abstraction, job ownership, concurrency limits, cancellation and terminal state transitions. A nil backend always rejects job submission.
- `cmd/sentinel-sandboxd` — read-only Linux prerequisite inspection (`doctor`) only; **no server/listener** and no code-execution mode.
- `plugins/sentinel-sandbox` — read-only Sentinel SSH/SML interface.

**Crucial:** `sandboxcore.Backend` is an *interface for future implementation*, not an isolation guarantee. Tests use fake in-process backends for lifecycle validation. Any real adapter must enforce memory/CPU/PID/disk/time/network limits at the kernel or VM boundary, guarantee teardown before `Run` returns, verify pinned images and fixtures, and pass negative isolation tests on actual hardware. Current controller state is in-memory and lost on process restart.

## Roadmap and security gates

1. Implement Sentinel core `sandbox.submit/get/cancel` broker capabilities with authenticated identity, tenant/workspace scope and immutable delegated policies. Do not let plugins contact a privileged daemon directly.
2. Implement Linux `sandboxd` restricted control API, durable job state and policy-revocation/timeout recovery.
3. Add a guarded rootless OCI+gVisor adapter with real cgroup v2 enforcement and negative escape tests.
4. Add Firecracker+jailer backend for untrusted AI-generated code with a separate worker host.
5. Connect AI Lab only after runner attestation, immutable fixture packaging, SML smoke tests and third-party review.
6. Add managed signed packaging and Windows-controller-to-Linux-runner transport through a separate reviewed protocol.

See [architecture proposal PR #22](https://github.com/AmpedWasTaken/sentinel-v5-plugins/pull/22) and `docs/SENTINEL_SANDBOX_BASE.md`.
