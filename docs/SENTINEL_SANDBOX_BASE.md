# Sentinel Sandbox v0.1 — implementation boundaries and follow-up tasks

**Status:** Code foundation, not a sandbox security feature or installer release.

## What this PR actually implements

- Source-only admin-disabled `sentinel-sandbox` Go plugin with `status`, `profiles`, `plan` and `doctor` commands; SML v3 informational views.
- Reusable `pkg/sandboxpolicy`: immutable profile structures, strict resource ceilings, offline/no-network/no-privileged/no-mount/no-GPU v1, fixed digest validation and policy hashing.
- Reusable `pkg/sandboxcore`: nil-backend fails closed; optional fake backend injection for tests; restricted fixture IDs and immutable digests; tenant+owner-bound status/cancellation; bounded global/per-owner admission; async lifecycle and cancellation signal.
- `cmd/sentinel-sandboxd`: read-only `doctor`, explicit no-listener/no-execution baseline and host-capability visibility checks. It never starts containers or processes.
- Local tests for fail-closed submission, cross-owner/tenant denial, resource and policy rejection, quota release, cancellation, CLI and plugin responses.

## What this PR **does not** implement

- Kernel-enforced sandbox/container/VM isolation or a real `Backend` implementation.
- Privileged or unprivileged control daemon, brokered authentication or remote worker protocol.
- Runtime resource enforcement (cgroups, seccomp, namespaces, Landlock or jailer).
- Persistent queue/restart recovery, forced termination of a misbehaving backend, distributed accounting, off-host immutable audit or signed runtime images.
- Any support for executing user-submitted or model-generated code, network access, cloud multi-tenancy or GPU jobs.

The profile examples deliberately use the **all-zero SHA-256 digest** as a conspicuous placeholder. The admission method rejects it. They must be replaced with operator-pinned and independently verified artifacts before a real runner is added.

## Important internal contracts

`Controller.Submit` accepts an `Identity` struct, but **that is not a user-facing API**. A future Sentinel core broker must derive principal, tenant and capabilities from authenticated state and pass an unforgeable scoped delegation. Never accept `Identity` values from SSH arguments, plugin JSON, HTTP request bodies or remote clients. `CanRun`, `CanSeeAll` and `CanCancelAll` in this package do not replace actual authorization or workspace checks.

`Backend.Ready` is a planning boundary. Its return value alone cannot prove secure isolation: a production implementation must use genuine OS capability checks, verified runtime configuration and negative isolation tests. `Backend.Run` must enforce hard resource ceilings, ensure no host secrets are mounted, terminate the complete guest process tree on timeout/cancel, and only return when cleanup is confirmed. The current manager's cancellation is **cooperative** and does not satisfy that guarantee for arbitrary backends.

`pkg/sandboxcore` has **in-memory lifecycle state**. The first production daemon must not rely on it for durable jobs, leases, accounting or crash recovery. Replace with a reconciled transactional store and fencing IDs before exposing a submit API.

## Work items in order

### P1: Core authorization and broker
- Extend capability vocabulary and core plugin host services with `sandbox.submit`, `sandbox.get`, `sandbox.list`, `sandbox.cancel`, `sandbox.logs` (optional bounded), `sandbox.profiles`.
- Independently authorize actor, role ceiling, rank restrictions, explicit denies, tenant/workspace, plugin identity, image and fixture digests and policy version.
- Require a separate authorization decision for network-enabled or GPU workloads; they remain disabled in v1.
- Introduce short-lived delegation, audience binding, anti-replay and revocation, plus immutable audit events.

### P2: Durable Linux worker
- Implement local Unix socket with file permissions, verified peer identity and application-layer delegation; no public TCP listener.
- Persist job state and owner/tenant with transactional leases, idempotency keys, forced cancellation and reconciliation on startup.
- Deny unknown runtime adapters and unsupported host features; implement node drain/kill switch.

### P3: OS isolation proof
- Add rootless OCI+gVisor integration on a **dedicated Linux worker**; pinned images, no host mounts, network off, seccomp and cgroup v2 budgets.
- Validate hard kill with nested fork-bomb/CPU/RAM/disk/log workloads and orphan-cleanup tests; use throwaway servers for adversarial cases.
- Add Firecracker+jailer as a separately reviewed strong backend. Do not downgrade hostile workloads to ordinary OCI.

### P4: End-to-end integration and release
- Connect signed fixtures and AI Lab; publish metrics only after the guest exits and results are verified.
- Confirm permissions and terminal rendering in PuTTY and other supported SSH clients.
- Extend signed marketplace packaging for SML/runtime assets without allowing arbitrary privileged plugin executables.
- Obtain independent security review and release only after full negative test suite and support/rollback procedures pass.

## Proposed operating principle

**Untrusted workloads must run on a disposable dedicated worker, not on the production Sentinel host.** The plugin asks for work; the trusted core broker authorizes it; the remote runner enforces it. The user-facing plugin cannot access Docker, host sockets, KVM or raw shell commands.
