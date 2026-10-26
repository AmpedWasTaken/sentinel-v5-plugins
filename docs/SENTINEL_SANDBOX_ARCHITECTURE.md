# Sentinel Sandbox — architecture and implementation plan

**Status:** Design proposal, not an implemented or security-approved sandbox.  
**Date:** 2026-10-26  
**Target:** Reusable, optional first-party Sentinel V5 sandbox service and SSH/SML plugin.  
**Initial platform:** Hardened Linux worker nodes. Windows remains unsupported for executing untrusted jobs until a separately reviewed isolation backend exists.  
**First consumer:** Sentinel AI Lab; future consumers include developer tools, build/test plugins, plugin CI, controlled code evaluations and disposable lab tasks.

> **Non-negotiable boundary:** Installing or enabling this plugin must never grant arbitrary host shell, Docker-socket, KVM-device, filesystem or privileged container access to SSH users or other plugins. A security-sensitive broker and worker service enforce the policy independently of the UI.

## 1. Executive technical decision

**Do not implement a new container runtime or hypervisor in C.** C provides access to Linux system calls, not extra security privileges or inherently better isolation. Code written in C would add memory-corruption risk in precisely the privileged boundary that needs the smallest attack surface.

Recommended split:

| Component | Implementation | Privilege |
| --- | --- | --- |
| Sentinel SSH/TUI integration and plugin commands | Go, using current Sentinel plugin SDK | Unprivileged, no host socket access |
| Sentinel **core** sandbox broker and effective-capability checks | Go | Sentinel process, no raw workload execution |
| Sandbox controller and lifecycle daemon | Go | Dedicated identity; tightly scoped access to preconfigured runtimes |
| Strong isolation engine | Firecracker + its official jailer, or gVisor/runsc | Runtime-specific constrained supervisor |
| Development/trusted OCI engine | Supported rootless OCI/container runtime | Non-root daemon, dedicated environment |
| Optional native syscall helper | Tiny, auditable C **only if needed**, after proof existing runtimes cannot meet a requirement | Fixed, allowlisted action; no parsing commands |
| Benchmarks and language-specific tasks | Go/Python/Node/C++ *inside* sandboxes | No host privileges |

If a syscall helper is needed, prefer a safe higher-level interface or Rust where maintainability permits. Never expose "execute arbitrary command" through a privileged native bridge. Do not build a custom seccomp parser, container engine or kernel emulator.

## 2. Repository placement and ownership

- Community repository: \`plugins/sentinel-sandbox/\` — UI, command protocol, SML v3 views, documentation, user-facing validation.
- Sentinel core repository: \`internal/sandboxbroker/\` — **new, explicitly approved** host-service APIs, principal/tenant/workspace authorization, delegation token creation, audit hooks.
- Separate runner deployment/repository: \`sentinel-sandboxd\` — daemon with runtime adapters, policy engine, job state, resource controller and cleanup/reconciliation.
- AI Lab stays a separate plugin and requests approved sandbox jobs through a broker, never through arbitrary host process launching.
- Source code merged into a repository is **not** a signed, approved or installable marketplace release.

The core changes are required: the current \`exec-rpc\` plugin host APIs include namespaced storage, events, UI publish and aggregate metrics; they do **not** offer sandbox create/run/stop or arbitrary job scheduling. Current code-plugin worker processes are not general OS sandboxes.

## 3. Security goals, non-goals and threats

### Goals

1. A compromised guest workload cannot read Sentinel credentials, SSH keys, private host files, host runtime sockets, network interfaces or another workload's state.
2. Resource exhaustion by guests is bounded at the **runtime and kernel** layer, including CPU, RAM, process count, writable storage, log volume, duration and concurrent jobs.
3. Each operation is authorized on **principal, tenant, workspace, profile, plugin identity and requested resource scope**. A display rank alone never provides authority.
4. No workload receives internet connectivity, host networking, attached block devices, host mounts, metadata credentials, GPU devices or privileged Linux capabilities by default.
5. All artifacts are explicit, size-bounded, scanned/validated where appropriate, scoped to owner and immutable after completion.
6. Worker crashes and restarts cannot strand long-lived privileged workloads or silently bypass termination and audit.
7. A policy/runtimes capability mismatch must **fail closed**, not downgrade to a weaker backend.
8. Signed, pinned and reviewed runtime images; reproducible runs with recorded toolchain versions, policy version and hardware profile.

### Adversaries

- AI-generated or otherwise malicious programs running inside a job.
- Malicious input files, tarballs, source archives, symlinks, special files and decompression bombs.
- Authenticated users attempting cross-user/cross-tenant access, quota evasion, unauthorized egress or privileged profiles.
- A compromised community plugin attempting to call the daemon directly.
- A compromised guest attempting kernel/VM escape, side-channel leakage, infinite loops, fork bombs, I/O floods and artifact poisoning.
- A compromised worker node; mitigate blast radius with separate host/tenant placement, short-lived credentials and off-host audit.
  
### Explicit non-goals for v1

- No unrestricted SSH-to-container shell for general users.
- No customer-managed Docker socket, privileged containers or kernel module mounting.
- No GPU passthrough for anonymous untrusted workloads.
- No public multi-tenant SaaS claim or "escape-proof" guarantee.
- No host-network traffic testing or DDoS dispatch.
- No general VM administration/control-plane exposed to plugins.

## 4. Trust boundaries and data flow

\`\`\`text
SSH/TUI user + authenticated session
               |
               v
     Sentinel core authorization
 (principal, tenant, role, rank, denies,
  profile, quota, target and scope)
               |
               v
    Host capability broker [NEW]
    sandbox.submit/status/cancel/list
      | signed, bound delegation |
      v                            (policy decisions are repeated)
  Sentinel Sandbox plugin ---> sandboxd control API
      |                           |
      | view-only RPC data        +--> image/fixture verifier
      |                           +--> durable scheduler
      v                           +--> quota manager
    SML v3 dashboard             +--> runtime adapter
                                  |       |
                                  |       +--> rootless OCI / gVisor
                                  |       +--> Firecracker + jailer
                                  |
                                  +--> log/artifact collector
                                  +--> immutable audit/export
\`\`\`

**Only the core broker can mint a short-lived, single-purpose job delegation credential.** It binds the authenticated principal and active session, issuing plugin ID, tenant/workspace, exact profile/fixture digest, approved runtime class, maximum resources, expiry and a unique nonce. The daemon validates its signature, audience, replay status, scope and current policy. It must also support immediate policy revocation from Sentinel and cancel jobs affected by revocations; plugin-provided strings or arguments cannot override identity or permissions.

Local control traffic: Unix domain socket with strict filesystem permissions and peer credential validation plus application-layer delegation. Remote workers: mutually authenticated TLS with node enrollment/rotation, pinned role and separately verified signed job authorization. **Never** forward a host-privileged runtime socket into the plugin.

## 5. Profile model (immutable policy contract)

Users select **named, versioned profiles**, not arbitrary runtime flags. Admins publish profiles after validating them against a server-side schema. A profile contains:

\`\`\`yaml
api_version: sandbox.sentinel.dev/v1
id: python-safe-v1
security_class: guarded
runtime: gvisor
image_digest: sha256:<operator-pinned-real-digest>
entrypoint_id: python-eval-v1
filesystem:
  root_read_only: true
  tmpfs_mib: 128
  outputs_mib: 32
network:
  mode: none
resources:
  cpu_millicores: 1000
  memory_mib: 512
  pids: 64
  disk_mib: 256
  wall_seconds: 60
  max_output_bytes: 1048576
  max_artifacts: 8
policy:
  allow_gpu: false
  allow_host_mounts: false
  allow_privileged: false
  max_concurrent_per_principal: 1
\`\`\`

This is illustrative configuration, **not yet a supported manifest format**. Hash the canonical resolved policy and include the hash in each job's signed authorization, audit record and final result. Tenant admins may **narrow**, never expand, centrally approved ceilings.

Proposed backend classifications:

| Security class | Backend | Intended use | Availability gate |
| --- | --- | --- | --- |
| \`guarded\` | Rootless OCI with gVisor \`runsc\` | General disposable testing in separately hardened Linux workers | Linux/runtime requirements pass; negative tests pass |
| \`strong\` | Firecracker microVM + official jailer | Hostile/generated code, external user submissions | KVM, patching, guest/host hardening, release security review |
| \`trusted-dev\` | Rootless OCI (without gVisor) | Reviewed developer-controlled builds | Explicit admin-only assignment; **never** auto-select for untrusted jobs |

Use a stronger backend when available, but never silently replace an unavailable strong backend with a weaker one. GPU execution is a separate node class and requires dedicated hardware, a documented IOMMU/device exposure model and independent risk sign-off. Firecracker is **not** assumed to provide general GPU passthrough.

## 6. Isolation controls (layered, not marketing claims)

### Host and daemon

- Dedicated Linux worker host(s) separate from Sentinel's production SSH/auth/database server.
- Minimal patched OS, locked-down service identity, scoped cgroup delegation, no login shell, restricted runtime and storage paths.
- Drop ambient capabilities, enable \`no_new_privs\` where compatible, AppArmor/SELinux policies, no unchecked host mounts.
- If Firecracker is used, follow the official host-setup and jailer recommendations: KVM device control, Firecracker's default seccomp filters, dedicated UID/GID, restrictive paths, namespaces and cgroups.
- Supervise \`sandboxd\` under systemd; keep a separate worker-side kill switch; preserve a host-level emergency shutdown.
- Only admin-approved fixture and base image sources. Verify SHA-256 pin and signing/trust policy before launch. Prevent writable supply-chain mount paths.

### Guest isolation

- Read-only root filesystem; fresh temporary writable overlay/workdir per job; encrypted ephemeral disk if at-rest sensitivity warrants.
- Deny capabilities, privileged mode, device mounting, host PID/IPC/network namespaces, Docker socket, \`/dev/kvm\` and unnecessary \`/proc\`/\`/sys\` interfaces to guests.
- cgroup v2 enforcement: \`cpu.max\`, \`memory.max\`, \`pids.max\`, I/O throttling/quotas as supported; overlay/tmpfs storage accounting; \`cgroup.kill\` on teardown when available.
- Seccomp profiles through maintained runtime components; optional Landlock/AppArmor/SELinux as defense in depth and capability-tested on each supported kernel.
- Set RLIMITs where helpful but **never** rely on RLIMITs alone for containment.
- Wall clock measured by daemon monotonic deadline. Escalating termination with forced kill, cleanup and leak-detection; a disconnected SSH session does not unbind authorization or bypass expiration.

### Network and model inference

- Default: no vNIC and no egress. DNS, loopback/metadata access and any communication with the daemon are denied from the guest.
- Explicit network-required profiles use a *separate controlled egress proxy* with approved destination policy, IP-range/metadata blocks, DNS rebinding defense, rate and byte quotas and detailed logging.
- AI Lab invokes operator-managed inference via a **host-side narrow inference broker**; guest code never gets a model API token, Ollama listener access or raw HTTP proxy.
- No credential/environment inheritance. Only scoped one-use tokens injected for an authorized task; omit entirely for offline code runs.

## 7. API and capabilities

Versioned local API, with protobuf/gRPC or an equally strict framed transport. Examples below are **contracts to implement**, not commands available today.

\`\`\`text
sandbox.submit       -> job_id, accepted_at, resolved_policy_hash
sandbox.get          -> status/progress/limits/attestation/exit reason
sandbox.list         -> owner-scoped paginated jobs
sandbox.cancel       -> accepted; separate confirmed termination event
sandbox.logs         -> bounded, escaped and paginated, cursor-based
sandbox.artifacts    -> typed, signed metadata and short-lived download grants
sandbox.profiles     -> only profiles visible to the authenticated principal
sandbox.nodes        -> admin-only redacted node health/capability
\`\`\`

Proposed Sentinel permission model:

- \`sandbox.read.own\`, \`sandbox.run\`, \`sandbox.cancel.own\`
- \`sandbox.read.all\`, \`sandbox.cancel.all\` (admin/operator policy-gated)
- \`sandbox.profiles.manage\`, \`sandbox.nodes.manage\`, \`sandbox.audit.read\` (admin only)
- \`sandbox.network.request\` (separate, explicit approval path; never implied by \`sandbox.run\`)
- \`sandbox.strong.run\` and \`sandbox.gpu.run\` (only after their isolation readiness gates)

At every API entry and **inside daemon executor**: effective-role ceiling + account denies + tenant + profile + explicit cap + resource limits + policy epoch/revocation. All list/get/cancel responses owner-filtered at storage query level. A command may enqueue a job; no RPC command may wait for a 20-minute guest process.

## 8. State machine and durability

\`\`\`text
requested -> validating -> queued -> provisioning -> running
                                  |                    |
                                  v                    v
                               rejected            collecting
                                                      |
                                    completed / failed / timed_out
                                    cancelled / policy_revoked
                                                      |
                                               cleaning -> cleaned
                                                      |
                                           cleanup_failed (alert)
\`\`\`

- Postgres or SQLite WAL with single-writer discipline for **single-node v1**; PostgreSQL recommended for multi-node.
- DB transaction contains job owner, tenant, immutable fixture/image/policy hashes, lease/fencing token, idempotency key, timestamps, backend, node, status, quotas, result hash and audit sequence.
- Scheduler supports at-least-once delivery **without at-least-once execution of side-effecting commands**: allocate job with a single fenced lease; reconcile actual VM/container identity before restart; never blindly replay work after timeout.
- Persist desired cancellation independently; executor checks it and terminates. Status transitions must remain monotonic and auditable.
- On daemon restart reconcile every in-flight runtime, clean unknown/orphan sandboxes, preserve evidence, revoke expired delegation credentials.
- Retention: configurable, default short; secure deletion of ephemeral data and documented limits for storage/VM snapshots.
- Output streams are byte-limited and UTF-8/ANSI-sanitized before TUI display. Keep raw bounded artifacts only in a separate access-controlled store.

## 9. UX and integration

Planned CLI examples (not yet implemented):

\`\`\`text
plugins install sentinel-sandbox           # only after a signed release
plugins enable sentinel-sandbox
sandbox doctor
sandbox profiles
sandbox run profile=python-safe-v1 fixture=hello-python-v1
sandbox list
sandbox show id=<job-id>
sandbox logs id=<job-id>
sandbox stop id=<job-id>
sandbox results id=<job-id>
sandbox nodes                              # admin only
\`\`\`

Do not accept \`sandbox run --privileged\`, raw container runtime arguments, free-form bind mounts, arbitrary shell strings or an arbitrary image URL. A controlled developer profile can accept packaged source artifacts by digest with strict path traversal, symlink, device file, decompression and total-size validation. Build steps run **inside** the guest.

SML v3 screens:

- \`dashboard.sml\` — slots available, running/queued, recent jobs, failures and backend health.
- \`job.sml\` — live state, quota bars, clock, cancellation status, policy class and denial reason.
- \`profiles.sml\` — available capabilities, explicit limitations and security classes.
- \`results.sml\` — exit status, sealed output checksums, logs and reproducibility metadata.
- \`admin.sml\` — queue health, node drain, orphan count, policy revisions and kill switch.

Terminal colors are semantic and subtle; narrow PuTTY-compatible fallback avoids fancy Unicode box assumptions. Do not reveal host paths, credentials or raw errors to unprivileged users.

## 10. AI Lab and third-party plugin integration

AI Lab becomes a **consumer**, not the sandbox owner:

1. User selects model, versioned benchmark suite and one approved execution profile.
2. AI Lab creates a run manifest and asks the core broker for authorization.
3. Broker freezes policy and submits the work to \`sandboxd\` (or delegates model requests to inference broker).
4. AI Lab receives a job ID and polls/receives bounded progress, not host privileges.
5. Generated program is compiled/executed **inside a strong sandbox only**; fixture runner computes pass/fail and writes signed results.
6. A result includes suite version, fixture digest, runner image, backend security class, resource consumption, elapsed time, token info when actually reported and validity flags.
7. A failed or unavailable sandbox yields **no score**; do not silently mark tasks passed or switch to plain host exec.

Other plugins use the same \`sandbox.submit\` contract. Every caller has an allowlisted plugin ID and a maximum set of runnable profile IDs. Plugins cannot delegate their identity to other plugins.

## 11. Benchmarks and acceptance tests

### Unit and integration

- Manifest schema fuzzing; reject duplicate YAML keys, unknown fields, overlong inputs, ambiguous Unicode and noncanonical resource names.
- Broker authorization matrix: revoked role, denied rank, expired account, cross-tenant accesses, replayed token, changed policy digest, missing node capability.
- Deterministic state-machine tests for crash/restart, duplicate submit, repeated cancel, lease expiry, partial output and migration rollback.
- Real PTY/SSH tests on small and large terminal widths; SML action authorization.
- Runtime integration tests on genuine Linux kernels with supported namespaces/KVM and independent CI hardware; mock-only tests cannot claim security properties.

### Negative isolation suite — release blockers

| Attempt from guest | Required observation |
| --- | --- |
| Read preplaced host-only canary/SSH key | Denied; no canary bytes in logs |
| Reach host, metadata address, peer guest or internet | Denied in offline profile |
| Open runtime/control socket or \`/dev/kvm\` | Denied |
| Escalate privileges, mount host filesystem, join host namespaces | Denied |
| Fork bomb, memory flood, CPU saturation, disk/log exhaustion | Bounded and terminated; host stays healthy |
| Symlink, tar traversal, hardlink and device-file import | Rejected before launch |
| Kill/control another tenant's job via guessed job ID | Denied at core, broker and daemon |
| Policy revocation / cancellation during active job | Actual processes stop within verified bound |
| Worker daemon crash / node reboot | Orphans reconciled or quarantined; alert on failed cleanup |
| Fake metrics/results or malicious ANSI from guest | Cannot spoof terminal commands or trusted results |
| Runtime/KVM unavailable or configured policy unsupported | Fail closed; no insecure fallback |

### Exit gates

- **Development:** unit + integration tests, disposable runner, no customer uploads.
- **Private pilot:** KVM/gVisor backend proof, negative suite, durable cancellation and orphan cleanup, scoped per-user audit, security review.
- **Public single-tenant:** independently reviewed security model, signed artifacts/SBOM, patch policy, backups/restore, telemetry, incident runbook, production hardening.
- **Multi-tenant SaaS:** independent penetration test and isolation red team, off-host audit, tenant network/storage separation, MFA, quotas, abuse review, disaster recovery and data handling agreements.

No "production-ready" claim merely because an OCI container starts.

## 12. Milestones and GitHub issue breakdown

| Phase | Deliverable | Prerequisite / definition of done |
| --- | --- | --- |
| **P0 / Design** | ADR, threat model, policy schema, Linux capability survey and proof-of-concept test harness | Review by at least one maintainer other than author; no guest execution shipped |
| **P1 / Core broker** | \`sandbox.*\` capabilities, per-principal auth, delegation, deny precedence, audit contracts | Cross-tenant and revoked-session negative tests; no raw shell bridge |
| **P2 / Linux controller** | Go \`sandboxd\`, durable job lifecycle, resource policy, cancellation, supervisor | Bounded jobs and restart reconciliation proven on disposable host |
| **P3 / First guarded backend** | rootless OCI + gVisor adapter, pinned images, no egress, cgroup quotas | Negative isolation suite + renderer smoke tests |
| **P4 / SSH plugin** | Go \`sentinel-sandbox\`, SML v3 dashboards, explicit admin install workflow | Can run/monitor/cancel safe fixtures; no unauthorized job access |
| **P5 / Strong backend** | Firecracker+jailer microVM adapter and ephemeral guest image pipeline | KVM host validation, no fallback, independent isolation review |
| **P6 / AI Lab integration** | Coding execution with signed fixtures, sandboxed grading, reproducible results | Only strong profile executes AI-written code |
| **P7 / Distributed nodes** | mTLS enrollment, quotas, node pools, drain/reconcile, durable event stream | Tenant/node access tests, failure injection, signed upgrades |
| **P8 / Optional advanced** | Dedicated GPU workers, scheduling, policy templates, CI/webhooks | Dedicated hardware threat model; independent audit |

Do **not** make advanced scheduling or monetization block baseline safety. Security controls, containment, cancellation and basic auditing remain free.

## 13. Example default resource ceilings (proposal; revise per workload)

| Profile | CPU | Memory | PIDs | Disk writable | Wall timeout | Network | Concurrency |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| \`python-safe-v1\` | 1 vCPU | 512 MiB | 64 | 256 MiB | 60 s | None | 1/user |
| \`go-build-v1\` | 2 vCPU | 2 GiB | 128 | 1 GiB | 120 s | None | 1/user |
| \`agent-code-v1\` | 2 vCPU | 2 GiB | 128 | 1 GiB | 180 s | Brokered model only | 1/user |
| \`plugin-review-v1\` | 1 vCPU | 1 GiB | 64 | 512 MiB | 90 s | None | Admin only |

Resource values are conservative **illustrations** and must be capacity-tested. Separate systemwide/tenant budgets apply, e.g. a default two active sandbox slots per worker host, queue ceiling, daily CPU-seconds, output-byte budgets and automatic cancellation when a grant is revoked. VM overhead must be accounted for in node allocations.

## 14. Cross-platform and operational notes

- Linux is the only proposed initial execution host. Sentinel's SSH/TUI UI can operate on Windows while dispatching to a separately enrolled Linux worker **only after** remote authorization and mTLS exist.
- Windows "managed plugin execution" currently fails closed under the marketplace's Linux-only isolation. Do not weaken that policy as a shortcut.
- Windows-native sandbox backends (Hyper-V/Windows Sandbox) need their own design, kernel boundaries, deployment privileges and independent testing; **out of v1 scope**.
- A lightweight Windows GUI/CLI controller may manage Linux jobs via approved authenticated APIs, but is not itself evidence of isolation.
- Separate local-model inference traffic from benchmark guest network access; keep Ollama/local LLM endpoints bound to trusted interfaces and require brokered quotas.
- Never market a sandbox as "impossible to escape." Track runtime/kernel CVEs and emergency mitigation/disable controls.

## 15. References and implementation reading

- [Linux cgroup v2 resource controllers](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Landlock userspace API and limitations](https://docs.kernel.org/userspace-api/landlock.html)
- [gVisor architecture and syscall mediation](https://gvisor.dev/docs/architecture_guide/intro/)
- [Firecracker production host recommendations](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Docker rootless mode and constraints](https://docs.docker.com/engine/security/rootless/)
- Sentinel core: \`docs/plugin-app-runtime.md\`, \`docs/production-readiness.md\`, \`docs/access-control.md\`
- Community plugin: \`plugins/ai-lab/README.md\`

### Open architecture decisions

1. Local API transport: protobuf/gRPC over Unix socket vs small framed binary protocol. Neither may carry arbitrary shell argv or self-asserted identities.
2. v1 secure backend: gVisor-first for convenient dev environments or Firecracker-first for external/untrusted execution; **AI code requires strong isolation policy**.
3. Required Linux distribution/kernel baselines, user namespace configuration, SELinux/AppArmor support, KVM availability.
4. Dedicated \`sandboxd\` repository vs monorepo subproject; release signing/updater ownership.
5. How Sentinel issues a revocable delegated job token with current session/role state.
6. Isolation/retention requirements for customer artifacts and tenancy.
7. GPU worker host threat model; do not commit to GPU guests until researched.

**Recommendation:** Begin with P0/P1 and a Linux runner prototype that cannot see the Sentinel host's production state. No custom C sandbox engine is required to start.
