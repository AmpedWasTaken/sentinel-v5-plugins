# Sentinel Native Sandbox — experimental custom Linux runtime

**Status: SECURITY RESEARCH PREVIEW ONLY. NOT production-ready. NOT a Docker/gVisor replacement.**

This is the beginning of a **Sentinel-owned runtime** using C for a minimal single-purpose guest launcher and Go for immutable policy admission, cgroup v2 supervision and job orchestration. There are no Docker, Podman, OCI, gVisor or Firecracker runtime dependencies for this experimental path. There is **no authenticated Sentinel SSH plugin broker** and absolutely **no permission to run arbitrary external/customer/AI-produced code yet**.

## Architecture

```
operator-owned JSON profile (NOT from user/SSH input)
    -> Go sandboxnative.Backend.Ready
        -> pin/check rootfs tree hash and executable SHA256
        -> check approved cgroup v2 delegated subtree
    -> Go sandboxcore.Controller.Submit (local only)
        -> create per-job cgroup / cpu.max / memory.max / memory.swap.max / pids.max
        -> launch C executable, BLOCKED on FD3
        -> attach process to job cgroup, THEN unblock FD3
           -> C unshare userns + map caller uid/gid
           -> unshare mount/ipc/uts/net/pid namespaces; fork PID1
           -> new private mounts; readonly bind + pivot_root + detach old root
           -> independent bounded noexec tmpfs at /tmp
           -> no_new_privs, capability drop, seccomp filter, close_range
           -> sanitized environment and fixed execv path from approved config
        -> bounded digest-only stdout/stderr, timeout, cgroup.kill, cleanup
```

**Current scope** is small statically linked Linux/amd64 fixtures with no dynamic libraries or procfs requirements. No general-purpose distro image unpacking, build kit, dev shell, network access, GPU, multi-tenant access, OCI image compatibility, graphical programs, arbitrary volume mounts or remote runner available.

## Security properties and limitations

- Rejects root launcher execution and refuses to execute without delegated cpu/memory/pids cgroup v2 controls and a `cgroup.kill` file. The process waits behind a pipe gate until moved into its quota cgroup.
- C launcher requires non-root user and root-owned, non-world/group-writable rootfs. Go checks every guest file is ordinary (no symlinks/devices) and that rootfs path/mode/content tree matches a pinned SHA-256 profile digest. SHA-256 is **not a signature**; operator controls trust and protects files from concurrent mutation.
- Guest gets no host network namespace, new PID/mount/IPC/UTS/user namespaces, no procfs mount, private mount propagation, pivoted read-only filesystem, bounded tmpfs, and no host bind mounts or inherited descriptors.
- C seccomp checks x86-64 ABI, denies x32 and selected high-risk syscalls including mount, unshare, ptrace, kernel/module loading, BPF, and namespace creation. **This is a denylist defense in depth, not a comprehensive syscall allowlist, and is not proof of secure containment.** Kernel documentation explicitly states seccomp alone is not a sandbox.
- A Linux kernel vulnerability or namespace/configuration error could still allow escape. This is NOT suitable for untrusted users without hostile-case isolation testing and independent security review.
- C group `memory.max`/`pids.max`/`cpu.max` are set per job; `memory.swap.max=0` and `cgroup.kill` are required. Writable /tmp is limited to 1024 MiB. Output is hashed (first bounded bytes only), discarded, and rejected on overflow.
- Cancellation kills the cgroup, then the top-level process. Startup/cgroup failures do not release the child startup gate. Cleanup retries are best-effort; no durable orphan reconciliation or independent host watchdog yet.
- The Go/SSH broker from the main Sentinel repository does not yet implement session-bound sandbox capabilities, delegation, revocation or tenant scope at daemon boundary. The current API's `Identity` model is only for internal trusted code. There is no public TCP socket or shell RPC.
- The initial C policy is architecture-specific. Linux arm64/Windows/macOS are unsupported, and run-local from the old Docker runner remains separate.
- Isolation tests that truly launch guest workloads **have not been run**. CI can test strict rejection, Go controller logic and build the C helper, but cannot substitute for security verification on a real Linux host.

## Directory layout

- `cmd/sentinel-sandbox-init/main.c`: C rootless namespace launcher; **must never be setuid**.
- `pkg/sandboxnative/backend.go`: Go cgroup-supervised runtime implementing `sandboxcore.Backend`.
- `cmd/sentinel-native/main.go`: dedicated operator-only local CLI (`digest`, `doctor`, `run`).
- `pkg/sandboxpolicy/profile.go`: adds experimental `native` runtime type; existing gVisor/Firecracker retained.

## Build

```
go test ./pkg/sandboxnative ./cmd/sentinel-native ./pkg/sandboxpolicy ./pkg/sandboxcore
go test -race ./pkg/sandboxnative ./cmd/sentinel-native
go vet ./pkg/sandboxnative ./cmd/sentinel-native
gcc -std=c11 -Wall -Wextra -Werror -O2 -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
    -o sentinel-sandbox-init ./cmd/sentinel-sandbox-init/main.c
go build -o sentinel-native ./cmd/sentinel-native
```

Operator must separately install `sentinel-sandbox-init` into a **root-owned location with no write access for the worker user**, provision a minimal root-owned immutable guest rootfs, and prepare a dedicated delegated cgroup v2 directory. Do **not** run as root, do not run on your production Sentinel machine, do not expose the controller from SSH, and do not grant a writable Docker or cgroup control socket to plugins. A Linux host may explicitly forbid unprivileged user namespaces; **do not weaken host hardening** to make this experiment run.

### Example conceptual operator config (placeholder hashes; not runnable)

```
{
  "profile": {
    "id":"native-minimal-v1", "version":1, "runtime":"native",
    "image_digest":"sha256:REPLACE_WITH_ACTUAL_TREE_HASH",
    "entrypoint_id":"hello-v1", "cpu_millicores":500,
    "memory_mib":128, "pids":16, "disk_mib":64,
    "wall_seconds":10, "max_output_bytes":4096, "max_artifacts":0,
    "network":"none", "read_only_root":true,
    "allow_privileged":false, "allow_host_mounts":false,
    "allow_gpu":false
  },
  "native": {
    "launcher":"/usr/local/libexec/sentinel-sandbox-init",
    "rootfs":"/var/lib/sentinel-sandbox/verified/hello-rootfs",
    "cgroup_root":"/sys/fs/cgroup/sentinel-operator",
    "entrypoint":"/bin/hello-static",
    "fixture_id":"hello-v1", "fixture_digest":"sha256:REPLACE_WITH_ACTUAL_FIXTURE_HASH"
  }
}
```

To compute digests on a disposable host, use:

```
sentinel-native digest --rootfs /var/lib/sentinel-sandbox/verified/hello-rootfs --fixture /bin/hello-static
sentinel-native doctor --config /etc/sentinel-sandbox/approved.json
sentinel-native run --config /etc/sentinel-sandbox/approved.json
```

`doctor` is a **preflight check**, not an attestation. `run` executes only the pinned static fixture, not a caller-supplied shell command. Start with harmless fixtures on an isolated lab host; not with untrusted user code.

## Unfinished release blockers / next commits

1. Formal attack-surface review of C launcher; mount traversal, uid/gid, inherited FD, seccomp ABI and kernel behavior across tested kernels.
2. Harden the rootfs source with immutable tree leasing or protected readonly snapshot, close verification-to-execution TOCTOU and verify all parent directories.
3. Implement durable orphan tracking/reconciliation, watchdog and guaranteed cgroup cleanup on SIGKILL/worker reboot.
4. Dedicated host service with authenticated Unix socket, broker-derived principals/tenants, capability checks, scope binding, revocation and separate immutable audit trail.
5. Full negative isolation suite on real unprivileged KVM/dev worker: filesystem host canaries, namespace escapes, dangerous syscalls, nested forks, memory pressure, /tmp exhaustion, signals and fatal cleanup.
6. Migrate beyond static demos to verified immutable fixture bundles with mount-independent filesystems and safe image supply chain.
7. Add default-deny explicit seccomp allowlists per workload, Linux Security Module policy (Landlock/AppArmor/SELinux) and independent security review.
8. Only after all above, consider AI Lab integration; no claim of multi-tenant or arbitrary untrusted code safety.

**Do not deprecate the gVisor implementation based solely on this experimental C runner.** Existing reviewed/supported runtimes remain the recommended execution path until independent adversarial testing shows a convincing security and reliability case for this native backend.

Kernel references:
- [user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [seccomp/filter](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [pivot_root](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
