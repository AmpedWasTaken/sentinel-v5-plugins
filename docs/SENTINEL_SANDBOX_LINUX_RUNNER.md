# Sentinel Sandbox — actual Linux OCI execution, milestone P3 (experimental)

**Status:** An actual, **local-only** Docker/gVisor backend is implemented in `pkg/sandboxoci`. It has not been validated on a real worker node in CI or by an independent security assessment. It is **not** wired into Sentinel's SSH plugin, is **not** a public multi-user sandbox, and is **not** an approved marketplace release.

## What now runs

`sentinel-sandboxd run-local` on a **dedicated disposable Linux worker** can execute an operator-allowlisted, digest-pinned container image/fixture with the Docker runtime explicitly set to `runsc` (gVisor). It verifies rootless Docker, cgroup v2, systemd cgroup delegation, registered `runsc`, existing local image repository digest, read-only root filesystem, container resource policy, denied networking, dropped capabilities, and container exit state. It captures a bounded output hash and force-removes the container after exit, error, or cooperative cancellation. Docker CLI subprocesses are invoked without a shell.

This is a useful working isolation backend, but the launcher has **not** yet been tested on a host with a real rootless Docker + runsc installation. Safety properties need adversarial live testing before you treat the runner as secure for untrusted inputs.

## Why this is NOT exposed as `sentinel-sandbox run` over SSH yet

The Sentinel core broker and owner/session/tenant-bound delegation protocol do **not** exist yet. A plugin process must not be able to access the Docker socket (even a rootless Docker socket grants control over that user's containers and processes). Consequently the current `sentinel-sandbox` SSH plugin stays informational; only the operator of the isolated Linux worker can call `sentinel-sandboxd run-local` directly. **Never** add a shortcut using `os/exec`, a raw Docker socket, user-supplied CLI arguments, or a public HTTP listener in the plugin.

## Operator prerequisites

1. Separate non-production Linux VM/host with patched kernel and cgroup v2/systemd delegation. Run all commands as an unprivileged dedicated account. **Never run `sentinel-sandboxd` as root.**
2. Install and configure a supported **rootless** Docker daemon with Docker CLI at `/usr/bin/docker`. The Docker UNIX socket must be owned by the executing account and be located in a non-world-writable directory.
3. Install and register the official gVisor `runsc` runtime with that **rootless daemon** under the name `runsc`; verify it via `docker info`. There is no fallback to `runc`.
4. Operator reviews a fixture OCI image, signs/verifies its release separately, and explicitly pulls it using a specific registry digest (not a mutable tag). The image **must not** declare `VOLUME` entries, and should have a short deterministic entrypoint with no network requirements.
5. Preload the exact pinned `registry/name@sha256:<64-lowercase-hex>` image and create a JSON config with only approved profiles and their approved fixed fixture args. Image signature governance is an additional release gate: a content digest alone does not authenticate the publisher.

The code checks Linux socket ownership, Docker rootless/security status, cgroup v2 driver, runtime registration, image pin, and container HostConfig *before* starting a workload. The check is not a kernel isolation certification.

## Minimal config shape (placeholders are deliberately not executable)

Save as `/home/sandboxd/approved-sandboxes.json` owned by your dedicated sandbox user, not writable by group/others:

```json
{
  "version": 1,
  "docker_socket": "/run/user/1000/docker.sock",
  "profiles": [
    {
      "id": "python-safe-v1",
      "version": 1,
      "runtime": "gvisor",
      "image_digest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX_DIGEST",
      "entrypoint_id": "hello-v1",
      "cpu_millicores": 1000,
      "memory_mib": 512,
      "pids": 64,
      "disk_mib": 256,
      "wall_seconds": 60,
      "max_output_bytes": 65536,
      "max_artifacts": 0,
      "network": "none",
      "read_only_root": true,
      "allow_privileged": false,
      "allow_host_mounts": false,
      "allow_gpu": false
    }
  ],
  "fixtures": [
    {
      "id": "hello-v1",
      "profile_id": "python-safe-v1",
      "image_ref": "registry.example.org/approved/fixture@sha256:REPLACE_WITH_SAME_64_HEX_DIGEST",
      "args": ["--fixture=hello-v1"]
    }
  ]
}
```

These placeholders **must** be replaced with a real independently reviewed registry digest before validation succeeds; neither example is a real artifact or installer endpoint. The JSON fixture identity is calculated from its immutable ID, profile, image reference and arguments inside the controller, not chosen by the SSH user.

## Building and running (on the dedicated Linux worker only)

```sh
go test -race ./pkg/sandboxpolicy ./pkg/sandboxcore ./pkg/sandboxoci ./cmd/sentinel-sandboxd
go vet ./pkg/sandboxpolicy ./pkg/sandboxcore ./pkg/sandboxoci ./cmd/sentinel-sandboxd
go build -o sentinel-sandboxd ./cmd/sentinel-sandboxd
./sentinel-sandboxd doctor
./sentinel-sandboxd run-local --config /home/sandboxd/approved-sandboxes.json --profile python-safe-v1 --fixture hello-v1
```

The output is a JSON job record with a final state, an exit code on success and the SHA-256 of the bounded combined output. The guest stdout is not streamed back over SSH. On Ctrl+C/SIGTERM the Go runner requests cancellation, stops the Docker CLI and force-removes the named container using a separate short-lived cleanup context.

## Effective enforcement and deliberate limitations

- Docker create uses `--runtime=runsc`, `--network=none`, `--read-only`, `--cap-drop=ALL`, `no-new-privileges`, UID/GID 65534, private PID/IPC namespaces, a short pids limit, CPU quota, memory+swap quotas, bounded tmpfs `/workspace` and `/tmp`, small `/dev/shm`, bounded local container logs, no arbitrary bind mounts or Docker device requests, fixed image and fixed argv. The controller reads the resulting Docker HostConfig and refuses to start if required limits are absent or mismatched.
- No source/artifact import from users is implemented. Guest code is limited to the operator's preloaded immutable image and arguments. It is **not** a generic `docker run` wrapper and has no `shell=true` shortcut.
- Job state is **in memory**. The controller cannot recover jobs or prevent orphaned containers if the daemon is abruptly SIGKILLed or the host powers off. The current runner is **not production ready** without durable state, safe reconciliation, node quarantine, fail-safe cleanup and off-host audit.
- Only a fixed local operator can submit a job by invoking the process directly. The core broker/mTLS/token revocation and per-tenant permissions are still missing.
- Disk size is bounded through memory-backed tmpfs, rather than a fully accounted persistent overlay-layer quota. This is not a general disk-quota solution. The image must not declare volumes.
- No Firecracker backend, GPU passthrough, egress policies, multi-node scheduling, signing service or tool-calling bridge exists.
- The backend tests use a fake Docker CLI to verify arguments, policy checks, denial scenarios, effective HostConfig requirements, failure cleanup and nonzero/OOM detection. **No real Docker/gVisor workload ran in CI.**

## Next gates

1. Live test the runner with a small reviewed/signed digest-pinned fixture image on a disposable Linux worker, including egress attempts, host file access attempts, resource exhaustion, log floods, timeouts and process tree cleanup. Obtain an independent negative-test report.
2. Implement server-side durable jobs, active-container reconciliation and quarantine when cleanup cannot be verified.
3. Build the authenticated Sentinel core broker with host capability delegation and revocation; never proxy user-supplied runtime flags.
4. Connect the sandbox plugin and AI Lab through the broker only after the preceding checks pass.
5. Add Firecracker separately for hostile generated code and a security-class enforcement policy that never silently downgrades to a weaker backend.
