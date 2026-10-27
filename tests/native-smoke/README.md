# Manual isolated launcher smoke test

**Not a release isolation test.** The direct test sends the FD3 startup byte without a cgroup controller to inspect the C guest launcher independently. This **does not test CPU/RAM/process quotas, crash recovery, or the full Go supervisor**; it must never be exposed to SSH users. Run only in a disposable Linux host/container with unprivileged user namespaces enabled. The regular Go runtime still enforces cgroup membership before releasing its gate.

The operator creates a root-owned minimal rootfs and compiles a harmless, statically linked fixture:

```
sudo mkdir -p /var/lib/sentinel-sandbox/lab-rootfs/{bin,tmp}
sudo chmod 755 /var/lib/sentinel-sandbox/lab-rootfs/{,bin,tmp}
sudo gcc -static -O2 -Wall -Wextra -o /var/lib/sentinel-sandbox/lab-rootfs/bin/native-smoke tests/native-smoke/fixture.c
sudo gcc -std=c11 -Wall -Wextra -Werror -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -o /usr/local/libexec/sentinel-sandbox-init cmd/sentinel-sandbox-init/main.c
sudo chmod 755 /usr/local/libexec/sentinel-sandbox-init
sudo chown -R root:root /var/lib/sentinel-sandbox/lab-rootfs
```

Run `tests/native-smoke/smoke.py /usr/local/libexec/sentinel-sandbox-init /var/lib/sentinel-sandbox/lab-rootfs` as a non-root user. Expected: PID 1, cannot open host `/etc/passwd`, cannot mount or unshare again, can create in `/tmp` only and cannot write to the guest's read-only `/`. A nonzero exit indicates a failure or unavailable host prerequisite. This does **not** prove resistance to hostile escape attempts. Clean up disposable files after the test.
