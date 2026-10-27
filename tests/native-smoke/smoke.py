#!/usr/bin/env python3
"""Operator-triggered launcher-only smoke test. NOT a full cgroup/security audit.

Runs as unprivileged user. Its hand-written FD3 gate bypasses the Go controller
so CPU/memory/pids quotas are NOT tested here; use only a disposable worker.
"""
import os
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        print("usage: smoke.py /absolute/sentinel-sandbox-init /absolute/rootfs", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("refusing root execution", file=sys.stderr)
        return 2
    reader, writer = os.pipe()

    def before_exec():
        os.dup2(reader, 3)
        if reader != 3:
            os.close(reader)

    try:
        process = subprocess.Popen(
            [sys.argv[1], "--rootfs", sys.argv[2], "--tmp-mib", "16", "--wall-sec", "5", "--", "/bin/native-smoke"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(reader, 3) if reader != 3 else (reader,), preexec_fn=before_exec,
        )
        os.close(reader)
        os.write(writer, b"!")
        os.close(writer)
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        os.close(reader)
        os.close(writer)
        raise
    print(stdout.decode(errors="replace"))
    print(stderr.decode(errors="replace"), file=sys.stderr)
    print("exit", process.returncode)
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
