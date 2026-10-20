#!/bin/sh
set -eu
mkdir -p build-local
for name in netcatty pktpeek portfox sysmon reqr dnsdig certcheck logtail latency socktop filewatch docktop sshwatch hookbin ioclookup; do
  printf 'building %s\n' "$name"
  go build -o "build-local/$name" "./plugins/$name"
done
