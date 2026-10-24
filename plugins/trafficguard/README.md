# TrafficGuard — defensive log analysis and safe firewall planning

TrafficGuard analyzes explicitly supplied Nginx/Apache combined access-log samples
and builds **nonexecuting** iptables/ip6tables single-address change proposals.
It never reads private logs automatically, makes outbound requests, escalates
privileges, captures packets, edits firewall state or invokes a shell.

Commands in a Sentinel SSH session, after review and enablement:

```text
trafficguard analyze log="203.0.113.10 - - [24/Oct/2026:20:00:00 +0200] \"GET / HTTP/1.1\" 429 7"
trafficguard block-plan ip=1.1.1.1
```

The terminal quote/escape rules differ by SSH client. Supplying a log as a
single `log` argument is required. The plugin SDK enforces a 16 KiB request
limit; TrafficGuard additionally limits samples to 10 KB and reports only the
first ten clients by count. It is deliberately not a per-second detection engine.

## Security

This is a read-only, self-contained CLI using only standard Go libraries and
the pinned community SDK. Address parsing uses `net/netip`. Private, loopback,
link-local, multicast and unspecified IP addresses are rejected in firewall
plans. A planned DROP rule can still disrupt service and therefore **must not
be applied** without verified authorization, recovery access and a timed
rollback workflow.

### Future production firewall integration

Actual host traffic monitoring and firewall changes require a privileged,
audited host-side broker with:
- explicit admin/rank authorization and registered customer-owned server scope;
- approved changes with expiration time, maximum rules and per-tenant quotas;
- atomic snapshots and guaranteed rollback even on SSH disconnect;
- immutable before/after audit evidence and kill switch;
- iptables/nftables backend selection, not shell execution exposed to plugins.

Do not run Sentinel itself as root to grant plugins these abilities.

## Release status

Source contribution; **not** an approved public SSH marketplace release until
the installer-compatible archive is built, reviewed, signed, tested in Linux
bubblewrap, and added to a pinned release catalog.
