# Security policy

## Scope

This public repository accepts community plugin **source**, manifests and views. A submitted PR, successful validation workflow, or a matching SHA-256 does **not** establish that a plugin is safe, approved or runnable without isolation.

Executable code plugins can access the operating-system privileges available to their host process. Sentinel's current plugin runtime is **not** a complete OS sandbox. Never run unreviewed community code on production or privileged hosts.

## Report a vulnerability privately

**Do not open a public issue containing an unpatched exploit, secrets, tokens, or sensitive infrastructure data.**

Use GitHub's private vulnerability reporting if it is enabled for this repository (**Security → Report a vulnerability**). Otherwise contact the maintainers through a private channel before publishing technical exploit details. We do not publish an unverified security email address here.

Please provide a concise description, affected plugin/revision, reproducible steps, impact and recommended remediation. Redact secrets and customer data. Maintainers will triage reports as resources allow; no response or remediation SLA is promised.

## Community submission rules

- Never commit passwords, API keys, live tokens, private keys, sessions or real customer exports.
- Prefer read-only behavior and scope requests to the smallest necessary role, host capability, path and endpoint.
- Disclose file, process, network and host-service access in each plugin README.
- Do not add opaque binaries, packaged malware, booters, credential harvesting or privilege bypasses.
- Keep `enabled: false` in submitted manifests.
- Review dependencies and pin versions where possible; scanners cannot prove code is benign.

## Trust and releases

The repository's CI intentionally does not execute arbitrary submitted plugin code. Reviewers must inspect source, dependencies and build artifacts independently.

An installer-provided checksum protects against unexpected byte changes relative to an approved hash; it is **not** proof of safe behavior or publisher identity. Publication requires separate verification and administrator approval.

See [Review process](docs/REVIEW_PROCESS.md).
