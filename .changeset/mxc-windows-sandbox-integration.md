---
"@kilocode/cli": minor
"kilo-code": minor
---

Windows MXC sandbox (integration/mxc-windows-sandbox): the sandbox backend for Windows gains the Microsoft MXC engine as a full backend — NT-kernel-mode grant tables, the sidecar's loopback egress proxy with a normalised hostname allowlist, recorded CIDR/port relaxations, and per-session relaxations granted through the TUI (`/sandbox-relax` dialog) or the `/session/:id/sandbox/relax` route, each recorded in the session log with its config|prompt source. Adds the host-gate route (`/session/:id/sandbox/gate`) with abort / continue-unsandboxed choices, a TUI gate dialog and status indicator, and audit-mode sessions that run unsandboxed while logging the grant table each command would have had.

Performance note: the enforced per-command ceiling is kept as a regression guard, not the spec's budget — full-stack per-command overhead measured ~440–470 ms median per trivial confined command vs ~30 ms for a bare MXC SDK spawn; a session-scoped sidecar is the recorded optimisation follow-up.
