# Ticket 16 — Loopback proxy and egress allowlist (operator log)

Branch: `ticket/16-loopback-proxy-egress-allowlist`
Commits: feature `ee1a05d1c6`; merge of `integration/mxc-windows-sandbox` (ce1c9116f2) → `3599b54650`
Base: ca5a9f01f1 → merged integration tip ce1c9116f2 (tickets 13+14) before reporting done

## Decisions

- 2026-10-13 Sidecar-owned proxy per ADR 0003 Model 2. One egress proxy per proxied run (allowlist is per-command policy; proxies are never shared). `withEgressProxy` wraps the runtime; `toSdkRequest` composes `egress deny + ingress allow + hostLoopback allow + runtimeConfig.networkProxy` for proxy runs. Unpackaged Node sidecar ⇒ identity-less path; `allowedProxyPeer` not applicable (documented deviation).
- 2026-10-13 No Proxy-Authorization on the sidecar proxy: MXC sets per-container WinHTTP proxy config and env vars without credentials; a 407 would break WinHTTP clients. Containment (WFP endpoint pinning) is the authorisation; host processes are trusted computing base.
- 2026-10-13 CONNECT tunnels dial only after a TLS ClientHello with matching SNI validates (parity with the audited macOS proxy); plain HTTP forwarded for absolute-URI requests; resolved addresses must be public (RFC1918/loopback/link-local/CGNAT/transition/multicast refused) so DNS rebinding cannot relay into host-private networks.
- 2026-10-13 CIDR relaxations replace the hostname allowlist for the runs they govern (MXC rejects direct rules alongside `networkProxy`); they are recorded as `egress relaxation: <cidrs> [proto:port]` warnings on every such run.
- 2026-10-13 Starter allowlist default-on via `resolveEgressPosture`: unset `allowed_hosts` under restricted network → starter registries/git-over-HTTPS; trim to deny-all = `network: "deny"` or `allowed_hosts: []` (one edit each). `network: "deny"` now always means deny-all (previously hosts could override it to proxy mode — tightened, noted in report).
- 2026-10-13 `sdk.ts` maps cidr `to: string[]` → wire `NetworkPeerConfig` structs `{ cidr }` (live probe rejected the string form; fixed from the typed parse error).
- 2026-10-13 client.ts hardened: a sidecar that dies mid-request no longer hangs its caller — pending waiters reject on socket close and post-close calls reject immediately (found via a hanging test finally; bounded-race tests cover both).
- 2026-10-13 Merge with tickets 13+14: union of RunUi (GUI kill switch off — node/git/PS need USER32) + my RunEgress union; union of grant-table (credential-store denial, cache redirection) + egress composition + proxy-env stripping in `translate`.

## Activity

- Sidecar: `proxy.ts` (loopback HTTP/S proxy), `egress.ts` (per-run proxy lifecycle + relaxation warnings), `destination.ts`/`tls-client-hello.ts` vendored dependency-free from kilo-sandbox (unit ships src only), `run.ts` RunEgress union + validation, `sdk.ts` Model 1/2/3 composition + `RunBindings`, `main.ts` shutdown wiring, `client.ts` close-rejection.
- kilo-sandbox: `egress.ts` (starter allowlist, `normalizeCidrRules`, `resolveEgressPosture`), `profile.ts` `allowedCidrs`, `mxc.ts` egressOf + proxy-env strip + proxy-mode support flip, index exports.
- opencode: `allowed_cidrs` schema + validation, resolve via posture helper, snapshot/policy plumbing (limits/matches/intersect/execute).
- Tests: sidecar 96 (proxy 9, egress wrapper 6, sdk 10, run validation 11 incl. UI contract); kilo-sandbox mxc 44 + egress 11 + probe 11 (node:test; `.ts` specifiers added where the node runner needs them — bun compatible).
- Live (probe-gated, base-container host): registry metadata flows through the real sidecar proxy (allow), example.com fails closed (deny), empty allowlist denies (trim), cidr relaxation to example.com's resolved /32:443 enables the flow with the recorded warning (denied without it), proxy-pinned run refused fail-closed (`hostLoopback='allow'` typed error — host lacks `baseContainerSupportsIngressHostLoopbackAllow`), inbound listener in-container (node) + host loopback connect denied.

## Caveats

- This host cannot host the identity-less Model 2 flow (`baseContainerSupportsIngressHostLoopbackAllow: false`); the live proxy-pinned test asserts MXC's typed fail-closed refusal here and contains the full allow/deny/trim flow for capable hosts (PSEC 1.1 ingress) — unexercised on this machine.
- Full npm install optional per ticket; covered with registry metadata via curl (express/latest) through the real proxy.
- 0xC0000142 in-container init failures of node/git/PowerShell during ticket work were caused by the UI kill switch (DisallowWin32kSystemCalls vs USER32.dll) — resolved by ticket 13's `ui.disable: false`; the inbound listener live test now runs for real (initially skipped with that reason).
- opencode package cannot be fully typechecked on this host (no bun, no workspace node_modules); changed files typechecked via a stripped tsconfig against junctioned deps — only pre-existing host-only errors (unresolved `@opencode-ai/*`) remain. CI with the full tree must confirm.
- 228 oxlint warnings on the merged tree = 0 errors; warning classes match the repo baseline (plus type-aware plugin noise from the same unresolved deps).
