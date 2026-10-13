# 19: Probe-gated enforcement suite and perf budget

Branch: `ticket/19-enforcement-suite-perf-budget`, base `0a1c4f4e20` (integration tip; merge-base verified equal before starting and before reporting).

## Activity

- Assembled the seam-3 end-to-end enforcement suite: `packages/kilo-sandbox/test/enforcement.test.ts` (node:test, probe-gated). One test per matrix cell, each attributed to the ADR 0006 containment promise it witnesses.
- Added a capability matrix fixture in the suite: one cached probe session classifies the host (win32 / SDK install / bun runner / base-container tier / Model 2 host-loopback capability / credential-store presence / UI capability facts), and every cell either selects the right assertions for this host or skips with the precise missing capability named.
- Added the session-layer half of the relaxation story: `packages/opencode/test/kilocode/sandbox/relaxation-logging.test.ts` (bun:test) — durable config grants logged at session init with source `config`, prompt grants with source `prompt`, identical regrant recorded once. Discovered automatically by the repo runner's `kilocode/sandbox/*.test.ts` profile glob.

## Matrix results on this host (base-container, no Model 2)

- FS-ALLOW-01 pass live; FS-DENY-01/02/03 pass live ("Access is denied", no host artefact, no stdout leak).
- RX-READ-01 pass live: the identical read denied without the relaxation and returns the real content with exactly one recorded `{kind:"path", access:"read"}` relaxation in the profile; the write grant untouched.
- EG-DENY-01 pass live (deny-all default lets no page through). EG-REFUSE-01 pass live: a proxy-pinned run is refused with MXC's typed hostLoopback/proxy error on this host — never a degraded run. EG-ALLOW-01/EG-DENY-02/EG-DENY-03 skip here by name (probe says `baseContainerSupportsIngressHostLoopbackAllow=false`) and run the full proxied flow on capable hosts.
- TCB-01 pass live: a host-side sidecar with a real authenticated pipe; a confined node probe holding the endpoint name attempt `net.connect` records `TCB_FAILED:ENOENT` (the container cannot even see host pipes), a poisoned `KILO_MXC_CONTROL_TOKEN` never reaches the container env (`TOKEN_ABSENT`), and the sidecar still handshakes afterwards.
- UI-DENY-01 pass live: probe `uiCapabilities` reports the denied fields (clipboard read/write, input injection, desktop switching blockable=true for all ten fields; only the ticket-named four are asserted). UI-POSTURE-01: translated request keeps `ui.disable === false` (GUI subsystem available; win32k itself never asserted per the ticket).
- PERF-BUDGET-01 pass: trivial confined `cmd /c echo PERF_OK` spawn-to-completion through the full stack (shim + transient sidecar + engine round trip), median of 5 samples = 469.1 ms (samples 469/484/468/485/469) against the documented ceiling of 1000 ms (~30x the ~30 ms bare-SDK baseline in the spike; generous host-variance margin; every sample emitted as a test diagnostic for attribution).

Perf numbers by cell context (single runs, one transient sidecar each): FS-ALLOW ~0.67–0.70 s, FS-DENY ~0.48 s, TCB ~0.72–0.95 s, EG-DENY ~0.48 s, RX-READ pair ~1.44 s.

## Verification

- `node --import ./test/register-extensions.mjs --test test/enforcement.test.ts test/probe.test.ts test/relaxation.test.ts test/audit.test.ts test/egress.test.ts test/terminal.test.ts` (kilo-sandbox): 56 tests, 53 pass, 3 capability skips, 0 fail.
- Sidecar `node --test test/`: 117 tests, 115 pass, 2 env-skips, 0 fail — unchanged baseline.
- tsgo (`@typescript/native-preview` `--noEmit`): clean on kilo-sandbox including the new suite.
- oxlint 1.60.0 (mirrored core ruleset, no type-aware rules — host lacks tsgolint): 0 warnings, 0 errors on both touched files.
- Suite B cannot run on this host (no bun): full TS parse clean (`ts.createSourceFile` parse diagnostics asserting), to be run by CI's bun runner.

## Environment notes for future sessions

- Host has no bun and no node_modules anywhere. The worktree test environment was provisioned with npm (registry) into `%TEMP%\kilo\pkg` plus junctions into `packages/kilo-sandbox/node_modules/`: `effect@4.0.0-beta.83` (exact pin — a later 4.0.4 loses the `unstable/*` subpath), `ipaddr.js@2.4.0`, `typescript@5.9.3` (the loader hook needs it), `@typescript/native-preview`, `@tsconfig/bun`, `@types/bun`, `@effect/platform-node@4.0.0-beta.83`, and `@kilocode/mxc-sidecar -> ../../kilo-mxc-sidecar`. `node_modules` is gitignored and was never committed.
- Shell tool note: the `workdir` parameter is pinned to the workspace root on this host; all worktree operations must use `git -C`/`Push-Location` (same as ticket 17 noted).

## Caveats

- Durable config terminal-kind relaxations are deliberately NOT asserted (ticket 17's recorded follow-up: the PTY gate does not honour them yet); the suite would need a durable-terminal cell when upstream lands that surface.
- The relaxation-logging JSONL assertions live in the opencode bun suite (CI), not the node suite: the session audit JSONL is written by opencode's `SandboxStore`, which kilo-sandbox cannot depend on. The runner-level file points at the pin; the live OS effects of the same grants are pinned here (RX-READ-01).
- MXC telemetry settings untouched. Git work was add/commit only; no pushes, no deletions outside the worktree's own temp directories.
