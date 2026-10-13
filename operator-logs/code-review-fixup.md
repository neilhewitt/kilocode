# Code-review fix-up: MXC sandbox integration

Branch: `integration/mxc-windows-sandbox`, worktree `C:\projects\kilocode-mxc-worktrees\integration`, single commit at the tip (`fix(sandbox): code-review fixes for the MXC sandbox integration`).

## Activity — findings fixed

1. **Missing changeset** — added `.changeset/mxc-windows-sandbox-integration.md` (`@kilocode/cli` + `kilo-code`, minor), covering the Windows MXC sandbox backend, gate endpoint, TUI dialog, audit/relaxation surfaces, plus the performance note (below).
2. **`any` in sidecar client.ts** — the pending-call map now stores `{ resolve: (value: unknown) => void; reject }` (`type Waiter`); the promise resolver is bridged with `as (value: unknown) => void` instead of `as (result: any)`.
3. **terminal.ts docstring** — now states the truth: only prompt-granted relaxations via the relax seam can serve an unsandboxed PTY today; the durable-config half is the recorded follow-up and cannot serve a terminal.
4. **Egress posture-switch warning** — `RunEgress`'s cidr arm gained an optional `switchedFromProxy` marker (validated in `isEgress`, ignored by the SDK request composition); the backend marks it when a non-empty allowed_cidrs relaxation replaces a proxy posture with a non-empty allowlist, and the sidecar's egress wrapper emits a per-run warning naming the switch and the hostnames that stopped flowing, beside the existing relaxation records. Tests in both packages.
5. **Permission-prompt surface for relaxations** — the gate-dialog precedent in `plugins/sandbox.tsx` now has a relaxation sibling: `/sandbox-relax` palette command → dialog (read path / write path / PTY terminal grant) → posts the request through the `/session/:id/sandbox/relax` seam (raw-fetch helper `applyRelaxation`, same connection-config posture as `resolveGate`, whose plumbing was deduped into `sandboxRoute`). The grant is persisted and recorded by `SandboxPolicy.relax` itself with source `prompt` — the plugin never writes a session-log line of its own. Source-contract pins added to the opencode bun suite.
6. **Secret-named denial sweep honesty** — the sweep now fails closed on what it cannot bridge: a granted directory it cannot enumerate (ACL anomaly, dangling junction) is denied outright instead of silently skipped, and junction/symlink directory entries are followed so deny-named files behind in-grant links are found (cycles bounded by canonical-path set). The engine's tolerance of literal denials that do not resolve as files (credential stores) is what the fail-closed denial relies on. The residual fail-open is documented in code and here: `deniedPaths` is a composition-time literal list — the engine has no name rules — so a deny-named file created after composition stays readable for the in-flight run; the next command composes a fresh table that denies it. Absent deny-named paths cannot be pre-denied because a name does not say whether the path would become a file or directory (`.git` is exactly that ambiguity).
7. **Minor cleanups** — kilo-sandbox `tsconfig.json` restored to the repo's readable multi-line shape; the duplicated `[...allowWrite, ...relaxedWrite].filter(exists)` expression extracted as `grantedSubtrees`; the module-level `let revision` in policy.ts is now scoped to its only mutation (closure getter; all readers sample `revision()`).
8. **Perf budget honesty** — the asserted ceiling stays as a regression guard but no longer claims to be the spec's budget: header + in-cell comments state ~440–470 ms median full-stack vs ~30 ms bare-SDK, session-scoped sidecar as the recorded optimisation follow-up; assertion failure text matches. Changeset/release-note line added.

## Discretionary items

- **tls-client-hello dedupe** — left both copies deliberately: kilo-sandbox's copy pre-exists on main (upstream expects it); the sidecar copy is a documented vendored duplicate (the sidecar unit ships sources alone). No change.
- **Ref-count pools** — the three acquireUseRelease copies in policy.ts were collapsed into a shared `pooled` shape (`locked`/`refreshing` fixed acquire-count 1; `gated` per-call count as before — call-site signatures unchanged). The terminal.ts `(limits as { allowedCidrs?: … })` reach-back cast was removed (fallback typed as `SandboxStore.Snapshot`); the adjacent redundant `as ReadonlyArray<Relaxation>` went too. NOTE: the filtered tsgo run caught a first version of this refactor breaking 13 call sites (TS2554) — fixed before commit.

## Verification (this host: no bun, base-container Windows)

- Sidecar `node --test test/`: **119 tests, 117 pass, 2 env-skips, 0 fail** (baseline 117/115/2 + the two new posture-switch cells).
- kilo-sandbox `node --test` (enforcement, probe, relaxation, audit, egress, terminal, mxc) via `test/register-extensions.mjs`: **110 tests, 107 pass, 3 capability skips, 0 fail** — includes the live enforcement cells on this host class.
- `tsgo --noEmit`: clean on kilo-sandbox and kilo-mxc-sidecar full programs.
- oxlint 1.60.0 (repo ruleset minus type-aware — host lacks tsgolint, same as tickets 14–19): **0 warnings, 0 errors** on all eleven touched files. Two pre-existing warnings in touched files were cleared along the way (a literal-concat diagnostic and an unused `network` parameter, renamed `_network`).
- opencode touched files (terminal.ts, policy.ts, plugins/sandbox.tsx, relaxation.test.ts): TS parse clean; filtered tsgo run shows zero diagnostics beyond the recorded dep-absent noise classes.
- opencode bun suites cannot run on this host (no bun) — new bun-suite cells are source-contract style and run in CI's bun runner.

## Caveats

- The junction-based sweep traversal follows in-grant links host-side; the engine's own link resolution remains the deciding runtime behaviour (the denial entries are the paths the confined process opens).
- Nothing else changed intentionally: no pushes, no branches, no deletions, MXC telemetry untouched; `node_modules` junctions are gitignored and were never committed.
