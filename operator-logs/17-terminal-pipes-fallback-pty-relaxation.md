# Operator log — ticket 17: terminal handling (pipes fallback, PTY relaxation)

Branch: `ticket/17-terminal-pipes-fallback-pty-relaxation`, based on integration tip
88bb53b3cc (verified unchanged before and after: merge-base == tip at commit time).
Scope: ADR 0004 (authoritative) + spec story "Terminal handling: pipes fallback and
PTY relaxation" + `.scratch/mxc-windows-sandbox/issues/17-terminal-pipes-fallback-pty-relaxation.md`.

## Decisions (log style)

- **Run contract grows two optional fields.** `RunCommand.timeoutMs` (positive whole
  milliseconds; maps onto the engine's per-request `timeoutMs` — the SDK v1 surface
  documented in the spike's cached types; absence = no engine deadline) and
  `RunCommand.stream` (the pipes-fallback live-forwarding ask). Both validated by
  `isRunCommand`; both carried through `toSdkRequest`/`translate`.
- **Streaming = same contract, surfaced earlier.** A streamed run forwards
  base64 `{"id","event":"stdout"|"stderr","data"}` NDJSON frames on the control
  connection before the settled response; the settled response still carries the
  full captured result — captured and streamed commands settle identically, and
  the streamed consumer never receives a replay of what it already saw.
- **Every streamed run carries the degradation warning.** `PIPES_FALLBACK_WARNING`
  (sidecar-side wording, mirrored to `PIPES_FALLBACK_SIGNAL` in kilo-sandbox —
  the sidecar cannot import the sandbox package; dependency direction) is appended
  to the result warnings, so the shim prints `[kilo-mxc] …` and the terminal shows
  it. The reason it rides `stream` runs only: agent shell commands are not
  interactive surfaces (no TTY in that path with or without the sandbox), and the
  signal targets the terminal surfaces.
- **Session terminal gate (core seam).** Core's `Pty.createBody` consults an
  injected `KiloPtySpawnGate` (`core/src/kilocode/pty/spawn-gate.ts`), a global
  registry in the established `KiloPtyRegistry` style. No gate installed (non-Kilo
  host) → the plain PTY spawn, unchanged. Gate decision "pipes" → the registry,
  attach, write, resize, teardown paths receive a `pipesTty` Proc (`pipi-fallback`
  adapter in `kilo-sandbox/src/terminal.ts`, structural twin of the `Proc`
  contract: `write`/`resize` are degraded no-ops, `kill` delegates to the tree
  kill). A gate failure is a defect (Effect.orDie) — fail-closed; the create never
  silently degrades to an unconsulted plain PTY.
- **The fallback launch is the SAME run-shim contract the agent's commands take**
  (`confine()` exported from @kilocode/sandbox; launch composed with
  `stream: true`), spawned by `nodeSpawn` with piped stdio and `windowsHide`.
  Output streams live into the session buffer; the banner
  (`PIPES_FALLBACK_SIGNAL`) prints first; `Info.tty: "pipes"` (new optional literal
  on the shared Pty Info) marks the session for clients. Teardown via the shim's
  pid hits the spawner semantics documented on ticket 12: `taskkill /f /t` takes
  shim + sidecar + confined child, and the job object reaps the remainder.
- **PTY relaxation = per-command, explicit, recorded.** The relaxation seam
  (ticket 15) already validates/persists kind "terminal" grants (prompt source,
  POST /session/:id/sandbox/relax). The PTY gate consumes the session's
  prompt-granted terminal entries on the first unsandboxed terminal spawn
  (`SandboxPolicy.consumeTerminalGrant` — locked write, version bump,
  `sandbox.terminal.use` audit record): one grant is one command. Every terminal
  create records `sandbox.terminal.start` in the session log.
- **Input is intentionally unavailable in the pipes fallback and the
  `write` refusal is silent-but-signalled.** The MXC SDK's spawn child exposes
  `standardOutput`/`standardError` streams and `wait()` only — there is no stdin
  stream on the API surface (verified against the cached SDK typings), so no input
  path exists for confined commands. The banner explains it; the escape hatch is
  the PTY relaxation.

## AC coverage

- [x] An interactive command runs confined without TTY semantics, with the
      difference signalled — session-terminal pipes fallback streamed through the
      shim; banner + `tty: "pipes"` + `PIPES_FALLBACK_WARNING` + audit records.
- [x] A Kilo session terminal is confined like any agent command — the gate
      swaps the ConPTY spawn for the same run-shim contract.
- [x] A PTY relaxation grants an unsandboxed terminal for one command, on
      explicit request, and is logged — grant via the seam, consumed once,
      grant + use recorded.
- [x] Cancelling a command kills the entire process tree — spawner tree-kill +
      shim kill-on-disconnect (existing, pinned by tests), the pipes Proc's kill
      uses the same tree kill.
- [x] Timeouts preserve existing shell semantics through the per-request
      timeout — the tool-level timeout path is untouched; `timeoutMs` maps onto
      the engine's per-request deadline for surfaces that carry one.
- [x] Output streams and completion behave identically for captured and
      streamed commands — same RunResult, same warnings/exit semantics, no
      duplicated bytes (unit + scripted + live evidence below).

## Test evidence (this host: no bun, base-container Windows)

- Sidecar: `node --test test/` — 117 tests, 115 pass, 2 skipped (env-gated
  SDK-liveness), 0 fail. New: `test/streaming.test.ts` (control event frames,
  captured runs emit no frames, client `onOutput` routing + identical settled
  result, shim live-forward/no-replay/captured-replay) and contract tests in
  `run.test.ts`/`sdk.test.ts` (timeoutMs + stream validation, engine mapping,
  forward hook channel, fallback warning annotation).
- kilo-sandbox: node-native suites (terminal, mxc, relaxation, audit, probe,
  egress) — 94 tests, 94 pass, 0 fail. New: `test/terminal.test.ts`
  (PTY_REVISIT_TRIGGER content, decision matrix, pipesTty chunk-safe decode,
  degraded write/resize, delegated tree kill, exactly-once exit) and
  ticket-17 blocks in `test/mxc.test.ts` (translate/prepare carry stream +
  timeoutMs; wire contract round-trip).
- Live (probe-gated, SDK present at %TEMP%/kilo/mxc-smoke): the streamed
  confined run through the REAL MXC SDK forwarded `L1\nL2\n` as live chunks
  (each byte once — never replayed), exit code 7 round-tripped, and the
  stderr carries the pipes-fallback warning. A second live run confirmed the
  SDK emits incremental stdout chunks (~47ms/59ms apart).
- tsgo `--noEmit` clean on: kilo-mxc-sidecar, kilo-sandbox, packages/schema, and
  the touched core files (src/pty.ts, kilocode/pty/spawn-gate.ts) within a
  dependency-junctioned scope. Full core/opencode programs still need the
  workspace dep tree (absent here); every touched core/opencode/schema file is
  transpiler-parsed clean, and the touched opencode files typecheck clean under
  filtered tsgo runs (pre-existing missing-module noise from absent deps remains,
  as on tickets 14–16). opencode bun tests are compile/syntax-verified only
  (ticket-15 precedent).
- oxlint (repo config, tsgolint companion unavailable on this host): touched
  files produce no new findings; only pre-existing warnings in untouched files.

## Deviations and caveats

1. **Agent shell tool**: unchanged. Upstream there is no TTY for agent commands
   with or without the sandbox, so no new prompt was added; the interactive
   surface IS the session terminal, and its relaxation path is the seam above.
   The pre-existing `sandbox_escalation` git-mutation prompt keeps its existing
   semantics.
2. **Durable config kind:"terminal" relaxations are not honoured by the PTY
   gate yet**: the gate is file-backed (session snapshot → directory
   preference) because core's layer ambient does not include the opencode
   config service (`@opencode/Config` vs core `@opencode/v2/Config` — different
   tags). Prompt-granted relaxations are honoured. A durable-terminal config
   entry will need either a config-file read or an init snapshot composition;
   noted as follow-up.
3. **No-session terminals** (created without a sessionID): confined iff the
   directory's last `/sandbox` toggle is on; otherwise the plain PTY. A session
   whose snapshot was never initialised behaves the same. The policy itself
   falls back to the config default when a session initialises via a tool call;
   a terminal created before any such call cannot see the config default from
   the core ambient — same root cause as (2).
4. **Input forwarding**: absent by design (see decision above); the
   relaxation is the escape hatch. If upstream MXC exposes a stdin stream on
   the spawn child, `pipesTty` should forward `write()` and drop the degraded
   no-op (same revisit trigger).
5. The environment's `workdir`/offset quirks: shell workdir param is pinned to
   the workspace root on this host; all worktree operations ran via Push-Location
   (no repo content impact).

## Files

- packages/kilo-mxc-sidecar: src/{run,sdk,control,client,egress,run-shim}.ts;
  test/{run,sdk,streaming}.test.ts; test/fixtures/scripted-runtime.mjs
- packages/kilo-sandbox: src/{terminal (new),backend,mxc,index}.ts;
  test/{terminal (new),mxc}.test.ts
- packages/core: src/pty.ts; src/kilocode/pty/spawn-gate.ts (new)
- packages/opencode: src/kilocode/sandbox/{terminal (new),policy}.ts;
  src/server/routes/instance/httpapi/handlers/pty.ts (gate install);
  test/kilocode/sandbox/terminal.test.ts (new)
- packages/schema: src/pty.ts (CreateInput.sessionID, Info.tty)
