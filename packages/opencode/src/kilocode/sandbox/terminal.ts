import { spawn as nodeSpawn, spawnSync } from "node:child_process"
import { realpathSync } from "node:fs"
import path from "node:path"
import { Effect } from "effect"
import {
  backendSupport,
  confine,
  isRelaxation,
  PIPES_FALLBACK_SIGNAL,
  pipesTty,
  PTY_REVISIT_TRIGGER,
  terminalDecision,
  type Profile,
  type Relaxation,
} from "@kilocode/sandbox"
import { Global } from "@opencode-ai/core/global"
import * as KiloPtySpawnGate from "@opencode-ai/core/kilocode/pty/spawn-gate" // kilocode_change
import type { SessionID } from "@/session/schema"
import * as SandboxGate from "./gate"
import * as SandboxPolicy from "./policy"
import { SandboxPreference } from "./preference"
import { SandboxStore } from "./store"

// Ticket 17 — terminals under the sandbox (ADR 0004). The MXC engine cannot
// give a confined command a PTY — spawnWithPty is typed in the SDK's plumbing
// but the native engine refuses on the processcontainer backend with
// `unsupported_containment`; PTY_REVISIT_TRIGGER carries the upstream
// revisit. So every sandboxed session terminal runs the pipes fallback from
// the same run contract the agent's commands take: output streams live,
// input and resize are degraded no-ops, and the degradation is signalled —
// the terminal Info carries tty: "pipes", the banner prints into the
// terminal, and the session log records the start.
//
// A genuinely TTY-needed terminal runs unsandboxed only through an explicit,
// recorded PTY relaxation: a durable config relaxation (re-composed each
// time), or a prompt-granted one created via the relaxation seam
// (POST /session/:id/sandbox/relax, kind "terminal", source "prompt") that
// the first terminal spawn consumes — one grant, one command.

export namespace SandboxTerminal {
  function root(value: string) {
    return { path: value, kind: "subtree" as const }
  }

  // The terminal's grant table composes from the terminal's own directory —
  // the location the user opened the terminal in — plus the global state
  // roots, mirroring SandboxPolicy.profile for the surfaces it can reach
  // without an instance context. Network posture comes from the session's
  // stored snapshot limits; relaxations come from the relaxation seam.
  function profile(
    directory: string,
    mode: Profile["network"]["mode"],
    allowedHosts: readonly string[],
    allowedCidrs: Profile["network"]["allowedCidrs"],
    relaxations: ReadonlyArray<Relaxation>,
  ): Profile {
    return {
      filesystem: {
        allowWrite: [
          root(directory),
          root(Global.Path.data),
          root(Global.Path.cache),
          root(Global.Path.config),
          root(Global.Path.state),
          root(Global.Path.tmp),
          root(Global.Path.bin),
          root(Global.Path.log),
          root(Global.Path.repos),
        ],
        denyWrite: [root(SandboxStore.root), root(SandboxPreference.root), root(Global.Path.config)],
        denyNames: [".git"],
        temporaryDirectory: Global.Path.tmp,
      },
      network: {
        mode,
        allowedHosts,
        ...(allowedCidrs && allowedCidrs.length > 0 ? { allowedCidrs } : {}),
      },
      environment: {
        deny: [
          "KILO_CONFIG",
          "KILO_CONFIG_CONTENT",
          "KILO_CONFIG_DIR",
          "KILO_SERVER_PASSWORD",
          "KILO_SERVER_USERNAME",
          "KILO_BROWSER_BROKER_URL",
          "KILO_BROWSER_BROKER_TOKEN",
        ],
        set: {
          TMPDIR: Global.Path.tmp,
          TMP: Global.Path.tmp,
          TEMP: Global.Path.tmp,
        },
      },
      ...(relaxations.length > 0 ? { relaxations } : {}),
    }
  }

  function canonicalised(value: string) {
    try {
      return realpathSync.native(value)
    } catch {
      return path.resolve(value)
    }
  }

  /** The prompt-granted terminal relaxation grants, if any, from the session snapshot. */
  function promptTerminalGrants(relaxations: ReadonlyArray<Relaxation> | undefined) {
    return (relaxations ?? []).filter((entry) => isRelaxation(entry) && entry.kind === "terminal")
  }

  function audit(sessionID: SessionID | undefined, entry: Record<string, unknown>) {
    if (sessionID === undefined) return Effect.void
    return Effect.ignore(Effect.promise(() => SandboxStore.appendAudit(sessionID, entry)))
  }

  // The consulted gate (core consults it for every session terminal spawn).
  // Requires only Config.Service — present in the PTY service's layer — plus
  // file-backed sandbox state: everything the session-scoped decision needs
  // is keyed by (directory, sessionID), both of which the spawn input
  // carries.
  export const gate = Effect.fn("SandboxTerminal.gate")(function* (input: KiloPtySpawnGate.SpawnGateInput) {
    const sessionID: SessionID | undefined = (input.sessionID ?? undefined) as SessionID | undefined
    const directory = canonicalised(input.directory)
    const stored =
      sessionID === undefined ? undefined : yield* Effect.promise(() => SandboxStore.read(directory, sessionID))
    // File-backed only, deliberately: core's layer ambient does not include
    // the opencode config service, so the posture follows the session's
    // stored snapshot first (written at session init from the config default
    // and preferences), then the directory's last /sandbox toggle.
    const enabled = stored?.enabled ?? (yield* Effect.promise(() => SandboxPreference.read(directory)) ?? false)
    const limits = stored ?? {
      mode: "deny" as const,
      allowedHosts: [],
      writablePaths: [],
      audit: false,
    }
    const gateAssessment = yield* SandboxGate.assess()
    const support = backendSupport({ mode: limits.mode, allowedHosts: limits.allowedHosts })
    const mergedGate = SandboxGate.fold(support, gateAssessment)
    const promptGrants = promptTerminalGrants(stored?.relaxations)
    const decision = terminalDecision({
      confinementActive: enabled === true && mergedGate.available,
      terminalRelaxed: promptGrants.length > 0,
    })

    if (decision.mode !== "pipes-fallback") {
      // The unsandboxed real PTY: consume a prompt-granted relaxation (one
      // grant is one command) and record the use. Durable config entries are
      // never consumed — removing one from config ends the posture.
      if (sessionID !== undefined && promptGrants.length > 0) {
        yield* SandboxPolicy.consumeTerminalGrant(sessionID, directory)
      }
      yield* audit(sessionID, {
        type: "sandbox.terminal.start",
        sessionID,
        directory,
        signal: "unsandboxed terminal relaxation",
        backendNote: PTY_REVISIT_TRIGGER,
      })
      return { mode: "pty" } as const
    }

    // The pipes fallback: run the same run-contract shim the agent's commands
    // take, streamed (output forwarded live; input and resize degraded).
    const launch = yield* Effect.scoped(
      confine(
        profile(
          directory,
          limits.mode,
          limits.allowedHosts,
          (limits as { allowedCidrs?: Profile["network"]["allowedCidrs"] }).allowedCidrs,
          (stored?.relaxations ?? []) as ReadonlyArray<Relaxation>,
        ),
        { command: input.command, args: input.args, cwd: input.cwd || input.directory, environment: input.env, stream: true },
      ),
    )
    const child = nodeSpawn(launch.command, launch.args, {
      cwd: launch.cwd,
      env: launch.environment,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    })
    const tty = pipesTty({
      pid: child.pid,
      kill: () => {
        // Tree kill: the pid is the shim's; taskkill /f /t takes the shim,
        // the transient sidecar, and the confined MXC child, and the
        // sidecar's parent-link break reaps the confined child too.
        if (process.platform === "win32" && child.pid) {
          spawnSync("taskkill", ["/pid", String(child.pid), "/f", "/t"], { stdio: "ignore" })
        } else {
          child.kill()
        }
      },
    })
    child.stdout.on("data", (chunk: Buffer) => tty.emit("stdout", chunk))
    child.stderr.on("data", (chunk: Buffer) => tty.emit("stderr", chunk))
    child.on("error", () => tty.emitExit({ exitCode: 1 }))
    child.on("close", (code) => tty.emitExit({ exitCode: code ?? 1 }))
    // The degradation signal, in band: the first thing the terminal shows.
    tty.emit("stdout", Buffer.from(`\r\n${PIPES_FALLBACK_SIGNAL}\r\n\r\n`))
    yield* Effect.logInfo("session terminal ran the pipes fallback", {
      sessionID,
      directory,
      signal: PIPES_FALLBACK_SIGNAL,
      shimNote: PTY_REVISIT_TRIGGER,
    })
    yield* audit(sessionID, {
      type: "sandbox.terminal.start",
      sessionID,
      directory,
      signal: PIPES_FALLBACK_SIGNAL,
      shimNote: PTY_REVISIT_TRIGGER,
    })
    return { mode: "pipes", proc: tty } as const
  })

  // Installs the gate for the core PTY service. Idempotent; called when this
  // module loads.
  export function install(): void {
    KiloPtySpawnGate.setSpawnGate(gate)
  }
}

SandboxTerminal.install()
