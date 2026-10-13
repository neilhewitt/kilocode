import { accessSync, constants, readFileSync, realpathSync, statSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { Effect, Semaphore } from "effect"
import { Global } from "@opencode-ai/core/global"
import { Database } from "@opencode-ai/core/database/database"
import {
  backendSupport,
  deniedByProfile,
  run as runSandbox,
  translate,
  unrestricted,
  type Profile,
  type Relaxation,
} from "@kilocode/sandbox"
import { Bus } from "@/bus"
import { GlobalBus } from "@/bus/global"
import { Instance } from "@/kilocode/instance"
import { Config } from "@/config/config"
import { InstanceState } from "@/effect/instance-state"
import type { InstanceContext } from "@/project/instance-context"
import type { SessionID } from "@/session/schema"
import { Changed } from "./event"
import * as SandboxGate from "./gate"
import * as Network from "./network"
import * as SandboxRelaxation from "./relaxation"
import { SandboxPreference } from "./preference"
import * as SandboxState from "./state"
import { SandboxConfig } from "./config"
import { SandboxStore } from "./store"

export type Snapshot = SandboxStore.Snapshot
export type Target = { id: SessionID; directory: string }

const snapshots = new Map<string, Snapshot>()
const synced = new Map<string, number>()
const locks = new Map<SessionID, { semaphore: Semaphore.Semaphore; refs: number }>()
const refreshes = new Map<SessionID, { semaphore: Semaphore.Semaphore; refs: number }>()
const gates = new Map<SessionID, { semaphore: Semaphore.Semaphore; refs: number }>()
const permits = 1_000_000
let revision = 0

GlobalBus.on("event", (event) => {
  if (event.payload?.type === "global.config.updated" && event.payload.properties?.sandbox === true) revision++
})

function key(directory: string, sessionID: SessionID) {
  return directory + "\0" + sessionID
}

function limits(fallback: ReturnType<typeof SandboxConfig.resolve>) {
  return {
    mode: fallback.mode,
    allowedHosts: fallback.allowedHosts,
    writablePaths: fallback.writablePaths.map((value) =>
      value.startsWith("~") ? path.join(os.homedir(), value.slice(1)) : value,
    ),
    audit: fallback.audit,
    ...(fallback.allowedCidrs !== undefined && fallback.allowedCidrs.length > 0
      ? { allowedCidrs: fallback.allowedCidrs }
      : {}),
  }
}

function apply(current: Snapshot, fallback: ReturnType<typeof SandboxConfig.resolve>) {
  return { ...current, ...limits(fallback) }
}

function cidrsEqual(left: ReadonlyArray<Snapshot["allowedCidrs"]>[number] | undefined, right: ReadonlyArray<Snapshot["allowedCidrs"]>[number] | undefined) {
  return JSON.stringify(left ?? []) === JSON.stringify(right ?? [])
}

function matches(current: Snapshot, next: Snapshot) {
  return (
    current.mode === next.mode &&
    current.allowedHosts.join("\0") === next.allowedHosts.join("\0") &&
    current.writablePaths.join("\0") === next.writablePaths.join("\0") &&
    current.audit === next.audit &&
    cidrsEqual(current.allowedCidrs, next.allowedCidrs)
  )
}

const publishChanged = Effect.fn("SandboxPolicy.publishChanged")(function* (sessionID: SessionID, directory: string, next: Snapshot) {
  const gate = yield* SandboxGate.assess()
  const support = backendSupport({ mode: next.mode, allowedHosts: next.allowedHosts })
  const merged = SandboxGate.fold(support, gate)
  GlobalBus.emit("event", {
    directory,
    payload: {
      id: Bus.createID(),
      type: Changed.type,
      properties: {
        sessionID,
        directory,
        enabled: next.enabled && merged.available,
        available: merged.available,
        reason: merged.reason,
        diagnostics: [...merged.diagnostics],
        unsandboxed: next.unsandboxed === true,
        audit: next.audit === true,
        version: next.version,
      },
    },
  })
})

function initial(
  chosen: boolean | undefined,
  pref: boolean | undefined,
  cfgDefault: boolean,
  fallback: ReturnType<typeof SandboxConfig.resolve>,
): Snapshot {
  const state = {
    ...limits(fallback),
    version: 0,
  }
  if (chosen !== undefined) return { ...state, enabled: chosen }
  if (pref !== undefined) return { ...state, enabled: pref }
  return { ...state, enabled: cfgDefault }
}

const resolveInitial = Effect.fn("SandboxPolicy.resolveInitial")(function* (directory: string, sessionID: SessionID) {
  const cfg = yield* (yield* Config.Service).get()
  const chosen = yield* SandboxState.read(sessionID)
  const pref = yield* Effect.promise(() => SandboxPreference.read(directory))
  const fallback = SandboxConfig.resolve(cfg)
  return initial(chosen?.enabled, pref, fallback.enabled, fallback)
})

// The one command's relaxations: durable config entries first, then the
// session's prompt-granted ones (ADR 0002). Durable relaxations are never
// persisted — each command re-composes them from config, so removing one
// restores the default table on the next session.
function relaxationsFor(state: Snapshot, config: ReturnType<typeof SandboxConfig.resolve>) {
  return SandboxRelaxation.effective(config.relaxations, state.relaxations)
}

// Durable config relaxations take effect with the session: each grant is
// recorded once per session in the session log with its source (config).
const logConfigRelaxations = Effect.fn("SandboxPolicy.logConfigRelaxations")(function* (
  sessionID: SessionID,
  state: Snapshot,
) {
  if (!state.enabled && state.audit !== true) return
  if (!SandboxRelaxation.once(`config\0${sessionID}`)) return
  const cfg = yield* (yield* Config.Service).get()
  for (const entry of SandboxConfig.resolve(cfg).relaxations) {
    yield* Effect.promise(() => SandboxStore.appendAudit(sessionID, SandboxRelaxation.record(entry, "config")))
  }
})

// Audit mode's engine path — MXC captureDenials allow-mode — is wired end to
// end but crashes the SDK host process (0xC0000005) in MXC SDK 1.0.0 on a
// live base-container host (verified in an isolated child; the byte-identical
// request without captureDenials enforces cleanly). Until upstream fixes it,
// audit sessions run on the unsandboxed dry-run path; a host with a fixed
// engine opts in with KILO_MXC_AUDIT_ENGINE=1.
function engineAudit() {
  return process.env.KILO_MXC_AUDIT_ENGINE === "1"
}
function locked<A, E, R>(sessionID: SessionID, effect: Effect.Effect<A, E, R>) {
  return Effect.acquireUseRelease(
    Effect.sync(() => {
      const entry = locks.get(sessionID) ?? { semaphore: Semaphore.makeUnsafe(1), refs: 0 }
      entry.refs++
      locks.set(sessionID, entry)
      return entry
    }),
    (entry) => entry.semaphore.withPermits(1)(effect),
    (entry) =>
      Effect.sync(() => {
        entry.refs--
        if (entry.refs === 0 && locks.get(sessionID) === entry) locks.delete(sessionID)
      }),
  )
}

function lockedAll<A, E, R>(sessions: readonly SessionID[], effect: Effect.Effect<A, E, R>) {
  return [...new Set(sessions)].reduceRight((next, sessionID) => locked(sessionID, next), effect)
}

function refreshing<A, E, R>(sessionID: SessionID, effect: Effect.Effect<A, E, R>) {
  return Effect.acquireUseRelease(
    Effect.sync(() => {
      const entry = refreshes.get(sessionID) ?? { semaphore: Semaphore.makeUnsafe(1), refs: 0 }
      entry.refs++
      refreshes.set(sessionID, entry)
      return entry
    }),
    (entry) => entry.semaphore.withPermits(1)(effect),
    (entry) =>
      Effect.sync(() => {
        entry.refs--
        if (entry.refs === 0 && refreshes.get(sessionID) === entry) refreshes.delete(sessionID)
      }),
  )
}

function gated<A, E, R>(sessionID: SessionID, count: number, effect: Effect.Effect<A, E, R>) {
  return Effect.acquireUseRelease(
    Effect.sync(() => {
      const entry = gates.get(sessionID) ?? { semaphore: Semaphore.makeUnsafe(permits), refs: 0 }
      entry.refs++
      gates.set(sessionID, entry)
      return entry
    }),
    (entry) => entry.semaphore.withPermits(count)(effect),
    (entry) =>
      Effect.sync(() => {
        entry.refs--
        if (entry.refs === 0 && gates.get(sessionID) === entry) gates.delete(sessionID)
      }),
  )
}

function gatedAll<A, E, R>(sessions: readonly SessionID[], effect: Effect.Effect<A, E, R>) {
  return [...new Set(sessions)].reduceRight((next, sessionID) => gated(sessionID, permits, next), effect)
}

function root(path: string) {
  return { path, kind: "subtree" as const }
}

function marker(dir: string) {
  try {
    const file = path.join(dir, ".git")
    const entry = statSync(file, { throwIfNoEntry: false })
    if (!entry?.isFile()) return false
    const match = readFileSync(file, "utf8")
      .trim()
      .match(/^gitdir:\s*(.+)$/i)
    if (!match) return true
    const git = path.resolve(dir, match[1])
    if (!statSync(git, { throwIfNoEntry: false })?.isDirectory()) return true
    return statSync(path.join(git, "commondir"), { throwIfNoEntry: false })?.isFile() ?? false
  } catch {
    return true
  }
}

function linked(dir: string, stop: string): boolean {
  if (marker(dir)) return true
  if (dir === stop) return false
  const parent = path.dirname(dir)
  if (parent === dir) return false
  return linked(parent, stop)
}

function isolated(ctx: InstanceContext) {
  if (ctx.worktree === "/") return true
  return linked(path.resolve(ctx.directory), path.resolve(ctx.worktree))
}

function canonical(dir: string) {
  try {
    return realpathSync.native(dir)
  } catch {
    return path.resolve(dir)
  }
}

function ancestor(value: string, target: string) {
  const relative = path.relative(canonical(value), canonical(target))
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative)
}

function accessible(dir: string) {
  try {
    accessSync(dir, constants.R_OK)
    return true
  } catch {
    return false
  }
}

function filterWritable(ctx: InstanceContext, values: readonly string[]) {
  const list = values.filter(accessible)
  if (!isolated(ctx)) return list
  // A nested macOS sandbox cannot reliably canonicalize an inherited writable
  // ancestor of the linked worktree. The active worktree is already writable;
  // keep unrelated explicit paths, but do not widen it back to the repository.
  return list.filter((value) => !ancestor(value, ctx.directory))
}

export function profile(
  ctx: InstanceContext,
  mode: Profile["network"]["mode"] = "deny",
  extraWritable?: readonly string[],
  allowedHosts: readonly string[] = [],
  relaxations?: readonly Relaxation[],
  allowedCidrs: NonNullable<Profile["network"]["allowedCidrs"]> = [],
): Profile {
  const project = isolated(ctx)
    ? [ctx.directory]
    : ctx.directory === ctx.worktree
      ? [ctx.directory]
      : [ctx.worktree, ctx.directory]
  const writable = [
    ...project,
    Global.Path.data,
    Global.Path.cache,
    Global.Path.config,
    Global.Path.state,
    Global.Path.tmp,
    Global.Path.bin,
    Global.Path.log,
    Global.Path.repos,
    ...filterWritable(ctx, extraWritable ?? []),
  ].map(root)
  return {
    filesystem: {
      allowWrite: writable,
      denyWrite: [root(SandboxStore.root), root(SandboxPreference.root), root(Global.Path.config)],
      denyNames: [".git"],
      temporaryDirectory: Global.Path.tmp,
    },
    network: {
      mode,
      allowedHosts,
      ...(allowedCidrs.length > 0 ? { allowedCidrs } : {}),
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
    ...(relaxations === undefined || relaxations.length === 0 ? {} : { relaxations }),
  }
}

const read = Effect.fn("SandboxPolicy.read")(function* (directory: string, sessionID: SessionID) {
  const id = key(directory, sessionID)
  const current = snapshots.get(id)
  if (current) return current
  const stored = yield* Effect.promise(() => SandboxStore.read(directory, sessionID))
  if (stored) snapshots.set(id, stored)
  return stored
})

const snapshot = Effect.fn("SandboxPolicy.snapshot")(function* (sessionID: SessionID) {
  const directory = yield* InstanceState.directory
  const current = yield* read(directory, sessionID)
  if (current) return { directory, state: current }

  return yield* locked(
    sessionID,
    Effect.gen(function* () {
      const existing = yield* read(directory, sessionID)
      if (existing) return { directory, state: existing }
      // A session's create-time kilocode.sandbox toggle takes precedence over the config default, so a
      // session moved or created with an explicit choice keeps that choice instead of resetting. The
      // persisted per-directory preference (last toggled state) is the next precedence, so new sessions
      // inherit the last /sandbox choice. The config default applies when neither is present.
      const version = revision
      const next = yield* resolveInitial(directory, sessionID)
      yield* Effect.promise(() => SandboxStore.write(directory, sessionID, next))
      const id = key(directory, sessionID)
      snapshots.set(id, next)
      synced.set(id, version)
      yield* logConfigRelaxations(sessionID, next)
      return { directory, state: next }
    }),
  )
})

function current(
  sessionID: SessionID,
  inside = false,
): Effect.Effect<{ directory: string; state: Snapshot }, never, Config.Service | Database.Service> {
  return Effect.gen(function* () {
    const expected = revision
    const state = yield* snapshot(sessionID)
    const id = key(state.directory, sessionID)
    if (synced.get(id) !== expected) yield* inside ? reconcile(sessionID, expected) : refresh(sessionID, expected)
    if (revision !== expected) return yield* current(sessionID, inside)
    return yield* snapshot(sessionID)
  })
}

export const configuredSupport = Effect.fn("SandboxPolicy.configuredSupport")(function* () {
  const cfg = yield* (yield* Config.Service).get()
  const state = SandboxConfig.resolve(cfg)
  return backendSupport({ mode: state.mode, allowedHosts: state.allowedHosts })
})

export function fallback(config: Config.Info) {
  return SandboxConfig.resolve(config)
}

export const status = Effect.fn("SandboxPolicy.status")(function* (sessionID: SessionID) {
  const active = yield* current(sessionID)
  const gate = yield* SandboxGate.assess()
  const support = backendSupport({ mode: active.state.mode, allowedHosts: active.state.allowedHosts })
  const merged = SandboxGate.fold(support, gate)
  const unsandboxed = active.state.unsandboxed === true
  const audit = active.state.audit === true
  return {
    directory: active.directory,
    enabled: active.state.enabled && merged.available,
    available: merged.available,
    reason:
      unsandboxed && !merged.available && merged.reason
        ? `${SandboxGate.UNSANDBOXED_SIGNAL}: ${merged.reason}`
        : merged.reason,
    diagnostics: [...merged.diagnostics],
    unsandboxed,
    audit,
    version: active.state.version,
  }
})

export const networkRestricted = Effect.fn("SandboxPolicy.networkRestricted")(function* (sessionID: SessionID) {
  const active = yield* current(sessionID)
  return active.state.enabled && active.state.mode !== "allow"
})

const reconcile = Effect.fn("SandboxPolicy.reconcile")(function* (sessionID: SessionID, version = revision) {
  const directory = yield* InstanceState.directory
  return yield* refreshing(
    sessionID,
    Effect.gen(function* () {
      const id = key(directory, sessionID)
      if (synced.get(id) === version) return false
      const current = yield* read(directory, sessionID)
      if (!current) return false
      const config = yield* (yield* Config.Service).get()
      const next: Snapshot = {
        ...apply(current, SandboxConfig.resolve(config)),
        version: current.version + 1,
      }
      if (matches(current, next)) {
        synced.set(id, version)
        return false
      }
      yield* Effect.promise(() => SandboxStore.write(directory, sessionID, next))
      snapshots.set(id, next)
      synced.set(id, version)
      yield* publishChanged(sessionID, directory, next)
      return true
    }),
  )
})

export const refresh = Effect.fn("SandboxPolicy.refresh")((sessionID: SessionID, version = revision) =>
  locked(sessionID, reconcile(sessionID, version)),
)

function change<E, R, F = never, Q = never, P = never, S = never>(
  sessionID: SessionID,
  guard:
    | Effect.Effect<unknown, E, R>
    | ((enabling: boolean, family: readonly Target[]) => Effect.Effect<unknown, E, R>),
  family?: Effect.Effect<readonly Target[], F, Q>,
  preflight?: (family: readonly Target[]) => Effect.Effect<unknown, P, S>,
) {
  return Effect.gen(function* () {
    const directory = yield* InstanceState.directory
    return yield* locked(
      sessionID,
      Effect.gen(function* () {
        const stored = yield* read(directory, sessionID)
        const current = stored ?? (yield* resolveInitial(directory, sessionID))
        const enabling = !current.enabled
        const version = revision
        const base = enabling ? apply(current, SandboxConfig.resolve(yield* (yield* Config.Service).get())) : current
        const gate = yield* SandboxGate.assess()
        const support = backendSupport({ mode: base.mode, allowedHosts: base.allowedHosts })
        const merged = SandboxGate.fold(support, gate)
        const status = {
          directory,
          enabled: current.enabled && merged.available,
          available: merged.available,
          reason: merged.reason,
          version: current.version,
        }
        if (enabling && !status.available) return status
        const targets = enabling && family ? yield* family : [{ id: sessionID, directory }]
        const sessions = targets.map((target) => target.id)
        const update = refreshing(
          sessionID,
          Effect.gen(function* () {
            yield* typeof guard === "function" ? guard(enabling, targets) : guard
            // A regular toggle clears any gate resolution: the unsandboxed marker
            // is written only by resolveGate, never by ordinary state changes.
            const { unsandboxed: _resolved, ...rest } = base
            const next: Snapshot = { ...rest, enabled: enabling, version: status.version + 1 }
            yield* Effect.promise(() => SandboxStore.write(directory, sessionID, next))
            const id = key(directory, sessionID)
            snapshots.set(id, next)
            synced.set(id, version)
            if (enabling) yield* logConfigRelaxations(sessionID, next)
            if (enabling) {
              yield* Effect.forEach(
                targets,
                (target) =>
                  target.id === sessionID
                    ? Effect.void
                    : refreshing(target.id, inheritSnapshot(target.directory, next, target.id)),
                { discard: true },
              )
            }
            // The per-session SandboxStore is the authoritative state; the per-directory
            // preference only seeds future sessions. A preference write failure must not
            // fail the toggle or desync the in-memory cache from the persisted snapshot.
            yield* Effect.promise(() => SandboxPreference.write(directory, next.enabled)).pipe(
              Effect.catch(() => Effect.void),
            )
            const value = { ...status, enabled: next.enabled && merged.available, version: next.version }
            // Publish through the standalone Bus facade so HTTP handlers do not need Bus.Service.
            yield* Effect.promise(() => Bus.publish(Instance.current, Changed, { sessionID, ...value }))
            return value
          }),
        )
        if (enabling) {
          const children = sessions.filter((id) => id !== sessionID)
          return yield* lockedAll(
            children,
            Effect.gen(function* () {
              if (preflight) yield* preflight(targets)
              return yield* gatedAll(sessions, update)
            }),
          )
        }
        return yield* update
      }),
    )
  })
}

export const toggle = Effect.fn("SandboxPolicy.toggle")((sessionID: SessionID) => change(sessionID, Effect.void))

export type GateChoice = "abort" | "continue-unsandboxed"

// Resolves a host-gate refusal with the one explicit choice the gate offers.
// Both paths leave confinement off — the difference is what they record:
// abort keeps the refusal only, while continue-unsandboxed marks the session
// unmistakably and audits exactly which denials are not in force.
export const resolveGate = Effect.fn("SandboxPolicy.resolveGate")(function* (sessionID: SessionID, choice: GateChoice) {
  const directory = yield* InstanceState.directory
  const gate = yield* SandboxGate.assess()
  return yield* locked(
    sessionID,
    Effect.gen(function* () {
      const stored = yield* read(directory, sessionID)
      const base = stored ?? (yield* resolveInitial(directory, sessionID))
      const version = base.version + 1
      const next: Snapshot = { ...base, enabled: false, version, ...(choice === "continue-unsandboxed" ? { unsandboxed: true } : {}) }
      yield* Effect.promise(() => SandboxStore.write(directory, sessionID, next))
      const id = key(directory, sessionID)
      snapshots.set(id, next)
      synced.set(id, revision)
      const refusal = gate.verdict === "refuse" ? gate.reason : undefined
      const continued = choice === "continue-unsandboxed"
      const reason = continued
        ? `${SandboxGate.UNSANDBOXED_SIGNAL}: ${refusal ?? "the sandbox is unavailable on this host"} — commands run with full reach and every audited denial is not in force`
        : refusal
      const value = { directory, enabled: false, available: false, reason, diagnostics: [...gate.diagnostics], unsandboxed: continued, version }
      yield* Effect.promise(() => Bus.publish(Instance.current, Changed, { sessionID, ...value }))
      const ctx = yield* InstanceState.context
      const audit = {
        type: continued ? "sandbox.gate.continue-unsandboxed" : "sandbox.gate.abort",
        sessionID,
        directory,
        osBuild: os.release(),
        tier: gate.tier,
        reason: refusal,
        diagnostics: [...gate.diagnostics],
        ...(continued
          ? {
              denied: deniedByProfile(
                profile(
                  ctx,
                  base.mode,
                  base.writablePaths,
                  base.allowedHosts,
                  base.relaxations ?? [],
                  base.allowedCidrs ?? [],
                ),
              ),
            }
          : {}),
      }
      yield* Effect.promise(() => SandboxStore.appendAudit(sessionID, audit))
      return value
    }),
  )
})

/** Stored confinement for a session in an explicit directory, without seeding from config. */
export const peek = Effect.fn("SandboxPolicy.peek")(function* (directory: string, sessionID: SessionID) {
  return yield* read(directory, sessionID)
})

// The relaxation grant seam (ticket 15): the permission prompt, config, and
// the PTY surface (ticket 17) all end here. A granted relaxation is stored
// with the session snapshot — it applies to this session only and never
// seeds the next one — and is recorded in the session log with its source
// (prompt). Durable config relaxations never pass through here: they are
// re-composed from config each command and logged once per session at init.
export const relax = Effect.fn("SandboxPolicy.relax")(function* (sessionID: SessionID, request: unknown) {
  if (!SandboxRelaxation.grantable(request)) {
    return yield* Effect.fail(new Error("Invalid sandbox relaxation request"))
  }
  const gate = yield* SandboxGate.assess()
  const directory = yield* InstanceState.directory
  return yield* locked(
    sessionID,
    Effect.gen(function* () {
      const stored = yield* read(directory, sessionID)
      const base = stored ?? (yield* resolveInitial(directory, sessionID))
      const { entries, added } = SandboxRelaxation.appended(base.relaxations ?? [], request)
      const next: Snapshot = added ? { ...base, relaxations: entries, version: base.version + 1 } : base
      if (added) {
        yield* Effect.promise(() => SandboxStore.write(directory, sessionID, next))
        const id = key(directory, sessionID)
        snapshots.set(id, next)
        synced.set(id, revision)
        yield* Effect.promise(() => SandboxStore.appendAudit(sessionID, SandboxRelaxation.record(request, "prompt")))
      }
      const support = backendSupport({ mode: next.mode, allowedHosts: next.allowedHosts })
      const merged = SandboxGate.fold(support, gate)
      const value = {
        directory,
        enabled: next.enabled && merged.available,
        available: merged.available,
        reason: merged.reason,
        unsandboxed: next.unsandboxed === true,
        audit: next.audit === true,
        version: next.version,
      }
      yield* Effect.promise(() => Bus.publish(Instance.current, Changed, { sessionID, ...value }))
      return value
    }),
  )
})

function intersect(parent: Snapshot, child: Snapshot) {
  const paths = child.writablePaths.filter((value) => parent.writablePaths.includes(value))
  const parentCidrs = parent.allowedCidrs ?? []
  const cidrs =
    parentCidrs.length > 0
      ? (child.allowedCidrs ?? []).filter((rule) => parentCidrs.some((entry) => JSON.stringify(entry) === JSON.stringify(rule)))
      : []
  if (parent.mode === "deny" || child.mode === "deny") {
    return { mode: "deny" as const, allowedHosts: [], writablePaths: paths, ...(cidrs.length > 0 ? { allowedCidrs: cidrs } : {}) }
  }
  if (parent.mode === "allow" && child.mode === "allow") {
    return { mode: "allow" as const, allowedHosts: [], writablePaths: paths, ...(cidrs.length > 0 ? { allowedCidrs: cidrs } : {}) }
  }
  const hosts =
    parent.mode === "proxy" && child.mode === "proxy"
      ? child.allowedHosts.filter((value) => parent.allowedHosts.includes(value))
      : parent.mode === "proxy"
        ? parent.allowedHosts
        : child.allowedHosts
  return {
    mode: hosts.length > 0 ? ("proxy" as const) : ("deny" as const),
    allowedHosts: hosts,
    writablePaths: paths,
    ...(cidrs.length > 0 ? { allowedCidrs: cidrs } : {}),
  }
}

const inheritSnapshot = Effect.fn("SandboxPolicy.inheritSnapshot")(function* (
  directory: string,
  parent: Snapshot,
  sessionID: SessionID,
  version = revision,
) {
  const child = yield* read(directory, sessionID)
  const next: Snapshot = child
    ? {
        enabled: parent.enabled || child.enabled,
        ...intersect(parent, child),
        version: child.version + 1,
      }
    : { ...parent, version: 0 }
  if (
    child &&
    child.enabled === next.enabled &&
    child.mode === next.mode &&
    child.allowedHosts.join("\0") === next.allowedHosts.join("\0") &&
    child.writablePaths.join("\0") === next.writablePaths.join("\0") &&
    cidrsEqual(child.allowedCidrs, next.allowedCidrs)
  )
    return
  yield* Effect.promise(() => SandboxStore.write(directory, sessionID, next))
  const id = key(directory, sessionID)
  snapshots.set(id, next)
  synced.set(id, version)
  yield* publishChanged(sessionID, directory, next)
})

export const inherit = Effect.fn("SandboxPolicy.inherit")(function* (
  parentID: SessionID,
  sessionID: SessionID,
  fallback?: Omit<Snapshot, "version">,
  sourceDirectory?: string,
) {
  const directory = yield* InstanceState.directory
  const source = sourceDirectory ?? directory
  yield* refreshing(
    parentID,
    Effect.gen(function* () {
      const stored = yield* read(source, parentID)
      const parent: Snapshot | undefined = stored ?? (fallback && { ...fallback, version: 0 })
      if (!parent) return
      // Only persist the parent snapshot when it actually belongs to this directory. A fallback
      // carries confinement from another directory (e.g. forking into a worktree) and must not be
      // written back under the parent's key here, or it leaks a phantom parent record.
      yield* refreshing(
        sessionID,
        inheritSnapshot(directory, parent, sessionID, synced.get(key(source, parentID)) ?? -1),
      )
    }),
  )
})

export function toggleGuarded<E, R, F = never, Q = never, P = never, S = never>(
  sessionID: SessionID,
  guard:
    | Effect.Effect<unknown, E, R>
    | ((enabling: boolean, family: readonly Target[]) => Effect.Effect<unknown, E, R>),
  family?: Effect.Effect<readonly Target[], F, Q>,
  preflight?: (family: readonly Target[]) => Effect.Effect<unknown, P, S>,
) {
  return change(sessionID, guard, family, preflight)
}

export function retire<A, E, R>(
  sessionID: SessionID,
  directory: string,
  effect: Effect.Effect<A, E, R>,
): Effect.Effect<A, E, R> {
  return locked(
    sessionID,
    Effect.gen(function* () {
      return yield* refreshing(
        sessionID,
        Effect.gen(function* () {
          const result = yield* effect
          yield* Effect.promise(() => SandboxStore.remove(directory, sessionID))
          const id = key(directory, sessionID)
          snapshots.delete(id)
          synced.delete(id)
          return result
        }),
      )
    }),
  )
}

export function dispose<A, E, R>(sessionID: SessionID, effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> {
  return locked(
    sessionID,
    Effect.gen(function* () {
      return yield* refreshing(
        sessionID,
        Effect.gen(function* () {
          const result = yield* effect
          yield* Effect.promise(() => SandboxStore.dispose(sessionID))
          const suffix = "\0" + sessionID
          for (const id of snapshots.keys()) {
            if (!id.endsWith(suffix)) continue
            snapshots.delete(id)
            synced.delete(id)
          }
          return result
        }),
      )
    }),
  )
}

function execute<A, E, R>(sessionID: SessionID, effect: Effect.Effect<A, E, R>) {
  return Effect.gen(function* () {
    // Initialize before taking the execution gate so activation can safely hold the policy lock while
    // waiting for an already-started tool to finish without deadlocking snapshot initialization.
    yield* snapshot(sessionID)
    return yield* gated(
      sessionID,
      1,
      Effect.gen(function* () {
        const active = yield* current(sessionID, true)
        const config = SandboxConfig.resolve(yield* (yield* Config.Service).get())
        const relaxations = relaxationsFor(active.state, config)
        if (active.state.audit === true) {
          // Audit mode (ADR 0002): commands run UNSANDBOXED while the table
          // that would have governed them — grants, denials, egress — is
          // composed per command and recorded in the session log under the
          // unsandboxed signal. Grant-table authoring aid, never silent
          // half-enforcement. The MXC engine's allow-capture path is wired
          // behind KILO_MXC_AUDIT_ENGINE=1 for hosts with a fixed engine; on
          // this SDK generation it crashes the host process (documented
          // upstream blocker), so the default is the unsandboxed dry run.
          const ctx = yield* InstanceState.context
          const composed = profile(
            ctx,
            active.state.mode,
            active.state.writablePaths,
            active.state.allowedHosts,
            relaxations,
            active.state.allowedCidrs ?? [],
          )
          const table = translate(composed, { command: "", args: [], cwd: ctx.directory, environment: process.env })
          yield* Effect.promise(() =>
            SandboxStore.appendAudit(sessionID, {
              type: "sandbox.audit.run",
              sessionID,
              directory: active.directory,
              signal: `${SandboxGate.UNSANDBOXED_SIGNAL} (audit mode)`,
              wouldEnforce: {
                readwrite: table.filesystem.readwritePaths,
                readonly: table.filesystem.readonlyPaths,
                denied: table.filesystem.deniedPaths,
                egress: table.network.egress,
              },
              relaxations,
            }),
          )
          if (engineAudit()) {
            const gate = yield* SandboxGate.assess()
            const support = backendSupport({ mode: active.state.mode, allowedHosts: active.state.allowedHosts })
            if (gate.verdict !== "refuse" && support.available) {
              return yield* runSandbox(
                { ...composed, audit: { denialsPath: SandboxStore.denialsPath(sessionID) } },
                effect,
              )
            }
          }
          return yield* unrestricted(effect)
        }
        if (!active.state.enabled) return yield* unrestricted(effect)
        const gate = yield* SandboxGate.assess()
        if (gate.verdict === "refuse") {
          // The host gate is the floor: a session never runs sandboxed on a host
          // whose probe returned anything but the base-container tier.
          return yield* Effect.fail(new Error(gate.reason ?? "The host cannot enforce the sandbox"))
        }
        const support = backendSupport({ mode: active.state.mode, allowedHosts: active.state.allowedHosts })
        if (!support.available) {
          return yield* Effect.fail(new Error(support.reason ?? "The configured sandbox backend is unavailable"))
        }
        return yield* runSandbox(
          profile(
            yield* InstanceState.context,
            active.state.mode,
            active.state.writablePaths,
            active.state.allowedHosts,
            relaxations,
            active.state.allowedCidrs ?? [],
          ),
          effect,
        )
      }),
    )
  })
}

export function executeTool<A, E, R>(sessionID: SessionID, tool: { id: string }, effect: Effect.Effect<A, E, R>) {
  return execute(sessionID, Network.tool(tool, effect))
}

export function executeEscalated<A, E, R>(approved: boolean, effect: Effect.Effect<A, E, R>) {
  return approved ? unrestricted(effect) : effect
}

export function executeMcp<A, E, R>(sessionID: SessionID, tool: object, effect: Effect.Effect<A, E, R>) {
  return execute(sessionID, Network.mcp(tool, effect))
}
