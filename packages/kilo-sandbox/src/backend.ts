import { Effect, PlatformError, Scope } from "effect"
import { ChildProcess } from "effect/unstable/process"
import { bubblewrap } from "./bubblewrap.ts"
import { current } from "./context.ts"
import { mxc } from "./mxc.ts"
import { assertProcessNetwork, networkEnvironment } from "./network.ts"
import type { Profile } from "./profile"
import { seatbelt } from "./seatbelt.ts"
import { currentProxy, type ProxyRuntime } from "./proxy.ts"

export interface Launch {
  readonly command: string
  readonly args: ReadonlyArray<string>
  readonly cwd?: string | undefined
  readonly environment?: Readonly<Record<string, string | undefined>> | undefined
  readonly shell?: boolean | string | undefined
  // Terminal handling (ADR 0004): `stream` asks the runner to forward output
  // live (the pipes-fallback surface for confined session terminals); absent
  // keeps captured output. `timeoutMs` maps a caller-known deadline onto the
  // engine's per-request timeout; absent means no engine deadline.
  readonly stream?: boolean | undefined
  readonly timeoutMs?: number | undefined
}

export interface Support {
  readonly available: boolean
  readonly reason?: string | undefined
}

export interface Backend {
  readonly support: (network?: Profile["network"]) => Support
  readonly prepare: (
    profile: Profile,
    launch: Launch,
    proxy?: ProxyRuntime,
  ) => Effect.Effect<Launch, PlatformError.PlatformError, Scope.Scope>
}

function unavailable(reason: string): Backend {
  return {
    support: () => ({ available: false, reason }),
    prepare: (_profile, launch) => Effect.succeed(launch),
  }
}

export function select(platform: NodeJS.Platform = process.platform): Backend {
  switch (platform) {
    case "darwin":
      return seatbelt
    case "linux":
      return bubblewrap
    case "win32":
      return mxc
    default:
      return unavailable("No sandbox backend is available for this operating system")
  }
}

const backend = select()

function environment(profile: Profile, launch: Launch, proxy?: ProxyRuntime) {
  const source = { ...launch.environment, ...profile.environment.set }
  const denied = new Set(profile.environment.deny)
  const entries = Object.entries(source).filter(
    (entry): entry is [string, string] => entry[1] !== undefined && !denied.has(entry[0]),
  )
  return networkEnvironment(profile, Object.fromEntries(entries), proxy)
}

export function prepare(launch: Launch) {
  return Effect.gen(function* () {
    const profile = yield* current
    if (!profile) return launch
    const proxy = yield* currentProxy
    const next = { ...launch, environment: environment(profile, launch, proxy) }
    yield* assertProcessNetwork(profile, launch.command)
    const support = backend.support(profile.network)
    if (!support.available) return yield* Effect.fail(unsupported(launch.command, "prepare", support))
    return yield* backend.prepare(profile, next, proxy)
  })
}

function unsupported(command: string, method: string, support: Support) {
  return PlatformError.systemError({
    _tag: "PermissionDenied",
    module: "Sandbox",
    method,
    pathOrDescriptor: command,
    description: support.reason ?? "The process sandbox backend is unavailable",
  })
}

export function confine(profile: Profile, launch: Launch) {
  return Effect.gen(function* () {
    const proxy = yield* currentProxy
    const next = { ...launch, environment: environment(profile, launch, proxy) }
    yield* assertProcessNetwork(profile, launch.command)
    const support = backend.support(profile.network)
    if (!support.available) return yield* Effect.fail(unsupported(launch.command, "confine", support))
    return yield* backend.prepare(profile, next, proxy)
  })
}

export function prepareCommand(
  command: ChildProcess.StandardCommand,
  cwd: string | undefined,
  env: Readonly<Record<string, string | undefined>> | undefined,
) {
  return Effect.gen(function* () {
    const profile = yield* current
    if (!profile) return command
    const launch = yield* confine(profile, {
      command: command.command,
      args: command.args,
      cwd,
      environment: env,
      shell: command.options.shell,
    })
    return ChildProcess.make(launch.command, launch.args, {
      ...command.options,
      cwd: launch.cwd,
      env: launch.environment,
      extendEnv: false,
      shell: false,
    })
  })
}

export function backendSupport(network?: Profile["network"]) {
  return backend.support(network)
}
