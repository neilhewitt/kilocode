// The MXC runtime surface the sidecar hosts. `Runtime` is the injectable seam: the
// default implementation lazily loads @microsoft/mxc-sdk/v1 under the bundled Node
// runtime (never Bun — the SDK's native modules require Node >= 24.21), while
// contract tests script it. `KILO_MXC_SDK_ENTRY` points the loader at an explicit
// SDK entry file for bundled deployments that ship the SDK outside node_modules
// resolution, and `KILO_MXC_RUNTIME_MODULE` swaps in an entirely scripted runtime.
//
// Telemetry: Kilo never touches MXC telemetry switches (ADR 0006). `sdkEnv` is the
// single place where the environment handed to SDK-driven subprocesses is
// composed: ambient telemetry keys pass through byte-identical, and the sidecar
// itself can never introduce one.

import type { RunCommand, RunHandle, RunResult } from "./run.ts"

export type PlatformSupport = object

export type Runtime = {
  getPlatformSupport: () => Promise<PlatformSupport>
  run: (command: RunCommand) => Promise<RunHandle>
}
export const TELEMETRY_KEY_PATTERN = /telemetry/i

export function sdkEnv(ambient: NodeJS.ProcessEnv, additions: Record<string, string> = {}): NodeJS.ProcessEnv {
  for (const key of Object.keys(additions)) {
    if (TELEMETRY_KEY_PATTERN.test(key)) throw new Error(`refusing to add telemetry key ${key} to the SDK environment`)
  }
  return { ...ambient, ...additions }
}

// The MXC SDK surface the sidecar consumes: only what confinement needs. The
// request is composed here so the wire contract stays SDK-agnostic.
type SdkModule = {
  getPlatformSupport: () => Promise<PlatformSupport>
  spawn: (request: Record<string, unknown>) => Promise<MxcChild>
}

type MxcChild = {
  standardOutput: NodeJS.ReadableStream | null
  standardError: NodeJS.ReadableStream | null
  wait: () => Promise<{ exitCode: number; timedOut: boolean }>
  warnings?: unknown
  outputMetadata?: unknown
  kill: () => void
}

// The SDK surface has drifted between a `warnings()` method and a getter;
// read either shape without ever failing the run for it.
function warningsOf(child: MxcChild): Array<string> {
  try {
    const value = typeof child.warnings === "function" ? child.warnings() : child.warnings
    return Array.isArray(value) ? value.map(String) : []
  } catch {
    return []
  }
}

// The engine's audit posture for a run: allow-and-capture. The wire contract
// carries allow-capture only — `mode: "block"` is enforced execution and is
// not an audit surface, so it is never set here (and the wire rejects it).
function containment(command: RunCommand): Record<string, unknown> {
  if (command.audit === undefined) return { type: "processcontainer" }
  return {
    type: "processcontainer",
    config: {
      captureDenials: {
        mode: "allow",
        ...(command.audit.denialsPath === undefined || command.audit.denialsPath === ""
          ? {}
          : { outputPath: command.audit.denialsPath }),
      },
    },
  }
}

export function toSdkRequest(command: RunCommand): Record<string, unknown> {
  return {
    command: command.command,
    ...(command.workingDirectory === undefined ? {} : { workingDirectory: command.workingDirectory }),
    containment: containment(command),
    filesystem: {
      readwritePaths: [...command.filesystem.readwritePaths],
      readonlyPaths: [...command.filesystem.readonlyPaths],
      deniedPaths: [...command.filesystem.deniedPaths],
    },
    network: { egress: { default: command.network.egress.default } },
    ui: { disable: command.ui.disable },
    environment: { ...command.environment },
    inheritDefaultEnvironment: true,
  }
}

// The captureDenials summary a finished run exposes, extracted from the SDK's
// output metadata. The SDK surface has drifted between method and getter
// before (cf. warnings), so both shapes are read. A malformed or absent
// report never masquerades as a capture: audit summaries must be complete or
// missing, never invented.
function auditOf(child: MxcChild): RunResult["audit"] {
  const metadata =
    typeof child.outputMetadata === "function" ? child.outputMetadata() : child.outputMetadata
  if (typeof metadata !== "object" || metadata === null) return undefined
  const capture = (metadata as Record<string, unknown>).captureDenials
  if (typeof capture !== "object" || capture === null || Array.isArray(capture)) return undefined
  const total = (capture as Record<string, unknown>).totalDenials
  if (typeof total !== "number" || !Number.isSafeInteger(total)) return undefined
  const report = (capture as Record<string, unknown>).outputPath
  return {
    totalDenials: total,
    ...(typeof report === "string" && report !== "" ? { reportPath: report } : {}),
  }
}

export function runThrough(sdk: Pick<SdkModule, "spawn">, command: RunCommand): Promise<RunHandle> {
  return sdk.spawn(toSdkRequest(command)).then((child) => {
    // Streams must be taken before wait(): waiting drains untaken output
    // internally and later access throws.
    const collect = (stream: NodeJS.ReadableStream | null) => {
      const chunks: Buffer[] = []
      if (stream) stream.on("data", (chunk: Buffer) => chunks.push(chunk))
      return () => Buffer.concat(chunks).toString("utf8")
    }
    const stdout = collect(child.standardOutput)
    const stderr = collect(child.standardError)
    const wait = child.wait().then(
      (result): RunResult => {
        const audit = auditOf(child)
        return {
          exitCode: result.exitCode,
          stdout: stdout(),
          stderr: stderr(),
          timedOut: result.timedOut,
          warnings: warningsOf(child),
          ...(audit === undefined ? {} : { audit }),
        }
      },
    )
    return {
      wait: () => wait,
      kill: () => child.kill(),
    }
  })
}

export async function defaultRuntime(): Promise<Runtime> {
  const entry = process.env.KILO_MXC_SDK_ENTRY
  if (entry) {
    const module = (await import(entry.startsWith("file://") ? entry : `file://${entry.replace(/\\/g, "/")}`)) as SdkModule
    return {
      getPlatformSupport: () => module.getPlatformSupport(),
      run: (command) => runThrough(module, command),
    }
  }
  // Non-literal on purpose: the SDK never resolves from this workspace and must
  // never be bundled into the sidecar — it ships beside the bundled Node runtime
  // as one versioned unit (ADR 0005) and is loaded at runtime.
  const specifier = "@microsoft/mxc-sdk/v1"
  const module = (await import(specifier)) as SdkModule
  return {
    getPlatformSupport: () => module.getPlatformSupport(),
    run: (command) => runThrough(module, command),
  }
}

export async function runtimeFromEnvironment(): Promise<Runtime> {
  const hook = process.env.KILO_MXC_RUNTIME_MODULE
  if (!hook) return defaultRuntime()
  const module = (await import(hook.startsWith("file://") ? hook : `file://${hook.replace(/\\/g, "/")}`)) as {
    createRuntime?: () => Runtime
  }
  if (typeof module.createRuntime !== "function") throw new Error(`runtime module ${hook} does not export createRuntime`)
  return module.createRuntime()
}
