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

export type PlatformSupport = object

export type Runtime = {
  getPlatformSupport: () => Promise<PlatformSupport>
}

export const TELEMETRY_KEY_PATTERN = /telemetry/i

export function sdkEnv(ambient: NodeJS.ProcessEnv, additions: Record<string, string> = {}): NodeJS.ProcessEnv {
  for (const key of Object.keys(additions)) {
    if (TELEMETRY_KEY_PATTERN.test(key)) throw new Error(`refusing to add telemetry key ${key} to the SDK environment`)
  }
  return { ...ambient, ...additions }
}

export async function defaultRuntime(): Promise<Runtime> {
  const entry = process.env.KILO_MXC_SDK_ENTRY
  if (entry) {
    const module = (await import(entry.startsWith("file://") ? entry : `file://${entry.replace(/\\/g, "/")}`)) as {
      getPlatformSupport: () => Promise<PlatformSupport>
    }
    return { getPlatformSupport: () => module.getPlatformSupport() }
  }
  // Non-literal on purpose: the SDK never resolves from this workspace and must
  // never be bundled into the sidecar — it ships beside the bundled Node runtime
  // as one versioned unit (ADR 0005) and is loaded at runtime.
  const specifier = "@microsoft/mxc-sdk/v1"
  const module = (await import(specifier)) as {
    getPlatformSupport: () => Promise<PlatformSupport>
  }
  return { getPlatformSupport: () => module.getPlatformSupport() }
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
