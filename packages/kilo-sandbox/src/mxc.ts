import { existsSync, readdirSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect, PlatformError } from "effect"
import type { RunCommand } from "@kilocode/mxc-sidecar"
import type { Backend, Launch, Support } from "./backend"
import type { PathRule, Profile } from "./profile"

// The Windows sandbox backend. Kilo's sandbox Profile is translated into an MXC
// run request carried by the sidecar's launcher shim: prepare() rewrites the
// launch into `<node> <run-shim> <request>`, so every command still flows
// through the existing per-command seam (prepareCommand → spawner) and the
// confined execution happens inside the sidecar's processcontainer sandbox.
// Execution is transient — one sandbox per command (ADR 0001) — and this ticket
// ships a deliberately minimal policy: workspace read-write, egress denied.
// The full strictest-default grant table (ancestors, credential stores, cache
// redirection) is composed by the default-grant-table work, not here.

declare const KILO_MXC_SHIM_PATH: string | undefined

const caseInsensitive = process.platform === "win32"

// Windows command-line quoting: an argument is quoted when it contains
// whitespace or quotes, with backslashes doubled before each quote and at the
// closing quote. The MXC engine re-parses the command line, so this must match
// the conventions the target executable expects.
export function quoteWindows(argument: string) {
  if (argument === "") return '""'
  if (!/[\s"]/.test(argument)) return argument
  let quoted = '"'
  let backslashes = 0
  for (const character of argument) {
    if (character === "\\") {
      backslashes += 1
      continue
    }
    if (character === '"') {
      quoted += "\\".repeat(backslashes * 2 + 1) + '"'
      backslashes = 0
      continue
    }
    quoted += "\\".repeat(backslashes) + character
    backslashes = 0
  }
  return quoted + "\\".repeat(backslashes * 2) + '"'
}

// Shell launches are composed the way the other backends do it, with Windows
// quoting because this backend is win32-only.
function commandLine(launch: Launch) {
  if (!launch.shell) return [launch.command, ...launch.args].map(quoteWindows).join(" ")
  const shell = typeof launch.shell === "string" ? launch.shell : "cmd.exe"
  const body = [launch.command, ...launch.args.map(quoteWindows)].join(" ")
  return `${shell} -c ${quoteWindows(body)}`
}

// The minimal read-only launch baseline: the OS and program directories every
// real command needs just to start. The full validated default table is the
// default-grant-table work's concern; this keeps the minimal policy launchable.
function baseline() {
  if (process.platform !== "win32") return []
  const roots = [process.env.SystemRoot, process.env.ProgramFiles, process.env["ProgramFiles(x86)"]]
  return roots.filter((value): value is string => typeof value === "string")
}

function exists(rule: PathRule) {
  if (!existsSync(rule.path)) return false
  const entry = statSync(rule.path)
  if (rule.kind === "literal") return entry.isFile()
  return entry.isDirectory()
}

function distinct(paths: ReadonlyArray<string>) {
  const seen = new Set<string>()
  const keep: Array<string> = []
  for (const entry of paths) {
    if (entry === "" || seen.has(entry)) continue
    seen.add(entry)
    keep.push(entry)
  }
  return keep
}

function list(dir: string) {
  try {
    return readdirSync(dir, { withFileTypes: true })
  } catch {
    return []
  }
}

// Finds deny-named entries under the writable roots so they can be denied
// outright (the spec maps denyNames onto denied paths). The scan is
// best-effort-bounded: an unreadable directory is denied as a whole rather than
// scanned, mirroring the Bubblewrap backend's fail-closed posture.
function scan(root: string, names: ReadonlySet<string>, found: Set<string>) {
  const pending = [root]
  while (pending.length > 0) {
    const dir = pending.pop()
    if (!dir) continue
    for (const entry of list(dir)) {
      const target = path.join(dir, entry.name)
      const name = caseInsensitive ? entry.name.toLowerCase() : entry.name
      const match = caseInsensitive ? [...names].some((n) => n.toLowerCase() === name) : names.has(name)
      if (match) {
        found.add(target)
        continue
      }
      if (entry.isDirectory()) pending.push(target)
    }
  }
}

function deniedNames(profile: Profile, allow: ReadonlyArray<PathRule>) {
  if (profile.filesystem.denyNames.length === 0) return []
  const names = new Set(profile.filesystem.denyNames)
  const found = new Set<string>()
  for (const rule of allow) {
    if (rule.kind === "subtree") scan(rule.path, names, found)
  }
  return [...found].sort((a, b) => a.length - b.length)
}

function safeEnvironment(environment: Launch["environment"]) {
  const source = environment ?? {}
  const safe: Record<string, string> = {}
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && !key.startsWith("KILO_MXC_")) safe[key] = value
  }
  return safe
}

// Seam 1: the pure Profile → MXC request translation.
export function translate(profile: Profile, launch: Launch): RunCommand {
  const allow = distinct(
    profile.filesystem.allowWrite.filter(exists).map((rule) => rule.path).sort((a, b) => a.length - b.length),
  )
  const temporary = profile.filesystem.temporaryDirectory
  const readwrite = temporary && existsSync(temporary) && !allow.includes(temporary) ? [...allow, temporary] : allow
  const readonly = distinct([
    ...profile.filesystem.denyWrite.filter(exists).map((rule) => rule.path),
    ...baseline(),
  ])
  return {
    command: commandLine(launch),
    ...(launch.cwd === undefined ? {} : { workingDirectory: launch.cwd }),
    filesystem: {
      readwritePaths: readwrite,
      readonlyPaths: readonly,
      deniedPaths: deniedNames(profile, profile.filesystem.allowWrite.filter(exists)),
    },
    network: {
      egress: { default: profile.network.mode === "allow" ? "allow" : "deny" },
    },
    environment: safeEnvironment(launch.environment),
  }
}

export function supportFor(platform: string, network?: Profile["network"]): Support {
  if (platform !== "win32") return { available: false, reason: "The MXC sandbox backend requires Windows" }
  if (network?.mode === "proxy") {
    return {
      available: false,
      reason: "The MXC sandbox backend requires the loopback proxy for proxy network mode; it is not available yet",
    }
  }
  return { available: true }
}

function support(network?: Profile["network"]): Support {
  return supportFor(process.platform, network)
}

function shim() {
  if (typeof KILO_MXC_SHIM_PATH !== "undefined") {
    return path.resolve(path.dirname(process.execPath), KILO_MXC_SHIM_PATH)
  }
  return fileURLToPath(import.meta.resolve("@kilocode/mxc-sidecar/run-shim"))
}

// The bundled Node runtime that hosts the sidecar (ADR 0005). Shared by the
// run shim and the read-only capability probe so both launch the same unit.
export function mxcRuntime() {
  return process.env.KILO_MXC_NODE ?? process.execPath
}

function runtime() {
  return mxcRuntime()
}

function setup(cause: unknown, launch: Launch) {
  return PlatformError.systemError({
    _tag: "PermissionDenied",
    module: "Sandbox",
    method: "prepareCommand",
    pathOrDescriptor: launch.command,
    description: cause instanceof Error ? cause.message : "Could not construct the Windows sandbox",
    cause,
  })
}

export const mxc: Backend = {
  support,
  prepare: (profile, launch) =>
    Effect.try({
      try: () => ({
        ...launch,
        command: runtime(),
        args: [shim(), JSON.stringify(translate(profile, launch))],
        shell: false,
      }),
      catch: (cause) => setup(cause, launch),
    }),
}
