import { existsSync, readdirSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect, PlatformError } from "effect"
import type { CidrPortRule, RunCommand, RunEgress } from "@kilocode/mxc-sidecar"
import { normalizeDestinations } from "./destination.ts"
import type { Backend, Launch, Support } from "./backend"
import type { PathRule, Profile } from "./profile"

// The Windows sandbox backend. Kilo's sandbox Profile is translated into an MXC
// run request carried by the sidecar's launcher shim: prepare() rewrites the
// launch into `<node> <run-shim> <request>`, so every command still flows
// through the existing per-command seam (prepareCommand → spawner) and the
// confined execution happens inside the sidecar's processcontainer sandbox.
// Execution is transient — one sandbox per command (ADR 0001). Egress is
// deny-all by default, allowlisted through the sidecar's loopback proxy, or
// relaxed by recorded raw CIDR/port rules (ADR 0003, ticket 16); the full
// strictest-default grant table (ancestors, credential stores, cache
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

// The proxy environment names are stripped from every confined environment:
// MXC sets the proxy variables itself when a run is pinned to the sidecar's
// loopback proxy, and a host-side proxy a container cannot reach would only
// turn allowed traffic into failures.
const proxyVariables = new Set([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
])

function safeEnvironment(environment: Launch["environment"]) {
  const source = environment ?? {}
  const safe: Record<string, string> = {}
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && !key.startsWith("KILO_MXC_") && !proxyVariables.has(key)) safe[key] = value
  }
  return safe
}

// Egress posture (ADR 0003): relaxations are explicit and recorded, and MXC
// rejects direct rules alongside a proxy, so a profile carrying raw CIDR/port
// rules runs on those rules alone; otherwise proxy mode rides the sidecar's
// loopback proxy with the normalised hostname allowlist (an empty list is a
// deliberate deny-all), deny stays Model 3, and allow is unrestricted.
function egressOf(network: Profile["network"]): RunEgress {
  const relaxations: ReadonlyArray<CidrPortRule> = network.allowedCidrs ?? []
  if (relaxations.length > 0) return { default: "cidr", allow: relaxations }
  if (network.mode === "allow") return { default: "allow" }
  if (network.mode === "proxy") return { default: "proxy", allowedHosts: normalizeDestinations(network.allowedHosts) }
  return { default: "deny" }
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
    network: { egress: egressOf(profile.network) },
    environment: safeEnvironment(launch.environment),
  }
}

export function supportFor(platform: string, network?: Profile["network"]): Support {
  if (platform !== "win32") return { available: false, reason: "The MXC sandbox backend requires Windows" }
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

function runtime() {
  return process.env.KILO_MXC_NODE ?? process.execPath
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
