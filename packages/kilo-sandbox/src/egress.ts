// Egress policy vocabulary for the Windows sandbox (ADR 0003): a named
// starter allowlist that ships default-on and trims to deny-all in one edit,
// plus the explicit raw CIDR/port relaxation path for non-HTTP egress. The
// posture resolution here is the single decision point the agent core's config
// layer delegates to, so the default and its trim behave identically everywhere.

import ipaddr from "ipaddr.js"
import type { CidrPortRule, CidrPortSelector } from "@kilocode/mxc-sidecar"
import { normalizeDestinations } from "./destination.ts"

// Major package registries plus GitHub/GitLab git-over-HTTPS, pre-normalised
// to destination authorities (hostname:port) in canonical sorted order. Entries:
// npm (registry.npmjs.org), NuGet (api/www.nuget.org), PyPI
// (pypi.org, files.pythonhosted.org), cargo (crates.io, index/static.crates.io),
// git-over-HTTPS (github.com + api/codeload/objects/raw, gitlab.com). Removing
// entries (or trimming the whole list via `network: "deny"` or
// `allowed_hosts: []`) is a one-edit config change; the list is never silently
// extended.
export const STARTER_EGRESS_ALLOWLIST = [
  "api.github.com:443",
  "api.nuget.org:443",
  "codeload.github.com:443",
  "crates.io:443",
  "files.pythonhosted.org:443",
  "github.com:443",
  "gitlab.com:443",
  "index.crates.io:443",
  "objects.githubusercontent.com:443",
  "pypi.org:443",
  "raw.githubusercontent.com:443",
  "registry.npmjs.org:443",
  "static.crates.io:443",
  "www.nuget.org:443",
] as const satisfies ReadonlyArray<string>

export type EgressPostureInput = {
  readonly network?: "allow" | "deny" | undefined
  readonly allowedHosts?: ReadonlyArray<string> | undefined
}

export type EgressPosture = {
  readonly mode: "allow" | "deny" | "proxy"
  readonly allowedHosts: ReadonlyArray<string>
}

// The default posture for restricted egress with no host list is the starter
// allowlist; an explicitly empty list (or `network: "deny"`) is deny-all.
export function resolveEgressPosture(input: EgressPostureInput): EgressPosture {
  if (input.network === "allow") return { mode: "allow", allowedHosts: [] }
  if (input.network === "deny") return { mode: "deny", allowedHosts: [] }
  const hosts =
    input.allowedHosts === undefined ? [...STARTER_EGRESS_ALLOWLIST] : normalizeDestinations(input.allowedHosts)
  return hosts.length > 0 ? { mode: "proxy", allowedHosts: hosts } : { mode: "deny", allowedHosts: [] }
}

const protocols = new Set(["tcp", "udp", "icmp", "any"])

function invalid(value: string) {
  return new Error(`Invalid sandbox egress relaxation: ${value}`)
}

function normalizeCidr(input: string): string {
  const candidate = input.includes("/") ? input : singleHost(input)
  try {
    const [address, prefix] = ipaddr.parseCIDR(candidate)
    return `${address.toString()}/${prefix}`
  } catch {
    throw invalid(`destination ${JSON.stringify(input)} is not a valid IPv4 or IPv6 CIDR`)
  }
}

function singleHost(input: string): string {
  if (!ipaddr.isValid(input)) throw invalid(`destination ${JSON.stringify(input)} is not a valid IPv4 or IPv6 address`)
  return `${input}/${ipaddr.parse(input).kind() === "ipv4" ? 32 : 128}`
}

function normalizePort(selector: CidrPortSelector): CidrPortSelector {
  if (!protocols.has(selector.protocol)) throw invalid(`protocol ${JSON.stringify(selector.protocol)}`)
  for (const key of ["port", "endPort"] as const) {
    const value = selector[key]
    if (value === undefined) continue
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
      throw invalid(`${key} ${JSON.stringify(value)} is not a valid port`)
    }
  }
  if (selector.endPort !== undefined && selector.port === undefined) throw invalid("endPort requires port")
  if (selector.endPort !== undefined && selector.port !== undefined && selector.endPort < selector.port) {
    throw invalid(`endPort ${selector.endPort} is below port ${selector.port}`)
  }
  return selector
}

// Validates and canonicalises recorded relaxations. Anything the sandbox
// cannot express exactly is refused here, before it ever reaches a container.
export function normalizeCidrRules(rules: ReadonlyArray<CidrPortRule>): ReadonlyArray<CidrPortRule> {
  return rules.map((rule) => {
    if (rule.to.length === 0) throw invalid("a relaxation rule needs at least one destination CIDR")
    if (rule.ports !== undefined && rule.ports.length === 0) {
      throw invalid("a relaxation rule with ports needs at least one port selector")
    }
    return {
      to: rule.to.map(normalizeCidr),
      ...(rule.ports === undefined ? {} : { ports: rule.ports.map(normalizePort) }),
    }
  })
}
