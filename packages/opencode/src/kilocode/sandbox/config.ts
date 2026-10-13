import { Schema } from "effect"
import type { CidrPortRule } from "@kilocode/sandbox"
import { normalizeCidrRules, parseDestination, resolveEgressPosture } from "@kilocode/sandbox"

export namespace SandboxConfig {
  export const Network = Schema.Literals(["allow", "deny"])
  export type Network = Schema.Schema.Type<typeof Network>

  const Destination = Schema.String.check(
    Schema.makeFilter((value: string) => {
      try {
        parseDestination(value)
        return undefined
      } catch {
        return "Expected an exact public DNS host with an optional port, for example api.github.com:443"
      }
    }),
  )

  const CidrPorts = Schema.Struct({
    protocol: Schema.Literals(["tcp", "udp", "icmp", "any"]).annotate({
      description: "Transport protocol the relaxation covers (default: any)",
    }),
    port: Schema.optional(Schema.Number.annotate({ description: "Destination port; omission matches every port" })),
    end_port: Schema.optional(
      Schema.Number.annotate({ description: "Inclusive end of a destination-port range; requires port" }),
    ),
  })

  function toRule(rule: { to: string[]; ports?: Array<{ protocol: "tcp" | "udp" | "icmp" | "any"; port?: number; end_port?: number }> | undefined }): CidrPortRule {
    return {
      to: rule.to,
      ...(rule.ports === undefined
        ? {}
        : {
            ports: rule.ports.map((port) => ({
              protocol: port.protocol,
              ...(port.port === undefined ? {} : { port: port.port }),
              ...(port.end_port === undefined ? {} : { endPort: port.end_port }),
            })),
          }),
    }
  }

  const CidrRuleShape = Schema.Struct({
    to: Schema.mutable(Schema.Array(Schema.String)).annotate({
      description: "IPv4 or IPv6 destination CIDRs the relaxation covers",
    }),
    ports: Schema.optional(
      Schema.mutable(Schema.Array(CidrPorts)).annotate({
        description: "Protocol/port selectors; omission matches every port",
      }),
    ),
  })
  type CidrRuleShape = Schema.Schema.Type<typeof CidrRuleShape>

  const CidrRule = CidrRuleShape.check(
    Schema.makeFilter((value: CidrRuleShape) => {
      try {
        normalizeCidrRules([toRule(value)])
        return undefined
      } catch (cause) {
        return cause instanceof Error ? cause.message : "Invalid egress relaxation"
      }
    }),
  )
  type CidrRule = Schema.Schema.Type<typeof CidrRule>

  export const Info = Schema.Struct({
    enabled: Schema.optional(
      Schema.Boolean.annotate({ description: "Enable sandbox confinement for new sessions (default: false)" }),
    ),
    network: Schema.optional(
      Network.annotate({
        description:
          "Control outbound network access from sandboxed tools (default: allowlisted through the sandbox proxy; 'deny' trims to deny-all)",
      }),
    ),
    writable_paths: Schema.optional(
      Schema.mutable(Schema.Array(Schema.String)).annotate({
        description: "Additional filesystem paths that sandboxed tools may write to",
      }),
    ),
    allowed_hosts: Schema.optional(
      Schema.mutable(Schema.Array(Destination)).annotate({
        description:
          "Exact network destinations sandboxed tools may access while network restriction is enabled (default: the starter registry/git-over-HTTPS allowlist)",
      }),
    ),
    allowed_cidrs: Schema.optional(
      Schema.mutable(Schema.Array(CidrRule)).annotate({
        description:
          "Explicit raw destination CIDR/port egress relaxations for non-HTTP flows; recorded with every run they apply to and governed by these rules alone",
      }),
    ),
  }).annotate({ description: "Sandbox configuration for agent tools" })
  export type Info = Schema.Schema.Type<typeof Info>

  export function resolve(config: { sandbox?: Info }) {
    const posture = resolveEgressPosture({
      network: config.sandbox?.network,
      allowedHosts: config.sandbox?.allowed_hosts,
    })
    const cidrs = normalizeCidrRules((config.sandbox?.allowed_cidrs ?? []).map(toRule))
    return {
      enabled: config.sandbox?.enabled ?? false,
      mode: posture.mode,
      allowedHosts: [...posture.allowedHosts],
      writablePaths: [...(config.sandbox?.writable_paths ?? [])],
      ...(cidrs.length > 0 ? { allowedCidrs: cidrs } : {}),
    }
  }

  export function scope<T extends { sandbox?: Info }>(config: T, source: "global" | "local"): T {
    if (source === "global" || config.sandbox === undefined) return config
    const scoped = { ...config }
    const sandbox: Info = {
      ...(config.sandbox.enabled === true ? { enabled: true } : {}),
      ...(config.sandbox.network === "deny" ? { network: "deny" as const, allowed_hosts: [] } : {}),
    }
    if (Object.keys(sandbox).length > 0) scoped.sandbox = sandbox
    else delete scoped.sandbox
    return scoped
  }
}
