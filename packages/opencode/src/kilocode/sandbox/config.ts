import { Schema } from "effect"
import { isRelaxation, normalizeDestinations, parseDestination, type Relaxation } from "@kilocode/sandbox"

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

  export const RelaxationEntry = Schema.Struct({
    kind: Schema.Literals(["path", "terminal"]),
    access: Schema.optional(Schema.Literals(["read", "write"])),
    path: Schema.optional(Schema.String),
    reason: Schema.optional(Schema.String),
  }).annotate({
    description:
      "A deliberate widening of the grant table: a path relaxation grants read or write outside the default table; the terminal kind is the PTY relaxation hook",
  })

  export const Info = Schema.Struct({
    enabled: Schema.optional(
      Schema.Boolean.annotate({ description: "Enable sandbox confinement for new sessions (default: false)" }),
    ),
    network: Schema.optional(
      Network.annotate({ description: "Control outbound network access from sandboxed tools (default: deny)" }),
    ),
    writable_paths: Schema.optional(
      Schema.mutable(Schema.Array(Schema.String)).annotate({
        description: "Additional filesystem paths that sandboxed tools may write to",
      }),
    ),
    allowed_hosts: Schema.optional(
      Schema.mutable(Schema.Array(Destination)).annotate({
        description: "Exact network destinations sandboxed tools may access while network restriction is enabled",
      }),
    ),
    relaxations: Schema.optional(
      Schema.mutable(Schema.Array(RelaxationEntry)).annotate({
        description:
          "Durable relaxations applied to every session (config source); removing one restores the default table next session",
      }),
    ),
    audit: Schema.optional(
      Schema.Boolean.annotate({
        description:
          "Audit mode: commands run unsandboxed while every denial the grant table would have enforced is recorded in the session log",
      }),
    ),
  }).annotate({ description: "Sandbox configuration for agent tools" })
  export type Info = Schema.Schema.Type<typeof Info>

  export function resolve(config: { sandbox?: Info }) {
    const hosts = normalizeDestinations(config.sandbox?.allowed_hosts ?? [])
    const restricted = config.sandbox?.network !== "allow"
    return {
      enabled: config.sandbox?.enabled ?? false,
      mode: restricted ? (hosts.length > 0 ? ("proxy" as const) : ("deny" as const)) : ("allow" as const),
      allowedHosts: restricted ? hosts : [],
      writablePaths: [...(config.sandbox?.writable_paths ?? [])],
      // Fail-closed: a malformed config relaxation never reaches a table.
      relaxations: (config.sandbox?.relaxations ?? []).filter(isRelaxation) as ReadonlyArray<Relaxation>,
      audit: config.sandbox?.audit ?? false,
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
