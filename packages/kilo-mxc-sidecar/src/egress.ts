// The run-level egress wrapper (ADR 0003): each proxied run is pinned to its
// own loopback egress proxy for exactly the run's lifetime — the allowlist is
// per-command policy, so proxies are never shared between runs — and every
// raw CIDR/port relaxation is recorded in the warnings the caller sees, so the
// deliberate widening is visible in the command's captured output. A cidr
// posture that replaced a proxy+allowlist one is warned about too: the
// hostnames the allowlist used to serve stopped flowing, silently by default.
// The proxy's lifecycle rides the sidecar: kills, shutdown, and sidecar exit
// all release every listener this wrapper started.

import { createEgressProxy, type EgressProxy } from "./proxy.ts"
import type { CidrPortRule, RunCommand, RunEgress, RunHandle, RunResult } from "./run.ts"
import type { RunBindings, RunOptions, Runtime } from "./sdk.ts"

export type EgressRuntime = Runtime & {
  readonly closeProxies: () => Promise<void>
}

function relaxationWarnings(rules: ReadonlyArray<CidrPortRule>): string[] {
  return rules.map((rule) => {
    const destinations = rule.to.join(", ")
    if (!rule.ports || rule.ports.length === 0) return `egress relaxation: ${destinations} [any]`
    const ports = rule.ports
      .map((selector) => {
        const range =
          selector.port === undefined ? "*" : selector.endPort === undefined ? `${selector.port}` : `${selector.port}-${selector.endPort}`
        return `${selector.protocol}:${range}`
      })
      .join(", ")
    return `egress relaxation: ${destinations} [${ports}]`
  })
}

// A cidr posture that replaced a proxy+allowlist one narrowed the run: those
// hostnames stopped flowing, so the switch is named in the run's warnings
// beside the relaxation record itself.
function postureSwitchWarnings(egress: Extract<RunEgress, { default: "cidr" }>): string[] {
  const dropped = egress.switchedFromProxy
  if (dropped === undefined || dropped.length === 0) return []
  return [
    `egress posture switch: raw CIDR relaxations replace the proxy allowlist for this run — these hostnames no longer flow: ${dropped.join(", ")}`,
  ]
}

export function withEgressProxy(runtime: Runtime): EgressRuntime {
  const live = new Set<EgressProxy>()

  const track = (proxy: EgressProxy) => {
    live.add(proxy)
    return () => {
      live.delete(proxy)
      void proxy.close().catch(() => {})
    }
  }

  const relaxationsFor = (command: RunCommand): string[] => {
    const egress = command.network.egress
    if (egress.default !== "cidr") return []
    return [...relaxationWarnings(egress.allow), ...postureSwitchWarnings(egress)]
  }

  const annotate = (handle: RunHandle, warnings: string[]): RunHandle => ({
    wait: () => handle.wait().then((result): RunResult => ({ ...result, warnings: [...result.warnings, ...warnings] })),
    kill: handle.kill,
  })

  const run = async (command: RunCommand, bindings: RunBindings = {}, options: RunOptions = {}): Promise<RunHandle> => {
    const egress = command.network.egress
    if (egress.default !== "proxy") {
      const warnings = relaxationsFor(command)
      const handle = await runtime.run(command, bindings, options)
      return warnings.length > 0 ? annotate(handle, warnings) : handle
    }
    const proxy = await createEgressProxy({ allowedHosts: egress.allowedHosts })
    const release = track(proxy)
    const settle = () => release()
    try {
      const handle = await runtime.run(command, { ...bindings, networkProxy: proxy.endpoint }, options)
      return {
        wait: () => handle.wait().finally(settle),
        kill: () => {
          try {
            handle.kill()
          } finally {
            settle()
          }
        },
      }
    } catch (cause) {
      settle()
      throw cause
    }
  }

  return {
    getPlatformSupport: runtime.getPlatformSupport,
    run,
    closeProxies: async () => {
      const proxies = [...live]
      live.clear()
      await Promise.all(proxies.map((proxy) => proxy.close().catch(() => {})))
    },
  }
}
