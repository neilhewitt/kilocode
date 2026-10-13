// Release-notes section for the sidecar unit. The spec's versioning decision
// requires release notes to carry the SDK pin and any contract changes; the
// manifest is the source of truth, so the section is generated from it.

import type { UnitManifest } from "./manifest.ts"

export function sidecarReleaseNotes(input: { current: UnitManifest; previous?: UnitManifest }): string {
  const { current, previous } = input
  const lines: string[] = []
  lines.push(`### Windows sandbox sidecar unit`)
  if (!previous) {
    lines.push(
      `First release of the bundled sidecar unit: Node ${current.node.version} (official nodejs.org distribution) with ${current.sdk.name}@${current.sdk.version}, control-channel protocol ${current.sidecar.protocol}.`,
    )
    return lines.join("\n")
  }

  lines.push(`- Node runtime pin: ${nodePinLine(current, previous)}`)
  lines.push(`- MXC SDK pin: ${sdkPinLine(current, previous)}`)
  const protocol = protocolLine(current, previous)
  lines.push(`- Control-channel protocol: ${protocol.text}`)
  if (protocol.contractChange) lines.push(`- **Contract change:** the sidecar control-channel protocol moved from ${previous.sidecar.protocol} to ${current.sidecar.protocol}; agent core and sidecar update together as one unit.`)
  if (current.sdk.version !== previous.sdk.version && !protocol.contractChange) {
    lines.push(`- SDK pin change: ${previous.sdk.name}@${previous.sdk.version} → ${current.sdk.name}@${current.sdk.version}.`)
  }
  return lines.join("\n")
}

function nodePinLine(current: UnitManifest, previous: UnitManifest): string {
  if (current.node.version === previous.node.version) return `${current.node.version} (unchanged)`
  return `${previous.node.version} → ${current.node.version}`
}

function sdkPinLine(current: UnitManifest, previous: UnitManifest): string {
  const pin = `${current.sdk.name}@${current.sdk.version}`
  if (current.sdk.version === previous.sdk.version) return `${pin} (unchanged)`
  return `${previous.sdk.name}@${previous.sdk.version} → ${pin}`
}

function protocolLine(current: UnitManifest, previous: UnitManifest): { text: string; contractChange: boolean } {
  if (current.sidecar.protocol === previous.sidecar.protocol) {
    return { text: `${current.sidecar.protocol} (unchanged)`, contractChange: false }
  }
  return { text: `${previous.sidecar.protocol} → ${current.sidecar.protocol}`, contractChange: true }
}
