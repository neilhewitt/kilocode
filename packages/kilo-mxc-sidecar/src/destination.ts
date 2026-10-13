// Destination parsing and DNS resolution for the egress proxy. Vendored from
// packages/kilo-sandbox/src/destination.ts (same semantics, no dependencies —
// the sidecar unit ships its sources alone beside the bundled Node runtime, so
// it must never grow a node_modules tree). Keep the two in step: an allowlist
// entry must normalise identically on both sides of the seam.

import { lookup } from "node:dns/promises"
import { isIP } from "node:net"
import { domainToASCII } from "node:url"

export interface Destination {
  readonly host: string
  readonly port: number
  readonly authority: string
}

function invalid(input: string) {
  return new TypeError(`Invalid sandbox network destination: ${JSON.stringify(input)}`)
}

function hostname(input: string) {
  if (input.length === 0 || input.length > 253 || isIP(input) !== 0 || /^[0-9.]+$/.test(input)) throw invalid(input)
  const host = domainToASCII(input.toLowerCase())
  if (!host || host.length > 253) throw invalid(input)
  const labels = host.split(".")
  if (
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        label.startsWith("-") ||
        label.endsWith("-") ||
        !/^[a-z0-9-]+$/.test(label),
    )
  ) {
    throw invalid(input)
  }
  return host
}

export function parseDestination(input: string, defaultPort = 443): Destination {
  if (input !== input.trim() || /[\u0000-\u0020\u007f/@?#*]/.test(input)) throw invalid(input)
  const colon = input.lastIndexOf(":")
  const hasPort = colon > -1
  const value = hasPort ? input.slice(0, colon) : input
  const raw = value.endsWith(".") ? value.slice(0, -1) : value
  const text = hasPort ? input.slice(colon + 1) : String(defaultPort)
  if (!/^\d+$/.test(text)) throw invalid(input)
  const port = Number(text)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw invalid(input)
  const host = hostname(raw)
  return { host, port, authority: `${host}:${port}` }
}

export function normalizeDestinations(input: ReadonlyArray<string>) {
  return [...new Set(input.map((value) => parseDestination(value).authority))].sort()
}

function octets(input: string) {
  const parts = input.split(".")
  if (parts.length !== 4) return undefined
  const values: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined
    const value = Number(part)
    if (value > 255) return undefined
    values.push(value)
  }
  return values
}

function ipv4Value(input: string): bigint | undefined {
  const parts = octets(input)
  if (!parts) return undefined
  return (BigInt(parts[0]) << 24n) | (BigInt(parts[1]) << 16n) | (BigInt(parts[2]) << 8n) | BigInt(parts[3])
}

// Parses an IPv6 literal (with "::" compression and an optional trailing IPv4
// tail) into its 128-bit value. Dependency-free on purpose; rejects anything
// ipaddr.js would not parse as a plain literal.
function ipv6Value(input: string): bigint | undefined {
  const sections = input.split("::")
  if (sections.length > 2) return undefined
  const side = (text: string, allowV4Tail: boolean): number[] | undefined => {
    if (text === "") return []
    const parts = text.split(":")
    const groups: number[] = []
    for (let index = 0; index < parts.length; index++) {
      const part = parts[index]
      if (/^[0-9a-fA-F]{1,4}$/.test(part)) {
        groups.push(Number.parseInt(part, 16))
        continue
      }
      const tail = octets(part)
      if (tail && allowV4Tail && index === parts.length - 1) {
        groups.push((tail[0] << 8) | tail[1], (tail[2] << 8) | tail[3])
        continue
      }
      return undefined
    }
    return groups
  }
  const head = side(sections[0] ?? "", sections.length === 1)
  const tail = sections.length === 2 ? side(sections[1], true) : head
  if (!head || !tail) return undefined
  if (sections.length === 1) {
    if (head.length !== 8) return undefined
  } else if (head.length + tail.length > 7) {
    return undefined
  }
  const groups = sections.length === 1 ? head : [...head, ...Array<number>(8 - head.length - tail.length).fill(0), ...tail]
  let value = 0n
  for (const group of groups) value = (value << 16n) | BigInt(group)
  return value
}

function within(value: bigint, base: bigint, bits: number) {
  const shift = BigInt(bits)
  return value >> shift === base >> shift
}

function v4(a: number, b: number, c: number, d: number) {
  return (BigInt(a) << 24n) | (BigInt(b) << 16n) | (BigInt(c) << 8n) | BigInt(d)
}

const ipv4Blocked: ReadonlyArray<readonly [base: bigint, bits: number]> = [
  [v4(0, 0, 0, 0), 8],
  [v4(10, 0, 0, 0), 8],
  [v4(100, 64, 0, 0), 10],
  [v4(127, 0, 0, 0), 8],
  [v4(169, 254, 0, 0), 16],
  [v4(172, 16, 0, 0), 12],
  [v4(192, 0, 0, 0), 24],
  [v4(192, 0, 2, 0), 24],
  [v4(192, 168, 0, 0), 16],
  [v4(198, 18, 0, 0), 15],
  [v4(198, 51, 100, 0), 24],
  [v4(203, 0, 113, 0), 24],
  [v4(224, 0, 0, 0), 3],
]

function inRange(value: bigint, ranges: ReadonlyArray<readonly [base: bigint, bits: number]>) {
  return ranges.some(([base, bits]) => within(value, base, bits))
}

const ipv6Blocked: ReadonlyArray<readonly [base: bigint, bits: number]> = [
  [0n, 96],
  [0xffffn << 96n, 96],
  [0x64ff9bn << 96n, 96],
  [0xfe80n << 112n, 10],
  [0xfc00n << 112n, 7],
  [0xff00n << 112n, 8],
  [(0x2001n << 112n) | (0x0db8n << 96n), 32],
]

// A resolve target must be a public unicast address: loopback, RFC1918,
// link-local, CGNAT, documentation, transition, and multicast/reserved ranges
// are all refused, so a rebinding allowlisted hostname cannot turn the proxy
// into a relay into the host's own private networks. IPv4-mapped and
// IPv4-compatible IPv6 forms are refused wholesale, as on the macOS backend.
export function isPublicAddress(input: string) {
  const family = isIP(input)
  if (family === 4) {
    const value = ipv4Value(input)
    return value !== undefined && !inRange(value, ipv4Blocked)
  }
  if (family === 6) {
    const value = ipv6Value(input)
    return value !== undefined && !inRange(value, ipv6Blocked)
  }
  return false
}

export interface ResolvedDestination {
  readonly address: string
  readonly family: number
}

export type EgressResolver = (destination: Destination) => Promise<ResolvedDestination>

export async function resolveDestination(destination: Destination) {
  const addresses = await lookup(destination.host, { all: true, verbatim: true })
  if (addresses.length === 0 || addresses.some((entry) => !isPublicAddress(entry.address))) {
    throw new Error(`Sandbox denied a non-public address for ${destination.authority}`)
  }
  return addresses[0]
}
