// The versioned sidecar unit's pins: one Node runtime, one @microsoft/mxc-sdk
// version, and the sidecar server ship and update together per Kilo release
// (ADR 0005). These constants are the single source of truth for the build-time
// assembly, the unit manifest, release notes, and the runtime pin check. The
// digests are the ones nodejs.org published in
// https://nodejs.org/dist/v24.21.0/SHASUMS256.txt — the download path verifies
// against them and against a freshly fetched SHASUMS256.txt.
//
// The MXC SDK's Windows native-stdio gate accepts Node >=24.21.0 <25 or
// >=26.8.0; the pin sits on the 24.x LTS ("Krypton") line at that floor.

export type UnitPlatform = {
  os: "win32" | "linux" | "darwin"
  arch: "x64" | "arm64"
}

type ArchivePin = {
  archive: string
  sha256: string
}

export const NODE_DIST_BASE = "https://nodejs.org/dist"

export const UNIT_PINS = {
  node: {
    version: "24.21.0",
    archives: {
      "win32-x64": {
        archive: "node-v24.21.0-win-x64.zip",
        sha256: "158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541",
      },
      "win32-arm64": {
        archive: "node-v24.21.0-win-arm64.zip",
        sha256: "8779b1bde1d39f8d420e3b57aa657b39891af434d3de44a919044cec06785921",
      },
      "linux-x64": {
        archive: "node-v24.21.0-linux-x64.tar.gz",
        sha256: "6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff",
      },
      "linux-arm64": {
        archive: "node-v24.21.0-linux-arm64.tar.gz",
        sha256: "724282c3b43aec998aa9527380465b45d229e021b58035f5f4f63095eabfe5d5",
      },
      "darwin-x64": {
        archive: "node-v24.21.0-darwin-x64.tar.gz",
        sha256: "1462cb3b3046b815cf8ea436d3da450ec1a9f11dac7e5a46b0ada5305d7e8097",
      },
      "darwin-arm64": {
        archive: "node-v24.21.0-darwin-arm64.tar.gz",
        sha256: "bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057",
      },
    } satisfies Record<string, ArchivePin>,
  },
  sdk: {
    name: "@microsoft/mxc-sdk",
    version: "1.0.0",
  },
} as const

export function nodeArchivePin(os: UnitPlatform["os"], arch: UnitPlatform["arch"]): ArchivePin {
  const pin = UNIT_PINS.node.archives[`${os}-${arch}`]
  if (!pin) throw new Error(`No pinned Node distribution for ${os}-${arch}`)
  return pin
}

export function nodeArchiveName(os: UnitPlatform["os"], arch: UnitPlatform["arch"]): string {
  return nodeArchivePin(os, arch).archive
}

export function nodeDistUrl(os: UnitPlatform["os"], arch: UnitPlatform["arch"]): string {
  const pin = nodeArchivePin(os, arch)
  return `${NODE_DIST_BASE}/v${UNIT_PINS.node.version}/${pin.archive}`
}

export function nodeShasumsUrl(): string {
  return `${NODE_DIST_BASE}/v${UNIT_PINS.node.version}/SHASUMS256.txt`
}

// The SDK's supportsNativeStdio gate (mxc sdk/node/src/bindings/native-stdio.ts):
// win32 needs Node >=24.21.0 <25 || >=26.8.0. Kept here so the pin can be
// checked against the floor it was chosen for.
export function satisfiesWindowsNodeFloor(version: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version)
  if (!match) return false
  const major = Number(match[1])
  const minor = Number(match[2])
  if (major === 24) return minor >= 21
  return major >= 26 && (major > 26 || minor >= 8)
}
