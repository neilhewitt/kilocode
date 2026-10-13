import path from "node:path"
import { assembleUnit } from "../../../kilo-mxc-sidecar/src/unit/assemble.ts"

// Stages the versioned MXC sidecar unit (pinned Node runtime, pinned
// @microsoft/mxc-sdk, sidecar server, manifest) beside the compiled CLI
// binary, following the bundled-bubblewrap pattern: build-time assembly from
// official sources, so a fresh install needs no system Node and no admin
// steps. Windows-only — the MXC sandbox is the Windows backend (ADR 0005).
export async function stageMxcSidecarUnit(os: string, arch: "x64" | "arm64", binDir: string) {
  if (os !== "win32") return undefined
  if (process.env.KILO_SKIP_MXC_SIDECAR_UNIT === "1") return undefined
  const output = path.join(binDir, "mxc-sidecar-unit")
  await assembleUnit({
    output,
    os: "win32",
    arch,
    cacheDir: process.env.KILO_MXC_SIDECAR_UNIT_CACHE ?? path.join(import.meta.dir, ".mxc-sidecar-unit-cache"),
    log: (message) => console.log(`[mxc-sidecar-unit] ${message}`),
  })
  return output
}
