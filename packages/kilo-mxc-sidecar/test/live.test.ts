import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { existsSync } from "node:fs"
import os from "node:os"
import { pathToFileURL } from "node:url"
import { startSidecar } from "../src/client.ts"

// Probe-gated live passthrough (spec seam 3 style): runs only where the real MXC
// SDK is present (KILO_MXC_SDK_ENTRY or the research smoke install) AND the host
// runs Node (the SDK's native modules cannot load under Bun) AND the probe
// returns the base-container enforcement tier. Everywhere else this skips with a
// reason; the wire contract itself is covered by control.test.ts and
// sidecar.test.ts, which run on any host.
function resolveEntry() {
  return (
    process.env.KILO_MXC_SDK_ENTRY ?? `${os.tmpdir()}/kilo/mxc-smoke/node_modules/@microsoft/mxc-sdk/dist/v1/index.js`
  )
}

describe("live platform-support passthrough", () => {
  test("sidecar platform support matches a direct probe", async (t) => {
    const entry = resolveEntry()
    const versions = process.versions as Record<string, string | undefined>
    if (!existsSync(entry)) return t.skip(`MXC SDK not installed at ${entry}`)
    if (versions.bun) return t.skip("the MXC SDK cannot run under Bun; run under Node on a probe-capable host")
    const sdk = (await import(pathToFileURL(entry).href)) as {
      getPlatformSupport: () => Promise<Record<string, unknown>>
    }
    const direct = await sdk.getPlatformSupport()
    if (direct.isolationTier !== "base-container") {
      return t.skip(`host enforcement tier is ${String(direct.isolationTier)}, not base-container`)
    }
    const sidecar = await startSidecar({ env: { KILO_MXC_SDK_ENTRY: entry } })
    try {
      await sidecar.handshake()
      const via = await sidecar.platformSupport()
      assert.equal(via.isSupported, direct.isSupported)
      assert.equal(via.isolationTier, direct.isolationTier)
      assert.deepEqual(via.availableMethods, direct.availableMethods)
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
  })
})
