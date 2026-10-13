// One-off live smoke (not part of the suite): start the sidecar from the
// freshly assembled unit using its own bundled node.exe and the REAL MXC SDK,
// exactly as a fresh install would — no system Node, no scripted runtime.
import { resolveUnit } from "../src/unit/resolve.ts"
import { startSidecar } from "../src/client.ts"

const unit = process.argv[2]
if (!unit) throw new Error("usage: node script/live-unit-smoke.ts <unit-dir>")
const resolved = await resolveUnit({ env: { KILO_MXC_UNIT: unit } })
if (!resolved.ok) throw new Error(resolved.reasons.join("; "))
console.log(`node: ${resolved.node}`)
console.log(`entry: ${resolved.entry}`)
console.log(`sdk entry: ${resolved.env.KILO_MXC_SDK_ENTRY}`)
const sidecar = await startSidecar({ node: resolved.node, entry: resolved.entry, env: resolved.env })
try {
  const handshake = await sidecar.handshake()
  console.log(`handshake: protocol ${handshake.protocol}, pid ${handshake.pid}`)
  const support = await sidecar.platformSupport()
  console.log(`platform support (real SDK): ${JSON.stringify(support)}`)
} finally {
  await sidecar.shutdown()
}
console.log("sidecar shut down cleanly")
