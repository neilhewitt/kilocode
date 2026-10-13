import { createControlServer } from "./control.ts"
import { controlEndpoint } from "./endpoint.ts"
import { PROTOCOL_VERSION } from "./protocol.ts"
import { runtimeFromEnvironment } from "./sdk.ts"

// Sidecar entrypoint. The agent core (or the contract tests) spawns this under the
// bundled Node runtime with KILO_MXC_CONTROL_ID and KILO_MXC_CONTROL_TOKEN in the
// environment. Readiness is a single JSON line on stdout — the only thing this
// process ever writes to stdout — carrying the control endpoint. On Windows the
// named pipe's default security descriptor admits only the creating user and
// administrators, which is the principal scoping the threat model requires.
const id = process.env.KILO_MXC_CONTROL_ID
const token = process.env.KILO_MXC_CONTROL_TOKEN
if (!id || !token) {
  process.stderr.write("kilo-mxc-sidecar requires KILO_MXC_CONTROL_ID and KILO_MXC_CONTROL_TOKEN\n")
  process.exit(2)
}

const runtime = await runtimeFromEnvironment()
const server = createControlServer({ runtime, endpoint: controlEndpoint(id), token })
server.onShutdown(async () => {
  await server.stop()
  process.exit(0)
})
await server.listen()
process.stdout.write(
  JSON.stringify({ ready: true, channel: "control", endpoint: server.endpoint, protocol: PROTOCOL_VERSION, pid: process.pid }) + "\n",
)
// The parent holds stdin; when it goes away the sidecar must not linger — and
// any confined command it is still running must not outlive its caller.
const farewell = () => {
  server.killAll()
  void server.stop().then(() => process.exit(0))
}
process.stdin.resume()
process.stdin.on("close", farewell)
process.stdin.on("end", farewell)
