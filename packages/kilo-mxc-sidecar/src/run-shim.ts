// The per-command launcher the Windows sandbox backend rewrites launches into.
// It owns a transient sidecar for exactly one confined command: start, handshake,
// run, forward the captured stdio and exit code, shut down. If this process is
// killed, the sidecar observes stdin closing and tree-kills the confined command
// (MXC kill is a job-object tree kill), so a cancelled launch never leaves a
// sandboxed process running unowned.

import process from "node:process"
import { startSidecar } from "./client.ts"
import { isRunCommand, type RunCommand } from "./run.ts"

function fail(message: string): never {
  process.stderr.write(`kilo-mxc-shim: ${message}\n`)
  process.exit(1)
}

const encoded = process.argv[2]
if (encoded === undefined) fail("no run payload given")
let payload: unknown
try {
  payload = JSON.parse(encoded)
} catch (cause) {
  fail(`run payload is not JSON: ${cause instanceof Error ? cause.message : String(cause)}`)
}
if (!isRunCommand(payload)) fail("run payload is not a valid confined command")
const command: RunCommand = payload

let sidecar: Awaited<ReturnType<typeof startSidecar>>
try {
  sidecar = await startSidecar()
} catch (cause) {
  fail(`could not start the sandbox sidecar: ${cause instanceof Error ? cause.message : String(cause)}`)
}
let code = 1
try {
  await sidecar.handshake()
  const result = await sidecar.run(command)
  if (result.stdout !== "") process.stdout.write(result.stdout)
  if (result.stderr !== "") process.stderr.write(result.stderr)
  for (const warning of result.warnings) process.stderr.write(`[kilo-mxc] ${warning}\n`)
  code = result.exitCode
} catch (cause) {
  process.stderr.write(`kilo-mxc-shim: ${cause instanceof Error ? cause.message : String(cause)}\n`)
} finally {
  // Bounded teardown: a sidecar that will not answer shutdown must not keep
  // the launcher (and its reported exit code) alive.
  await Promise.race([
    sidecar.shutdown().catch(() => {}),
    new Promise<void>((resolve) => setTimeout(resolve, 2_000)),
  ])
  sidecar.stop()
  process.exit(code)
}
