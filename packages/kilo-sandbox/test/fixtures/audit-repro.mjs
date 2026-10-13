// KNOWN-RISK repro isolating the MXC engine path for audit mode (ticket 15).
// Loads the real SDK in this child process so an access violation kills only
// this child, never the test runner, and runs ONE confined command whose grant
// table explicitly denies a file the command writes to, with captureDenials in
// allow-mode (the SDK's audit mode: denials suspended, captured, reported).
// Prints one JSON verdict line; exits 0 unless the engine takes the process
// down first.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"

const entry =
  process.env.KILO_MXC_SDK_ENTRY ??
  `${os.tmpdir()}/kilo/mxc-smoke/node_modules/@microsoft/mxc-sdk/dist/v1/index.js`
const sdk = await import(pathToFileURL(entry).href)
const support = await sdk.getPlatformSupport()
if (support.isSupported !== true || support.isolationTier !== "base-container") {
  console.log(JSON.stringify({ outcome: "skip", tier: String(support.isolationTier ?? "") }))
  process.exit(0)
}
const root = mkdtempSync(path.join(os.tmpdir(), "kilo-audit-repro-"))
try {
  const denied = path.join(root, "data", "probe.txt")
  mkdirSync(path.dirname(denied), { recursive: true })
  writeFileSync(denied, "blocked")
  const child = await sdk.spawn({
    command: `cmd /c echo answer > ${denied}`,
    workingDirectory: root,
    containment: { type: "processcontainer", config: { captureDenials: { mode: "allow" } } },
    filesystem: { readwritePaths: [root], readonlyPaths: [], deniedPaths: [denied] },
    network: { egress: { default: "deny" } },
    inheritDefaultEnvironment: true,
  })
  const err = []
  if (child.standardError) child.standardError.on("data", (chunk) => err.push(String(chunk)))
  const result = await child.wait()
  const metadata = child.outputMetadata?.()
  const capture = metadata?.captureDenials
  console.log(
    JSON.stringify({
      outcome: "captured",
      exitCode: result.exitCode,
      rewritten: existsSync(denied) ? readFileSync(denied, "utf8").trim() : "",
      totalDenials: capture?.totalDenials ?? 0,
      report: capture?.outputPath ?? "",
      captured: capture !== undefined,
      stderr: err.join(""),
      warnings: [...child.warnings],
    }),
  )
} finally {
  rmSync(root, { recursive: true, force: true })
}
