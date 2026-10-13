// Build-time entrypoint: assembles the versioned sidecar unit (pinned Node +
// pinned MXC SDK + sidecar server + manifest) into an output directory.
//
//   node script/build-unit.ts --output ../../opencode/dist/kilo-windows-x64/bin/mxc-sidecar-unit
//
// Options: --output <dir> (required), --os <win32|linux|darwin>, --arch
// <x64|arm64> (default: this machine), --cache <dir> (default: a temp cache).
// Downloads come only from official nodejs.org distributions and are verified
// against the pins in src/unit/pins.ts and against SHASUMS256.txt.

import path from "node:path"
import os from "node:os"
import { assembleUnit } from "../src/unit/assemble.ts"

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`)
  return index >= 0 ? process.argv[index + 1] : undefined
}

const output = argument("output")
if (!output) {
  process.stderr.write("usage: node script/build-unit.ts --output <dir> [--os win32] [--arch x64] [--cache <dir>]\n")
  process.exit(2)
}

const targetOs = (argument("os") ?? process.platform) as "win32" | "linux" | "darwin"
const arch = (argument("arch") ?? process.arch) as "x64" | "arm64"
const cacheDir = argument("cache") ?? path.join(os.tmpdir(), "kilo-mxc-sidecar-unit-cache")

try {
  const unit = await assembleUnit({
    output: path.resolve(output),
    os: targetOs,
    arch,
    cacheDir,
    log: (message) => process.stdout.write(`[mxc-sidecar-unit] ${message}\n`),
  })
  process.stdout.write(`${unit}\n`)
} catch (cause) {
  process.stderr.write(`[mxc-sidecar-unit] ${cause instanceof Error ? cause.message : String(cause)}\n`)
  process.exit(1)
}
