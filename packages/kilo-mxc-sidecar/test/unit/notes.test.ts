import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { sidecarReleaseNotes } from "../../src/unit/notes.ts"
import type { UnitManifest } from "../../src/unit/manifest.ts"

function manifest(overrides: { sdk?: string; protocol?: number } = {}): UnitManifest {
  return {
    unitFormat: 1,
    platform: { os: "win32", arch: "x64" },
    node: {
      version: "24.21.0",
      archive: "node-v24.21.0-win-x64.zip",
      sha256: "158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541",
      source: "https://nodejs.org/dist/v24.21.0/node-v24.21.0-win-x64.zip",
    },
    sdk: { name: "@microsoft/mxc-sdk", version: overrides.sdk ?? "1.0.0" },
    sidecar: { package: "@kilocode/mxc-sidecar", version: "7.8.9", protocol: overrides.protocol ?? 1, entry: "sidecar/src/main.ts" },
    created: "2026-10-13T00:00:00.000Z",
  }
}

describe("sidecar release notes", () => {
  test("always carry the SDK pin and Node pin", () => {
    const notes = sidecarReleaseNotes({ current: manifest() })
    assert.match(notes, /@microsoft\/mxc-sdk@1\.0\.0/)
    assert.match(notes, /Node 24\.21\.0/)
    assert.match(notes, /protocol 1/)
  })

  test("a first release says the unit is new rather than changed", () => {
    const notes = sidecarReleaseNotes({ current: manifest() })
    assert.match(notes, /first/i)
  })

  test("an SDK pin change is called out as a pin change", () => {
    const notes = sidecarReleaseNotes({ current: manifest({ sdk: "1.1.0" }), previous: manifest() })
    assert.match(notes, /SDK pin .*1\.0\.0.* → .*1\.1\.0|1\.0\.0.*→.*@microsoft\/mxc-sdk@1\.1\.0/)
  })

  test("a protocol bump is called out as a contract change", () => {
    const notes = sidecarReleaseNotes({ current: manifest({ protocol: 2 }), previous: manifest() })
    assert.match(notes, /contract change|protocol .*1.* → .*2|2.*contract/i)
  })

  test("unchanged pins across a release are reported as unchanged", () => {
    const current = manifest()
    const notes = sidecarReleaseNotes({ current, previous: { ...manifest(), created: "2026-09-01T00:00:00.000Z" } })
    assert.match(notes, /unchanged/i)
    assert.doesNotMatch(notes, /contract change/i)
  })
})
