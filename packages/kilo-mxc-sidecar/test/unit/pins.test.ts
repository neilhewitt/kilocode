import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { UNIT_PINS, nodeArchiveName, satisfiesWindowsNodeFloor } from "../../src/unit/pins.ts"

// ADR 0005 and the spec's Implementation Decisions are the source of truth for
// these literals: pinned Node >= 24.21 from official nodejs.org distributions,
// @microsoft/mxc-sdk pinned exactly per release, one versioned unit.
describe("sidecar unit pins", () => {
  test("pins the Node runtime on the 24.x LTS line at or above the 24.21 Windows floor", () => {
    assert.equal(UNIT_PINS.node.version, "24.21.0")
    assert.ok(satisfiesWindowsNodeFloor(UNIT_PINS.node.version), "pinned Node must satisfy >=24.21.0 <25 || >=26.8.0")
  })

  test("pins @microsoft/mxc-sdk to an exact version, never a range", () => {
    assert.equal(UNIT_PINS.sdk.name, "@microsoft/mxc-sdk")
    assert.match(UNIT_PINS.sdk.version, /^\d+\.\d+\.\d+$/)
    assert.equal(UNIT_PINS.sdk.version, "1.0.0")
  })

  test("every Node distribution archive carries a pinned sha256 from nodejs.org", () => {
    for (const file of Object.values(UNIT_PINS.node.archives)) {
      assert.match(file.sha256, /^[0-9a-f]{64}$/, "archive digests must be lowercase hex sha256")
      assert.match(file.archive, /^node-v24\.21\.0-(win|linux|darwin)-[a-z0-9-]+\.(zip|tar\.gz)$/)
    }
  })

  test("records the digests nodejs.org published for v24.21.0", () => {
    // Independent source of truth: https://nodejs.org/dist/v24.21.0/SHASUMS256.txt
    assert.equal(UNIT_PINS.node.archives["win32-x64"].sha256, "158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541")
    assert.equal(UNIT_PINS.node.archives["win32-arm64"].sha256, "8779b1bde1d39f8d420e3b57aa657b39891af434d3de44a919044cec06785921")
  })

  test("resolves the official archive name for a platform", () => {
    assert.equal(nodeArchiveName("win32", "x64"), "node-v24.21.0-win-x64.zip")
    assert.equal(nodeArchiveName("linux", "arm64"), "node-v24.21.0-linux-arm64.tar.gz")
    assert.equal(nodeArchiveName("darwin", "x64"), "node-v24.21.0-darwin-x64.tar.gz")
    assert.throws(() => nodeArchiveName("aix" as unknown as "win32", "x64"))
  })
})

