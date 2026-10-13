import { describe, test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { createHash } from "node:crypto"
import { fetchNodeRuntime } from "../../src/unit/node-runtime.ts"

// Fake distribution server: serves fixture bytes at nodejs.org-shaped URLs and
// records every URL requested. Extraction and version probing are injected so
// these tests exercise integrity behaviour, not archive tooling.
function fixtureServer(archiveBytes: Buffer, shasums: string) {
  const urls: string[] = []
  const fetchImpl = async (url: string) => {
    urls.push(url)
    if (url.endsWith("SHASUMS256.txt")) return new Response(shasums, { status: 200 })
    if (url.endsWith(".zip") || url.endsWith(".tar.gz")) return new Response(archiveBytes, { status: 200 })
    return new Response("not found", { status: 404 })
  }
  return { fetchImpl, urls }
}

function pins(archiveBytes: Buffer) {
  const digest = createHash("sha256").update(archiveBytes).digest("hex")
  return {
    version: "24.21.0",
    archives: {
      "win32-x64": { archive: "node-v24.21.0-win-x64.zip", sha256: digest },
    },
  }
}

async function temp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "kilo-mxc-node-"))
}

const extract = async (archive: string, dest: string) => {
  await fs.mkdir(path.join(dest, "node-v24.21.0-win-x64"), { recursive: true })
  await fs.writeFile(path.join(dest, "node-v24.21.0-win-x64", "node.exe"), "fake-node")
}

const probeVersion = async () => "v24.21.0"

describe("pinned Node runtime acquisition", () => {
  test("downloads only from nodejs.org and verifies against the pin and SHASUMS256.txt", async () => {
    const archive = Buffer.from("official-node-archive-bytes")
    const shasums = `${pins(archive).archives["win32-x64"]!.sha256}  node-v24.21.0-win-x64.zip\n`
    const { fetchImpl, urls } = fixtureServer(archive, shasums)
    const cache = await temp()
    try {
      const runtime = await fetchNodeRuntime({
        os: "win32",
        arch: "x64",
        cacheDir: cache,
        pins: pins(archive),
        fetchImpl,
        extract,
        probeVersion,
      })
      assert.ok(urls.every((url) => url.startsWith("https://nodejs.org/dist/")), `urls: ${urls.join(", ")}`)
      assert.ok(urls.some((url) => url.endsWith("SHASUMS256.txt")), "must fetch the official checksum list")
      assert.equal(path.basename(runtime.nodeExecutable), "node.exe")
      assert.equal(runtime.version, "24.21.0")
    } finally {
      await fs.rm(cache, { recursive: true, force: true })
    }
  })

  test("refuses an archive whose digest does not match the pin", async () => {
    const archive = Buffer.from("tampered-archive")
    const pinned = pins(Buffer.from("official-node-archive-bytes"))
    const shasums = `${pinned.archives["win32-x64"]!.sha256}  node-v24.21.0-win-x64.zip\n`
    const { fetchImpl } = fixtureServer(archive, shasums)
    const cache = await temp()
    try {
      await assert.rejects(
        fetchNodeRuntime({ os: "win32", arch: "x64", cacheDir: cache, pins: pinned, fetchImpl, extract, probeVersion }),
        /digest mismatch/,
      )
      // Nothing may be extracted from a rejected download.
      const entries = await fs.readdir(cache)
      assert.ok(!entries.includes("node-v24.21.0-win-x64"), "rejected archive must not be extracted")
    } finally {
      await fs.rm(cache, { recursive: true, force: true })
    }
  })

  test("refuses an archive that contradicts the fetched SHASUMS256.txt", async () => {
    // The pin is satisfied but nodejs.org's checksum list names a different
    // digest for this archive: the download must be refused all the same.
    const archive = Buffer.from("official-node-archive-bytes")
    const pinned = pins(archive)
    const shasums = `${"0".repeat(64)}  node-v24.21.0-win-x64.zip\n`
    const { fetchImpl } = fixtureServer(archive, shasums)
    const cache = await temp()
    try {
      await assert.rejects(
        fetchNodeRuntime({ os: "win32", arch: "x64", cacheDir: cache, pins: pinned, fetchImpl, extract, probeVersion }),
        /SHASUMS256/,
      )
    } finally {
      await fs.rm(cache, { recursive: true, force: true })
    }
  })

  test("refuses a SHASUMS256.txt fetch failure rather than trusting TLS alone", async () => {
    const archive = Buffer.from("official-node-archive-bytes")
    const pinned = pins(archive)
    const fetchImpl = async (url: string) => {
      if (url.endsWith("SHASUMS256.txt")) return new Response("gone", { status: 404 })
      return new Response(archive)
    }
    const cache = await temp()
    try {
      await assert.rejects(
        fetchNodeRuntime({ os: "win32", arch: "x64", cacheDir: cache, pins: pinned, fetchImpl, extract, probeVersion }),
        /SHASUMS256/,
      )
    } finally {
      await fs.rm(cache, { recursive: true, force: true })
    }
  })

  test("refuses an extracted runtime that reports the wrong version", async () => {
    const archive = Buffer.from("official-node-archive-bytes")
    const pinned = pins(archive)
    const shasums = `${pinned.archives["win32-x64"]!.sha256}  node-v24.21.0-win-x64.zip\n`
    const { fetchImpl } = fixtureServer(archive, shasums)
    const cache = await temp()
    try {
      await assert.rejects(
        fetchNodeRuntime({
          os: "win32",
          arch: "x64",
          cacheDir: cache,
          pins: pinned,
          fetchImpl,
          extract,
          probeVersion: async () => "v22.0.0",
        }),
        /reports v22\.0\.0/,
      )
    } finally {
      await fs.rm(cache, { recursive: true, force: true })
    }
  })

  test("reuses a cached archive without any download", async () => {
    const archive = Buffer.from("official-node-archive-bytes")
    const pinned = pins(archive)
    const shasums = `${pinned.archives["win32-x64"]!.sha256}  node-v24.21.0-win-x64.zip\n`
    const { fetchImpl, urls } = fixtureServer(archive, shasums)
    const cache = await temp()
    try {
      await fetchNodeRuntime({ os: "win32", arch: "x64", cacheDir: cache, pins: pinned, fetchImpl, extract, probeVersion })
      urls.length = 0
      const second = await fetchNodeRuntime({
        os: "win32",
        arch: "x64",
        cacheDir: cache,
        pins: pinned,
        fetchImpl,
        extract,
        probeVersion,
      })
      assert.deepEqual(urls, [], "cache hit must not hit the network")
      assert.equal(second.fromCache, true)
    } finally {
      await fs.rm(cache, { recursive: true, force: true })
    }
  })
})
