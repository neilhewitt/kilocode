import { $ } from "bun"
// kilocode_change - the sidecar unit's pins belong in release notes (ADR 0005)
import { expectedManifest } from "../../packages/kilo-mxc-sidecar/src/unit/manifest"
import { sidecarReleaseNotes } from "../../packages/kilo-mxc-sidecar/src/unit/notes"
import { PROTOCOL_VERSION } from "../../packages/kilo-mxc-sidecar/src/protocol"

const fallback = "No notable changes"
const pattern = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/

type Release = {
  tagName: string
  isDraft: boolean
  isPrerelease: boolean
}

export function buildNotes(input: { version: string; prerelease: boolean; releases: Release[]; changelog: string }) {
  const target = version(input.version)
  if (!target) throw new Error(`Invalid release version: ${input.version}`)

  const sections = parse(input.changelog)
  const current = sections.find((section) => section.version === target)
  if (!current) return fallback
  if (input.prerelease) return current.body || fallback

  const stable = input.releases
    .flatMap((release) => {
      const value = version(release.tagName)
      if (!value || release.isDraft || release.isPrerelease || compare(value, target) >= 0) return []
      return [value]
    })
    .sort((a, b) => compare(b, a))[0]
  const versions = new Set([
    target,
    ...input.releases.flatMap((release) => {
      const value = version(release.tagName)
      if (!value || release.isDraft || !release.isPrerelease || compare(value, target) >= 0) return []
      if (stable && compare(value, stable) <= 0) return []
      return [value]
    }),
  ])
  const notes = sections
    .filter((section) => versions.has(section.version) && section.body)
    .map((section) => `## ${section.version}\n\n${section.body}`)
  return notes.join("\n\n") || fallback
}

export function buildReleaseNotes(input: {
  version: string
  prerelease: boolean
  releases: Release[]
  vscode: string
  cli: string
}) {
  const notes = (
    [
      ["VS Code", input.vscode],
      ["CLI", input.cli],
    ] as const
  ).flatMap(([name, changelog]) => {
    const body = buildNotes({ ...input, changelog })
    if (body === fallback) return []
    return [`## ${name}\n\n${input.prerelease ? body : body.replace(/^(#+) /gm, "#$1 ")}`]
  })
  return notes.join("\n\n") || fallback
}

// kilocode_change start - append the sidecar unit pins to every release's
// notes (spec: release notes include the SDK pin and contract changes). The
// section is generated from the manifest the unit build produces; when a
// previous release's manifest is available, pass it to get pin-change diffs.
// The MXC sidecar unit ships for Windows only (ADR 0005); the notes text
// itself carries node/SDK/protocol pins, not the platform.
export function sidecarSection(version: string, previous?: ReturnType<typeof expectedManifest>) {
  const current = expectedManifest(
    { os: "win32", arch: "x64" },
    { version, protocol: PROTOCOL_VERSION, entry: "sidecar/src/main.ts" },
  )
  return sidecarReleaseNotes({ current, previous })
}
// kilocode_change end

export async function publishNotes(input: { version: string; prerelease: boolean; repo?: string; temp?: string }) {
  const repo = input.repo ? ["--repo", input.repo] : []
  const releases: Release[] = await $`gh release list --limit 1000 --json tagName,isDraft,isPrerelease ${repo}`.json()
  const [vscode, cli] = await Promise.all([
    Bun.file(new URL("../../packages/kilo-vscode/CHANGELOG.md", import.meta.url)).text(),
    // The inherited "opencode" folder contains Kilo's CLI (@kilocode/cli), not upstream release notes.
    // Read Kilo's changelog, including compact upstream summaries added when those changes are merged into Kilo.
    Bun.file(new URL("../../packages/opencode/CHANGELOG.md", import.meta.url)).text(),
  ])
  const body = buildReleaseNotes({ ...input, releases, vscode, cli })
  // kilocode_change - the sidecar unit section travels with every release
  const withSidecar = `${body}\n\n${sidecarSection(version(input.version))}`
  const notes = `${input.temp ?? "/tmp"}/release-notes.txt`
  const target = input.version.startsWith("v") ? input.version : `v${input.version}`
  const flags = input.prerelease ? ["--draft=false", "--prerelease"] : ["--draft=false"]
  await Bun.write(notes, withSidecar)
  flags.push("--title", `${target} (${input.prerelease ? "pre-release" : "release"})`, "--notes-file", notes)
  await $`gh release edit ${target} ${flags} ${repo}`
}

function parse(input: string) {
  const matches = Array.from(input.matchAll(/^##\s+(.+)$/gm))
  return matches.flatMap((match, index) => {
    const value = version(match[1] ?? "")
    if (!value) return []
    const start = (match.index ?? 0) + match[0].length
    const end = matches[index + 1]?.index ?? input.length
    return [{ version: value, body: input.slice(start, end).trim() }]
  })
}

function version(input: string) {
  return input.trim().match(pattern)?.[1]
}

function compare(a: string, b: string) {
  return Bun.semver.order(a, b)
}
