// One-off helper: fetch the runtime dependency closure of a set of packages
// into node_modules via `npm pack`, for hosts without a workspace install.
import { execSync } from "node:child_process"
import { existsSync, mkdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "node_modules")
const queue = ["effect", "ipaddr.js"]
const walked = new Set()

const pack = (spec, cwd) => execSync(`npm pack ${spec} --silent`, { cwd, shell: true, encoding: "utf8" }).trim().split("\n").pop()

while (queue.length > 0) {
  const name = queue.shift()
  if (walked.has(name)) continue
  walked.add(name)
  const manifest = path.join(root, name, "package.json")
  if (!existsSync(manifest)) {
    console.error(`missing ${name} — pack it first`)
    process.exit(1)
  }
  const meta = JSON.parse(readFileSync(manifest, "utf8"))
  for (const dependency of Object.keys(meta.dependencies ?? {})) {
    if (dependency.startsWith("@types/")) continue
    if (walked.has(dependency) || queue.includes(dependency)) continue
    if (existsSync(path.join(root, dependency, "package.json"))) {
      queue.push(dependency)
      continue
    }
    const version = meta.dependencies[dependency]
    const packDir = path.join(root, ".pack-tmp")
    mkdirSync(packDir, { recursive: true })
    console.log(`packing ${dependency}@${version}`)
    const tarball = pack(`${dependency}@${version}`, packDir)
    const target = path.join(root, dependency)
    mkdirSync(target, { recursive: true })
    execSync(`tar -xzf "${path.join(packDir, tarball)}" -C "${target}" --strip-components 1`, { shell: true })
    queue.push(dependency)
  }
}
console.log("closure complete")
