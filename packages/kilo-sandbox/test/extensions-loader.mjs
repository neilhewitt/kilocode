// Test loader: this package's sources target the Bun toolchain — extensionless
// relative imports and non-erasable TypeScript (parameter properties). Plain
// `node --test` needs this hook to (a) append `.ts` to extensionless relative
// specifiers and (b) transpile `.ts` through the real TypeScript compiler.
// Bun hosts load the same sources natively and never register this file.
import { readFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import ts from "typescript"

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context)
  } catch (error) {
    if (specifier.startsWith(".") || specifier.startsWith("/")) {
      return nextResolve(`${specifier}.ts`, context)
    }
    throw error
  }
}

export async function load(url, context, nextLoad) {
  if (url.endsWith(".ts")) {
    const source = await readFile(fileURLToPath(url), "utf8")
    const output = ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ESNext,
        verbatimModuleSyntax: false,
      },
    })
    return { format: "module", shortCircuit: true, source: output.outputText }
  }
  return nextLoad(url, context)
}
