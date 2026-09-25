// Bundles an entry into one classic script. For Hermes it then applies babel-preset-expo's
// hermes-v1 profile, which carries fixes for Hermes V1 bugs the app build would also get.
import { build } from "esbuild"
import { createRequire } from "node:module"

const [entry, outfile, ...rest] = process.argv.slice(2)
const require = createRequire(import.meta.url)
const optional = ["@noble/post-quantum", "@hpke/ml-kem", "@hpke/hybridkem-x-wing", "@hpke/dhkem-x448", "@hpke/chacha20poly1305"]
const missing = optional.filter((p) => {
  try {
    require.resolve(`${p}/package.json`)
    return false
  } catch {
    return true
  }
})
const stubMissing = {
  name: "stub-missing-optional-peers",
  setup(b) {
    const filter = new RegExp(`^(${missing.map((m) => m.replace(/[/@-]/g, "\\$&")).join("|") || "$^"})(/|$)`)
    b.onResolve({ filter }, (a) => ({ path: a.path, namespace: "stub" }))
    b.onLoad({ filter: /.*/, namespace: "stub" }, (a) => ({ contents: `throw new Error("optional dependency ${a.path} is not bundled")`, loader: "js" }))
  },
}
const hermes = rest.includes("--hermes")
await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  format: "iife",
  platform: "neutral",
  mainFields: ["module", "main"],
  conditions: ["import", "default"],
  target: hermes ? "es2019" : "es2022",
  supported: hermes ? { bigint: true, "dynamic-import": false } : {},
  inject: hermes ? ["./hermes-prelude.js"] : [],
  plugins: [stubMissing],
  logLevel: "warning",
})
if (hermes) {
  const { transformFileAsync } = await import("@babel/core")
  const { writeFileSync } = await import("node:fs")
  const out = await transformFileAsync(outfile, {
    babelrc: false,
    configFile: false,
    compact: false,
    presets: [require.resolve("babel-preset-expo/build/configs/hermes-v1")],
  })
  writeFileSync(outfile, out.code)
}
console.log(`${outfile} (stubbed: ${missing.join(", ") || "none"})`)
