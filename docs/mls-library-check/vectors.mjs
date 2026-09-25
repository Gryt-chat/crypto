// Runs the RFC 9420 interop vectors against the installed ts-mls.
// Usage: node vectors.mjs [vectorDir] [--provider=default|noble|pure] [--json=out.json]
import { readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { runVectors } from "./vectors-core.mjs"

const args = process.argv.slice(2)
const dir = args.find((a) => !a.startsWith("--")) ?? new URL("./vectors/", import.meta.url).pathname
const providerName = (args.find((a) => a.startsWith("--provider=")) ?? "--provider=default").split("=")[1]
const jsonOut = args.find((a) => a.startsWith("--json="))?.split("=")[1]

const report = await runVectors({
  load: (file) => JSON.parse(readFileSync(join(dir, file), "utf8")),
  providerName,
  only: process.env.ONLY,
  log: (m) => console.log(m),
  now: () => performance.now(),
})
const failed = report.reduce((a, r) => a + r.fail, 0)
const version = JSON.parse(readFileSync(new URL("./node_modules/ts-mls/package.json", import.meta.url))).version
console.log(`\nprovider=${providerName} ts-mls=${version} node=${process.version}`)
console.log(failed === 0 ? "all vectors passed" : `${failed} vectors failed`)
if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ runtime: `node ${process.version}`, provider: providerName, report }, null, 2))
process.exitCode = failed === 0 ? 0 : 1
