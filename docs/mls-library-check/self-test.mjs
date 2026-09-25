// Proves the vector checks can fail: corrupts one expected value per file and expects
// every file to report exactly one failing vector. Usage: node self-test.mjs
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { corruptions as corrupt, runVectors } from "./vectors-core.mjs"

const dir = new URL("./vectors/", import.meta.url).pathname
const report = await runVectors({
  load: (file) => {
    const vectors = JSON.parse(readFileSync(join(dir, file), "utf8"))
    corrupt[file](vectors[0])
    return vectors
  },
  now: () => performance.now(),
})
let bad = 0
for (const r of report) {
  const ok = r.fail === 1
  if (!ok) bad++
  console.log(`${ok ? "caught " : "MISSED "} ${r.file} (${r.fail} failing)`)
}
console.log(bad === 0 ? "\nevery corruption was caught" : `\n${bad} corruptions went unnoticed`)
process.exitCode = bad === 0 ? 0 : 1
