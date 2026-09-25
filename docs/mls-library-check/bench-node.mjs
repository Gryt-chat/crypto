// Node entry for bench-core. Usage: node bench-node.mjs [--provider=default|noble] [--sizes=2,10,100]
import { runBench, formatBench } from "./bench-core.mjs"

const arg = (name, dflt) => process.argv.find((a) => a.startsWith(`--${name}=`))?.split("=")[1] ?? dflt
const provider = arg("provider", "default")
const sizes = arg("sizes", "2,10,100").split(",").map(Number)
const suites = arg("suites", "MLS_128_DHKEMP256_AES128GCM_SHA256_P256,MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519").split(",")
const results = []
for (const suite of suites) {
  const res = await runBench({ suite, provider, sizes, now: () => performance.now(), log: (m) => console.error(m) })
  results.push(res)
  console.log(formatBench(res) + "\n")
}
console.log(`node ${process.version}`)
const out = arg("json")
if (out) (await import("node:fs")).writeFileSync(out, JSON.stringify({ runtime: `node ${process.version}`, results }, null, 2))
