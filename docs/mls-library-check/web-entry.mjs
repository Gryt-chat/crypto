// Browser and Electron entry: runs the vectors or the bench, selected by location.hash,
// and leaves the result on window.__result for the runner to collect.
import { runVectors } from "./vectors-core.mjs"
import { runBench, formatBench } from "./bench-core.mjs"

const log = (m) => console.log(m)
const now = () => performance.now()
const suites = ["MLS_128_DHKEMP256_AES128GCM_SHA256_P256", "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"]

async function main() {
  const [mode, provider = "default"] = location.hash.slice(1).split(",")
  if (mode === "vectors") {
    const base = new URL("./vectors/", location.href)
    const load = async (f) => (await fetch(new URL(f, base))).json()
    const report = await runVectors({ load, providerName: provider, log, now })
    return { runtime: navigator.userAgent, provider, report }
  }
  const results = []
  for (const suite of suites) {
    const res = await runBench({ suite, provider, now, log })
    log(formatBench(res))
    results.push(res)
  }
  return { runtime: navigator.userAgent, results }
}

main().then(
  (r) => (window.__result = r),
  (e) => (window.__result = { error: String(e?.stack ?? e) }),
)
