import { runBench, formatBench } from "./bench-core.mjs"

const cfg = globalThis.__benchConfig ?? {}
const suites = cfg.suites ?? ["MLS_128_DHKEMP256_AES128GCM_SHA256_P256", "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"]
;(async () => {
  const results = []
  for (const suite of suites) {
    const res = await runBench({ suite, provider: "pure", sizes: cfg.sizes ?? [2, 10, 100], rounds: cfg.rounds ?? 5, now: () => performance.now(), log: (m) => print(m) })
    results.push(res)
    print(formatBench(res) + "\n")
  }
  print("RESULT_JSON " + JSON.stringify({ runtime: "hermes " + HermesInternal.getRuntimeProperties()["OSS Release Version"], results }))
})().catch((e) => {
  print("FAILED " + (e && e.stack ? e.stack : e))
  globalThis.__exitCode = 1
})
