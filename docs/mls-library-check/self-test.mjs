// Proves the vector checks can fail: corrupts one expected value per file and expects
// every file to report exactly one failing vector. Usage: node self-test.mjs
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { runVectors } from "./vectors-core.mjs"

const dir = new URL("./vectors/", import.meta.url).pathname
const flip = (h) => h.slice(0, -1) + (h.at(-1) === "0" ? "1" : "0")
const corrupt = {
  "tree-math.json": (v) => (v.root += 1),
  "crypto-basics.json": (v) => (v.derive_secret.out = flip(v.derive_secret.out)),
  "secret-tree.json": (v) => (v.leaves[0][0].application_key = flip(v.leaves[0][0].application_key)),
  "message-protection.json": (v) => (v.application = flip(v.application)),
  "key-schedule.json": (v) => (v.epochs[0].exporter.secret = flip(v.epochs[0].exporter.secret)),
  "psk_secret.json": (v) => (v.psk_secret = flip(v.psk_secret)),
  "transcript-hashes.json": (v) => (v.interim_transcript_hash_after = flip(v.interim_transcript_hash_after)),
  "welcome.json": (v) => (v.signer_pub = flip(v.signer_pub)),
  "tree-operations.json": (v) => (v.tree_hash_after = flip(v.tree_hash_after)),
  "tree-validation.json": (v) => (v.tree_hashes[0] = flip(v.tree_hashes[0])),
  "treekem.json": (v) => (v.update_paths[0].commit_secret = flip(v.update_paths[0].commit_secret)),
  "messages.json": (v) => (v.commit += "00"),
  "deserialization.json": (v) => (v.length += 1),
  "passive-client-welcome.json": (v) => (v.initial_epoch_authenticator = flip(v.initial_epoch_authenticator)),
  "passive-client-handling-commit.json": (v) => (v.epochs[0].epoch_authenticator = flip(v.epochs[0].epoch_authenticator)),
  "passive-client-random.json": (v) => (v.epochs.at(-1).epoch_authenticator = flip(v.epochs.at(-1).epoch_authenticator)),
}
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
