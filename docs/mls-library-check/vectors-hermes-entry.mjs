// Hermes entry for vectors-core: the vector files are bundled in, since there is no filesystem.
import { runVectors } from "./vectors-core.mjs"
import v_tree_math from "./vectors/tree-math.json"
import v_crypto_basics from "./vectors/crypto-basics.json"
import v_secret_tree from "./vectors/secret-tree.json"
import v_message_protection from "./vectors/message-protection.json"
import v_key_schedule from "./vectors/key-schedule.json"
import v_psk_secret from "./vectors/psk_secret.json"
import v_transcript_hashes from "./vectors/transcript-hashes.json"
import v_welcome from "./vectors/welcome.json"
import v_tree_operations from "./vectors/tree-operations.json"
import v_tree_validation from "./vectors/tree-validation.json"
import v_treekem from "./vectors/treekem.json"
import v_messages from "./vectors/messages.json"
import v_deserialization from "./vectors/deserialization.json"
import v_passive_client_welcome from "./vectors/passive-client-welcome.json"
import v_passive_client_handling_commit from "./vectors/passive-client-handling-commit.json"
import v_passive_client_random from "./vectors/passive-client-random.json"

const files = {
  "tree-math.json": v_tree_math,
  "crypto-basics.json": v_crypto_basics,
  "secret-tree.json": v_secret_tree,
  "message-protection.json": v_message_protection,
  "key-schedule.json": v_key_schedule,
  "psk_secret.json": v_psk_secret,
  "transcript-hashes.json": v_transcript_hashes,
  "welcome.json": v_welcome,
  "tree-operations.json": v_tree_operations,
  "tree-validation.json": v_tree_validation,
  "treekem.json": v_treekem,
  "messages.json": v_messages,
  "deserialization.json": v_deserialization,
  "passive-client-welcome.json": v_passive_client_welcome,
  "passive-client-handling-commit.json": v_passive_client_handling_commit,
  "passive-client-random.json": v_passive_client_random,
}

runVectors({ load: (f) => files[f], providerName: "pure", log: (m) => print(m), now: () => performance.now() })
  .then((report) => {
    const failed = report.reduce((a, r) => a + r.fail, 0)
    print(`\nprovider=pure hermes=${HermesInternal.getRuntimeProperties()["OSS Release Version"]}`)
    print(failed === 0 ? "all vectors passed" : `${failed} vectors failed`)
    print("RESULT_JSON " + JSON.stringify({ runtime: "hermes", provider: "pure", report }))
    globalThis.__exitCode = failed === 0 ? 0 : 1
  })
  .catch((e) => {
    print("FAILED " + (e && e.stack ? e.stack : e))
    globalThis.__exitCode = 1
  })
