// Group properties Gryt depends on that the interop vectors don't exercise: a removed member
// stops reading, a new member can't read back, replays fail, late messages still open.

// Usage: node properties.mjs [--provider=default|noble|pure]

import {
  acceptAll,
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeMlsMessage,
  defaultCapabilities,
  defaultCryptoProvider,
  defaultLifetime,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  nobleCryptoProvider,
} from "ts-mls"
import { processMessage } from "ts-mls"
import { readFileSync } from "node:fs"

const providerName = (process.argv.find((a) => a.startsWith("--provider=")) ?? "--provider=default").split("=")[1]
const provider = providerName === "pure" ? (await import("./pure-provider.mjs")).pureCryptoProvider : providerName === "noble" ? nobleCryptoProvider : defaultCryptoProvider
const enc = new TextEncoder()
const dec = new TextDecoder()

async function world(suite) {
  const cs = await getCiphersuiteImpl(getCiphersuiteFromName(suite), provider)
  const kp = (name) => generateKeyPackage({ credentialType: "basic", identity: enc.encode(name) }, defaultCapabilities(), defaultLifetime, [], cs)
  const wire = (m) => encodeMlsMessage(m)
  const unwire = (b) => decodeMlsMessage(b, 0)[0]
  const commit = async (state, extraProposals = []) => {
    const r = await createCommit({ state, cipherSuite: cs }, { extraProposals, ratchetTreeExtension: true })
    return { state: r.newState, commit: wire(r.commit), welcome: r.welcome && wire({ version: "mls10", wireformat: "mls_welcome", welcome: r.welcome }) }
  }
  const join = (w, k) => joinGroup(unwire(w).welcome, k.publicPackage, k.privatePackage, emptyPskIndex, cs)
  const send = async (state, text) => {
    const m = await createApplicationMessage(state, enc.encode(text), cs)
    return { state: m.newState, bytes: wire({ version: "mls10", wireformat: "mls_private_message", privateMessage: m.privateMessage }) }
  }
  const receive = async (state, bytes) => processMessage(unwire(bytes), state, emptyPskIndex, acceptAll, cs)
  const read = async (state, bytes) => {
    try {
      const r = await receive(state, bytes)
      return r.kind === "applicationMessage" ? dec.decode(r.message) : undefined
    } catch {
      return undefined
    }
  }
  const add = (name) => ({ proposalType: "add", add: { keyPackage: name.publicPackage } })
  return { cs, kp, commit, join, send, receive, read, add }
}

const checks = {
  async "removed member cannot read the next epoch"(w) {
    const [a, b, c] = await Promise.all(["alice", "bob", "carol"].map(w.kp))
    let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], w.cs)
    const added = await w.commit(alice, [w.add(b), w.add(c)])
    alice = added.state
    let bob = await w.join(added.welcome, b)
    // A single Remove, the shape GHSA-gwp3-968w-m7gv got wrong before 1.6.4
    const removed = await w.commit(alice, [{ proposalType: "remove", remove: { removed: 1 } }])
    alice = removed.state
    bob = (await w.receive(bob, removed.commit)).newState
    const m = await w.send(alice, "bob must not read this")
    return (await w.read(bob, m.bytes)) === undefined
  },
  async "new member cannot read messages from before the join"(w) {
    const [a, b, c] = await Promise.all(["alice", "bob", "carol"].map(w.kp))
    let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], w.cs)
    const first = await w.commit(alice, [w.add(b)])
    alice = first.state
    const before = await w.send(alice, "before carol")
    alice = before.state
    const second = await w.commit(alice, [w.add(c)])
    const carol = await w.join(second.welcome, c)
    return (await w.read(carol, before.bytes)) === undefined
  },
  async "a replayed message is rejected (its key is gone)"(w) {
    const [a, b] = await Promise.all(["alice", "bob"].map(w.kp))
    let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], w.cs)
    const added = await w.commit(alice, [w.add(b)])
    alice = added.state
    let bob = await w.join(added.welcome, b)
    const m = await w.send(alice, "once")
    const first = await w.receive(bob, m.bytes)
    bob = first.newState
    return first.kind === "applicationMessage" && (await w.read(bob, m.bytes)) === undefined
  },
  async "out-of-order messages in one epoch both open"(w) {
    const [a, b] = await Promise.all(["alice", "bob"].map(w.kp))
    let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], w.cs)
    const added = await w.commit(alice, [w.add(b)])
    alice = added.state
    let bob = await w.join(added.welcome, b)
    const m1 = await w.send(alice, "one")
    const m2 = await w.send(m1.state, "two")
    const r2 = await w.receive(bob, m2.bytes)
    const r1 = await w.receive(r2.newState, m1.bytes)
    return dec.decode(r2.message) === "two" && dec.decode(r1.message) === "one"
  },
  async "a message from the previous epoch opens after the commit"(w) {
    const [a, b] = await Promise.all(["alice", "bob"].map(w.kp))
    let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], w.cs)
    const added = await w.commit(alice, [w.add(b)])
    alice = added.state
    let bob = await w.join(added.welcome, b)
    const late = await w.send(bob, "sent before the commit")
    bob = late.state
    const update = await w.commit(alice, [])
    bob = (await w.receive(bob, update.commit)).newState
    const aliceAfter = update.state
    return (await w.read(aliceAfter, late.bytes)) === "sent before the commit"
  },
  async "a tampered ciphertext is rejected"(w) {
    const [a, b] = await Promise.all(["alice", "bob"].map(w.kp))
    let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], w.cs)
    const added = await w.commit(alice, [w.add(b)])
    alice = added.state
    const bob = await w.join(added.welcome, b)
    const m = await w.send(alice, "intact")
    const bad = m.bytes.slice()
    bad[bad.length - 5] ^= 1
    return (await w.read(bob, bad)) === undefined
  },
}

let failed = 0
for (const suite of ["MLS_128_DHKEMP256_AES128GCM_SHA256_P256", "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"]) {
  const w = await world(suite)
  for (const [name, check] of Object.entries(checks)) {
    let ok = false
    try {
      ok = await check(w)
    } catch (e) {
      console.log(`       threw: ${e.message}`)
    }
    if (!ok) failed++
    console.log(`${ok ? "PASS" : "FAIL"} ${suite.slice(4, 21)} ${name}`)
  }
}
const version = JSON.parse(readFileSync(new URL("./node_modules/ts-mls/package.json", import.meta.url))).version
console.log(`\nprovider=${providerName} ts-mls=${version}: ${failed === 0 ? "all properties hold" : `${failed} failed`}`)
process.exitCode = failed === 0 ? 0 : 1
