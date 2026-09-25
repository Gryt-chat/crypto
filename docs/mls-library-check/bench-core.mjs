// Group-operation timings for ts-mls through its public API, with every message going over
// the wire format. No Node APIs, so the same file runs in Node, Chrome, Electron and Hermes.

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
  processMessage,
} from "ts-mls"
import { pureCryptoProvider } from "./pure-provider.mjs"

const enc = new TextEncoder()
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b)
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2
}

const dec = new TextDecoder()
function leafOf(state, name) {
  const i = state.ratchetTree.findIndex((node) => node?.nodeType === "leaf" && dec.decode(node.leaf.credential.identity) === name)
  if (i < 0) throw new Error(`no leaf for ${name}`)
  return i / 2
}

export async function runBench({ suite, provider = "default", sizes = [2, 10, 100], rounds = 5, messages = 100, now, log = () => {} }) {
  const cs = await getCiphersuiteImpl(getCiphersuiteFromName(suite), { default: defaultCryptoProvider, noble: nobleCryptoProvider, pure: pureCryptoProvider }[provider])
  const time = async (fn) => {
    const t = now()
    const r = await fn()
    return [now() - t, r]
  }
  const wire = (m) => encodeMlsMessage(m)
  const unwire = (b) => decodeMlsMessage(b, 0)[0]
  const keyPackage = (name) =>
    generateKeyPackage({ credentialType: "basic", identity: enc.encode(name) }, defaultCapabilities(), defaultLifetime, [], cs)
  const commit = async (state, extraProposals) => {
    const r = await createCommit({ state, cipherSuite: cs }, { extraProposals, ratchetTreeExtension: true })
    return {
      state: r.newState,
      commit: wire(r.commit),
      welcome: r.welcome && wire({ version: "mls10", wireformat: "mls_welcome", welcome: r.welcome }),
    }
  }
  const process = async (state, bytes) => (await processMessage(unwire(bytes), state, emptyPskIndex, acceptAll, cs)).newState
  const join = async (welcomeBytes, kp) => joinGroup(unwire(welcomeBytes).welcome, kp.publicPackage, kp.privatePackage, emptyPskIndex, cs)

  const out = { suite, provider, sizes: {} }

  const kpTimes = []
  for (let i = 0; i < 10; i++) kpTimes.push((await time(() => keyPackage(`kp${i}`)))[0])
  out.keyPackage = median(kpTimes)

  for (const n of sizes) {
    log(`${suite} ${provider}: group of ${n}`)
    const r = { n, createGroup: [], addCommit: [], addProcess: [], addJoin: [], removeCommit: [], removeProcess: [], updateCommit: [], updateProcess: [] }

    // Alice alone, then everybody else in one Add commit; Bob follows every epoch. Only Alice
    // ever commits, so each path is encrypted to about n leaves: the worst case for a tree.
    const aliceKp = await keyPackage("alice")
    const [tCreate, created] = await time(() => createGroup(enc.encode(`group-${n}`), aliceKp.publicPackage, aliceKp.privatePackage, [], cs))
    r.createGroup.push(tCreate)
    const others = []
    for (let i = 1; i < n; i++) others.push(await keyPackage(i === 1 ? "bob" : `member${i}`))
    const [tBulk, setup] = await time(() => commit(created, others.map((kp) => ({ proposalType: "add", add: { keyPackage: kp.publicPackage } }))))
    r.bulkAdd = tBulk
    let alice = setup.state
    let bob = await join(setup.welcome, others[0])

    for (let round = 0; round < rounds; round++) {
      const carolKp = await keyPackage(`carol${round}`)
      const [tAdd, added] = await time(() => commit(alice, [{ proposalType: "add", add: { keyPackage: carolKp.publicPackage } }]))
      r.addCommit.push(tAdd)
      r.welcomeBytes = added.welcome.length
      alice = added.state
      const [tAddProc, bobAfterAdd] = await time(() => process(bob, added.commit))
      r.addProcess.push(tAddProc)
      bob = bobAfterAdd
      const [tJoin] = await time(() => join(added.welcome, carolKp))
      r.addJoin.push(tJoin)

      const carolLeaf = leafOf(alice, `carol${round}`)
      const [tRemove, removed] = await time(() => commit(alice, [{ proposalType: "remove", remove: { removed: carolLeaf } }]))
      r.removeCommit.push(tRemove)
      alice = removed.state
      const [tRemProc, bobAfterRemove] = await time(() => process(bob, removed.commit))
      r.removeProcess.push(tRemProc)
      bob = bobAfterRemove

      const [tUpdate, updated] = await time(() => commit(alice, []))
      r.updateCommit.push(tUpdate)
      r.commitBytes = updated.commit.length
      alice = updated.state
      const [tUpdProc, bobAfterUpdate] = await time(() => process(bob, updated.commit))
      r.updateProcess.push(tUpdProc)
      bob = bobAfterUpdate
    }

    // Application messages: 256-byte payloads, Alice encrypts, Bob decrypts in order.
    const payload = new Uint8Array(256).fill(7)
    const sent = []
    const tEnc = now()
    for (let i = 0; i < messages; i++) {
      const m = await createApplicationMessage(alice, payload, cs)
      alice = m.newState
      sent.push(wire({ version: "mls10", wireformat: "mls_private_message", privateMessage: m.privateMessage }))
    }
    r.encrypt = (now() - tEnc) / messages
    r.messageBytes = sent[0].length
    const tDec = now()
    for (const bytes of sent) {
      const res = await processMessage(unwire(bytes), bob, emptyPskIndex, acceptAll, cs)
      if (res.kind !== "applicationMessage") throw new Error("expected an application message")
      bob = res.newState
    }
    r.decrypt = (now() - tDec) / messages

    for (const k of ["createGroup", "addCommit", "addProcess", "addJoin", "removeCommit", "removeProcess", "updateCommit", "updateProcess"]) r[k] = median(r[k])
    out.sizes[n] = r
  }
  return out
}

export function formatBench(res) {
  const f = (x) => (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2))
  const lines = [`${res.suite} (${res.provider} provider), key package ${f(res.keyPackage)} ms`]
  lines.push("n    create  add:commit process join   remove:commit process  update:commit process  encrypt decrypt  update commit/welcome/message bytes")
  for (const r of Object.values(res.sizes)) {
    lines.push(
      [String(r.n).padEnd(4), f(r.createGroup).padStart(6), f(r.addCommit).padStart(11), f(r.addProcess).padStart(7), f(r.addJoin).padStart(6),
        f(r.removeCommit).padStart(14), f(r.removeProcess).padStart(7), f(r.updateCommit).padStart(14), f(r.updateProcess).padStart(7),
        f(r.encrypt).padStart(8), f(r.decrypt).padStart(7), `  ${r.commitBytes}/${r.welcomeBytes}/${r.messageBytes}`].join(" "),
    )
  }
  return lines.join("\n")
}
