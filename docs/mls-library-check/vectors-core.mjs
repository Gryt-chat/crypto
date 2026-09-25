// Checks for the RFC 9420 interop vectors from mlswg/mls-implementations, written from
// test-vectors.md. No Node APIs, so the Hermes bundle can run the same checks.

import {
  acceptAll,
  defaultCryptoProvider,
  getCiphersuiteImpl,
  makePskIndex,
  joinGroup,
  processMessage,
  nobleCryptoProvider,
} from "ts-mls"
import { getCiphersuiteFromId, getCiphersuiteNameFromId } from "ts-mls/crypto/ciphersuite.js"
import { signWithLabel, verifyWithLabel } from "ts-mls/crypto/signature.js"
import { refhash } from "ts-mls/crypto/hash.js"
import { deriveSecret, deriveTreeSecret, expandWithLabel } from "ts-mls/crypto/kdf.js"
import { decryptWithLabel, encryptWithLabel } from "ts-mls/crypto/hpke.js"
import { left, right, parent, sibling, root, nodeWidth, toNodeIndex, toLeafIndex, leafToNodeIndex, nodeToLeafIndex } from "ts-mls/treemath.js"
import { expandSenderDataKey, expandSenderDataNonce } from "ts-mls/sender.js"
import { createSecretTree, deriveKey, deriveNonce, ratchetUntil } from "ts-mls/secretTree.js"
import { defaultKeyRetentionConfig } from "ts-mls/keyRetentionConfig.js"
import { encodeGroupContext } from "ts-mls/groupContext.js"
import { initializeEpoch, mlsExporter } from "ts-mls/keySchedule.js"
import { computePskSecret } from "ts-mls/presharedkey.js"
import { decodeAuthenticatedContent } from "ts-mls/authenticatedContent.js"
import { createConfirmedHash, createInterimHash } from "ts-mls/transcriptHash.js"
import { decodeMlsMessage, encodeMlsMessage } from "ts-mls/message.js"
import { makeKeyPackageRef } from "ts-mls/keyPackage.js"
import { decryptGroupInfo, decryptGroupSecrets } from "ts-mls/welcome.js"
import { verifyGroupInfoConfirmationTag, verifyGroupInfoSignature } from "ts-mls/groupInfo.js"
import {
  decodeRatchetTree,
  encodeRatchetTree,
  resolution,
  addLeafNode,
  removeLeafNode,
  updateLeafNode,
  getHpkePublicKey,
} from "ts-mls/ratchetTree.js"
import { treeHash, treeHashRoot } from "ts-mls/treeHash.js"
import { verifyParentHashes } from "ts-mls/parentHash.js"
import { verifyLeafNodeSignature } from "ts-mls/leafNode.js"
import {
  decodeProposal,
  decodeAdd,
  encodeAdd,
  decodeUpdate,
  encodeUpdate,
  decodeRemove,
  encodeRemove,
  decodePSK,
  encodePSK,
  decodeReinit,
  encodeReinit,
  decodeExternalInit,
  encodeExternalInit,
  decodeGroupContextExtensions,
  encodeGroupContextExtensions,
} from "ts-mls/proposal.js"
import { decodeCommit, encodeCommit } from "ts-mls/commit.js"
import { decodeGroupSecrets, encodeGroupSecrets } from "ts-mls/groupSecrets.js"
import { applyUpdatePath, createUpdatePath, decodeUpdatePath } from "ts-mls/updatePath.js"
import { applyUpdatePathSecret } from "ts-mls/createCommit.js"
import { getCommitSecret } from "ts-mls/pathSecrets.js"
import { toPrivateKeyPath } from "ts-mls/privateKeyPath.js"
import { determineLength } from "ts-mls/codec/variableLength.js"
import { protectApplicationData, protectProposal, unprotectPrivateMessage } from "ts-mls/messageProtection.js"
import { protectProposalPublic, protectPublicMessage, unprotectPublicMessage } from "ts-mls/messageProtectionPublic.js"
import { defaultPaddingConfig } from "ts-mls/paddingConfig.js"
import { defaultCapabilities } from "ts-mls/defaultCapabilities.js"
import { bytesToBase64 } from "ts-mls/util/byteArray.js"
import { pureCryptoProvider } from "./pure-provider.mjs"

const providers = { default: defaultCryptoProvider, noble: nobleCryptoProvider, pure: pureCryptoProvider }
let provider = defaultCryptoProvider
const impls = new Map()

const hex = (s) => {
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16)
  return out
}
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
const same = (a, b) => a !== undefined && b !== undefined && a.length === b.length && a.every((x, i) => x === b[i])
const orNull = (fn) => {
  try {
    return fn()
  } catch {
    return null
  }
}
const rejects = async (fn) => {
  try {
    await fn()
    return false
  } catch {
    return true
  }
}


async function impl(id) {
  if (!impls.has(id)) impls.set(id, await getCiphersuiteImpl(getCiphersuiteFromId(id), provider))
  return impls.get(id)
}

function groupContext(id, v, treeHashBytes, epoch) {
  return {
    version: "mls10",
    cipherSuite: getCiphersuiteNameFromId(id),
    groupId: hex(v.group_id),
    epoch: BigInt(epoch ?? v.epoch),
    treeHash: treeHashBytes ?? hex(v.tree_hash),
    confirmedTranscriptHash: hex(v.confirmed_transcript_hash),
    extensions: [],
  }
}

// Each check gets `ok(name, condition)`; a vector passes when every condition held and nothing threw.

async function treeMath(v, ok) {
  ok("n_nodes", nodeWidth(v.n_leaves) === v.n_nodes)
  ok("root", root(v.n_leaves) === v.root)
  for (let i = 0; i < v.n_nodes; i++) {
    const n = toNodeIndex(i)
    ok(`left[${i}]`, orNull(() => left(n)) === v.left[i])
    ok(`right[${i}]`, orNull(() => right(n)) === v.right[i])
    ok(`parent[${i}]`, orNull(() => parent(n, v.n_leaves)) === v.parent[i])
    ok(`sibling[${i}]`, orNull(() => sibling(n, v.n_leaves)) === v.sibling[i])
  }
}

async function cryptoBasics(v, ok) {
  const cs = await impl(v.cipher_suite)
  ok("ref_hash", same(await refhash(v.ref_hash.label, hex(v.ref_hash.value), cs.hash), hex(v.ref_hash.out)))
  const e = v.expand_with_label
  ok("expand_with_label", same(await expandWithLabel(hex(e.secret), e.label, hex(e.context), e.length, cs.kdf), hex(e.out)))
  const d = v.derive_secret
  ok("derive_secret", same(await deriveSecret(hex(d.secret), d.label, cs.kdf), hex(d.out)))
  const t = v.derive_tree_secret
  ok("derive_tree_secret", same(await deriveTreeSecret(hex(t.secret), t.label, t.generation, t.length, cs.kdf), hex(t.out)))

  const s = v.sign_with_label
  ok("verify_with_label(vector)", await verifyWithLabel(hex(s.pub), s.label, hex(s.content), hex(s.signature), cs.signature))
  const mine = await signWithLabel(hex(s.priv), s.label, hex(s.content), cs.signature)
  ok("verify_with_label(own)", await verifyWithLabel(hex(s.pub), s.label, hex(s.content), mine, cs.signature))
  const tampered = hex(s.content)
  tampered[0] ^= 1
  ok("reject tampered signature content", !(await verifyWithLabel(hex(s.pub), s.label, tampered, hex(s.signature), cs.signature).catch(() => false)))

  const h = v.encrypt_with_label
  const priv = await cs.hpke.importPrivateKey(hex(h.priv))
  const pub = await cs.hpke.importPublicKey(hex(h.pub))
  const pt = await decryptWithLabel(priv, h.label, hex(h.context), hex(h.kem_output), hex(h.ciphertext), cs.hpke)
  ok("decrypt_with_label(vector)", same(new Uint8Array(pt), hex(h.plaintext)))
  const { ct, enc } = await encryptWithLabel(pub, h.label, hex(h.context), hex(h.plaintext), cs.hpke)
  const pt2 = await decryptWithLabel(priv, h.label, hex(h.context), enc, ct, cs.hpke)
  ok("encrypt_with_label roundtrip", same(new Uint8Array(pt2), hex(h.plaintext)))
  const badCt = hex(h.ciphertext)
  badCt[0] ^= 1
  ok("reject tampered HPKE ciphertext", await rejects(() => decryptWithLabel(priv, h.label, hex(h.context), hex(h.kem_output), badCt, cs.hpke)))
}

async function secretTree(v, ok) {
  const cs = await impl(v.cipher_suite)
  const sd = v.sender_data
  ok("sender_data key", same(await expandSenderDataKey(cs, hex(sd.sender_data_secret), hex(sd.ciphertext)), hex(sd.key)))
  ok("sender_data nonce", same(await expandSenderDataNonce(cs, hex(sd.sender_data_secret), hex(sd.ciphertext)), hex(sd.nonce)))
  const tree = await createSecretTree(v.leaves.length, hex(v.encryption_secret), cs.kdf)
  for (const [i, gens] of v.leaves.entries()) {
    const node = tree[leafToNodeIndex(toLeafIndex(i))]
    for (const g of gens) {
      for (const kind of ["handshake", "application"]) {
        const [r] = await ratchetUntil(node[kind], g.generation, { ...defaultKeyRetentionConfig, maximumForwardRatchetSteps: 1 << 20 }, cs.kdf)
        ok(`${kind} key leaf ${i} gen ${g.generation}`, same(await deriveKey(r.secret, r.generation, cs), hex(g[`${kind}_key`])))
        ok(`${kind} nonce leaf ${i} gen ${g.generation}`, same(await deriveNonce(r.secret, r.generation, cs), hex(g[`${kind}_nonce`])))
      }
    }
  }
}

const leafOneTree = () => [
  undefined,
  undefined,
  {
    nodeType: "leaf",
    leaf: {
      leafNodeSource: "commit",
      hpkePublicKey: new Uint8Array(),
      signaturePublicKey: new Uint8Array(),
      capabilities: defaultCapabilities(),
      parentHash: new Uint8Array(),
      extensions: [],
      signature: new Uint8Array(),
      credential: { credentialType: "basic", identity: new Uint8Array() },
    },
  },
]

async function messageProtection(v, ok) {
  const cs = await impl(v.cipher_suite)
  const gc = groupContext(v.cipher_suite, v)
  const membership = hex(v.membership_key)
  const sigPub = hex(v.signature_pub)
  const sigPriv = hex(v.signature_priv)
  const sds = hex(v.sender_data_secret)
  const tree = () => createSecretTree(2, hex(v.encryption_secret), cs.kdf)
  const unprotectPriv = async (pm) =>
    unprotectPrivateMessage(sds, pm, await tree(), leafOneTree(), gc, defaultKeyRetentionConfig, cs, sigPub)
  const decodeMsg = (h) => decodeMlsMessage(hex(h), 0)[0]

  // PublicMessage vectors: proposal and commit
  const pp = await unprotectPublicMessage(membership, gc, [], decodeMsg(v.proposal_pub).publicMessage, cs, sigPub)
  ok("proposal_pub unprotects to proposal", pp.content.contentType === "proposal")
  const commitPub = await unprotectPublicMessage(membership, gc, [], decodeMsg(v.commit_pub).publicMessage, cs, sigPub)
  ok("commit_pub unprotects to commit", same(encodeCommit(commitPub.content.commit), hex(v.commit)))
  const wrongKey = hex(v.membership_key)
  wrongKey[0] ^= 1
  ok("proposal_pub rejected under wrong membership_key", await rejects(() => unprotectPublicMessage(wrongKey, gc, [], decodeMsg(v.proposal_pub).publicMessage, cs, sigPub)))

  const proposal = decodeProposal(hex(v.proposal), 0)[0]
  const ownPub = await protectProposalPublic(sigPriv, membership, gc, new Uint8Array(), proposal, 1, cs)
  const ownPubOpen = await unprotectPublicMessage(membership, gc, [], ownPub.publicMessage, cs, sigPub)
  ok("own proposal PublicMessage roundtrip", ownPubOpen.content.contentType === "proposal")

  // PrivateMessage vectors
  const propPriv = await unprotectPriv(decodeMsg(v.proposal_priv).privateMessage)
  ok("proposal_priv unprotects to proposal", propPriv.content.content.contentType === "proposal")
  const commitPriv = await unprotectPriv(decodeMsg(v.commit_priv).privateMessage)
  ok("commit_priv unprotects to commit", same(encodeCommit(commitPriv.content.content.commit), hex(v.commit)))
  const appPriv = await unprotectPriv(decodeMsg(v.application_priv).privateMessage)
  ok("application_priv unprotects to application", same(appPriv.content.content.applicationData, hex(v.application)))

  const tamperedApp = decodeMsg(v.application_priv).privateMessage
  tamperedApp.ciphertext = tamperedApp.ciphertext.slice()
  tamperedApp.ciphertext[tamperedApp.ciphertext.length - 1] ^= 1
  ok("tampered application_priv rejected", await rejects(() => unprotectPriv(tamperedApp)))

  // Own PrivateMessages must unprotect again
  const ownApp = await protectApplicationData(sigPriv, sds, hex(v.application), new Uint8Array(), gc, await tree(), 1, defaultPaddingConfig, cs)
  const ownAppOpen = await unprotectPriv(ownApp.privateMessage)
  ok("own application PrivateMessage roundtrip", same(ownAppOpen.content.content.applicationData, hex(v.application)))
  const ownProp = await protectProposal(sigPriv, sds, proposal, new Uint8Array(), gc, await tree(), 1, defaultPaddingConfig, cs)
  const ownPropOpen = await unprotectPriv(ownProp.privateMessage)
  ok("own proposal PrivateMessage roundtrip", ownPropOpen.content.content.contentType === "proposal")

  // An application message must not be sendable as a PublicMessage
  const asPublic = {
    wireformat: "mls_public_message",
    content: { ...appPriv.content.content, groupId: gc.groupId, epoch: gc.epoch, sender: { senderType: "member", leafIndex: 1 }, authenticatedData: new Uint8Array() },
    auth: appPriv.content.auth,
  }
  ok("application as PublicMessage refused", await rejects(() => protectPublicMessage(membership, gc, asPublic, cs)))
}

async function keySchedule(v, ok) {
  const cs = await impl(v.cipher_suite)
  let init = hex(v.initial_init_secret)
  for (const [i, e] of v.epochs.entries()) {
    const gc = groupContext(v.cipher_suite, { ...v, ...e }, hex(e.tree_hash), i)
    ok(`epoch ${i} group_context`, same(encodeGroupContext(gc), hex(e.group_context)))
    const r = await initializeEpoch(init, hex(e.commit_secret), gc, hex(e.psk_secret), cs.kdf)
    const k = r.keySchedule
    const pairs = {
      joiner_secret: r.joinerSecret,
      welcome_secret: r.welcomeSecret,
      encryption_secret: r.encryptionSecret,
      init_secret: k.initSecret,
      sender_data_secret: k.senderDataSecret,
      exporter_secret: k.exporterSecret,
      epoch_authenticator: k.epochAuthenticator,
      external_secret: k.externalSecret,
      confirmation_key: k.confirmationKey,
      membership_key: k.membershipKey,
      resumption_psk: k.resumptionPsk,
    }
    for (const [name, got] of Object.entries(pairs)) ok(`epoch ${i} ${name}`, same(got, hex(e[name])))
    const { publicKey } = await cs.hpke.deriveKeyPair(k.externalSecret)
    ok(`epoch ${i} external_pub`, same(await cs.hpke.exportPublicKey(publicKey), hex(e.external_pub)))
    const x = e.exporter
    ok(`epoch ${i} exporter`, same(await mlsExporter(k.exporterSecret, x.label, hex(x.context), x.length, cs), hex(x.secret)))
    init = k.initSecret
  }
}

async function pskSecret(v, ok) {
  const cs = await impl(v.cipher_suite)
  const psks = v.psks.map((p) => [{ psktype: "external", pskId: hex(p.psk_id), pskNonce: hex(p.psk_nonce) }, hex(p.psk)])
  ok("psk_secret", same(await computePskSecret(psks, cs), hex(v.psk_secret)))
}

async function transcriptHashes(v, ok) {
  const cs = await impl(v.cipher_suite)
  const [ac] = decodeAuthenticatedContent(hex(v.authenticated_content), 0)
  ok("content is a commit", ac.content.contentType === "commit")
  const tag = ac.auth.confirmationTag
  ok("confirmation_tag verifies", await cs.hash.verifyMac(hex(v.confirmation_key), tag, hex(v.confirmed_transcript_hash_after)))
  const confirmed = await createConfirmedHash(hex(v.interim_transcript_hash_before), { wireformat: ac.wireformat, content: ac.content, signature: ac.auth.signature }, cs.hash)
  ok("confirmed_transcript_hash_after", same(confirmed, hex(v.confirmed_transcript_hash_after)))
  ok("interim_transcript_hash_after", same(await createInterimHash(confirmed, tag, cs.hash), hex(v.interim_transcript_hash_after)))
}

async function welcome(v, ok) {
  const cs = await impl(v.cipher_suite)
  const w = decodeMlsMessage(hex(v.welcome), 0)[0].welcome
  const kp = decodeMlsMessage(hex(v.key_package), 0)[0].keyPackage
  const ref = await makeKeyPackageRef(kp, cs.hash)
  ok("welcome has an entry for key_package", w.secrets.some((s) => same(s.newMember, ref)))
  const priv = await cs.hpke.importPrivateKey(hex(v.init_priv))
  const secrets = await decryptGroupSecrets(priv, ref, w, cs.hpke)
  ok("group secrets decrypt", secrets !== undefined)
  const zero = new Uint8Array(cs.kdf.size)
  const gi = await decryptGroupInfo(w, secrets.joinerSecret, zero, cs)
  ok("group info decrypts", gi !== undefined)
  ok("group info signature", await verifyGroupInfoSignature(gi, hex(v.signer_pub), cs.signature))
  ok("group info confirmation_tag", await verifyGroupInfoConfirmationTag(gi, secrets.joinerSecret, zero, cs))
  const wrong = await cs.hpke.generateKeyPair()
  ok("wrong init key cannot open group secrets", await rejects(async () => {
    const s = await decryptGroupSecrets(wrong.privateKey, ref, w, cs.hpke)
    if (s === undefined) throw new Error("undefined")
  }))
}

async function treeOperations(v, ok) {
  const cs = await impl(v.cipher_suite)
  const [before] = decodeRatchetTree(hex(v.tree_before), 0)
  ok("tree_hash_before", same(await treeHashRoot(before, cs.hash), hex(v.tree_hash_before)))
  const [p] = decodeProposal(hex(v.proposal), 0)
  let after
  if (p.proposalType === "add") after = addLeafNode(before, p.add.keyPackage.leafNode)[0]
  else if (p.proposalType === "update") after = updateLeafNode(before, p.update.leafNode, toLeafIndex(v.proposal_sender))
  else if (p.proposalType === "remove") after = removeLeafNode(before, toLeafIndex(p.remove.removed))
  ok(`tree_after (${p.proposalType})`, same(encodeRatchetTree(after), hex(v.tree_after)))
  ok("tree_hash_after", same(await treeHashRoot(after, cs.hash), hex(v.tree_hash_after)))
}

async function treeValidation(v, ok) {
  const cs = await impl(v.cipher_suite)
  const [tree] = decodeRatchetTree(hex(v.tree), 0)
  for (const [i, r] of v.resolutions.entries()) {
    const got = resolution(tree, toNodeIndex(i))
    ok(`resolution[${i}]`, got.length === r.length && got.every((x, j) => x === r[j]))
  }
  for (const [i, h] of v.tree_hashes.entries()) ok(`tree_hash[${i}]`, same(await treeHash(tree, toNodeIndex(i), cs.hash), hex(h)))
  ok("parent hashes valid", await verifyParentHashes(tree, cs.hash))
  for (const [i, n] of tree.entries()) {
    if (n?.nodeType === "leaf") {
      const idx = nodeToLeafIndex(toNodeIndex(i))
      ok(`leaf ${idx} signature`, await verifyLeafNodeSignature(n.leaf, hex(v.group_id), idx, cs.signature))
    }
  }
  // Negative: a flipped parent-node key must break the parent-hash chain, when there is one
  const pi = tree.findIndex((n) => n?.nodeType === "parent")
  if (pi >= 0) {
    const [bad] = decodeRatchetTree(hex(v.tree), 0)
    bad[pi].parent.hpkePublicKey = bad[pi].parent.hpkePublicKey.slice()
    bad[pi].parent.hpkePublicKey[0] ^= 1
    ok("tampered parent node breaks parent hashes", !(await verifyParentHashes(bad, cs.hash).catch(() => false)))
  }
}

async function treekem(v, ok) {
  const cs = await impl(v.cipher_suite)
  const [tree] = decodeRatchetTree(hex(v.ratchet_tree), 0)
  const gc = groupContext(v.cipher_suite, v, await treeHashRoot(tree, cs.hash))

  const privates = new Map()
  for (const lp of v.leaves_private) {
    const secrets = Object.fromEntries(lp.path_secrets.map((p) => [p.node, hex(p.path_secret)]))
    const path = await toPrivateKeyPath(secrets, lp.index, cs)
    path.privateKeys = { ...path.privateKeys, [leafToNodeIndex(toLeafIndex(lp.index))]: hex(lp.encryption_priv) }
    privates.set(lp.index, path)
    for (const [node, priv] of Object.entries(path.privateKeys)) {
      const pub = getHpkePublicKey(tree[Number(node)])
      const { ct, enc } = await cs.hpke.seal(await cs.hpke.importPublicKey(pub), hex("00"), new Uint8Array())
      const opened = await cs.hpke.open(await cs.hpke.importPrivateKey(priv), enc, ct, new Uint8Array()).catch(() => undefined)
      ok(`leaf ${lp.index} private key matches node ${node}`, opened !== undefined)
    }
  }

  for (const up of v.update_paths) {
    const [path] = decodeUpdatePath(hex(up.update_path), 0)
    const merged = await applyUpdatePath(tree, toLeafIndex(up.sender), path, cs.hash)
    const mergedHash = await treeHashRoot(merged, cs.hash)
    ok(`sender ${up.sender}: tree_hash_after`, same(mergedHash, hex(up.tree_hash_after)))
    ok(`sender ${up.sender}: merged tree parent-hash valid`, await verifyParentHashes(merged, cs.hash))
    const ctx = { ...gc, treeHash: mergedHash }
    for (const [j, priv] of privates) {
      if (j === up.sender) {
        ok(`sender ${up.sender}: path_secrets[sender] is null`, up.path_secrets[j] === null)
        continue
      }
      const got = await applyUpdatePathSecret(tree, priv, toLeafIndex(up.sender), ctx, path, [], cs)
      ok(`sender ${up.sender}: leaf ${j} path_secret`, same(got.pathSecret, hex(up.path_secrets[j])))
      ok(`sender ${up.sender}: leaf ${j} commit_secret`, same(await getCommitSecret(tree, got.nodeIndex, got.pathSecret, cs.kdf), hex(up.commit_secret)))
    }

    // Own UpdatePath from the same sender: every other leaf must reach the same commit secret
    const sender = v.leaves_private.find((l) => l.index === up.sender)
    const [newTree, newPath, newSecrets] = await createUpdatePath(tree, toLeafIndex(up.sender), gc, hex(sender.signature_priv), cs)
    const last = newSecrets.at(-1)
    const expected = await getCommitSecret(newTree, last.nodeIndex, last.secret, cs.kdf)
    // ts-mls encrypts to the provisional context, which carries epoch + 1 (RFC 9420 12.4.2)
    const newCtx = { ...gc, treeHash: await treeHashRoot(newTree, cs.hash), epoch: gc.epoch + 1n }
    for (const [j, priv] of privates) {
      if (j === up.sender) continue
      const got = await applyUpdatePathSecret(tree, priv, toLeafIndex(up.sender), newCtx, newPath, [], cs)
      ok(`sender ${up.sender}: own path, leaf ${j} commit_secret`, same(await getCommitSecret(tree, got.nodeIndex, got.pathSecret, cs.kdf), expected))
    }
  }
}

const messageCodecs = {
  ratchet_tree: [decodeRatchetTree, encodeRatchetTree],
  group_secrets: [decodeGroupSecrets, encodeGroupSecrets],
  add_proposal: [decodeAdd, encodeAdd],
  update_proposal: [decodeUpdate, encodeUpdate],
  remove_proposal: [decodeRemove, encodeRemove],
  pre_shared_key_proposal: [decodePSK, encodePSK],
  re_init_proposal: [decodeReinit, encodeReinit],
  external_init_proposal: [decodeExternalInit, encodeExternalInit],
  group_context_extensions_proposal: [decodeGroupContextExtensions, encodeGroupContextExtensions],
  commit: [decodeCommit, encodeCommit],
}
const mlsMessageFields = {
  mls_welcome: "mls_welcome",
  mls_group_info: "mls_group_info",
  mls_key_package: "mls_key_package",
  public_message_application: "mls_public_message",
  public_message_proposal: "mls_public_message",
  public_message_commit: "mls_public_message",
  private_message: "mls_private_message",
}

async function messages(v, ok) {
  for (const [field, wf] of Object.entries(mlsMessageFields)) {
    const bytes = hex(v[field])
    const r = decodeMlsMessage(bytes, 0)
    ok(`${field} decodes as ${wf}`, r?.[0].wireformat === wf)
    ok(`${field} consumes all bytes`, r?.[1] === bytes.length)
    ok(`${field} re-encodes`, r !== undefined && same(encodeMlsMessage(r[0]), bytes))
  }
  for (const [field, [dec, enc]] of Object.entries(messageCodecs)) {
    const bytes = hex(v[field])
    const r = dec(bytes, 0)
    ok(`${field} decodes`, r !== undefined)
    ok(`${field} consumes all bytes`, r?.[1] === bytes.length)
    ok(`${field} re-encodes`, r !== undefined && same(enc(r[0]), bytes))
  }
}

async function deserialization(v, ok) {
  ok(`vlbytes ${v.vlbytes_header}`, determineLength(hex(v.vlbytes_header)).length === v.length)
}

// Passive client: join by Welcome and follow every epoch through the public processMessage API.
async function passiveClient(v, ok) {
  const cs = await impl(v.cipher_suite)
  const kp = decodeMlsMessage(hex(v.key_package), 0)[0].keyPackage
  const sig = await cs.signature.sign(hex(v.signature_priv), hex("01"))
  ok("signature_priv matches key package", await cs.signature.verify(kp.leafNode.signaturePublicKey, hex("01"), sig))
  const psks = Object.fromEntries(v.external_psks.map((p) => [bytesToBase64(hex(p.psk_id)), hex(p.psk)]))
  const w = decodeMlsMessage(hex(v.welcome), 0)[0].welcome
  const tree = v.ratchet_tree === null ? undefined : decodeRatchetTree(hex(v.ratchet_tree), 0)[0]
  const privateKeys = { hpkePrivateKey: hex(v.encryption_priv), initPrivateKey: hex(v.init_priv), signaturePrivateKey: hex(v.signature_priv) }
  let state = await joinGroup(w, kp, privateKeys, makePskIndex(undefined, psks), cs, tree)
  ok("initial_epoch_authenticator", same(state.keySchedule.epochAuthenticator, hex(v.initial_epoch_authenticator)))
  for (const [i, e] of v.epochs.entries()) {
    for (const p of e.proposals) {
      state = (await processMessage(decodeMlsMessage(hex(p), 0)[0], state, makePskIndex(state, psks), acceptAll, cs)).newState
    }
    state = (await processMessage(decodeMlsMessage(hex(e.commit), 0)[0], state, makePskIndex(state, psks), acceptAll, cs)).newState
    ok(`epoch ${i + 1} epoch_authenticator`, same(state.keySchedule.epochAuthenticator, hex(e.epoch_authenticator)))
  }
}

export const vectorFiles = [
  ["tree-math.json", treeMath],
  ["crypto-basics.json", cryptoBasics],
  ["secret-tree.json", secretTree],
  ["message-protection.json", messageProtection],
  ["key-schedule.json", keySchedule],
  ["psk_secret.json", pskSecret],
  ["transcript-hashes.json", transcriptHashes],
  ["welcome.json", welcome],
  ["tree-operations.json", treeOperations],
  ["tree-validation.json", treeValidation],
  ["treekem.json", treekem],
  ["messages.json", messages],
  ["deserialization.json", deserialization],
  ["passive-client-welcome.json", passiveClient],
  ["passive-client-handling-commit.json", passiveClient],
  ["passive-client-random.json", passiveClient],
]


// load(file) returns the parsed JSON array; the pure provider only covers HKDF-SHA256 suites 1 to 3.
export async function runVectors({ load, providerName = "default", only, log = () => {}, now }) {
  provider = providers[providerName]
  impls.clear()
  const supported = (suite) => providerName !== "pure" || suite === undefined || suite <= 3
  const report = []
  for (const [file, check] of vectorFiles) {
    if (only && !file.includes(only)) continue
    const vectors = await load(file)
    const bySuite = new Map()
    const started = now()
    for (const [i, v] of vectors.entries()) {
      if (!supported(v.cipher_suite)) continue
      const suite = v.cipher_suite ?? "-"
      const row = bySuite.get(suite) ?? { suite, pass: 0, fail: 0, checks: 0, failures: [] }
      bySuite.set(suite, row)
      const failed = []
      let checks = 0
      const ok = (name, cond) => {
        checks++
        if (!cond) failed.push(name)
      }
      try {
        await check(v, ok)
      } catch (err) {
        failed.push(`threw: ${err?.name ?? ""} ${String(err?.message ?? err).slice(0, 160)}`)
      }
      row.checks += checks
      if (failed.length === 0) row.pass++
      else {
        row.fail++
        row.failures.push({ vector: i, failed: failed.slice(0, 5) })
      }
    }
    const suites = [...bySuite.values()]
    const pass = suites.reduce((a, r) => a + r.pass, 0)
    const fail = suites.reduce((a, r) => a + r.fail, 0)
    const ms = Math.round(now() - started)
    log(`${fail === 0 ? "PASS" : "FAIL"} ${file.padEnd(38)} ${pass}/${pass + fail} vectors  ${ms} ms`)
    for (const r of suites) {
      log(`       suite ${String(r.suite).padEnd(2)} ${r.pass}/${r.pass + r.fail} (${r.checks} checks)`)
      for (const f of r.failures.slice(0, 3)) log(`         vector ${f.vector}: ${f.failed.join("; ")}`)
    }
    report.push({ file, pass, fail, ms, suites })
  }
  return report
}
