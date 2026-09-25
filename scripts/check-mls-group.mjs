/* eslint-env node */

/**
 * A DM through the group engine, over the wire and through saved state at every step. Two
 * people, three devices, one of them removed, and the things a DM has to refuse.
 */

import assert from "node:assert/strict";

import {
  addMlsMembers,
  asIdentityScope,
  base64Url,
  createMlsDevice,
  createMlsGroup,
  decodeMlsGroupState,
  decryptMlsMessage,
  derivePersonKeyPair,
  encodeMlsGroupState,
  encryptMlsMessage,
  forgetMlsSecrets,
  generateMlsKeyPackage,
  inspectMlsMessage,
  joinMlsGroup,
  mlsCiphersuite,
  mlsGroupInfo,
  mlsGroupMembers,
  mlsWelcomeRefs,
  processMlsMessage,
  readMlsKeyPackage,
  removeMlsMembers,
  updateMlsLeaf,
} from "../dist/index.js";
import { createCommit, decodeMlsMessage, encodeMlsMessage } from "ts-mls";

const SCOPE = asIdentityScope("srv:engine");
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);
const text = (s) => new TextEncoder().encode(s);
const read = (b) => new TextDecoder().decode(b);
const hex = (b) => Buffer.from(b).toString("hex");

const KARI = seed(3);
const OLA = seed(5);
const people = new Set([KARI, OLA].map((s) => hex(derivePersonKeyPair(s, SCOPE).publicKey)));
const trust = { scope: SCOPE, trustPersonKey: (c) => people.has(hex(c.personPublicKey)) };

// Every step goes through bytes, the way a client that restarted would pick it up.
const reload = (state) => decodeMlsGroupState(encodeMlsGroupState(state), trust);

const kariLaptop = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "laptop" });
const kariPhone = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "phone" });
const olaPhone = createMlsDevice({ seed: OLA, scope: SCOPE, deviceName: "phone" });

/* ── KeyPackages: what the server checks on upload ─────────────────────── */

const kpKariPhone = await generateMlsKeyPackage(kariPhone);
const kpOla = await generateMlsKeyPackage(olaPhone);
{
  const seen = await readMlsKeyPackage(kpOla.keyPackage, SCOPE);
  assert.equal(seen.certificate.deviceId, olaPhone.deviceId);
  assert.equal(seen.ref, kpOla.ref);
  await assert.rejects(readMlsKeyPackage(kpOla.keyPackage, asIdentityScope("srv:other")), /no device certificate/);
  const bad = kpOla.keyPackage.slice();
  bad[bad.length - 3] ^= 1;
  await assert.rejects(readMlsKeyPackage(bad, SCOPE), "a KeyPackage with a broken signature was accepted");
  await assert.rejects(readMlsKeyPackage(kpOla.keyPackage.slice(0, -1), SCOPE), /one whole MLS message/);
}

/* ── Kari's laptop starts the DM and adds Ola and her own phone ────────── */

let laptop = await createMlsGroup(kariLaptop, trust);
const added = await addMlsMembers(laptop, [kpOla.keyPackage, kpKariPhone.keyPackage]);
laptop = reload(added.state);
forgetMlsSecrets(added.consumed);

{
  const seen = inspectMlsMessage(added.commit);
  assert.deepEqual(
    { wireformat: seen.wireformat, epoch: seen.epoch, contentType: seen.contentType, groupId: seen.groupId },
    { wireformat: "mls_public_message", epoch: 0n, contentType: "commit", groupId: mlsGroupInfo(laptop).groupId },
    "the server can't read the epoch and type off a commit",
  );
  assert.deepEqual(new Set(mlsWelcomeRefs(added.welcome)), new Set([kpOla.ref, kpKariPhone.ref]));
}

let ola = reload(await joinMlsGroup(added.welcome, kpOla.keyPackage, kpOla.privatePackage, trust));
let phone = reload(await joinMlsGroup(added.welcome, kpKariPhone.keyPackage, kpKariPhone.privatePackage, trust));
assert.equal(mlsGroupInfo(ola).epoch, 1n);
assert.deepEqual(
  mlsGroupMembers(ola, SCOPE).map((m) => m.certificate.deviceName).sort(),
  ["laptop", "phone", "phone"],
);

/* ── messages go every way, and each one is padded ─────────────────────── */

async function send(from, to, words) {
  const out = await encryptMlsMessage(from, text(words));
  const seen = inspectMlsMessage(out.message);
  assert.equal(seen.wireformat, "mls_private_message");
  assert.equal(seen.contentType, "application");
  const results = [];
  for (const state of to) {
    const r = await decryptMlsMessage(state, out.message);
    assert.equal(read(r.plaintext), words);
    results.push(reload(r.state));
  }
  return { from: reload(out.state), to: results, bytes: out.message };
}

{
  const a = await send(laptop, [ola, phone], "hei Ola");
  [laptop, ola, phone] = [a.from, ...a.to];
  const b = await send(ola, [laptop, phone], "hei Kari");
  [ola, laptop, phone] = [b.from, ...b.to];

  // Text plus its length prefix, rounded up to 256: two lengths in one step look the same.
  const step = (n) => Math.ceil((n + (n < 64 ? 1 : n < 16384 ? 2 : 4)) / 256);
  const sizes = new Map();
  for (const n of [0, 1, 62, 63, 64, 200, 254, 255, 300, 510, 511, 16380, 16381, 16383, 16384, 16400]) {
    const out = await encryptMlsMessage(laptop, text("x".repeat(n)));
    laptop = out.state;
    ola = (await decryptMlsMessage(ola, out.message)).state;
    const size = sizes.get(step(n));
    if (size !== undefined) assert.equal(out.message.length, size, `${n} bytes of text came out a different size from others in its step`);
    sizes.set(step(n), out.message.length);
  }
  assert.equal(sizes.get(2) - sizes.get(1), 256, "the step is not 256 bytes");
  assert.equal(sizes.size, 5);
}

/* ── a DM refuses what could let the server or a member widen it ───────── */

{
  const cs = await mlsCiphersuite();
  const extensions = await createCommit(
    { state: laptop, cipherSuite: cs },
    { extraProposals: [{ proposalType: "group_context_extensions", groupContextExtensions: { extensions: [] } }], wireAsPublicMessage: true },
  );
  await assert.rejects(
    processMlsMessage(ola, encodeMlsMessage(extensions.commit)),
    /isn't allowed in a DM/,
    "a DM took a commit that changes the group's extensions",
  );

  const other = await createMlsGroup(olaPhone, trust);
  const stray = await encryptMlsMessage(other, text("wrong group"));
  await assert.rejects(processMlsMessage(ola, stray.message), /another group/);
  await assert.rejects(decryptMlsMessage(ola, added.commit), /application message/);
}

/* ── Kari removes her phone; the phone is out and knows it ─────────────── */

{
  const removed = await removeMlsMembers(laptop, [kariPhone.deviceId], SCOPE);
  const r1 = await processMlsMessage(ola, removed.commit);
  const r2 = await processMlsMessage(phone, removed.commit);
  assert.equal(r1.removed, false);
  assert.equal(r2.removed, true, "the phone doesn't know it was removed");
  laptop = reload(removed.state);
  ola = reload(r1.state);
  phone = reload(r2.state);
  forgetMlsSecrets(removed.consumed);

  const after = await encryptMlsMessage(laptop, text("the phone can't read this"));
  laptop = after.state;
  await assert.rejects(decryptMlsMessage(phone, after.message), "a removed device read the next message");
  ola = (await decryptMlsMessage(ola, after.message)).state;
  assert.deepEqual(mlsGroupMembers(ola, SCOPE).map((m) => m.certificate.deviceId).sort(), [kariLaptop.deviceId, olaPhone.deviceId].sort());
  await assert.rejects(removeMlsMembers(laptop, [kariPhone.deviceId], SCOPE), /None of those devices/);
}

/* ── an update commit moves the epoch and both sides keep talking ──────── */

{
  const before = mlsGroupInfo(ola).epoch;
  const update = await updateMlsLeaf(ola);
  laptop = reload((await processMlsMessage(laptop, update.commit)).state);
  ola = reload(update.state);
  assert.equal(mlsGroupInfo(ola).epoch, before + 1n);
  const m = await send(laptop, [ola], "after the update");
  assert.equal(mlsGroupInfo(m.to[0]).epoch, mlsGroupInfo(m.from).epoch);
}

/* ── the state encoding refuses what isn't its own ────────────────────── */

{
  const bytes = encodeMlsGroupState(ola);
  assert.equal(bytes[0], 1);
  assert.throws(() => decodeMlsGroupState(Uint8Array.of(2, ...bytes.subarray(1)), trust), /format/);
  assert.throws(() => decodeMlsGroupState(new Uint8Array([...bytes, 0]), trust), /damaged/);
  assert.equal(base64Url(decodeMlsGroupState(bytes, trust).groupContext.groupId), mlsGroupInfo(ola).groupId);
}

console.log("mls-group: a DM of three devices creates, adds, talks, removes and updates through saved state, pads, and refuses what a DM shouldn't take");
