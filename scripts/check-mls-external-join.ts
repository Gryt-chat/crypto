/**
 * A device joining a DM by itself from the GroupInfo (GRYT-1859): your own device gets in, a lost
 * one resyncs into its old place, and nobody new comes in that way, even with a trusted key.
 */

import assert from "node:assert/strict";

import { decodeMlsMessage, defaultCapabilities, defaultLifetime, encodeMlsMessage, generateKeyPackageWithKey, joinGroupExternal } from "ts-mls";

import {
  addMlsMembers,
  asIdentityScope,
  createMlsDevice,
  createMlsGroup,
  decryptMlsMessage,
  derivePersonKeyPair,
  encryptMlsMessage,
  generateMlsKeyPackage,
  joinMlsGroup,
  joinMlsGroupExternally,
  MLS_CIPHERSUITE,
  mlsCiphersuite,
  type MlsDevice,
  type MlsGroupState,
  mlsGroupInfoDeviceIds,
  mlsGroupInfoForJoining,
  mlsGroupMembers,
  type MlsTrust,
  processMlsMessage,
  removeMlsMembers,
} from "../dist/index.js";

const SCOPE = asIdentityScope("srv:external-join");
const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);
const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const KARI = seed(3);
const MIA = seed(5);
const PER = seed(7);
const trusted = (...seeds: Uint8Array[]): MlsTrust => {
  const keys = new Set(seeds.map((s) => hex(derivePersonKeyPair(s, SCOPE).publicKey)));
  return { scope: SCOPE, trustPersonKey: (c) => keys.has(hex(c.personPublicKey)) };
};
const trust = trusted(KARI, MIA);
// Per's key is trusted here, so only the "already in this DM" rule can stop Per.
const lenient = trusted(KARI, MIA, PER);

const kariLaptop = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "laptop" });
const kariPhone = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "phone" });
const miaPhone = createMlsDevice({ seed: MIA, scope: SCOPE, deviceName: "phone" });
const perLaptop = createMlsDevice({ seed: PER, scope: SCOPE, deviceName: "laptop" });

async function dm(): Promise<{ kari: MlsGroupState; mia: MlsGroupState }> {
  const kari = await createMlsGroup(kariLaptop, trust);
  const kp = await generateMlsKeyPackage(miaPhone);
  const add = await addMlsMembers(kari, [kp.keyPackage]);
  assert.ok(add.welcome, "adding Mia made no Welcome");
  return { kari: add.state, mia: await joinMlsGroup(add.welcome, kp.keyPackage, kp.privatePackage, trust) };
}

/* An external join made straight with ts-mls, as a client without our checks would. */
async function joinRaw(groupInfo: Uint8Array, device: MlsDevice): Promise<Uint8Array> {
  const cs = await mlsCiphersuite();
  const kp = await generateKeyPackageWithKey(
    { credentialType: "basic", identity: device.certificate },
    { ...defaultCapabilities(), ciphersuites: [MLS_CIPHERSUITE] },
    defaultLifetime,
    [],
    { signKey: device.signKey, publicKey: device.publicKey },
    cs,
  );
  const m = decodeMlsMessage(groupInfo, 0)?.[0];
  if (m?.wireformat !== "mls_group_info") throw new Error("not a GroupInfo");
  const r = await joinGroupExternal(m.groupInfo, kp.publicPackage, kp.privatePackage, false, cs);
  return encodeMlsMessage({ version: "mls10", wireformat: "mls_public_message", publicMessage: r.publicMessage });
}

async function says(from: MlsGroupState, to: MlsGroupState, body: string) {
  const out = await encryptMlsMessage(from, text(body));
  const got = await decryptMlsMessage(to, out.message);
  assert.equal(read(got.plaintext), body);
  return { from: out.state, to: got.state };
}

{
  // Kari's phone joins by itself; Kari's laptop and Mia's phone take the commit.
  let { kari, mia } = await dm();
  const joined = await joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(mia), device: kariPhone, trust });
  kari = (await processMlsMessage(kari, joined.commit, SCOPE)).state;
  mia = (await processMlsMessage(mia, joined.commit, SCOPE)).state;
  let phone = joined.state;
  assert.equal(mlsGroupMembers(mia, SCOPE).length, 3);

  ({ from: mia, to: phone } = await says(mia, phone, "hei telefon"));
  ({ from: phone, to: kari } = await says(phone, kari, "fra telefonen"));
}

{
  // Without the scope, the join is refused: who joined can't be checked.
  const { mia } = await dm();
  const joined = await joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(mia), device: kariPhone, trust });
  await assert.rejects(processMlsMessage(mia, joined.commit), /needs the scope/);
}

{
  // Per's key is trusted, but Per isn't in this DM, so Per can't join it this way.
  const kari = await createMlsGroup(kariLaptop, lenient);
  const kp = await generateMlsKeyPackage(miaPhone);
  const add = await addMlsMembers(kari, [kp.keyPackage]);
  assert.ok(add.welcome, "adding Mia made no Welcome");
  const mia = await joinMlsGroup(add.welcome, kp.keyPackage, kp.privatePackage, lenient);
  const groupInfo = await mlsGroupInfoForJoining(mia);
  await assert.rejects(joinMlsGroupExternally({ groupInfo, device: perLaptop, trust: lenient }), /a member has to add this one/);
  // A client without that check still can, so members refuse it too.
  const perCommit = await joinRaw(groupInfo, perLaptop);
  await assert.rejects(processMlsMessage(mia, perCommit, SCOPE), /somebody already in this DM/);
  await assert.rejects(processMlsMessage(add.state, perCommit, SCOPE), /somebody already in this DM/);
  // Refusing didn't spend Mia's state: it still reads Kari.
  await says(add.state, mia, "still here");
}

{
  // Who's in a group, from its GroupInfo alone: what a device checks before rebuilding a DM.
  const { mia } = await dm();
  assert.deepEqual(new Set(mlsGroupInfoDeviceIds(await mlsGroupInfoForJoining(mia), SCOPE)), new Set([kariLaptop.deviceId, miaPhone.deviceId]));
  const out = await removeMlsMembers(mia, [kariLaptop.deviceId], SCOPE);
  assert.deepEqual(mlsGroupInfoDeviceIds(await mlsGroupInfoForJoining(out.state), SCOPE), [miaPhone.deviceId]);
}

{
  // Every device of Kari's has been removed: members would refuse Kari's phone joining by itself,
  // so it doesn't make that commit, and asks to be added instead.
  const { mia } = await dm();
  const out = await removeMlsMembers(mia, [kariLaptop.deviceId], SCOPE);
  await assert.rejects(
    joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(out.state), device: kariPhone, trust }),
    /a member has to add this one/,
  );
}

{
  // Kari's laptop lost its state: joining again replaces its own old leaf, without being told to.
  let { mia } = await dm();
  const back = await joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(mia), device: kariLaptop, trust });
  mia = (await processMlsMessage(mia, back.commit, SCOPE)).state;
  assert.equal(mlsGroupMembers(mia, SCOPE).length, 2, "the old leaf went, the new one came");
  await says(mia, back.state, "velkommen tilbake");
}

console.log(
  "mls-external-join: your own device joins from the GroupInfo, a lost one resyncs, nobody new gets in that way or tries to, and nothing is taken without the scope",
);
