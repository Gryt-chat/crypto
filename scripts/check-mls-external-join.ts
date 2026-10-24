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
const OLA = seed(5);
const PER = seed(7);
const trusted = (...seeds: Uint8Array[]): MlsTrust => {
  const keys = new Set(seeds.map((s) => hex(derivePersonKeyPair(s, SCOPE).publicKey)));
  return { scope: SCOPE, trustPersonKey: (c) => keys.has(hex(c.personPublicKey)) };
};
const trust = trusted(KARI, OLA);
// Per's key is trusted here, so only the "already in this DM" rule can stop Per.
const lenient = trusted(KARI, OLA, PER);

const kariLaptop = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "laptop" });
const kariPhone = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "phone" });
const olaPhone = createMlsDevice({ seed: OLA, scope: SCOPE, deviceName: "phone" });
const perLaptop = createMlsDevice({ seed: PER, scope: SCOPE, deviceName: "laptop" });

async function dm(): Promise<{ kari: MlsGroupState; ola: MlsGroupState }> {
  const kari = await createMlsGroup(kariLaptop, trust);
  const kp = await generateMlsKeyPackage(olaPhone);
  const add = await addMlsMembers(kari, [kp.keyPackage]);
  assert.ok(add.welcome, "adding Ola made no Welcome");
  return { kari: add.state, ola: await joinMlsGroup(add.welcome, kp.keyPackage, kp.privatePackage, trust) };
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
  // Kari's phone joins by itself; Kari's laptop and Ola's phone take the commit.
  let { kari, ola } = await dm();
  const joined = await joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(ola), device: kariPhone, trust });
  kari = (await processMlsMessage(kari, joined.commit, SCOPE)).state;
  ola = (await processMlsMessage(ola, joined.commit, SCOPE)).state;
  let phone = joined.state;
  assert.equal(mlsGroupMembers(ola, SCOPE).length, 3);

  ({ from: ola, to: phone } = await says(ola, phone, "hei telefon"));
  ({ from: phone, to: kari } = await says(phone, kari, "fra telefonen"));
}

{
  // Without the scope, the join is refused: who joined can't be checked.
  const { ola } = await dm();
  const joined = await joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(ola), device: kariPhone, trust });
  await assert.rejects(processMlsMessage(ola, joined.commit), /needs the scope/);
}

{
  // Per's key is trusted, but Per isn't in this DM, so Per can't join it this way.
  const kari = await createMlsGroup(kariLaptop, lenient);
  const kp = await generateMlsKeyPackage(olaPhone);
  const add = await addMlsMembers(kari, [kp.keyPackage]);
  assert.ok(add.welcome, "adding Ola made no Welcome");
  const ola = await joinMlsGroup(add.welcome, kp.keyPackage, kp.privatePackage, lenient);
  const groupInfo = await mlsGroupInfoForJoining(ola);
  await assert.rejects(joinMlsGroupExternally({ groupInfo, device: perLaptop, trust: lenient }), /a member has to add this one/);
  // A client without that check still can, so members refuse it too.
  const perCommit = await joinRaw(groupInfo, perLaptop);
  await assert.rejects(processMlsMessage(ola, perCommit, SCOPE), /somebody already in this DM/);
  await assert.rejects(processMlsMessage(add.state, perCommit, SCOPE), /somebody already in this DM/);
  // Refusing didn't spend Ola's state: it still reads Kari.
  await says(add.state, ola, "still here");
}

{
  // Every device of Kari's has been removed: members would refuse Kari's phone joining by itself,
  // so it doesn't make that commit, and asks to be added instead.
  const { ola } = await dm();
  const out = await removeMlsMembers(ola, [kariLaptop.deviceId], SCOPE);
  await assert.rejects(
    joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(out.state), device: kariPhone, trust }),
    /a member has to add this one/,
  );
}

{
  // Kari's laptop lost its state: joining again replaces its own old leaf, without being told to.
  let { ola } = await dm();
  const back = await joinMlsGroupExternally({ groupInfo: await mlsGroupInfoForJoining(ola), device: kariLaptop, trust });
  ola = (await processMlsMessage(ola, back.commit, SCOPE)).state;
  assert.equal(mlsGroupMembers(ola, SCOPE).length, 2, "the old leaf went, the new one came");
  await says(ola, back.state, "velkommen tilbake");
}

console.log(
  "mls-external-join: your own device joins from the GroupInfo, a lost one resyncs, nobody new gets in that way or tries to, and nothing is taken without the scope",
);
