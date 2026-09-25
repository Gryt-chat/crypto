/* eslint-env node */

/**
 * Six things Gryt relies on that the RFC vectors can't see, through the group engine and saved
 * state. The first is GHSA-gwp3-968w-m7gv: ts-mls below 1.6.4 fails it and passes every vector.
 */

import assert from "node:assert/strict";

import {
  addMlsMembers,
  asIdentityScope,
  createMlsDevice,
  createMlsGroup,
  decodeMlsGroupState,
  decryptMlsMessage,
  encodeMlsGroupState,
  encryptMlsMessage,
  generateMlsKeyPackage,
  joinMlsGroup,
  processMlsMessage,
  removeMlsMembers,
  updateMlsLeaf,
} from "../dist/index.js";

const SCOPE = asIdentityScope("srv:properties");
const trust = { scope: SCOPE, trustPersonKey: () => true };
const text = (s) => new TextEncoder().encode(s);
const words = (b) => new TextDecoder().decode(b);
const reload = (state) => decodeMlsGroupState(encodeMlsGroupState(state), trust);

let n = 0;
const device = (name) => {
  n++;
  return createMlsDevice({ seed: Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251), scope: SCOPE, deviceName: name });
};

/** Alice starts a group and adds everybody else in one commit. */
async function group(...others) {
  const alice = device("alice");
  const packages = await Promise.all(others.map(async (name) => ({ name, device: device(name) })));
  for (const p of packages) p.kp = await generateMlsKeyPackage(p.device);
  const added = await addMlsMembers(await createMlsGroup(alice, trust), packages.map((p) => p.kp.keyPackage));
  const states = { alice: reload(added.state) };
  for (const p of packages) states[p.name] = reload(await joinMlsGroup(added.welcome, p.kp.keyPackage, p.kp.privatePackage, trust));
  return { states, devices: Object.fromEntries(packages.map((p) => [p.name, p.device])) };
}

async function opens(state, bytes) {
  try {
    return words((await decryptMlsMessage(state, bytes)).plaintext);
  } catch {
    return undefined;
  }
}

const properties = {
  async "a removed member can't read the next epoch"() {
    const { states: s, devices } = await group("bob", "carol");
    // One Remove on its own, the exact commit ts-mls before 1.6.4 sent without an UpdatePath.
    const removed = await removeMlsMembers(s.alice, [devices.bob.deviceId], SCOPE);
    const bob = await processMlsMessage(s.bob, removed.commit);
    const carol = await processMlsMessage(s.carol, removed.commit);
    assert.equal(bob.removed, true);
    const m = await encryptMlsMessage(reload(removed.state), text("bob must not read this"));
    assert.equal(await opens(reload(carol.state), m.message), "bob must not read this", "the control failed: carol can't read it either");
    return (await opens(reload(bob.state), m.message)) === undefined;
  },

  async "a new member can't read messages from before the join"() {
    const { states: s } = await group("bob");
    const before = await encryptMlsMessage(s.alice, text("before carol"));
    assert.equal(await opens(s.bob, before.message), "before carol", "the control failed: bob can't read it");
    const carol = device("carol");
    const kp = await generateMlsKeyPackage(carol);
    const added = await addMlsMembers(before.state, [kp.keyPackage]);
    const joined = reload(await joinMlsGroup(added.welcome, kp.keyPackage, kp.privatePackage, trust));
    return (await opens(joined, before.message)) === undefined;
  },

  async "a replayed message is rejected"() {
    const { states: s } = await group("bob");
    const m = await encryptMlsMessage(s.alice, text("once"));
    const first = await decryptMlsMessage(s.bob, m.message);
    assert.equal(words(first.plaintext), "once");
    return (await opens(reload(first.state), m.message)) === undefined;
  },

  async "two messages from one epoch open out of order"() {
    const { states: s } = await group("bob");
    const m1 = await encryptMlsMessage(s.alice, text("one"));
    const m2 = await encryptMlsMessage(m1.state, text("two"));
    const r2 = await decryptMlsMessage(s.bob, m2.message);
    const r1 = await decryptMlsMessage(reload(r2.state), m1.message);
    return words(r2.plaintext) === "two" && words(r1.plaintext) === "one";
  },

  async "a message from the previous epoch opens after a commit"() {
    const { states: s } = await group("bob");
    const late = await encryptMlsMessage(s.bob, text("sent before the commit"));
    const update = await updateMlsLeaf(s.alice);
    await processMlsMessage(late.state, update.commit);
    return (await opens(reload(update.state), late.message)) === "sent before the commit";
  },

  async "a tampered ciphertext is rejected"() {
    const { states: s } = await group("bob");
    const m = await encryptMlsMessage(s.alice, text("intact"));
    const bad = m.message.slice();
    bad[bad.length - 5] ^= 1;
    if ((await opens(s.bob, bad)) !== undefined) return false;
    return (await opens(s.bob, m.message)) === "intact";
  },
};

let failed = 0;
for (const [name, check] of Object.entries(properties)) {
  let ok = false;
  try {
    ok = await check();
  } catch (e) {
    console.error(`  ${name} threw: ${e.message}`);
  }
  if (!ok) {
    failed++;
    console.error(`FAIL ${name}`);
  }
}
assert.equal(failed, 0, `${failed} of the six MLS properties failed`);

console.log("mls-properties: all six hold — removal locks out, joining gives no history, replays fail, and late or out-of-order messages open");
