/* eslint-env node */

/**
 * The person key in the pin, the comparison code and the MLS trust check (GRYT-1507). A person
 * key rides on the identity already pinned, and a different one is refused like a DM key.
 */

import assert from "node:assert/strict";

import {
  addMlsMembers,
  asIdentityScope,
  comparisonCode,
  createMlsDevice,
  createMlsGroup,
  deriveDmKeyPair,
  derivePersonKeyPair,
  evaluateMemberKeys,
  evaluatePersonKey,
  forgetPeerPin,
  generateMlsKeyPackage,
  getPeerPin,
  markPeerCompared,
  pinPeerKey,
  pinPersonKey,
  signDmKeyBinding,
  signPersonKeyBinding,
  trustPinnedPersonKeys,
  verifyDmKeyBinding,
} from "../dist/index.js";

let pins = {};
const store = { read: () => pins, write: (next) => (pins = next) };

const SCOPE = asIdentityScope("srv:person-pins");
const OTHER = asIdentityScope("srv:elsewhere");
const BOB = "user_bob";
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);
const b64 = (bytes) => Buffer.from(bytes).toString("base64url");

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}
const bob = await identity();
const mallory = await identity();

const dmBinding = ({ who = bob, s = 7 } = {}) =>
  signDmKeyBinding({
    dmPublicKey: deriveDmKeyPair(seed(s), SCOPE).publicKey,
    scope: SCOPE,
    identityPrivateKey: who.privateKey,
    identityPublicJwk: who.publicJwk,
  });
const personBinding = ({ who = bob, s = 7, scope = SCOPE } = {}) =>
  signPersonKeyBinding({
    personPublicKey: derivePersonKeyPair(seed(s), scope).publicKey,
    scope,
    identityPrivateKey: who.privateKey,
    identityPublicJwk: who.publicJwk,
  });
const decide = (binding, memberId = BOB) => evaluatePersonKey({ store, scope: SCOPE, memberId, binding });
const pinDm = async (memberId, s = 7) => pinPeerKey(store, SCOPE, memberId, await verifyDmKeyBinding(await dmBinding({ s }), SCOPE));
const bobPerson = b64(derivePersonKeyPair(seed(7), SCOPE).publicKey);

/* ── nothing to check it against until the identity is pinned ─────────────── */

{
  for (const nothing of [null, undefined, ""]) assert.equal((await decide(nothing)).kind, "none");
  assert.equal((await decide("not.a.binding")).kind, "unusable");
  assert.equal((await decide(await personBinding({ scope: OTHER }))).kind, "unusable", "another server's binding was read");
  assert.equal((await decide(await dmBinding())).kind, "unusable", "a DM key binding passed as a person key binding");

  const unpinned = await decide(await personBinding());
  assert.equal(unpinned.kind, "unpinned");
  assert.equal(pinPersonKey(store, SCOPE, BOB, unpinned.verified), null, "a person key made a pin on its own");
  assert.equal(getPeerPin(store, SCOPE, BOB), null);
}

/* ── signed by the pinned identity: recorded, and the comparison survives ─── */

{
  pinPeerKey(store, SCOPE, BOB, await verifyDmKeyBinding(await dmBinding(), SCOPE), 1000);
  assert.equal(markPeerCompared(store, SCOPE, BOB, getPeerPin(store, SCOPE, BOB), 2000), true);

  const first = await decide(await personBinding());
  assert.equal(first.kind, "first");
  assert.equal((await decide(await personBinding())).kind, "first", "evaluating recorded something");

  const pin = pinPersonKey(store, SCOPE, BOB, first.verified, 3000);
  assert.equal(pin.personPublicKey, bobPerson);
  assert.deepEqual(
    [pin.firstSeenAt, pin.lastSeenAt, pin.comparedAt],
    [1000, 3000, 2000],
    "the compared identity signed it, so the comparison stays",
  );
  assert.equal((await decide(await personBinding())).kind, "known");
}

/* ── a different person key, or a different signer, is refused every time ── */

{
  const reseeded = await decide(await personBinding({ s: 11 }));
  assert.deepEqual([reseeded.kind, reseeded.changedIdentity, reseeded.changedKey], ["changed", false, true]);
  assert.equal(pinPersonKey(store, SCOPE, BOB, reseeded.verified), null, "a changed person key overwrote the pin");

  const swapped = await decide(await personBinding({ who: mallory }));
  assert.deepEqual([swapped.kind, swapped.changedIdentity, swapped.changedKey], ["changed", true, false]);
  assert.equal(pinPersonKey(store, SCOPE, BOB, swapped.verified), null, "another identity's binding was recorded");

  for (let i = 0; i < 3; i++) assert.equal((await decide(await personBinding({ s: 11 }))).kind, "changed");
  assert.equal(getPeerPin(store, SCOPE, BOB).personPublicKey, bobPerson);
}

/* ── marking a comparison checks the person key too ───────────────────────── */

{
  const pin = getPeerPin(store, SCOPE, BOB);
  const keys = { thumbprint: pin.thumbprint, dmPublicKey: pin.dmPublicKey };
  assert.equal(markPeerCompared(store, SCOPE, BOB, keys), false, "a code without the pinned person key was marked");
  assert.equal(markPeerCompared(store, SCOPE, BOB, { ...keys, personPublicKey: "something-else" }), false);
  assert.equal(markPeerCompared(store, SCOPE, BOB, { ...keys, personPublicKey: bobPerson }, 4000), true);
}

/* ── re-pinning: the same keys keep it, a move starts it over ─────────────── */

{
  await pinDm(BOB);
  assert.equal(getPeerPin(store, SCOPE, BOB).personPublicKey, bobPerson, "the same member list landing lost the person key");

  await pinDm(BOB, 11);
  const moved = getPeerPin(store, SCOPE, BOB);
  assert.equal(moved.personPublicKey, undefined, "a person key outlived the DM key it came with");
  assert.equal(moved.comparedAt, undefined);

  const fresh = await decide(await personBinding({ s: 11 }));
  assert.equal(fresh.kind, "first");
  assert.ok(pinPersonKey(store, SCOPE, BOB, fresh.verified));
  forgetPeerPin(store, SCOPE, BOB);
}

/* ── the code covers person keys, and stays put for pins without them ─────── */

{
  const alice = { thumbprint: "tp-alice", dmPublicKey: "dm-alice" };
  const bobSide = { thumbprint: "tp-bob", dmPublicKey: "dm-bob" };
  const before = "97499 56622 29587 82739 18885 14154 75034 49094 30750 82123 71739 12940";
  assert.equal(comparisonCode(alice, bobSide), before, "codes from before person keys moved");

  const [a, b] = [{ ...alice, personPublicKey: "pk-alice" }, { ...bobSide, personPublicKey: "pk-bob" }];
  const code = comparisonCode(a, b);
  assert.equal(code, comparisonCode(b, a));
  assert.notEqual(code, before);
  assert.notEqual(code, comparisonCode(a, { ...b, personPublicKey: "pk-other" }));
  assert.notEqual(code, comparisonCode({ ...a, personPublicKey: "pk-other" }, b));
  // A server holding back one person key shows as a mismatch, not as the old code.
  assert.notEqual(code, comparisonCode(a, bobSide));
  assert.notEqual(comparisonCode(a, bobSide), before);
  assert.notEqual(
    comparisonCode({ thumbprint: "a", dmPublicKey: "b", personPublicKey: "c" }, { thumbprint: "d", dmPublicKey: "e" }),
    comparisonCode({ thumbprint: "a", dmPublicKey: "b" }, { thumbprint: "c", dmPublicKey: "d", personPublicKey: "e" }),
  );
}

/* ── a member list records both at first sight, and never during a dispute ── */

{
  const me = derivePersonKeyPair(seed(3), SCOPE).publicKey;
  const mine = await identity();
  const run = (members) =>
    evaluateMemberKeys({ store, scope: SCOPE, ownKey: null, ownPersonKey: me, members, myServerUserId: "me" });
  const own = await signPersonKeyBinding({
    personPublicKey: me,
    scope: SCOPE,
    identityPrivateKey: mine.privateKey,
    identityPublicJwk: mine.publicJwk,
  });

  let states = await run([
    { serverUserId: BOB, dmKeyBinding: await dmBinding(), personKeyBinding: await personBinding() },
    { serverUserId: "me", personKeyBinding: own },
  ]);
  assert.equal(states[BOB].decision.kind, "first");
  assert.equal(states[BOB].personKey.kind, "first");
  assert.equal(getPeerPin(store, SCOPE, BOB).personPublicKey, bobPerson, "one pass didn't record the person key");
  assert.equal(states.me.ownPersonKeyRewritten, false);
  assert.equal(getPeerPin(store, SCOPE, "me"), null, "your own row got pinned");

  states = await run([{ serverUserId: "me", personKeyBinding: await personBinding() }]);
  assert.equal(states.me.ownPersonKeyRewritten, true, "somebody else's person key on your row went unnoticed");

  states = await run([{ serverUserId: BOB, dmKeyBinding: await dmBinding(), personKeyBinding: await personBinding() }]);
  assert.equal(states[BOB].personKey.kind, "known");

  forgetPeerPin(store, SCOPE, BOB);
  await pinDm(BOB);
  states = await run([{ serverUserId: BOB, dmKeyBinding: await dmBinding({ s: 11 }), personKeyBinding: await personBinding({ s: 11 }) }]);
  assert.equal(states[BOB].decision.kind, "changed");
  assert.equal(states[BOB].personKey.kind, "first");
  assert.equal(getPeerPin(store, SCOPE, BOB).personPublicKey, undefined, "a person key was recorded while the DM key was in dispute");
  forgetPeerPin(store, SCOPE, BOB);
}

/* ── trustPersonKey from the pins, through a real MLS add ─────────────────── */

{
  const KARI = seed(3);
  const kari = derivePersonKeyPair(KARI, SCOPE).publicKey;
  const trustPersonKey = trustPinnedPersonKeys({ store, scope: SCOPE, memberIds: [BOB], ownPersonKey: kari });
  const trust = { scope: SCOPE, trustPersonKey };

  const laptop = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "laptop" });
  const kariPhone = createMlsDevice({ seed: KARI, scope: SCOPE, deviceName: "phone" });
  const bobPhone = createMlsDevice({ seed: seed(7), scope: SCOPE, deviceName: "phone" });
  const carolPhone = createMlsDevice({ seed: seed(13), scope: SCOPE, deviceName: "phone" });
  const kp = async (d) => (await generateMlsKeyPackage(d)).keyPackage;

  const group = await createMlsGroup(laptop, trust);
  await addMlsMembers(group, [await kp(kariPhone)]);
  await assert.rejects(addMlsMembers(group, [await kp(bobPhone)]), /validate credential/, "a person key nobody pinned got in");

  await pinDm(BOB);
  await assert.rejects(addMlsMembers(group, [await kp(bobPhone)]), /validate credential/, "a pin with no person key let a device in");
  pinPersonKey(store, SCOPE, BOB, (await decide(await personBinding())).verified);
  assert.equal((await addMlsMembers(group, [await kp(bobPhone)])).state.groupContext.epoch, 1n);

  // Pinned, but for somebody who isn't in this conversation.
  await pinDm("user_carol", 13);
  pinPersonKey(store, SCOPE, "user_carol", (await decide(await personBinding({ s: 13 }), "user_carol")).verified);
  assert.equal(getPeerPin(store, SCOPE, "user_carol").personPublicKey, b64(derivePersonKeyPair(seed(13), SCOPE).publicKey));
  await assert.rejects(addMlsMembers(group, [await kp(carolPhone)]), /validate credential/, "a pinned non-member got into the DM");

  assert.equal(trustPersonKey({ scope: OTHER, personPublicKey: kari }), false, "a certificate for another server passed");
}

console.log(
  "person-key-pins: a person key needs the pinned identity, a different one is refused, the code covers it, and MLS trusts only pinned members and yourself",
);
