/* eslint-env node */

/**
 * Pinning the people you talk to, and refusing a swap (GRYT-726). Every case here is one
 * where getting it wrong looks like nothing being wrong, so they are driven, not reasoned.
 */

import assert from "node:assert/strict";

/**
 * Pins, in memory. The package does not decide where they live — see
 * `PeerPinStore` — so a check supplies the simplest thing that satisfies it.
 */
let pins = {};
const store = {
  read: () => pins,
  write: (next) => {
    pins = next;
  },
};


import {
  asIdentityScope,
  deriveDmKeyPair,
  signDmKeyBinding,
} from "../dist/index.js";


const {
  evaluatePeerKey,
  forgetPeerPin,
  forgetPeerPinsForScope,
  getPeerPin,
  pinPeerKey,
} = await import("../dist/index.js");

const SCOPE = asIdentityScope("srv:abc123");
const OTHER_SCOPE = asIdentityScope("srv:def456");
const BOB = "user_bob";

const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);

async function identity() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    privateKey: pair.privateKey,
    publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
  };
}

const bob = await identity();
const mallory = await identity();

const bind = ({ who = bob, dmSeed = 7, scope = SCOPE } = {}) =>
  signDmKeyBinding({
    dmPublicKey: deriveDmKeyPair(seed(dmSeed), scope).publicKey,
    scope,
    identityPrivateKey: who.privateKey,
    identityPublicJwk: who.publicJwk,
  });

const decide = (binding, scope = SCOPE, memberId = BOB) =>
  evaluatePeerKey({ store, scope, memberId, binding });

/* ── nothing published is not an error ──────────────────────────────────── */

{
  for (const nothing of [null, undefined, ""]) {
    const decision = await decide(nothing);
    assert.equal(decision.kind, "none",
      "a member who has published no key is an ordinary member, not a problem");
  }
}

/* ── first sight, and it is not pinned by asking ────────────────────────── */

{
  const binding = await bind();
  const first = await decide(binding);
  assert.equal(first.kind, "first");

  // Evaluating twice must still say "first". A function that pinned as a side effect would
  // answer "known" the second time, and nothing would ever report a change.
  const again = await decide(binding);
  assert.equal(again.kind, "first",
    "evaluating must not pin; the caller decides when to");

  pinPeerKey(store, SCOPE, BOB, first.verified);
  assert.equal((await decide(binding)).kind, "known",
    "after pinning, the same binding is the person we know");
}

/* ── the same person from a second device ───────────────────────────────── */

{
  // Same identity key, same seed, so the same binding is produced again. This is a phone
  // signing in alongside a laptop, and it must be silent.
  assert.equal((await decide(await bind())).kind, "known",
    "the same keys arriving again must not read as a change");
}

/* ── somebody else's identity over the same DM key ──────────────────────── */

{
  const swapped = await bind({ who: mallory });
  const decision = await decide(swapped);

  assert.equal(decision.kind, "changed",
    "a different identity key signing for this member is the substitution this exists to catch");
  assert.equal(decision.changedIdentity, true);
  assert.equal(decision.changedKey, false,
    "the DM key is the same one; only who vouched for it moved");
}

/* ── the same identity over a different DM key ──────────────────────────── */

{
  const reseeded = await bind({ dmSeed: 11 });
  const decision = await decide(reseeded);

  // An account holder's identity key is kept while their DM key comes from the seed, so
  // restoring a different seed lands here. Comparing only the thumbprint would miss it.
  assert.equal(decision.kind, "changed",
    "a new DM key under a known identity is still a change");
  assert.equal(decision.changedIdentity, false);
  assert.equal(decision.changedKey, true);
}

/* ── a change stays a change ────────────────────────────────────────────── */

{
  const swapped = await bind({ who: mallory });
  for (let i = 0; i < 3; i++) {
    assert.equal((await decide(swapped)).kind, "changed",
      "refusing has to be sticky; a client that gives in on the second try gives in");
  }

  const pin = getPeerPin(store, SCOPE, BOB);
  assert.equal(pin.thumbprint, (await decide(await bind())).pin?.thumbprint ?? pin.thumbprint,
    "the stored pin must not be quietly overwritten by the key that was refused");
}

/* ── accepting one is a deliberate act ──────────────────────────────────── */

{
  const swapped = await bind({ who: mallory });
  const before = getPeerPin(store, SCOPE, BOB);

  forgetPeerPin(store, SCOPE, BOB);
  const fresh = await decide(swapped);
  assert.equal(fresh.kind, "first", "forgetting a pin is what makes the next key pinnable");

  pinPeerKey(store, SCOPE, BOB, fresh.verified);
  const after = getPeerPin(store, SCOPE, BOB);
  assert.notEqual(after.thumbprint, before.thumbprint);
  assert.equal((await decide(swapped)).kind, "known");
}

/* ── a binding that does not check out never becomes a pin ──────────────── */

{
  forgetPeerPin(store, SCOPE, BOB);

  // Signed for another server. Perfectly valid there, and worthless here.
  const elsewhere = await bind({ scope: OTHER_SCOPE });
  const replayed = await decide(elsewhere);
  assert.equal(replayed.kind, "unusable",
    "a binding from another server is not a first sighting, it is a broken one");
  assert.equal(getPeerPin(store, SCOPE, BOB), null,
    "nothing unusable may leave a pin behind");

  for (const junk of ["not a jwt", "a.b.c", "one.two"]) {
    assert.equal((await decide(junk)).kind, "unusable", `"${junk}" was not refused`);
  }
  assert.equal(getPeerPin(store, SCOPE, BOB), null);
}

/* ── pins do not leak between servers ───────────────────────────────────── */

{
  const binding = await bind();
  const here = await decide(binding);
  pinPeerKey(store, SCOPE, BOB, here.verified);

  const there = await bind({ scope: OTHER_SCOPE });
  const overThere = await decide(there, OTHER_SCOPE);
  assert.equal(overThere.kind, "first",
    "the same member id on another server is somebody this pin says nothing about");
  pinPeerKey(store, OTHER_SCOPE, BOB, overThere.verified);

  assert.equal((await decide(binding)).kind, "known",
    "and pinning them there must not have disturbed the pin here");
}

/* ── one scope being a prefix of another ────────────────────────────────── */

{
  // `srv:abc` and `srv:abc123` are both legitimate scopes, and forgetting the first must not
  // take the second with it. The separator in the storage key is what stops that.
  const shorter = asIdentityScope("srv:abc");
  const decision = await decide(await bind({ scope: shorter }), shorter);
  pinPeerKey(store, shorter, BOB, decision.verified);

  forgetPeerPinsForScope(store, shorter);
  assert.equal(getPeerPin(store, shorter, BOB), null);
  assert.notEqual(getPeerPin(store, SCOPE, BOB), null,
    "forgetting srv:abc must not forget srv:abc123");
}

/* ── firstSeenAt survives a re-pin ──────────────────────────────────────── */

{
  const original = getPeerPin(store, SCOPE, BOB).firstSeenAt;
  const decision = await decide(await bind());
  pinPeerKey(store, SCOPE, BOB, decision.verified, original + 100_000);

  assert.equal(getPeerPin(store, SCOPE, BOB).firstSeenAt, original,
    "known since has to mean since this person was first seen, not since they last changed device");
  assert.equal(getPeerPin(store, SCOPE, BOB).lastSeenAt, original + 100_000);
}

/* ── leaving a server forgets the people on it ──────────────────────────── */

{
  forgetPeerPinsForScope(store, SCOPE);
  assert.equal(getPeerPin(store, SCOPE, BOB), null);
  assert.notEqual(getPeerPin(store, OTHER_SCOPE, BOB), null,
    "leaving one server must not forget the people on another");
}

console.log(
  "peer-keys: first sight is pinned only when asked, a changed key is refused every time, and nothing unusable is ever remembered",
);
