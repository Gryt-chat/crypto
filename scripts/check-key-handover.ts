/**
 * Key handovers (GRYT-1876): an identity you left signs for the new one, and somebody who pinned
 * the old one moves the pin by themselves. Anything short of a clean chain stays "changed".
 */

import assert from "node:assert/strict";

import {
  asIdentityScope,
  deriveDmKeyPair,
  derivePersonKeyPair,
  evaluateMemberKeys,
  getPeerPin,
  keyHandoverChain,
  markPeerCompared,
  signDmKeyBinding,
  signKeyHandover,
  signPersonKeyBinding,
  verifyKeyHandover,
} from "../dist/index.js";

type PinStore = Parameters<typeof evaluateMemberKeys>[0]["store"];
const SCOPE = asIdentityScope("srv:handover");
const OTHER = asIdentityScope("srv:elsewhere");
const SIVERT = "user_sivert";
const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);

async function identity(n: number) {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const s = seed(n);
  const row = async () => ({
    serverUserId: SIVERT,
    dmKeyBinding: await signDmKeyBinding({ dmPublicKey: deriveDmKeyPair(s, SCOPE).publicKey, scope: SCOPE, identityPrivateKey: pair.privateKey, identityPublicJwk: publicJwk }),
    personKeyBinding: await signPersonKeyBinding({ personPublicKey: derivePersonKeyPair(s, SCOPE).publicKey, scope: SCOPE, identityPrivateKey: pair.privateKey, identityPublicJwk: publicJwk }),
  });
  return { privateKey: pair.privateKey, publicJwk, person: derivePersonKeyPair(s, SCOPE).publicKey, row };
}
const handover = (from: Awaited<ReturnType<typeof identity>>, to: Awaited<ReturnType<typeof identity>>, scope = SCOPE) =>
  signKeyHandover({ scope, oldIdentityPrivateKey: from.privateKey, oldIdentityPublicJwk: from.publicJwk, newIdentityPublicJwk: to.publicJwk });

const iphone = await identity(3);
const desktop = await identity(5);
const browser = await identity(7);
const stranger = await identity(11);
const thumbOf = async (who: Awaited<ReturnType<typeof identity>>) => verifyKeyHandover(await handover(who, stranger), SCOPE).fromThumbprint;
const [I, D, B] = [await thumbOf(iphone), await thumbOf(desktop), await thumbOf(browser)];

/* ── the statement ───────────────────────────────────────────────────────── */
{
  const h = await handover(iphone, desktop);
  const v = verifyKeyHandover(h, SCOPE);
  assert.equal(v.fromThumbprint, I);
  assert.equal(v.toThumbprint, D);
  assert.throws(() => verifyKeyHandover(h, OTHER), /different server/);
  const [head, body, sig] = h.split(".");
  const flipped = sig.slice(0, -2) + (sig.at(-2) === "A" ? "B" : "A") + sig.at(-1);
  assert.throws(() => verifyKeyHandover(`${head}.${body}.${flipped}`, SCOPE), /signature/);
  await assert.rejects(handover(iphone, iphone), /one identity to another/);
}

/* ── chains ──────────────────────────────────────────────────────────────── */
{
  const iToD = await handover(iphone, desktop);
  const dToB = await handover(desktop, browser);
  assert.equal(keyHandoverChain([iToD], SCOPE, I, D), true);
  assert.equal(keyHandoverChain([dToB, iToD], SCOPE, I, B), true, "in any order");
  assert.equal(keyHandoverChain([iToD, "junk.junk.junk"], SCOPE, I, D), true, "unreadable ones are skipped");
  assert.equal(keyHandoverChain([], SCOPE, I, D), false);
  assert.equal(keyHandoverChain([dToB], SCOPE, I, B), false, "nothing from the pinned identity");
  assert.equal(keyHandoverChain([iToD, await handover(iphone, browser)], SCOPE, I, D), false, "handed over to two keys: one isn't you");
  assert.equal(keyHandoverChain([await handover(iphone, desktop, OTHER)], SCOPE, I, D), false, "for another server");
}

/* ── a member list with a handover moves the pin, the comparison and the person key ─ */
{
  let pins: ReturnType<PinStore["read"]> = {};
  const store: PinStore = { read: () => pins, write: (next) => (pins = next) };
  type Row = Parameters<typeof evaluateMemberKeys>[0]["members"][number];
  const evaluate = (row: Row) => evaluateMemberKeys({ store, scope: SCOPE, ownKey: null, members: [row], myServerUserId: "user_sable" });

  await evaluate(await iphone.row());
  const first = getPeerPin(store, SCOPE, SIVERT);
  assert.ok(first);
  assert.equal(markPeerCompared(store, SCOPE, SIVERT, first, 1234), true);

  const withoutProof = await evaluate(await desktop.row());
  assert.equal(withoutProof[SIVERT].decision.kind, "changed", "no handover: stop and ask");
  assert.equal(getPeerPin(store, SCOPE, SIVERT)?.thumbprint, I);

  const forged = await evaluate({ ...(await desktop.row()), keyHandovers: [await handover(stranger, desktop)] });
  assert.equal(forged[SIVERT].decision.kind, "changed", "signed by somebody who isn't pinned");

  const proven = await evaluate({ ...(await desktop.row()), keyHandovers: [await handover(iphone, desktop)] });
  assert.equal(proven[SIVERT].handedOver, true);
  assert.equal(proven[SIVERT].decision.kind, "known");
  const pin = getPeerPin(store, SCOPE, SIVERT);
  assert.equal(pin?.thumbprint, D);
  assert.equal(pin?.personPublicKey, Buffer.from(desktop.person).toString("base64url"));
  assert.equal(pin?.comparedAt, 1234, "the comparison carries over, since the compared key vouched");

  const again = await evaluate({ ...(await desktop.row()), keyHandovers: [await handover(iphone, desktop)] });
  assert.equal(again[SIVERT].handedOver, undefined, "only once");
}

console.log("key-handover: an old identity signs for the new one, a clean chain moves the pin and its comparison, and anything else stays changed");
