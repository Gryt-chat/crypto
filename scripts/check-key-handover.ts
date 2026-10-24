/**
 * Only the key being replaced can hand over (GRYT-1886). A note that verified when it
 * shouldn't lets someone with just the password swap the key everyone pinned.
 */

import assert from "node:assert/strict";

import { asIdentityScope, deriveDmKeyPair, signDmKeyBinding, signKeyHandover, verifyKeyHandover } from "../dist/index.js";

const SCOPE = asIdentityScope("srv:abc123");
const OTHER_SCOPE = asIdentityScope("srv:def456");
const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}

const binding = async (who: Awaited<ReturnType<typeof identity>>, n: number, scope = SCOPE) =>
  signDmKeyBinding({
    dmPublicKey: deriveDmKeyPair(seed(n), scope).publicKey,
    scope,
    identityPrivateKey: who.privateKey,
    identityPublicJwk: who.publicJwk,
  });

const oldMac = await identity();
const iphone = await identity();
const thief = await identity();
const oldBinding = await binding(oldMac, 1);
const newBinding = await binding(iphone, 2);
const thiefBinding = await binding(thief, 3);

const handover = (by = oldMac, to = newBinding, over = {}) =>
  signKeyHandover({ newBinding: to, scope: SCOPE, identityPrivateKey: by.privateKey, identityPublicJwk: by.publicJwk, ...over });
const check = (note: string, over = {}) => verifyKeyHandover(note, { oldBinding, newBinding, scope: SCOPE, ...over });

// The current key handing over to the new one is accepted.
await check(await handover());

// The new key can't vouch for itself, and neither can a thief.
await assert.rejects(check(await handover(iphone)), /isn't signed by the key it replaces/);
await assert.rejects(check(await handover(thief)), /isn't signed by the key it replaces/);

// A real note for one key can't be reused for another.
await assert.rejects(check(await handover(oldMac, newBinding), { newBinding: thiefBinding }), /different key/);

// Nor on another server, nor after it expires.
await assert.rejects(check(await handover(oldMac, newBinding, { scope: OTHER_SCOPE })), /different server/);
const tenMinutesAgo = Math.floor(Date.now() / 1000) - 601;
await assert.rejects(check(await handover(oldMac, newBinding, { now: tenMinutesAgo })), /expired/);

// Tampering with what it says breaks the signature.
{
  const [h, p, s] = (await handover()).split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString());
  payload.exp += 3600;
  const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`;
  await assert.rejects(check(forged), /signature does not check out/);
}

console.log("key handover: only the key being replaced can hand over, once, here, for that key");
