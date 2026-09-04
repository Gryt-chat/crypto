/**
 * The key a direct message is encrypted to (GRYT-709).
 *
 * A second key rather than the identity one, because identity is ECDSA P-256,
 * which signs and cannot do key agreement at all. This is X25519.
 *
 * Only {@link dmPublicKey} is published. The private half is derived here and
 * never sent, backed up or logged — the 24-word phrase carries the seed, which
 * is enough to re-derive it and read old messages again.
 *
 * One key per server, from the same scope `identity-seed.ts` uses, so two
 * servers cannot tell they are talking to the same person.
 *
 * **The scope, not the address (GRYT-719).** Deriving from the address would
 * change the key whenever a port is taken or a lease moves, and every message
 * ever encrypted to the old key would be unreadable with nothing logged.
 * `IdentityScope` is branded so the wrong string does not typecheck.
 *
 * This derives a keypair and computes a shared secret. Wrapping a per-message
 * key, and the certificate saying whose public key is whose, come later — and
 * the certificate is what decides whether any of this is worth anything.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { IdentityScope } from "./scope";

/**
 * Not `identity-seed.ts`'s label: one seed under one label would hand the same
 * 32 bytes to two algorithms. Changing this string changes every DM key that
 * has ever existed, so a `v2` arrives with a migration or not at all.
 */
const DERIVATION_SALT = "gryt-dm-v1";

/**
 * Exactly 32, unlike `deriveLocalKeyPair`'s 48-then-reduce: any 32 bytes is a
 * valid X25519 secret, and the algorithm clamps what it needs itself.
 */
const SECRET_BYTES = 32;

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>;
}

/**
 * A stub or a platform handing back a constant would give every device the same
 * DM key, and every user could read every conversation. A real seed being all
 * one byte is about 2^-248, so nothing legitimate is turned away.
 */
function assertUsableSeed(seed: Uint8Array): void {
  if (seed.length !== SECRET_BYTES) {
    throw new Error(`A seed is ${SECRET_BYTES} bytes, not ${seed.length}.`);
  }
  if (seed.every((byte) => byte === seed[0])) {
    throw new Error("That seed is a single repeated byte, which is not a seed.");
  }
}

export interface DmKeyPair {
  /** Never leaves this device. Not sent, not backed up, not logged. */
  privateKey: Uint8Array;
  /** The half that is published, so others can encrypt to you. */
  publicKey: Uint8Array;
}

/**
 * The DM keypair this seed gives for one server. Deterministic, so the recovery
 * phrase is enough to read old conversations, and the scope outliving an
 * address change keeps them readable after the server moves.
 */
export function deriveDmKeyPair(
  seed: Uint8Array,
  scope: IdentityScope,
): DmKeyPair {
  assertUsableSeed(seed);

  const privateKey = hkdf(
    sha256,
    seed,
    utf8(DERIVATION_SALT),
    utf8(scope),
    SECRET_BYTES,
  );

  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/** The public half alone, for the cases that should not touch the private one. */
export function dmPublicKey(
  seed: Uint8Array,
  scope: IdentityScope,
): Uint8Array {
  return deriveDmKeyPair(seed, scope).publicKey;
}

/**
 * The secret two people share. Run through HKDF because the X25519 output is a
 * curve point's x-coordinate, not uniform over 32 bytes; the conversation id
 * goes in as `info` so one pair talking twice does not reuse a key.
 *
 * **Not enough on its own.** Agreement with the wrong public key succeeds just
 * as well as with the right one. Whether `theirPublicKey` belongs to the person
 * named beside it is what the certificate answers, and until that exists a
 * caller is trusting the server for it.
 */
export function dmSharedSecret(
  privateKey: Uint8Array,
  theirPublicKey: Uint8Array,
  conversationId: string,
): Uint8Array {
  const shared = x25519.getSharedSecret(privateKey, theirPublicKey);
  return hkdf(
    sha256,
    shared,
    utf8(`${DERIVATION_SALT}-shared`),
    utf8(conversationId),
    SECRET_BYTES,
  );
}
