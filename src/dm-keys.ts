/**
 * The key a direct message is encrypted to (GRYT-709): X25519, because identity is ECDSA and
 * cannot do key agreement. Derived from the scope, not the address (GRYT-719).
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { IdentityScope } from "./scope";

/**
 * Not `identity-seed.ts`'s label: one seed under one label would hand the same 32 bytes to
 * two algorithms. Changing this string changes every DM key that has ever existed.
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
 * A stub or a platform handing back a constant would give every device the same DM key. A
 * real seed being all one byte is about 2^-248, so nothing legitimate is turned away.
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
 * The DM keypair this seed gives for one server. Deterministic, so the recovery phrase reads
 * old conversations, and the scope keeps them readable after the server moves.
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
 * The secret two people share, through HKDF because X25519's output is not uniform; the
 * conversation id is `info`. Not enough alone: the wrong public key agrees just as well.
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
