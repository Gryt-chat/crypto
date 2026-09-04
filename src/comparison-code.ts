/**
 * A code two people read to each other (GRYT-730).
 *
 * Everything since GRYT-720 catches a key that *changed*. Nothing can say the
 * first key was ever right, because the server introduced the two people. This
 * is the only way out: compare a short string over something the server is not
 * on, and if it matches neither of you is talking to the server.
 *
 * All four pinned values go in — both thumbprints, both DM keys — sorted, so
 * the two sides compute the same code without agreeing on who is first.
 *
 * It cannot say whose keys they are. A code compared with the wrong person
 * matches perfectly; at some point somebody recognises a voice.
 *
 * Digits rather than words, because `identity-seed.ts` already renders BIP39
 * words for the backup and this must never be mistaken for something worth
 * typing into a box or keeping secret.
 */

import { sha256 } from "@noble/hashes/sha2.js";

const GROUPS = 12;
const DIGITS_PER_GROUP = 5;

/** Sixty digits, chosen for reading aloud rather than for the margin. */
export const COMPARISON_CODE_DIGITS = GROUPS * DIGITS_PER_GROUP;

export interface ComparisonSide {
  /** Their identity key's JWK thumbprint, as pinned. */
  thumbprint: string;
  /** Their DM public key, base64url, as pinned. */
  dmPublicKey: string;
}

/**
 * One byte per digit, from a hash that produces 32. Wrapping the digest instead
 * would repeat 28 digits at the end — visibly, so it reads as a bug and invites
 * somebody to stop comparing.
 */
function stretch(seed: Uint8Array, count: number): Uint8Array {
  const out = new Uint8Array(count);
  for (let block = 0; block * 32 < count; block++) {
    const chunk = sha256(
      new Uint8Array([...seed, block]) as Uint8Array<ArrayBuffer>,
    );
    out.set(chunk.subarray(0, Math.min(32, count - block * 32)), block * 32);
  }
  return out;
}

function digitsFrom(bytes: Uint8Array, count: number): string {
  // Modulo ten is slightly biased, and does not matter: this is a fingerprint
  // to compare, not a secret to guess.
  let out = "";
  for (let i = 0; i < count; i++) out += (bytes[i] % 10).toString();
  return out;
}

/** The code for one pair. Sorted, so both sides compute the same string. */
export function comparisonCode(a: ComparisonSide, b: ComparisonSide): string {
  const halves = [
    [a.thumbprint, a.dmPublicKey],
    [b.thumbprint, b.dmPublicKey],
  ]
    .map((half) => JSON.stringify(half))
    .sort();

  /*
   * JSON, not a separator: `a` + `b:c` and `a:b` + `c` would join to the same
   * string and give two different key pairs the same code.
   */
  const digest = sha256(
    new TextEncoder().encode(JSON.stringify(halves)) as Uint8Array<ArrayBuffer>,
  );

  const digits = digitsFrom(stretch(digest, COMPARISON_CODE_DIGITS), COMPARISON_CODE_DIGITS);
  const groups: string[] = [];
  for (let i = 0; i < COMPARISON_CODE_DIGITS; i += DIGITS_PER_GROUP) {
    groups.push(digits.slice(i, i + DIGITS_PER_GROUP));
  }
  return groups.join(" ");
}
