import {
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

/**
 * The identity seed as 24 words, and back. A phrase written down on one client
 * has to restore on the other, so there is one implementation.
 *
 * The checksum lives inside the words, so a mistyped or reordered phrase is
 * rejected rather than quietly producing a different identity.
 *
 * Only the encoding is borrowed from wallets — no key stretching. These 256
 * bits are the seed already, not a passphrase to grind into one.
 */

/** Length of the seed every local identity is calculated from. */
export const SEED_BYTES = 32;

/** How many words a backup is. Stated once so the message and the check agree. */
export const BACKUP_WORDS = 24;

/**
 * The repeated-byte check is for a generator that has failed open and is handing
 * back zeros, which is worth catching loudly rather than deriving an identity.
 */
export function assertUsableSeed(seed: Uint8Array): void {
  if (seed.length !== SEED_BYTES) {
    throw new Error(`An identity seed is ${SEED_BYTES} bytes, not ${seed.length}.`);
  }
  const first = seed[0];
  if (seed.every((b) => b === first)) {
    throw new Error("Identity seed is a single repeated byte — the generator is broken.");
  }
}

export function seedToWords(seed: Uint8Array): string {
  assertUsableSeed(seed);
  return entropyToMnemonic(seed, wordlist);
}

/** Read by somebody typing 24 words back in, so they say what is wrong. */
export function wordsToSeed(phrase: string): Uint8Array {
  const normalised = phrase.trim().toLowerCase().split(/\s+/).join(" ");
  if (!normalised) throw new Error("Enter your identity words.");

  const count = normalised.split(" ").length;
  if (count !== BACKUP_WORDS) {
    throw new Error(`That is ${count} words — an identity backup is ${BACKUP_WORDS}.`);
  }
  if (!validateMnemonic(normalised, wordlist)) {
    throw new Error(
      "Those words aren't a valid identity backup. Check for a mistyped or swapped word.",
    );
  }

  const seed = mnemonicToEntropy(normalised, wordlist);
  assertUsableSeed(seed);
  return seed;
}
