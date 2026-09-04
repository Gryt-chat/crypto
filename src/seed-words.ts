import {
  entropyToMnemonic,
  mnemonicToEntropy,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

/**
 * The identity seed as 24 words, and back.
 *
 * Both apps had this, and a phrase written down from one has to restore on the
 * other or it is worthless. They agreed — same wordlist, same BIP-39 calls, the
 * same 24 — but they agreed by two people keeping two files in step, which is
 * the arrangement this package exists to end.
 *
 * The standard 2048-word list is 11 bits a word: 256 bits of seed plus 8 bits of
 * checksum makes 264, which is 24 words exactly. The checksum lives inside the
 * words rather than beside them, so a mistyped or reordered phrase is rejected
 * instead of quietly producing a different identity — and since no two words in
 * the list share their first four letters, a misread word usually is not a word
 * at all and fails before the checksum is reached.
 *
 * Only the encoding is borrowed from wallets. The key-stretching step they do on
 * top is not wanted here: these 256 bits are the seed already, not a passphrase
 * to grind into one.
 */

/** Length of the seed every local identity is calculated from. */
export const SEED_BYTES = 32;

/** How many words a backup is. Stated once so the message and the check agree. */
export const BACKUP_WORDS = 24;

/**
 * Refuse a seed that cannot be one.
 *
 * The length check is the real one. The repeated-byte check is for a generator
 * that has failed open and is handing back zeros, which is worth catching loudly
 * rather than deriving a whole identity from.
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

/**
 * The messages here are read by somebody typing 24 words back in, so they say
 * what is wrong rather than that something is.
 */
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
