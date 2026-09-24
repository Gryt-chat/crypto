/**
 * The vault password: six generated words by default, or a typed one behind a floor. The
 * floor is structural, not a strength meter, so no dictionary ships (GRYT-1473).
 */
import { wordlist } from "@scure/bip39/wordlists/english.js";

/** 66 bits. Enough that a GPU farm is out of reach at the vault's Argon2id cost. */
export const VAULT_PASSWORD_WORDS = 6;

/** The floor for a typed password. Only the UI enforces it, so an old one still re-seals. */
export const MIN_VAULT_PASSWORD = 12;

/** Six words from the BIP39 list. 2048 divides 65536, so the draw is uniform. */
export function generateVaultPassword(words: number = VAULT_PASSWORD_WORDS): string {
  const draws = new Uint16Array(words);
  crypto.getRandomValues(draws);
  return Array.from(draws, (n) => wordlist[n & 2047]).join(" ");
}
