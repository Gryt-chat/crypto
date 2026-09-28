/**
 * A recovery key: 256 random bits that open the vault on their own, shown once and kept by
 * the person. Crockford base32, so 0/O and 1/I/L cannot be misread (GRYT-1473).
 */

import { crockfordDecode, crockfordEncode, normalizeCrockford } from "./crockford";

export const RECOVERY_KEY_BYTES = 32;

const GROUP = 4;

export function generateRecoveryKey(): Uint8Array {
  const key = new Uint8Array(RECOVERY_KEY_BYTES);
  crypto.getRandomValues(key);
  return key;
}

/** Groups of four with dashes, 13 of them. The last character carries 1 bit and 4 zeros. */
export function formatRecoveryKey(key: Uint8Array): string {
  if (key.length !== RECOVERY_KEY_BYTES) throw new Error(`A recovery key is ${RECOVERY_KEY_BYTES} bytes.`);
  return crockfordEncode(key).match(new RegExp(`.{1,${GROUP}}`, "g"))!.join("-");
}

/**
 * The key back, or null if the text is not one. Case, spaces and dashes are forgiven.
 * Null rather than a throw, because the same field also takes a password.
 */
export function parseRecoveryKey(text: string): Uint8Array | null {
  return crockfordDecode(normalizeCrockford(text), RECOVERY_KEY_BYTES);
}
