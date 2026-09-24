/**
 * A recovery key: 256 random bits that open the vault on their own, shown once and kept by
 * the person. Crockford base32, so 0/O and 1/I/L cannot be misread (GRYT-1473).
 */

export const RECOVERY_KEY_BYTES = 32;

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 256 bits at 5 per character. The last character carries 1 bit and 4 zeros. */
const RECOVERY_KEY_CHARS = Math.ceil((RECOVERY_KEY_BYTES * 8) / 5);
const GROUP = 4;

const LOOKUP = new Map<string, number>();
for (let i = 0; i < ALPHABET.length; i++) LOOKUP.set(ALPHABET[i], i);
// Crockford's forgiving reads, for somebody copying it off paper.
for (const [alias, real] of [["O", "0"], ["I", "1"], ["L", "1"]] as const) {
  LOOKUP.set(alias, LOOKUP.get(real)!);
}

export function generateRecoveryKey(): Uint8Array {
  const key = new Uint8Array(RECOVERY_KEY_BYTES);
  crypto.getRandomValues(key);
  return key;
}

/** Groups of four with dashes, 13 of them. */
export function formatRecoveryKey(key: Uint8Array): string {
  if (key.length !== RECOVERY_KEY_BYTES) throw new Error(`A recovery key is ${RECOVERY_KEY_BYTES} bytes.`);

  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of key) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];

  return out.match(new RegExp(`.{1,${GROUP}}`, "g"))!.join("-");
}

/**
 * The key back, or null if the text is not one. Case, spaces and dashes are forgiven.
 * Null rather than a throw, because the same field also takes a password.
 */
export function parseRecoveryKey(text: string): Uint8Array | null {
  const clean = text.toUpperCase().replace(/[\s-]/g, "");
  if (clean.length !== RECOVERY_KEY_CHARS) return null;

  const out = new Uint8Array(RECOVERY_KEY_BYTES);
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of clean) {
    const value = LOOKUP.get(char);
    if (value === undefined) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      out[index++] = (buffer >> (bits - 8)) & 0xff;
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  // The four padding bits have to be zero, which catches some typos in the last character.
  if (buffer !== 0) return null;
  return out;
}
