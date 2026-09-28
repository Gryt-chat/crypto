/**
 * Crockford base32, shared by the recovery key and pairing so they can't drift apart.
 * No I, L, O or U, so nothing on screen or paper reads as two different characters.
 */

export const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const LOOKUP = new Map<string, number>();
for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) LOOKUP.set(CROCKFORD_ALPHABET[i], i);

/** Upper case, no spaces or dashes, and Crockford's forgiving reads for typed text. */
export function normalizeCrockford(text: string): string {
  return text.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
}

/** Big-endian, padded with zero bits at the end. */
export function crockfordEncode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD_ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += CROCKFORD_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/**
 * Exactly `byteLength` bytes back from canonical text, or null. The padding bits have to be
 * zero, so each byte string has one spelling and a typo in the last character is caught.
 */
export function crockfordDecode(text: string, byteLength: number): Uint8Array | null {
  if (text.length !== Math.ceil((byteLength * 8) / 5)) return null;

  const out = new Uint8Array(byteLength);
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of text) {
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
  if (buffer !== 0) return null;
  return out;
}
