/**
 * base64url, without `btoa` and `atob`: `btoa` is not safe on Hermes above `0x7f`, and this
 * package runs on both clients. Byte-identical to what `btoa` produced, and pinned.
 */

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function base64Url(bytes: Uint8Array): string {
  let out = "";

  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const c = i + 2 < bytes.length ? bytes[i + 2] : undefined;

    out += ALPHABET[a >> 2];
    out += ALPHABET[((a & 0x03) << 4) | ((b ?? 0) >> 4)];
    if (b === undefined) break;
    out += ALPHABET[((b & 0x0f) << 2) | ((c ?? 0) >> 6)];
    if (c === undefined) break;
    out += ALPHABET[c & 0x3f];
  }

  // Unpadded, which is what base64url means in a JWT.
  return out;
}

const LOOKUP = new Map<string, number>();
for (let i = 0; i < ALPHABET.length; i++) LOOKUP.set(ALPHABET[i], i);

/**
 * Takes either alphabet, padded or not. Both shapes turn up: a binding is
 * unpadded, and the callers disagreed before they shared a decoder.
 */
export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  const clean = value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));

  let bits = 0;
  let acc = 0;
  let written = 0;

  for (const ch of clean) {
    const digit = LOOKUP.get(ch);
    if (digit === undefined) throw new Error("Not base64url");
    acc = (acc << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = (acc >> bits) & 0xff;
    }
  }

  return out.subarray(0, written) as Uint8Array<ArrayBuffer>;
}
