/**
 * base64url, without `btoa` and `atob`.
 *
 * Every module here used to carry its own two-line pair built on the host's
 * base64: a string assembled one `String.fromCharCode` at a time, handed to
 * `btoa`. That is fine in a browser and it is what the client did for a year.
 *
 * It is not safe on Hermes, and the mobile app's own `encoding.ts` says so in a
 * comment written by somebody who hit it — a byte above `0x7f` and the engine's
 * idea of a binary string stops matching yours. This package exists so the two
 * clients run one implementation, so it cannot be the one that only works on
 * one of them. Bytes in, ASCII out, no globals involved.
 *
 * Byte-for-byte identical to what `btoa` produced. `check-crypto-vectors.mjs`
 * holds envelopes from before this file existed and is what says so.
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
 * Takes either alphabet and padding or none of it.
 *
 * The callers disagreed about this before they shared a decoder: one stripped
 * `+/` into `-_` and passed whatever padding arrived to `atob`, the other did
 * not. Both shapes turn up — a binding is unpadded and a wrapped key is written
 * by this file — so accepting both is the honest reading rather than a
 * convenience.
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
