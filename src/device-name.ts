/**
 * A device's name, sealed so only devices holding the same seed can read it. The identity
 * service stores the result without being able to open it.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";

import { base64Url, base64UrlDecode } from "./base64";

/** Longest name, in UTF-8 bytes. The sealed form is then at most 123 base64url characters. */
export const DEVICE_NAME_MAX_BYTES = 64;
const NONCE_BYTES = 12;
const AAD = new TextEncoder().encode("gryt device name v1");

const nameKey = (seed: Uint8Array) => hkdf(sha256, seed, AAD, new Uint8Array(0), 32);

function fit(name: string): Uint8Array {
  const bytes = new TextEncoder().encode(name.trim());
  if (bytes.length <= DEVICE_NAME_MAX_BYTES) return bytes;
  let chars = [...name.trim()];
  while (new TextEncoder().encode(chars.join("")).length > DEVICE_NAME_MAX_BYTES) chars = chars.slice(0, -1);
  return new TextEncoder().encode(chars.join(""));
}

/** Seals `name` under a fresh nonce. Trimmed and cut to 64 bytes on a character boundary. */
export function sealDeviceName(seed: Uint8Array, name: string, nonce: Uint8Array = randomBytes(NONCE_BYTES)): string {
  if (nonce.length !== NONCE_BYTES) throw new Error("A device name nonce is 12 bytes.");
  return base64Url(concatBytes(nonce, gcm(nameKey(seed), nonce, AAD).encrypt(fit(name))));
}

/** The name, or null when it wasn't sealed with this seed or was changed. */
export function openDeviceName(seed: Uint8Array, sealed: string): string | null {
  try {
    const bytes = base64UrlDecode(sealed);
    if (bytes.length < NONCE_BYTES + 16) return null;
    const plain = gcm(nameKey(seed), bytes.subarray(0, NONCE_BYTES), AAD).decrypt(bytes.subarray(NONCE_BYTES));
    return new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    return null;
  }
}
