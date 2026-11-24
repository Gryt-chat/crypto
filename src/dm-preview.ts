import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

import { base64Url, base64UrlDecode } from "./base64";

/* A DM's notification line, sealed by the sender to one recipient phone, which the server can't
   read (GRYT-2275). 0x02 | ephemeral X25519 (32) | nonce (12) | AES-256-GCM ciphertext and tag, base64url. */
const VERSION = 2;
const INFO = "gryt-dm-preview-1";
const KEY_STATEMENT = "gryt-dm-preview-key-1";

/** What the notification shows: who and the first line, and where a tap lands. */
export interface DmPreview {
  t: string;
  b: string;
  /** The conversation, so tapping opens it. */
  o?: string;
  m?: string;
}

const utf8 = (s: string) => new TextEncoder().encode(s);
const join = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

export function generateDmPreviewKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

function sealKey(shared: Uint8Array, ephemeral: Uint8Array, recipient: Uint8Array): Uint8Array {
  return hkdf(sha256, shared, join(ephemeral, recipient), utf8(INFO), 32);
}

export function sealDmPreview(
  recipientPublicKey: Uint8Array,
  deviceId: string,
  preview: DmPreview,
  random: (n: number) => Uint8Array = randomBytes,
): string {
  const ephemeralPrivate = random(32);
  const ephemeral = x25519.getPublicKey(ephemeralPrivate);
  const key = sealKey(x25519.getSharedSecret(ephemeralPrivate, recipientPublicKey), ephemeral, recipientPublicKey);
  const nonce = random(12);
  const sealed = gcm(key, nonce, utf8(`${INFO}|${deviceId}`)).encrypt(utf8(JSON.stringify(preview)));
  return base64Url(join(Uint8Array.of(VERSION), ephemeral, nonce, sealed));
}

/** Null for anything that isn't a preview sealed to this key for this device. */
export function openDmPreview(privateKey: Uint8Array, deviceId: string, blob: string): DmPreview | null {
  try {
    const raw = base64UrlDecode(blob);
    if (raw.length < 1 + 32 + 12 + 16 || raw[0] !== VERSION) return null;
    const ephemeral = raw.subarray(1, 33);
    const key = sealKey(x25519.getSharedSecret(privateKey, ephemeral), ephemeral, x25519.getPublicKey(privateKey));
    const plain = gcm(key, raw.subarray(33, 45), utf8(`${INFO}|${deviceId}`)).decrypt(raw.subarray(45));
    const p = JSON.parse(new TextDecoder().decode(plain)) as Partial<DmPreview>;
    if (typeof p.t !== "string" || typeof p.b !== "string") return null;
    return { t: p.t, b: p.b, ...(typeof p.o === "string" ? { o: p.o } : {}), ...(typeof p.m === "string" ? { m: p.m } : {}) };
  } catch {
    return null;
  }
}

/* What a phone signs with its MLS device key, so a sender only seals to a key that device chose. */
function keyStatement(deviceId: string, previewPublicKey: Uint8Array): Uint8Array {
  return join(utf8(`${KEY_STATEMENT}|${deviceId}|`), previewPublicKey);
}

export function signDmPreviewKey(deviceSignKey: Uint8Array, deviceId: string, previewPublicKey: Uint8Array): string {
  return base64Url(ed25519.sign(keyStatement(deviceId, previewPublicKey), deviceSignKey));
}

export function verifyDmPreviewKey(
  deviceSignaturePublicKey: Uint8Array,
  deviceId: string,
  previewPublicKey: Uint8Array,
  signature: string,
): boolean {
  try {
    return ed25519.verify(base64UrlDecode(signature), keyStatement(deviceId, previewPublicKey), deviceSignaturePublicKey);
  } catch {
    return false;
  }
}
