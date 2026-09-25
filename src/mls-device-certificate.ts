/**
 * A device certificate: the person key vouching for one device's MLS leaf key. Its bytes are
 * the identity in that leaf's `basic` credential (mls-design.md, section 1, decision 2).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";

import { base64Url, base64UrlDecode } from "./base64";
import { asIdentityScope, type IdentityScope } from "./scope";

/** Signed ahead of the body, so these bytes can't pass as any other Ed25519 statement. */
const SIGNATURE_CONTEXT = "gryt-mls-device-certificate-v1";

const FORMAT_VERSION = 1;
const DEVICE_ID_BYTES = 16;
/** In UTF-8 bytes. Long enough for "Sivert's MacBook Pro", short enough to sit in every tree. */
export const MAX_DEVICE_NAME_BYTES = 64;
const MAX_SCOPE_BYTES = 1024;

export interface DeviceCertificate {
  scope: IdentityScope;
  /** Ed25519, from `derivePersonKeyPair`. Whoever holds the seed. */
  personPublicKey: Uint8Array;
  /** The leaf's Ed25519 signature key, random and kept on this device only. */
  leafSignatureKey: Uint8Array;
  /** 16 random bytes as base64url. Names the device across every group on this server. */
  deviceId: string;
  deviceName: string;
  /** Seconds since the epoch. */
  signedAt: number;
}

/** A fresh leaf signature key. Random on purpose: from the seed, every device would be the same leaf. */
export function generateDeviceSignatureKeyPair(): { signKey: Uint8Array; publicKey: Uint8Array } {
  const signKey = ed25519.utils.randomSecretKey();
  return { signKey, publicKey: ed25519.getPublicKey(signKey) };
}

export function generateDeviceId(): string {
  return base64Url(randomBytes(DEVICE_ID_BYTES));
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function u16(n: number): Uint8Array {
  return new Uint8Array([n >>> 8, n & 0xff]);
}

function u64(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("A certificate time is a whole number of seconds.");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** version, scope, person key, leaf key, device id, name, time; lengths where they vary. */
function encodeBody(c: DeviceCertificate): Uint8Array {
  const scope = utf8(c.scope);
  const name = utf8(c.deviceName);
  const deviceId = base64UrlDecode(c.deviceId);
  if (scope.length === 0 || scope.length > MAX_SCOPE_BYTES) throw new Error("That scope is empty or too long.");
  if (name.length === 0 || name.length > MAX_DEVICE_NAME_BYTES) {
    throw new Error(`A device name is 1 to ${MAX_DEVICE_NAME_BYTES} bytes of UTF-8.`);
  }
  if (deviceId.length !== DEVICE_ID_BYTES || base64Url(deviceId) !== c.deviceId) {
    throw new Error(`A device id is ${DEVICE_ID_BYTES} bytes, as unpadded base64url.`);
  }
  if (c.personPublicKey.length !== 32 || c.leafSignatureKey.length !== 32) {
    throw new Error("A person key and a leaf key are 32 bytes each.");
  }
  return concat(
    new Uint8Array([FORMAT_VERSION]),
    u16(scope.length),
    scope,
    c.personPublicKey,
    c.leafSignatureKey,
    deviceId,
    new Uint8Array([name.length]),
    name,
    u64(c.signedAt),
  );
}

/** Returns the bytes that go in the credential. The person key has to match `personPrivateKey`. */
export function signDeviceCertificate({
  personPrivateKey,
  scope,
  leafSignatureKey,
  deviceId,
  deviceName,
  now = Math.floor(Date.now() / 1000),
}: {
  personPrivateKey: Uint8Array;
  scope: IdentityScope;
  leafSignatureKey: Uint8Array;
  deviceId: string;
  deviceName: string;
  now?: number;
}): Uint8Array {
  const personPublicKey = ed25519.getPublicKey(personPrivateKey);
  const body = encodeBody({ scope, personPublicKey, leafSignatureKey, deviceId, deviceName, signedAt: now });
  const signature = ed25519.sign(concat(utf8(SIGNATURE_CONTEXT), body), personPrivateKey);
  return concat(body, signature);
}

/**
 * Decode and check the person key's signature, throwing on anything wrong. Says nothing about
 * whose person key it is: that's the binding and the pin, in the `AuthenticationService`.
 */
export function readDeviceCertificate(bytes: Uint8Array, expectedScope: IdentityScope): DeviceCertificate {
  let offset = 0;
  const take = (n: number) => {
    if (offset + n > bytes.length) throw new Error("That device certificate is cut short.");
    const out = bytes.slice(offset, offset + n);
    offset += n;
    return out;
  };

  if (take(1)[0] !== FORMAT_VERSION) throw new Error("That device certificate is a format this version can't read.");
  const scopeLength = new DataView(take(2).buffer).getUint16(0);
  if (scopeLength === 0 || scopeLength > MAX_SCOPE_BYTES) throw new Error("That device certificate's scope is empty or too long.");
  const scope = new TextDecoder("utf-8", { fatal: true }).decode(take(scopeLength));
  const personPublicKey = take(32);
  const leafSignatureKey = take(32);
  const deviceId = base64Url(take(DEVICE_ID_BYTES));
  const nameLength = take(1)[0];
  if (nameLength === 0 || nameLength > MAX_DEVICE_NAME_BYTES) throw new Error("That device certificate's name is empty or too long.");
  const deviceName = new TextDecoder("utf-8", { fatal: true }).decode(take(nameLength));
  const signedAt = Number(new DataView(take(8).buffer).getBigUint64(0));
  const bodyLength = offset;
  const signature = take(64);
  if (offset !== bytes.length) throw new Error("That device certificate has bytes after the signature.");

  if (scope !== expectedScope) throw new Error("That device certificate was signed for a different server.");
  const signed = concat(utf8(SIGNATURE_CONTEXT), bytes.subarray(0, bodyLength));
  let ok = false;
  try {
    ok = ed25519.verify(signature, signed, personPublicKey, { zip215: false });
  } catch {
    ok = false;
  }
  if (!ok) throw new Error("That device certificate's signature does not check out.");
  if (!Number.isSafeInteger(signedAt)) throw new Error("That device certificate's time is out of range.");

  return { scope: asIdentityScope(scope), personPublicKey, leafSignatureKey, deviceId, deviceName, signedAt };
}
