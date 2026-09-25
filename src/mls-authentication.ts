/**
 * The `AuthenticationService` ts-mls asks about every leaf, whether it arrives in a KeyPackage,
 * a Welcome's tree or a commit. A leaf that fails here never gets into the group.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import type { AuthenticationService, Credential } from "ts-mls";

import { base64Url } from "./base64";
import { type DeviceCertificate, readDeviceCertificate } from "./mls-device-certificate";
import type { IdentityScope } from "./scope";

/**
 * Whether this person key is one you'll talk to here: bound by the member's identity and
 * matching the pin. The client answers it; this package has no pins of its own for it yet.
 */
export type TrustPersonKey = (certificate: DeviceCertificate) => boolean | Promise<boolean>;

/** A join checks every leaf, so certificates are verified once and remembered by hash. */
const VERIFIED_LIMIT = 4096;
const verified = new Map<string, DeviceCertificate>();

function readCached(identity: Uint8Array, scope: IdentityScope): DeviceCertificate {
  const key = `${scope} ${base64Url(sha256(identity))}`;
  const hit = verified.get(key);
  if (hit) return hit;
  const certificate = readDeviceCertificate(identity, scope);
  if (verified.size >= VERIFIED_LIMIT) verified.delete(verified.keys().next().value as string);
  verified.set(key, certificate);
  return certificate;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** The device certificate a credential carries, if it has one that checks out for `scope`. */
export function deviceCertificateOf(credential: Credential, scope: IdentityScope): DeviceCertificate | null {
  if (credential.credentialType !== "basic") return null;
  try {
    const c = readCached(credential.identity, scope);
    // Copies, so a caller writing into one can't change what the cache vouches for.
    return { ...c, personPublicKey: c.personPublicKey.slice(), leafSignatureKey: c.leafSignatureKey.slice() };
  } catch {
    return null;
  }
}

/**
 * Three things, all required: the certificate is signed by its person key for this server, it
 * names this leaf's signature key, and `trustPersonKey` says yes. Only the first is cached.
 */
export function createMlsAuthenticationService({
  scope,
  trustPersonKey,
}: {
  scope: IdentityScope;
  trustPersonKey: TrustPersonKey;
}): AuthenticationService {
  return {
    async validateCredential(credential, signaturePublicKey) {
      const certificate = deviceCertificateOf(credential, scope);
      if (!certificate) return false;
      if (!sameBytes(certificate.leafSignatureKey, signaturePublicKey)) return false;
      try {
        return (await trustPersonKey(certificate)) === true;
      } catch {
        return false;
      }
    },
  };
}
