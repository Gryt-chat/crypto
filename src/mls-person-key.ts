/**
 * The person key: Ed25519, one per server, from the seed, and the same on all your devices.
 * It signs your device certificates and never goes into an MLS tree (mls-design.md, 1).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url, base64UrlDecode } from "./base64";
import { asIdentityScope, type IdentityScope } from "./scope";
import { assertUsableSeed } from "./seed-words";
import { jwkThumbprint } from "./thumbprint";

/** Its own label, so no other key shares these bytes. Changing it changes every person key. */
const DERIVATION_SALT = "gryt-mls-person-v1";

/** The binding's `iss`. A DM key binding can't be passed off as one of these, or back. */
const BINDING_ISSUER = "gryt:mls-person-key";

export interface PersonKeyPair {
  /** The 32-byte Ed25519 seed. Never leaves the device, and can always be derived again. */
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface VerifiedPersonKeyBinding {
  personPublicKey: Uint8Array<ArrayBuffer>;
  /** The identity key that signed it, as a JWK thumbprint. This is what gets pinned. */
  identityThumbprint: string;
  scope: IdentityScope;
  /** Seconds since the epoch. */
  signedAt: number;
}

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>;
}

/** Deterministic, like `deriveDmKeyPair`: the 24 words give back the same person on each server. */
export function derivePersonKeyPair(seed: Uint8Array, scope: IdentityScope): PersonKeyPair {
  assertUsableSeed(seed);
  const privateKey = hkdf(sha256, seed, utf8(DERIVATION_SALT), utf8(scope), 32);
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

/** The identity you joined with says the person key is yours. No expiry, like the DM binding. */
export async function signPersonKeyBinding({
  personPublicKey,
  scope,
  identityPrivateKey,
  identityPublicJwk,
  now = Math.floor(Date.now() / 1000),
}: {
  personPublicKey: Uint8Array;
  scope: IdentityScope;
  /** A WebCrypto key on the desktop, a signing function on React Native. */
  identityPrivateKey: CryptoKey | ((bytes: Uint8Array) => Promise<Uint8Array>);
  identityPublicJwk: JsonWebKey;
  now?: number;
}): Promise<string> {
  if (personPublicKey.length !== 32) throw new Error("A person key is 32 bytes.");
  const header = { alg: "ES256", typ: "JWT", jwk: identityPublicJwk };
  const payload = { iss: BINDING_ISSUER, scope, person: base64Url(personPublicKey), iat: now };
  const signingInput = `${base64Url(utf8(JSON.stringify(header)))}.${base64Url(
    utf8(JSON.stringify(payload)),
  )}`;

  const bytes = utf8(signingInput);
  const signature =
    typeof identityPrivateKey === "function"
      ? await identityPrivateKey(bytes)
      : new Uint8Array(
          await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identityPrivateKey, bytes),
        );
  return `${signingInput}.${base64Url(signature)}`;
}

/** The same checks as `verifyDmKeyBinding`, under a different issuer. Throws on anything wrong. */
export async function verifyPersonKeyBinding(
  binding: string,
  expectedScope: IdentityScope,
): Promise<VerifiedPersonKeyBinding> {
  const parts = binding.split(".");
  if (parts.length !== 3) throw new Error("A person key binding is a compact JWT with three parts.");

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
  } catch {
    throw new Error("That person key binding is not readable.");
  }

  if (header.alg !== "ES256" || header.typ !== "JWT") {
    throw new Error("A person key binding is ES256, and this one says otherwise.");
  }
  const jwk = header.jwk as Record<string, unknown> | undefined;
  if (!jwk || typeof jwk !== "object") throw new Error("That person key binding carries no key.");
  if (jwk.d !== undefined) throw new Error("That person key binding carries private key material.");
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("A person key binding is signed with a P-256 key.");
  }

  if (payload.iss !== BINDING_ISSUER) throw new Error(`A person key binding is issued by ${BINDING_ISSUER}.`);
  if (payload.scope !== expectedScope) {
    throw new Error("That person key binding was signed for a different server.");
  }
  if (typeof payload.person !== "string" || typeof payload.iat !== "number") {
    throw new Error("That person key binding is missing a key or a time.");
  }

  const x = base64UrlDecode(jwk.x);
  const y = base64UrlDecode(jwk.y);
  const signature = base64UrlDecode(parts[2]);
  if (x.length !== 32 || y.length !== 32 || signature.length !== 64) {
    throw new Error("That person key binding's key or signature is the wrong length.");
  }
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 33);

  // `lowS: false` because about half of honest ES256 signatures have a high s.
  const ok = p256.verify(signature, sha256(utf8(`${parts[0]}.${parts[1]}`)), point, {
    prehash: false,
    lowS: false,
  });
  if (!ok) throw new Error("That person key binding's signature does not check out.");

  const personPublicKey = base64UrlDecode(payload.person);
  if (personPublicKey.length !== 32) throw new Error("A person key is 32 bytes.");

  return {
    personPublicKey,
    identityThumbprint: jwkThumbprint(jwk as JsonWebKey),
    scope: asIdentityScope(payload.scope as string),
    signedAt: payload.iat,
  };
}
