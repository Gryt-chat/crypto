/**
 * Saying that a DM key and an identity key belong to the same person (GRYT-720). It proves
 * the identity key chose this DM key, not whose identity key it is — pin the thumbprint.
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url, base64UrlDecode } from "./base64";
import { asIdentityScope, type IdentityScope } from "./scope";
import { jwkThumbprint } from "./thumbprint";

/**
 * The `iss` a binding carries: constant rather than the signer's id, because a binding is
 * not addressed to a server. A JWT on this path saying something else is refused.
 */
const BINDING_ISSUER = "gryt:dm-key";

export interface VerifiedDmKeyBinding {
  /** The X25519 public key, raw bytes, once the signature has been checked. */
  dmPublicKey: Uint8Array<ArrayBuffer>;
  /**
   * The identity key that signed this, as a JWK thumbprint. This is the thing to pin:
   * everything else here is a statement by whoever holds that key.
   */
  identityThumbprint: string;
  /** The scope the binding claims, already checked against the expected one. */
  scope: IdentityScope;
  /** When it was signed, seconds since the epoch. */
  signedAt: number;
}

/** A JWK's public point as `0x04 || x || y`, which the curve library takes. */
function jwkToPoint(jwk: Record<string, unknown>): Uint8Array<ArrayBuffer> {
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new Error("A DM key binding is signed with a P-256 key.");
  }
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("That DM key binding's key has no coordinates.");
  }

  const x = base64UrlDecode(jwk.x);
  const y = base64UrlDecode(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new Error("A P-256 coordinate is 32 bytes.");
  }

  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 33);
  return point as Uint8Array<ArrayBuffer>;
}

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>;
}

/**
 * Sign the statement. No expiry: the DM key does not roll, and one a client cannot renew
 * offline would make old messages unreadable for no reason to do with keys.
 */
export async function signDmKeyBinding({
  dmPublicKey,
  scope,
  identityPrivateKey,
  identityPublicJwk,
  now = Math.floor(Date.now() / 1000),
}: {
  dmPublicKey: Uint8Array;
  scope: IdentityScope;
  /**
   * A `CryptoKey`, or a function that signs bytes. Two shapes because the
   * desktop has a WebCrypto handle and React Native has raw bytes (GRYT-733).
   */
  identityPrivateKey: CryptoKey | ((bytes: Uint8Array) => Promise<Uint8Array>);
  /** Rides in the header, so a verifier that has never seen it can check. */
  identityPublicJwk: JsonWebKey;
  now?: number;
}): Promise<string> {
  const header = {
    alg: "ES256",
    typ: "JWT",
    jwk: identityPublicJwk,
  };
  const payload = {
    iss: BINDING_ISSUER,
    scope,
    dm: base64Url(dmPublicKey),
    iat: now,
  };

  const signingInput = `${base64Url(utf8(JSON.stringify(header)))}.${base64Url(
    utf8(JSON.stringify(payload)),
  )}`;

  const bytes = utf8(signingInput);
  const signature =
    typeof identityPrivateKey === "function"
      ? await identityPrivateKey(bytes)
      : new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            identityPrivateKey,
            bytes,
          ),
        );

  return `${signingInput}.${base64Url(signature)}`;
}

/**
 * Check a binding, throwing on anything wrong. `expectedScope` is required: without it a
 * binding signed for one server can be replayed by another.
 */
export async function verifyDmKeyBinding(
  binding: string,
  expectedScope: IdentityScope,
): Promise<VerifiedDmKeyBinding> {
  const parts = binding.split(".");
  if (parts.length !== 3) {
    throw new Error("A DM key binding is a compact JWT with three parts.");
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
  } catch {
    throw new Error("That DM key binding is not readable.");
  }

  // Pinned, not read off the header: `alg: "none"` and its softer variants all
  // start with taking the algorithm from the attacker.
  if (header.alg !== "ES256" || header.typ !== "JWT") {
    throw new Error("A DM key binding is ES256, and this one says otherwise.");
  }

  const jwk = header.jwk;
  if (!jwk || typeof jwk !== "object") {
    throw new Error("That DM key binding carries no key to check it with.");
  }
  if ((jwk as Record<string, unknown>).d !== undefined) {
    throw new Error("That DM key binding carries private key material.");
  }

  if (payload.iss !== BINDING_ISSUER) {
    throw new Error(`A DM key binding is issued by ${BINDING_ISSUER}.`);
  }
  if (payload.scope !== expectedScope) {
    // Replay from another server. The binding is perfectly valid there.
    throw new Error("That DM key binding was signed for a different server.");
  }
  if (typeof payload.dm !== "string" || typeof payload.iat !== "number") {
    throw new Error("That DM key binding is missing a key or a time.");
  }

  /*
   * Curve library, not `crypto.subtle`, which React Native lacks (GRYT-733). Same bytes:
   * ES256 is P-256 over SHA-256 with a raw 64-byte `r || s`.
   */
  const publicKey = jwkToPoint(jwk as Record<string, unknown>);
  const signature = base64UrlDecode(parts[2]);
  if (signature.length !== 64) {
    throw new Error("A DM key binding's signature is 64 bytes.");
  }

  /*
   * `lowS: false` is not a relaxation. Noble refuses high-`s` by default for blockchain
   * reasons; about half of all ES256 signatures are high, so the default rejects half.
   */
  const ok = p256.verify(
    signature,
    sha256(utf8(`${parts[0]}.${parts[1]}`)),
    publicKey,
    { prehash: false, lowS: false },
  );
  if (!ok) {
    throw new Error("That DM key binding's signature does not check out.");
  }

  const dmPublicKey = base64UrlDecode(payload.dm);
  // X25519 public keys are 32 bytes; the curve library would otherwise be the
  // place that found out.
  if (dmPublicKey.length !== 32) {
    throw new Error(
      `A DM public key is 32 bytes, and this one is ${dmPublicKey.length}.`,
    );
  }

  return {
    dmPublicKey,
    identityThumbprint: jwkThumbprint(jwk as JsonWebKey),
    scope: asIdentityScope(payload.scope as string),
    signedAt: payload.iat,
  };
}
