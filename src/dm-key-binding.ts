/**
 * Saying that a DM key and an identity key belong to the same person (GRYT-720).
 *
 * A short JWT, signed by the per-server identity key: "this DM public key is
 * mine, on this server". Without it a server that wanted to read a conversation
 * could give each side its own key and relay.
 *
 * It proves that whoever holds the identity key also chose this DM key, and
 * **not** whose identity key it is — the public half rides in the header, so a
 * server can mint a keypair and sign a valid binding with it. What it buys is
 * that the two keys become one thing to substitute instead of two, and the
 * identity key is the one the server challenged at join. The caller pins
 * {@link VerifiedDmKeyBinding.identityThumbprint}; that is the part that means
 * something, and `server-pins.ts` does the same three moves for server keys.
 *
 * The key lives inside the signed statement rather than beside it, so a server
 * cannot serve one person's key with another's signature. It is read out after
 * the signature verifies or not at all.
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url, base64UrlDecode } from "./base64";
import { asIdentityScope, type IdentityScope } from "./scope";
import { jwkThumbprint } from "./thumbprint";

/**
 * The `iss` a binding carries.
 *
 * Constant rather than the signer's own id, because a binding is not addressed
 * to a server and has no subject to name. What it is *for* is the thing worth
 * writing down, so a JWT that arrives on this path and says something else is
 * refused rather than read hopefully.
 */
const BINDING_ISSUER = "gryt:dm-key";

export interface VerifiedDmKeyBinding {
  /** The X25519 public key, raw bytes, once the signature has been checked. */
  dmPublicKey: Uint8Array<ArrayBuffer>;
  /**
   * The identity key that signed this, as a JWK thumbprint.
   *
   * **This is the thing to pin.** Everything else in here is a statement by
   * whoever holds that key, and is worth exactly what the key is worth.
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
 * Sign the statement. No expiry: the DM key does not roll, and an expiry a
 * client cannot renew offline would make old messages unreadable for a reason
 * that has nothing to do with anybody's keys.
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
 * Check a binding. Throws on anything wrong rather than returning something
 * partly checked.
 *
 * `expectedScope` is required: without it a binding signed for one server can
 * be replayed by another, which is the cheapest attack available to an operator
 * who can see a member list.
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
   * Curve library, not `crypto.subtle`, which React Native lacks (GRYT-733).
   * Same bytes either way: ES256 is P-256 over SHA-256 with a raw 64-byte
   * `r || s`.
   */
  const publicKey = jwkToPoint(jwk as Record<string, unknown>);
  const signature = base64UrlDecode(parts[2]);
  if (signature.length !== 64) {
    throw new Error("A DM key binding's signature is 64 bytes.");
  }

  /*
   * `lowS: false` is not a relaxation. Noble refuses high-`s` signatures by
   * default for blockchain replay reasons that do not apply here, WebCrypto
   * does not normalise, and about half of all ES256 signatures come out high —
   * so the default would reject half of every client's bindings at random.
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
