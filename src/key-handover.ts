/**
 * A key handover (GRYT-1876): your old identity key says "my new identity is this one", so the
 * people who pinned the old key can move the pin without asking you to prove it by hand.
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url, base64UrlDecode } from "./base64";
import type { IdentityScope } from "./scope";
import { jwkThumbprint } from "./thumbprint";

/** Its own `iss`, so a DM key or person key binding can't be passed off as a handover. */
const HANDOVER_ISSUER = "gryt:key-handover";

/** A chain longer than this is somebody walking in circles, not a person changing devices. */
const MAX_CHAIN = 16;

export interface VerifiedKeyHandover {
  /** The identity key that signed it, as a JWK thumbprint: the one being left. */
  fromThumbprint: string;
  /** The identity it hands over to. */
  toThumbprint: string;
  scope: IdentityScope;
  signedAt: number;
}

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>;
}

/** Signed with the identity key being left, for one server. */
export async function signKeyHandover({
  scope,
  oldIdentityPrivateKey,
  oldIdentityPublicJwk,
  newIdentityPublicJwk,
  now = Math.floor(Date.now() / 1000),
}: {
  scope: IdentityScope;
  /** A WebCrypto key on the desktop, a signing function on React Native. */
  oldIdentityPrivateKey: CryptoKey | ((bytes: Uint8Array) => Promise<Uint8Array>);
  oldIdentityPublicJwk: JsonWebKey;
  newIdentityPublicJwk: JsonWebKey;
  now?: number;
}): Promise<string> {
  const from = jwkThumbprint(oldIdentityPublicJwk);
  const to = jwkThumbprint(newIdentityPublicJwk);
  if (from === to) throw new Error("A handover is from one identity to another.");
  const header = { alg: "ES256", typ: "JWT", jwk: oldIdentityPublicJwk };
  const payload = { iss: HANDOVER_ISSUER, scope, to, iat: now };
  const signingInput = `${base64Url(utf8(JSON.stringify(header)))}.${base64Url(utf8(JSON.stringify(payload)))}`;
  const bytes = utf8(signingInput);
  const signature =
    typeof oldIdentityPrivateKey === "function"
      ? await oldIdentityPrivateKey(bytes)
      : new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, oldIdentityPrivateKey, bytes));
  return `${signingInput}.${base64Url(signature)}`;
}

/** Throws on anything wrong, like the bindings' verifiers. */
export function verifyKeyHandover(handover: string, expectedScope: IdentityScope): VerifiedKeyHandover {
  const parts = handover.split(".");
  if (parts.length !== 3) throw new Error("A key handover is a compact JWT with three parts.");
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
  } catch {
    throw new Error("That key handover is not readable.");
  }
  if (header.alg !== "ES256" || header.typ !== "JWT") throw new Error("A key handover is ES256.");
  const jwk = header.jwk as Record<string, unknown> | undefined;
  if (!jwk || typeof jwk !== "object" || jwk.d !== undefined) throw new Error("That key handover carries no usable public key.");
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("A key handover is signed with a P-256 key.");
  }
  if (payload.iss !== HANDOVER_ISSUER) throw new Error(`A key handover is issued by ${HANDOVER_ISSUER}.`);
  if (payload.scope !== expectedScope) throw new Error("That key handover was signed for a different server.");
  if (typeof payload.to !== "string" || typeof payload.iat !== "number") throw new Error("That key handover is missing who it's for.");

  const x = base64UrlDecode(jwk.x);
  const y = base64UrlDecode(jwk.y);
  const signature = base64UrlDecode(parts[2]);
  if (x.length !== 32 || y.length !== 32 || signature.length !== 64) throw new Error("That key handover's key or signature is the wrong length.");
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 33);
  // `lowS: false` because about half of honest ES256 signatures have a high s.
  const ok = p256.verify(signature, sha256(utf8(`${parts[0]}.${parts[1]}`)), point, { prehash: false, lowS: false });
  if (!ok) throw new Error("That key handover's signature does not check out.");

  const fromThumbprint = jwkThumbprint(jwk as JsonWebKey);
  if (fromThumbprint === payload.to) throw new Error("A handover is from one identity to another.");
  return { fromThumbprint, toThumbprint: payload.to, scope: expectedScope, signedAt: payload.iat };
}

/**
 * Whether `handovers` lead from the pinned identity to the new one. Unreadable ones are skipped.
 * An identity that handed over to two different keys stops the chain: one of them isn't you.
 */
export function keyHandoverChain(
  handovers: readonly string[],
  scope: IdentityScope,
  fromThumbprint: string,
  toThumbprint: string,
): boolean {
  const next = new Map<string, Set<string>>();
  for (const h of handovers) {
    let v: VerifiedKeyHandover;
    try {
      v = verifyKeyHandover(h, scope);
    } catch {
      continue;
    }
    next.set(v.fromThumbprint, (next.get(v.fromThumbprint) ?? new Set()).add(v.toThumbprint));
  }
  let at = fromThumbprint;
  for (let step = 0; step < MAX_CHAIN; step++) {
    const targets = next.get(at);
    if (!targets || targets.size !== 1) return false;
    at = [...targets][0];
    if (at === toThumbprint) return true;
  }
  return false;
}
