/**
 * The account's current key saying "this new key takes over on this server" (GRYT-1886). Without
 * it, anyone signed in to the account could swap the key everyone has pinned.
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url, base64UrlDecode } from "./base64";
import { verifyDmKeyBinding } from "./dm-key-binding";
import type { IdentityScope } from "./scope";
import { jwkThumbprint } from "./thumbprint";

const HANDOVER_ISSUER = "gryt:key-handover";

/** Long enough to approve on a phone, short enough that a note found later is useless. */
export const HANDOVER_TTL_SECONDS = 600;

function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>;
}

const digest = (binding: string) => base64Url(sha256(utf8(binding)));

export async function signKeyHandover({
  newBinding,
  scope,
  identityPrivateKey,
  identityPublicJwk,
  now = Math.floor(Date.now() / 1000),
}: {
  /** The DM key binding that takes over, as the new device published it. */
  newBinding: string;
  scope: IdentityScope;
  /** The current key's identity key: the one that signed the binding being replaced. */
  identityPrivateKey: CryptoKey | ((bytes: Uint8Array) => Promise<Uint8Array>);
  identityPublicJwk: JsonWebKey;
  now?: number;
}): Promise<string> {
  const header = { alg: "ES256", typ: "JWT", jwk: identityPublicJwk };
  const payload = { iss: HANDOVER_ISSUER, scope, to: digest(newBinding), iat: now, exp: now + HANDOVER_TTL_SECONDS };
  const signingInput = `${base64Url(utf8(JSON.stringify(header)))}.${base64Url(utf8(JSON.stringify(payload)))}`;
  const bytes = utf8(signingInput);
  const signature =
    typeof identityPrivateKey === "function"
      ? await identityPrivateKey(bytes)
      : new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identityPrivateKey, bytes));
  return `${signingInput}.${base64Url(signature)}`;
}

/**
 * Throws unless `note` was signed by the identity behind `oldBinding`, for `newBinding`, on
 * this scope, and hasn't expired. Both bindings must also verify on their own.
 */
export async function verifyKeyHandover(
  note: string,
  {
    oldBinding,
    newBinding,
    scope,
    now = Math.floor(Date.now() / 1000),
  }: { oldBinding: string; newBinding: string; scope: IdentityScope; now?: number },
): Promise<void> {
  const old = await verifyDmKeyBinding(oldBinding, scope);
  await verifyDmKeyBinding(newBinding, scope);

  const parts = note.split(".");
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
  if (!jwk || typeof jwk !== "object" || jwk.d !== undefined) throw new Error("That key handover carries no usable key.");
  if (jwkThumbprint(jwk as JsonWebKey) !== old.identityThumbprint) {
    throw new Error("That key handover isn't signed by the key it replaces.");
  }
  if (payload.iss !== HANDOVER_ISSUER) throw new Error(`A key handover is issued by ${HANDOVER_ISSUER}.`);
  if (payload.scope !== scope) throw new Error("That key handover was signed for a different server.");
  if (payload.to !== digest(newBinding)) throw new Error("That key handover is for a different key.");
  if (typeof payload.exp !== "number" || payload.exp < now) throw new Error("That key handover has expired.");

  const x = base64UrlDecode(String(jwk.x ?? ""));
  const y = base64UrlDecode(String(jwk.y ?? ""));
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || x.length !== 32 || y.length !== 32) {
    throw new Error("A key handover is signed with a P-256 key.");
  }
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 33);
  const signature = base64UrlDecode(parts[2]);
  // `lowS: false`, as in the DM key binding: about half of all ES256 signatures are high-s.
  if (signature.length !== 64 || !p256.verify(signature, sha256(utf8(`${parts[0]}.${parts[1]}`)), point, { prehash: false, lowS: false })) {
    throw new Error("That key handover's signature does not check out.");
  }
}
