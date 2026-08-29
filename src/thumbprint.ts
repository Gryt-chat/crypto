import { sha256 } from "@noble/hashes/sha2.js";

/**
 * A JWK thumbprint, RFC 7638, for the EC public keys Gryt uses.
 *
 * Copied out of the client's `server-pins.ts` rather than imported, because
 * that module is about pinning *servers* and this package has no business
 * knowing about those. The bytes are identical: the same canonical JSON with
 * the members in lexicographic order, SHA-256, base64url.
 *
 * `@noble/hashes` rather than `crypto.subtle.digest`, so it runs on React
 * Native (GRYT-733).
 */
export async function jwkThumbprint(jwk: {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
}): Promise<string> {
  if (jwk.kty !== "EC" || !jwk.crv || !jwk.x || !jwk.y) {
    throw new Error("Not an EC public JWK");
  }

  // Lexicographic, and only these four. RFC 7638 says a thumbprint is over the
  // required members with no whitespace — adding `ext` or `key_ops` would give
  // the same key two different thumbprints depending on where it came from.
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });

  return base64Url(sha256(new TextEncoder().encode(canonical) as Uint8Array<ArrayBuffer>));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
