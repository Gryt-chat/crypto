import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url } from "./base64";

/**
 * A JWK thumbprint, RFC 7638, for the EC public keys Gryt uses.
 *
 * Copied out of the client's `server-pins.ts` rather than imported, because
 * that module is about pinning *servers* and this package has no business
 * knowing about those. The bytes are identical: the same canonical JSON with
 * the members in lexicographic order, SHA-256, base64url.
 *
 * `@noble/hashes` rather than `crypto.subtle.digest`, so it runs on React
 * Native (GRYT-733) — and synchronous, which the WebCrypto version could not be.
 */
export function jwkThumbprint(jwk: {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
}): string {
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

