import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url } from "./base64";

/**
 * A JWK thumbprint, RFC 7638, for the EC public keys Gryt uses. Byte-identical
 * to the client's `server-pins.ts` version. `@noble/hashes` rather than
 * `crypto.subtle`, so it runs on React Native and synchronously (GRYT-733).
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

  // Only these four, lexicographic, no whitespace. Adding `ext` or `key_ops`
  // gives one key two thumbprints depending on where it came from.
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });

  return base64Url(sha256(new TextEncoder().encode(canonical) as Uint8Array<ArrayBuffer>));
}

