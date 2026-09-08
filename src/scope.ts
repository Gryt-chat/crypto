/**
 * What a per-server key is derived under. Branded, because the difference only shows up when
 * a server moves and every message encrypted to the old key is unreadable (GRYT-719).
 */
export type IdentityScope = string & { readonly __identityScope: unique symbol };

/**
 * Say that a string is a scope. Checks nothing and cannot — a bare address is legitimate for
 * a server that proved nothing. What it buys is that `deriveDmKeyPair(seed, host)` fails.
 */
export function asIdentityScope(value: string): IdentityScope {
  return value as IdentityScope;
}
