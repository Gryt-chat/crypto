/**
 * What a per-server key is derived under.
 *
 * Branded because `derive(seed, host)` and `derive(seed, scope)` are the same
 * call to a type checker, and the difference only shows up when a server moves
 * — at which point every message encrypted to the old key is unreadable and
 * nothing says why (GRYT-719).
 *
 * The caller supplies it because the two clients disagree about what it is:
 * desktop uses the lineage id from the pin, mobile still files its identity
 * under the address (GRYT-517) and passes the lineage in anyway.
 */
export type IdentityScope = string & { readonly __identityScope: unique symbol };

/**
 * Say that a string is a scope. Checks nothing and cannot — a bare address is a
 * legitimate scope for a server that proved nothing. What it buys is that
 * `deriveDmKeyPair(seed, host)` does not compile.
 */
export function asIdentityScope(value: string): IdentityScope {
  return value as IdentityScope;
}
