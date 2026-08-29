/**
 * What a per-server key is derived under.
 *
 * A branded string rather than a comment, because `derive(seed, host)` and
 * `derive(seed, scope)` are the same call to a type checker and the difference
 * only shows up when somebody's server moves — at which point every message
 * encrypted to the old key is unreadable and nothing says why (GRYT-719).
 *
 * The two clients disagree about what a scope *is*, and that is deliberate. On
 * the desktop it is the server's lineage id, from the pin, so a server that
 * changes address stays the same server. Mobile still files its identity under
 * the address (GRYT-517) and passes the lineage in here anyway, because a DM key
 * has no history to migrate and should not inherit that one.
 *
 * Which is exactly why this package takes the scope rather than working it out:
 * where it comes from is the caller's business, and it is not the same business
 * on both.
 */
export type IdentityScope = string & { readonly __identityScope: unique symbol };

/**
 * Say that a string is a scope.
 *
 * The brand has to be mintable somewhere or nothing could call these functions.
 * Keeping it to one named function means every scope is somewhere a person
 * wrote down that they meant one.
 *
 * It checks nothing and cannot: a scope is legitimately a bare address for a
 * server that offered no proof, so "looks like a host" is not a signal. What it
 * buys is that `deriveDmKeyPair(seed, host)` does not compile.
 */
export function asIdentityScope(value: string): IdentityScope {
  return value as IdentityScope;
}
