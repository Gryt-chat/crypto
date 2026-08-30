/**
 * The one thing GRYT-719 changed, asserted where a type checker can see it.
 *
 * `deriveDmKeyPair(seed, host)` and `deriveDmKeyPair(seed, scope)` are the same
 * call to read, and the difference only shows up when somebody's server changes
 * address — at which point every message encrypted to the old key is unreadable
 * and nothing says why. So the brand exists, and this is what proves it is still
 * doing its job.
 *
 * `@ts-expect-error` is the assertion. If `IdentityScope` ever collapses back to
 * `string`, these lines stop erroring, `tsc` reports the directive as unused,
 * and `npm run typecheck` fails. There is no runtime here to check:
 * `scripts/check-dm-keys.mjs` cannot see a type.
 *
 * Outside `src` so it is typechecked and never built. It moved here from the
 * client in GRYT-732, along with the brand it is about. The client keeps its own
 * copy for `deriveLocalKeyPair`, which stayed there.
 */

import { deriveDmKeyPair, dmPublicKey } from "../src/dm-keys";
import { asIdentityScope } from "../src/scope";

const seed = new Uint8Array(32).fill(1);
const scope = asIdentityScope("srv:abc123");
const host = "chat.example.invalid";

/* A scope is accepted, which is the whole point of having one. */
export const derivedDm = () => deriveDmKeyPair(seed, scope);
export const derivedPublic = () => dmPublicKey(seed, scope);

/* An address is not. */
// @ts-expect-error a DM key must not be derived from an address (GRYT-719)
export const dmFromHost = () => deriveDmKeyPair(seed, host);
// @ts-expect-error the public half is the same derivation, so the same rule
export const publicFromHost = () => dmPublicKey(seed, host);
