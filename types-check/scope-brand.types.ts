/**
 * The one thing GRYT-719 changed, asserted where a type checker can see it. `@ts-expect-error`
 * is the assertion: if `IdentityScope` collapses to `string`, `tsc` reports it unused.
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
