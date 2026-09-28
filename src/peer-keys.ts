/**
 * Trust-on-first-use pinning of the people you talk to (GRYT-726). There is no automatic
 * re-pin, and both halves are compared: a restored seed and a substituted key look alike.
 */

import { base64Url } from "./base64";
import {
  type VerifiedDmKeyBinding,
  verifyDmKeyBinding,
} from "./dm-key-binding";
import type { TrustPersonKey } from "./mls-authentication";
import { type VerifiedPersonKeyBinding, verifyPersonKeyBinding } from "./mls-person-key";
import type { IdentityScope } from "./scope";

/**
 * Synchronous on purpose: an async store would make every read here async and ripple into a
 * member list that is drawn synchronously.
 */
export interface PeerPinStore {
  read(): Record<string, PeerPin>;
  write(pins: Record<string, PeerPin>): void;
}

/** Shared so the two clients do not pick different storage keys. */
export const PEER_PINS_KEY = "peerDmKeyPins";

export interface PeerPin {
  /** The identity key that signed the binding, as a JWK thumbprint. */
  thumbprint: string;
  /** The DM public key it vouched for, base64url. */
  dmPublicKey: string;
  /** Their MLS person key, base64url, bound by the same identity. Absent until one is seen. */
  personPublicKey?: string;
  firstSeenAt: number;
  lastSeenAt: number;
  /**
   * When these keys were compared out of band (GRYT-730). Dropped when the identity or DM key
   * moves; kept when a person key is first recorded, since the compared identity signed it.
   */
  comparedAt?: number;
}

export type PeerKeyDecision =
  /** They have published nothing. Nothing to encrypt to, and nothing wrong. */
  | { kind: "none" }
  /**
   * Something arrived and did not check out. Not the same as a changed key —
   * this is broken rather than plausible, and it never becomes a pin.
   */
  | { kind: "unusable"; reason: string }
  /** Nobody pinned yet. The caller pins this and carries on. */
  | { kind: "first"; verified: VerifiedDmKeyBinding }
  /** The same person and the same keys as last time. */
  | { kind: "known"; verified: VerifiedDmKeyBinding; pin: PeerPin }
  /**
   * Different from what was pinned. Refuse and let somebody decide. Separate flags: a new
   * identity key is a different account, a new DM key is usually a restored seed.
   */
  | {
      kind: "changed";
      pin: PeerPin;
      verified: VerifiedDmKeyBinding;
      changedIdentity: boolean;
      changedKey: boolean;
    };

/**
 * One pin per server and member. The scope is redundant for uniqueness; it is
 * in the key so that forgetting a server forgets the people on it.
 */
function pinKey(scope: IdentityScope, memberId: string): string {
  return `${scope} ${memberId}`;
}

export function listPeerPins(store: PeerPinStore): Record<string, PeerPin> {
  return store.read();
}

export function getPeerPin(
  store: PeerPinStore,
  scope: IdentityScope,
  memberId: string,
): PeerPin | null {
  return store.read()[pinKey(scope, memberId)] ?? null;
}

/**
 * Record what this member's keys are, from here on. Called on `first`, and on `changed` only
 * after somebody has said to. Nothing calls it on `changed` by itself.
 */
export function pinPeerKey(
  store: PeerPinStore,
  scope: IdentityScope,
  memberId: string,
  verified: VerifiedDmKeyBinding,
  now = Date.now(),
): PeerPin {
  const pins = store.read();
  const key = pinKey(scope, memberId);
  const existing = pins[key];

  const sameKeys =
    existing?.thumbprint === verified.identityThumbprint &&
    existing?.dmPublicKey === base64Url(verified.dmPublicKey);

  const pin: PeerPin = {
    thumbprint: verified.identityThumbprint,
    dmPublicKey: base64Url(verified.dmPublicKey),
    // Kept across a deliberate re-pin, so "known since" stays true to when this
    // person was first seen rather than to when they last changed devices.
    firstSeenAt: existing?.firstSeenAt ?? now,
    lastSeenAt: now,
    // Dropped the moment either key moves: a card still saying "verified"
    // against keys nobody compared is worse than one that never said it.
    comparedAt: sameKeys ? existing?.comparedAt : undefined,
  };
  // A deliberate re-pin starts the person key over too; the next binding is recorded fresh.
  if (sameKeys && existing?.personPublicKey) pin.personPublicKey = existing.personPublicKey;

  pins[key] = pin;
  store.write(pins);
  return pin;
}

/**
 * Record that these keys were read out and matched (GRYT-730). Takes the keys and refuses if
 * they are not the pinned ones: a member list can land mid-comparison.
 */
export function markPeerCompared(
  store: PeerPinStore,
  scope: IdentityScope,
  memberId: string,
  keys: { thumbprint: string; dmPublicKey: string; personPublicKey?: string },
  now = Date.now(),
): boolean {
  const pins = store.read();
  const key = pinKey(scope, memberId);
  const pin = pins[key];

  if (
    !pin ||
    pin.thumbprint !== keys.thumbprint ||
    pin.dmPublicKey !== keys.dmPublicKey ||
    (pin.personPublicKey ?? null) !== (keys.personPublicKey ?? null)
  ) {
    return false;
  }

  pins[key] = { ...pin, comparedAt: now };
  store.write(pins);
  return true;
}

/** Forget one, which is what accepting a change amounts to before re-pinning. */
export function forgetPeerPin(
  store: PeerPinStore,
  scope: IdentityScope,
  memberId: string,
): void {
  const pins = store.read();
  delete pins[pinKey(scope, memberId)];
  store.write(pins);
}

/** Forget everybody on one server, for a server being left. */
export function forgetPeerPinsForScope(
  store: PeerPinStore,
  scope: IdentityScope,
): void {
  const pins = store.read();
  const prefix = `${scope} `;
  for (const key of Object.keys(pins)) {
    if (key.startsWith(prefix)) delete pins[key];
  }
  store.write(pins);
}

/**
 * What to do about the binding this member list carried. Writes nothing, even on `first`:
 * pinning as a side effect would make `first` mean "since the last render".
 */
export async function evaluatePeerKey({
  store,
  scope,
  memberId,
  binding,
}: {
  /** Where pins live. See {@link PeerPinStore}. */
  store: PeerPinStore;
  scope: IdentityScope;
  memberId: string;
  /** Straight off the member list. Null when they have published nothing. */
  binding: string | null | undefined;
}): Promise<PeerKeyDecision> {
  if (!binding) return { kind: "none" };

  let verified: VerifiedDmKeyBinding;
  try {
    verified = await verifyDmKeyBinding(binding, scope);
  } catch (error) {
    return {
      kind: "unusable",
      reason: error instanceof Error ? error.message : String(error),
    };
  }

  const pin = getPeerPin(store, scope, memberId);
  if (!pin) return { kind: "first", verified };

  const changedIdentity = pin.thumbprint !== verified.identityThumbprint;
  const changedKey = pin.dmPublicKey !== base64Url(verified.dmPublicKey);

  if (changedIdentity || changedKey) {
    return { kind: "changed", pin, verified, changedIdentity, changedKey };
  }

  return { kind: "known", verified, pin };
}

export type PersonKeyDecision =
  /** They have published no person key. */
  | { kind: "none" }
  /** A binding that doesn't check out. It never becomes part of a pin. */
  | { kind: "unusable"; reason: string }
  /** No pin for this member yet, so nothing to check who signed it against. Pin the DM key first. */
  | { kind: "unpinned"; verified: VerifiedPersonKeyBinding }
  /** Signed by the pinned identity, and no person key recorded yet. The caller records it. */
  | { kind: "first"; verified: VerifiedPersonKeyBinding; pin: PeerPin }
  | { kind: "known"; verified: VerifiedPersonKeyBinding; pin: PeerPin }
  /** A different signer or a different person key from the pin. Refused, like a changed DM key. */
  | {
      kind: "changed";
      verified: VerifiedPersonKeyBinding;
      pin: PeerPin;
      changedIdentity: boolean;
      changedKey: boolean;
    };

/** What to do about a member's person key binding. Writes nothing, like `evaluatePeerKey`. */
export async function evaluatePersonKey({
  store,
  scope,
  memberId,
  binding,
}: {
  store: PeerPinStore;
  scope: IdentityScope;
  memberId: string;
  binding: string | null | undefined;
}): Promise<PersonKeyDecision> {
  if (!binding) return { kind: "none" };

  let verified: VerifiedPersonKeyBinding;
  try {
    verified = await verifyPersonKeyBinding(binding, scope);
  } catch (error) {
    return { kind: "unusable", reason: error instanceof Error ? error.message : String(error) };
  }

  const pin = getPeerPin(store, scope, memberId);
  if (!pin) return { kind: "unpinned", verified };

  const changedIdentity = pin.thumbprint !== verified.identityThumbprint;
  const changedKey = pin.personPublicKey !== undefined && pin.personPublicKey !== base64Url(verified.personPublicKey);
  if (changedIdentity || changedKey) return { kind: "changed", verified, pin, changedIdentity, changedKey };
  return pin.personPublicKey === undefined ? { kind: "first", verified, pin } : { kind: "known", verified, pin };
}

/**
 * Record a person key on an existing pin. Refuses (null) unless the pin's identity signed it and
 * no other person key is there: accepting a change is `forgetPeerPin` and pinning from scratch.
 */
export function pinPersonKey(
  store: PeerPinStore,
  scope: IdentityScope,
  memberId: string,
  verified: VerifiedPersonKeyBinding,
  now = Date.now(),
): PeerPin | null {
  const pins = store.read();
  const key = pinKey(scope, memberId);
  const existing = pins[key];
  const personPublicKey = base64Url(verified.personPublicKey);
  if (!existing || verified.scope !== scope || existing.thumbprint !== verified.identityThumbprint) return null;
  if (existing.personPublicKey !== undefined && existing.personPublicKey !== personPublicKey) return null;

  const pin: PeerPin = { ...existing, personPublicKey, lastSeenAt: now };
  pins[key] = pin;
  store.write(pins);
  return pin;
}

/**
 * The `trustPersonKey` for one conversation: your own person key, or one pinned for one of
 * `memberIds`. Reads the pins on every call, so a key pinned later counts from then.
 */
export function trustPinnedPersonKeys({
  store,
  scope,
  memberIds,
  ownPersonKey,
}: {
  store: PeerPinStore;
  scope: IdentityScope;
  memberIds: readonly string[];
  /** From `derivePersonKeyPair`, public half. Your other devices carry it. */
  ownPersonKey: Uint8Array;
}): TrustPersonKey {
  const own = base64Url(ownPersonKey);
  return (certificate) => {
    if (certificate.scope !== scope) return false;
    const presented = base64Url(certificate.personPublicKey);
    if (presented === own) return true;
    return memberIds.some((id) => getPeerPin(store, scope, id)?.personPublicKey === presented);
  };
}
