/**
 * Trust-on-first-use pinning of the people you talk to (GRYT-726).
 *
 * A binding is worth something because the same one keeps arriving. This is
 * what remembers. Same three moves `server-pins.ts` has made for servers since
 * GRYT-51 — record on first sight, notice a change, refuse it — with separate
 * storage, since forgetting a server should not forget the people on it.
 *
 * **There is no automatic re-pin.** A change is reported and stays reported
 * until somebody decides, because a restored seed and a substituted key look
 * identical from here and only one is the person's own doing.
 *
 * Both halves are compared. An identity key is generated once and kept while a
 * DM key is derived from the seed, so somebody restoring a different seed
 * arrives with the same thumbprint and a new DM key. Comparing one leaves a
 * hole in whichever direction is left out.
 */

import { base64Url } from "./base64";
import {
  type VerifiedDmKeyBinding,
  verifyDmKeyBinding,
} from "./dm-key-binding";
import type { IdentityScope } from "./scope";

/**
 * Synchronous on purpose. An async store would make every read here async and
 * ripple into a member list that is drawn synchronously — so the caller hands
 * over `localStorage` on desktop, and a hydrated in-memory value on mobile.
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
  firstSeenAt: number;
  lastSeenAt: number;
  /**
   * When these exact keys were compared out of band (GRYT-730). Dropped by
   * `pinPeerKey` whenever either half moves — carrying it across would turn the
   * one honest claim here into the lie it exists to prevent.
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
   * Different from what was pinned. Refuse and let somebody decide. The two
   * flags are separate because a new identity key is a different account, while
   * a new DM key under the same identity is usually a restored seed.
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
 * Record what this member's keys are, from here on.
 *
 * Called on a `first` decision, and on a `changed` one only after somebody has
 * said to. Nothing calls it on `changed` by itself, which is the whole point.
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

  pins[key] = pin;
  store.write(pins);
  return pin;
}

/**
 * Record that these keys were read out and matched (GRYT-730). Takes the keys
 * and refuses if they are not the pinned ones: a member list can land between
 * reading a code aloud and pressing the button.
 */
export function markPeerCompared(
  store: PeerPinStore,
  scope: IdentityScope,
  memberId: string,
  keys: { thumbprint: string; dmPublicKey: string },
  now = Date.now(),
): boolean {
  const pins = store.read();
  const key = pinKey(scope, memberId);
  const pin = pins[key];

  if (
    !pin ||
    pin.thumbprint !== keys.thumbprint ||
    pin.dmPublicKey !== keys.dmPublicKey
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
 * What to do about the binding this member list carried. Writes nothing, even
 * on `first`: this runs on every member list, and pinning as a side effect
 * would make `first` mean "since the last render".
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
