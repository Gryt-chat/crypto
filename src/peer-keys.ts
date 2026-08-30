/**
 * Trust-on-first-use pinning of the people you talk to (GRYT-726).
 *
 * `dm-key-binding.ts` can check that a DM key and an identity key were chosen
 * by the same person. It cannot say who that person is, and nothing in band
 * can — so what makes a binding worth anything is that the same one keeps
 * arriving. This is the module that remembers.
 *
 * `server-pins.ts` does exactly this for servers and has since GRYT-51. Same
 * three moves: record on first sight, notice a change, refuse it. The shapes are
 * deliberately similar and the storage is deliberately separate, because a
 * server key and a person's key answer different questions, and one being
 * forgotten should not take the other with it.
 *
 * ## Refusing is the feature
 *
 * A client that quietly encrypts to a new key once the old one stops matching
 * has thrown away the only protection this design has. There is no automatic
 * re-pin here at all. A change is reported and stays reported until somebody
 * decides, because the two reasons for one — a person restored a different seed,
 * or a server substituted a key — look identical from here, and only one of them
 * is the person's own doing.
 *
 * ## Both halves are compared, not just the identity
 *
 * An account holder's identity key is generated once and kept; their DM key is
 * derived from the seed. Somebody who restores a different seed therefore keeps
 * the same identity key and arrives with a different DM key, and comparing only
 * the thumbprint would wave that through. Comparing only the DM key misses the
 * reverse. Both, or the check has a hole in whichever direction is left out.
 *
 * This module decides. It does not fetch, encrypt, or draw anything.
 */

import { base64Url } from "./base64";
import {
  type VerifiedDmKeyBinding,
  verifyDmKeyBinding,
} from "./dm-key-binding";
import type { IdentityScope } from "./scope";

/**
 * Where pins are kept, which this package deliberately does not decide.
 *
 * The desktop has `localStorage` and React Native does not. Rather than an
 * async storage abstraction — which would make every read here async and ripple
 * into a member list drawn synchronously — the caller hands over something it
 * can read and write without waiting.
 *
 * On the desktop that is `localStorage`. On mobile it is a value held in memory,
 * hydrated once at startup and flushed after a write. Both are ordinary and
 * neither belongs in here.
 */
export interface PeerPinStore {
  read(): Record<string, PeerPin>;
  write(pins: Record<string, PeerPin>): void;
}

/**
 * What a caller should file these under, offered so the two clients do not pick
 * different keys and quietly stop being the same app.
 */
export const PEER_PINS_KEY = "peerDmKeyPins";

export interface PeerPin {
  /** The identity key that signed the binding, as a JWK thumbprint. */
  thumbprint: string;
  /** The DM public key it vouched for, base64url. */
  dmPublicKey: string;
  firstSeenAt: number;
  lastSeenAt: number;
  /**
   * When these exact keys were compared out of band (GRYT-730).
   *
   * Absent until two people have read the code to each other. Not carried
   * across a change — `pinPeerKey` drops it whenever either half moves, because
   * a comparison is about the specific keys that were compared and keeping it
   * would turn the one honest claim here into the lie it exists to prevent.
   */
  comparedAt?: number;
}

export type PeerKeyDecision =
  /** They have published nothing. Nothing to encrypt to, and nothing wrong. */
  | { kind: "none" }
  /**
   * Something arrived and did not check out — a signature that fails, a binding
   * signed for another server, a shape that is not one at all.
   *
   * Not the same as a changed key. This is a server sending something broken
   * rather than something plausible, and it never becomes a pin.
   */
  | { kind: "unusable"; reason: string }
  /** Nobody pinned yet. The caller pins this and carries on. */
  | { kind: "first"; verified: VerifiedDmKeyBinding }
  /** The same person and the same keys as last time. */
  | { kind: "known"; verified: VerifiedDmKeyBinding; pin: PeerPin }
  /**
   * Different from what was pinned. Refuse, say so, and let somebody decide.
   *
   * `changedIdentity` and `changedKey` are separate because they mean different
   * things to a person: a new identity key is somebody arriving as a different
   * account, and a new DM key under the same identity is usually a restored
   * seed.
   */
  | {
      kind: "changed";
      pin: PeerPin;
      verified: VerifiedDmKeyBinding;
      changedIdentity: boolean;
      changedKey: boolean;
    };

/**
 * One pin per server and member.
 *
 * A `server_user_id` is already per-server, so the scope is redundant for
 * uniqueness. It is in the key anyway so that forgetting a server forgets the
 * people on it, and so nothing rests on ids from two servers never colliding.
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
    // Dropped the moment either key moves. Somebody who compared a code last
    // year and whose peer has since arrived with a new key has verified
    // nothing, and a card still saying "verified" would be worse than one that
    // never said it.
    comparedAt: sameKeys ? existing?.comparedAt : undefined,
  };

  pins[key] = pin;
  store.write(pins);
  return pin;
}

/**
 * Record that these keys were read out and matched (GRYT-730).
 *
 * Takes the keys it is marking rather than just the member, and refuses if they
 * are not the ones pinned. Between somebody reading a code aloud and pressing
 * the button, a member list can land and change the pin — marking blind would
 * put "verified" against keys nobody ever compared.
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
 * What to do about the binding this member list carried.
 *
 * Decides and returns. Nothing is written here, including on `first` — the same
 * evaluation runs on every member list, and a function that pinned as a side
 * effect would make `first` mean "since the last render".
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
