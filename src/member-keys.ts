/**
 * What a member list does to your pins (GRYT-727). Pinning on a change rather than a first
 * sighting turns the design off silently, and pinning your own row lets a server rewrite it.
 */

import { base64Url } from "./base64";
import {
  evaluatePeerKey,
  evaluatePersonKey,
  type PeerKeyDecision,
  type PeerPinStore,
  type PersonKeyDecision,
  pinPeerKey,
  pinPersonKey,
} from "./peer-keys";
import type { IdentityScope } from "./scope";

export interface MemberKeyState {
  decision: PeerKeyDecision;
  /** Whether this row is the person running this client. */
  isSelf: boolean;
  /**
   * Set only on your own row, when the list disagrees with the key you derived — this server
   * rewriting it (GRYT-727). Catches the careless version only.
   */
  ownKeyRewritten?: boolean;
  /** Their MLS person key binding, checked against the pin. `first` has been recorded. */
  personKey: PersonKeyDecision;
  /** Like `ownKeyRewritten`, for the person key, when `ownPersonKey` was given. */
  ownPersonKeyRewritten?: boolean;
}

/**
 * Work out what to do about every binding in a member list. `first` is pinned here;
 * `changed` is returned untouched, because re-pinning throws away the only protection.
 */
export async function evaluateMemberKeys({
  store,
  scope,
  ownKey,
  ownPersonKey = null,
  members,
  myServerUserId,
}: {
  /** Where pins live. See `PeerPinStore` — this package does not decide. */
  store: PeerPinStore;
  scope: IdentityScope;
  /**
   * The public half only, from `ownDmPublicKey`. Null when it cannot be worked
   * out, which turns the self-check off rather than making it fail.
   */
  ownKey: Uint8Array | null;
  /** The public half of `derivePersonKeyPair`, for the same self-check. */
  ownPersonKey?: Uint8Array | null;
  members: { serverUserId: string; dmKeyBinding?: string | null; personKeyBinding?: string | null }[];
  /** Null before the member list has said which row is yours. */
  myServerUserId: string | null;
}): Promise<Record<string, MemberKeyState>> {
  const mine = ownKey && myServerUserId ? base64Url(ownKey) : null;
  const minePerson = ownPersonKey && myServerUserId ? base64Url(ownPersonKey) : null;

  const states: Record<string, MemberKeyState> = {};

  for (const member of members) {
    const isSelf = member.serverUserId === myServerUserId;

    const decision = await evaluatePeerKey({
      store,
      scope,
      memberId: member.serverUserId,
      binding: member.dmKeyBinding,
    });

    if (decision.kind === "first" && !isSelf) {
      pinPeerKey(store, scope, member.serverUserId, decision.verified);
    }

    const personKey = await evaluatePersonKey({
      store,
      scope,
      memberId: member.serverUserId,
      binding: member.personKeyBinding,
    });
    // Not while the DM key is in dispute: a person key would let MLS go ahead where sealing won't.
    if (personKey.kind === "first" && !isSelf && (decision.kind === "first" || decision.kind === "known")) {
      pinPersonKey(store, scope, member.serverUserId, personKey.verified);
    }

    const state: MemberKeyState = { decision, isSelf, personKey };

    if (isSelf && mine && decision.kind !== "none") {
      const shown =
        decision.kind === "unusable" ? null : base64Url(decision.verified.dmPublicKey);
      // An unusable binding on your own row counts too: you published something
      // that verifies, so whatever is being shown is not it.
      state.ownKeyRewritten = shown !== mine;
    }
    if (isSelf && minePerson && personKey.kind !== "none") {
      const shown = personKey.kind === "unusable" ? null : base64Url(personKey.verified.personPublicKey);
      state.ownPersonKeyRewritten = shown !== minePerson;
    }

    states[member.serverUserId] = state;
  }

  return states;
}
