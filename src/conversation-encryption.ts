/**
 * Whether a conversation can be encrypted, and doing it (GRYT-729). Every member or nobody,
 * and a member whose key changed counts as not having one. The answer has to reach the sender.
 */

import type { SealedAttachmentKey } from "./attachments";
import {
  openMessage,
  type OpenedMessage,
  type SealedMessage,
  sealMessage,
} from "./message-keys";
import { type PeerKeyDecision } from "./peer-keys";

export interface ConversationMember {
  /** `server_user_id`, which is how the conversation names them. */
  memberId: string;
  /** What this client decided about their key, from `evaluateMemberKeys`. */
  keyState?: { decision: PeerKeyDecision } | undefined;
}

export type SealDecision =
  | { kind: "seal"; recipients: { memberId: string; publicKey: Uint8Array }[] }
  | {
      kind: "plaintext";
      /** Why, per member, so a composer can name them. */
      blockedBy: { memberId: string; reason: "no-key" | "changed" | "unusable" }[];
    };

/**
 * Can this conversation be sealed, and to whom. `self` goes into the recipients
 * here — a sender left out cannot read their own message back tomorrow.
 */
export function decideSealing({
  members,
  self,
}: {
  /** Everybody in the conversation apart from you. */
  members: ConversationMember[];
  /** Your own member id and DM public key on this server. */
  self: { memberId: string; publicKey: Uint8Array } | null;
}): SealDecision {
  if (!self) {
    // No key of our own is a device that has not finished joining, not a
    // problem with anybody else.
    return { kind: "plaintext", blockedBy: [] };
  }

  const recipients: { memberId: string; publicKey: Uint8Array }[] = [
    { memberId: self.memberId, publicKey: self.publicKey },
  ];
  const blockedBy: { memberId: string; reason: "no-key" | "changed" | "unusable" }[] = [];

  for (const member of members) {
    const decision = member.keyState?.decision;

    if (!decision || decision.kind === "none") {
      blockedBy.push({ memberId: member.memberId, reason: "no-key" });
      continue;
    }
    if (decision.kind === "unusable") {
      blockedBy.push({ memberId: member.memberId, reason: "unusable" });
      continue;
    }
    if (decision.kind === "changed") {
      // GRYT-726's refusal, arriving where it costs something: encrypting to
      // the new key would be pretending the change was fine.
      blockedBy.push({ memberId: member.memberId, reason: "changed" });
      continue;
    }

    recipients.push({
      memberId: member.memberId,
      publicKey: decision.verified.dmPublicKey,
    });
  }

  if (blockedBy.length > 0) return { kind: "plaintext", blockedBy };
  return { kind: "seal", recipients };
}

/**
 * Seal a message, or say why it cannot be. Null means send in the clear, and a
 * caller that ignores which it got is back to silent plaintext.
 */
export async function sealForConversation({
  plaintext,
  conversationId,
  senderKeys,
  decision,
  attachments,
}: {
  plaintext: string;
  conversationId: string;
  senderKeys: { privateKey: Uint8Array; publicKey: Uint8Array };
  decision: SealDecision;
  /**
   * File id to what `sealAttachment` returned (GRYT-729). Encrypt files after checking
   * `decision.kind`: an unsealable conversation returns null, and uploads would be orphaned.
   */
  attachments?: Record<string, SealedAttachmentKey>;
}): Promise<string | null> {
  if (decision.kind !== "seal") return null;

  const sealed = await sealMessage({
    plaintext,
    conversationId,
    senderKeys,
    recipients: decision.recipients,
    attachments,
  });

  return JSON.stringify(sealed);
}

/**
 * Read one back. Null for a late joiner, which a client draws as unreadable. Anything else
 * throws: a key present and not opening means tampering, and an empty bubble hides it.
 */
export async function openForConversation({
  sealed,
  conversationId,
  memberId,
  recipientKeys,
}: {
  /** The string off the wire. */
  sealed: string;
  conversationId: string;
  memberId: string;
  recipientKeys: { privateKey: Uint8Array; publicKey: Uint8Array };
}): Promise<OpenedMessage | null> {
  let envelope: SealedMessage;
  try {
    envelope = JSON.parse(sealed);
  } catch {
    throw new Error("That message is not a sealed envelope.");
  }

  return openMessage({ sealed: envelope, conversationId, memberId, recipientKeys });
}
