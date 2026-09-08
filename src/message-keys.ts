/**
 * One key per message, wrapped once per member (GRYT-718). Not authenticated as coming from
 * the sender, not end-to-end against the server yet, and not private about who is in it.
 */
import { gcm } from "@noble/ciphers/aes.js";

import type { SealedAttachmentKey } from "./attachments";
import { base64Url, base64UrlDecode } from "./base64";
import { type DmKeyPair, dmSharedSecret } from "./dm-keys";

const IV_BYTES = 12;
const CONTENT_KEY_BYTES = 32;

export const SEALED_MESSAGE_TYPE = "gryt-sealed-message";

/** One member's copy of the content key. */
export interface WrappedKey {
  iv: string;
  key: string;
}

export interface SealedMessage {
  type: typeof SEALED_MESSAGE_TYPE;
  version: 1;
  /**
   * The sender's DM public key, base64url. A reader needs it to derive the
   * secret that opens their wrapped key. It is *not* proof of who sent this.
   */
  sender: string;
  /** The body's nonce. */
  iv: string;
  /** The message, encrypted with the content key. */
  body: string;
  /** Member id to that member's wrapped copy of the content key. */
  keys: Record<string, WrappedKey>;
  /**
   * File id to that file's key and real metadata, encrypted (GRYT-729). Nothing here plus a
   * message carrying `attachments` means those files went up in the clear.
   */
  files?: Record<string, SealedFileKey>;
}

/** One file's key and metadata, encrypted under the message's content key. */
export interface SealedFileKey {
  iv: string;
  /** The JSON of a {@link SealedAttachmentKey}, encrypted. */
  meta: string;
}

/**
 * `attachments` is deliberately not optional: a caller that forgets it draws a conversation
 * where files silently do not appear.
 */
export interface OpenedMessage {
  text: string;
  attachments: Record<string, SealedAttachmentKey>;
}

export interface Recipient {
  /** How the conversation names this person. `conversation_members.user_id`. */
  memberId: string;
  /** Their DM public key, as `dmPublicKey` returns it. */
  publicKey: Uint8Array;
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes as Uint8Array<ArrayBuffer>;
}

/**
 * AES-256-GCM from a library, not `crypto.subtle`, which React Native lacks (GRYT-733). The
 * bytes match WebCrypto's, so everything sealed before this change still opens.
 */
function aesGcm(key: Uint8Array, iv: Uint8Array, aad: Uint8Array) {
  return gcm(key as Uint8Array<ArrayBuffer>, iv as Uint8Array<ArrayBuffer>, aad as Uint8Array<ArrayBuffer>);
}

/**
 * Binds the body to its conversation and sender, so a message lifted into another
 * conversation does not open. The sender field is not a signature.
 */
function bodyContext(conversationId: string, sender: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    `${SEALED_MESSAGE_TYPE}/v1/${conversationId}/${sender}`,
  ) as Uint8Array<ArrayBuffer>;
}

/**
 * The same, for one file's key. The file id is here as well as inside the
 * attachment's own envelope, so one file's entry cannot be moved onto another.
 */
function fileKeyContext(
  conversationId: string,
  sender: string,
  fileId: string,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    `${SEALED_MESSAGE_TYPE}/v1/${conversationId}/${sender}/file/${fileId}`,
  ) as Uint8Array<ArrayBuffer>;
}

/** The same, for one member's wrapped key. */
function wrapContext(
  conversationId: string,
  sender: string,
  memberId: string,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    `${SEALED_MESSAGE_TYPE}/v1/${conversationId}/${sender}/${memberId}`,
  ) as Uint8Array<ArrayBuffer>;
}

/**
 * Encrypt a message and wrap its key for everybody who should read it. `recipients` is the
 * whole membership, including the sender — leaving them out sends a message they cannot read.
 */
export async function sealMessage({
  plaintext,
  conversationId,
  senderKeys,
  recipients,
  attachments,
}: {
  plaintext: string;
  conversationId: string;
  senderKeys: DmKeyPair;
  recipients: Recipient[];
  /** File id to what `sealAttachment` handed back for it (GRYT-729). */
  attachments?: Record<string, SealedAttachmentKey>;
}): Promise<SealedMessage> {
  if (recipients.length === 0) {
    throw new Error("A message with no recipients cannot be read by anybody.");
  }

  const seen = new Set<string>();
  for (const { memberId } of recipients) {
    if (seen.has(memberId)) {
      throw new Error(`Member ${memberId} is in the recipient list twice.`);
    }
    seen.add(memberId);
  }

  const sender = base64Url(senderKeys.publicKey);
  if (!recipients.some((r) => base64Url(r.publicKey) === sender)) {
    throw new Error(
      "The sender is not among the recipients, so they could not read this back.",
    );
  }

  const contentKey = randomBytes(CONTENT_KEY_BYTES);
  const iv = randomBytes(IV_BYTES);

  const body = aesGcm(contentKey, iv, bodyContext(conversationId, sender)).encrypt(
    new TextEncoder().encode(plaintext) as Uint8Array<ArrayBuffer>,
  );

  const keys: Record<string, WrappedKey> = {};
  for (const recipient of recipients) {
    const secret = dmSharedSecret(
      senderKeys.privateKey,
      recipient.publicKey,
      conversationId,
    );
    const wrapIv = randomBytes(IV_BYTES);
    const wrapped = aesGcm(
      secret,
      wrapIv,
      wrapContext(conversationId, sender, recipient.memberId),
    ).encrypt(contentKey);
    keys[recipient.memberId] = {
      iv: base64Url(wrapIv),
      key: base64Url(wrapped),
    };
  }

  const files: Record<string, SealedFileKey> = {};
  for (const [fileId, meta] of Object.entries(attachments ?? {})) {
    const fileIv = randomBytes(IV_BYTES);
    files[fileId] = {
      iv: base64Url(fileIv),
      meta: base64Url(
        aesGcm(
          contentKey,
          fileIv,
          fileKeyContext(conversationId, sender, fileId),
        ).encrypt(
          new TextEncoder().encode(JSON.stringify(meta)) as Uint8Array<ArrayBuffer>,
        ),
      ),
    };
  }

  return {
    type: SEALED_MESSAGE_TYPE,
    version: 1,
    sender,
    iv: base64Url(iv),
    body: base64Url(body),
    keys,
    // Left off entirely when there are none, so a message with no files is
    // byte-identical to before this existed and the vector check still holds.
    ...(Object.keys(files).length > 0 ? { files } : null),
  };
}

/**
 * Read a message, if this member has a key for it. Null for a late joiner, which is ordinary;
 * a key that is present and does not open throws, because that means tampering.
 */
export async function openMessage({
  sealed,
  conversationId,
  memberId,
  recipientKeys,
}: {
  sealed: SealedMessage;
  conversationId: string;
  /** Which member you are, as the conversation names you. */
  memberId: string;
  recipientKeys: DmKeyPair;
}): Promise<OpenedMessage | null> {
  if (sealed.type !== SEALED_MESSAGE_TYPE || sealed.version !== 1) {
    throw new Error("That is not a sealed message this version can read.");
  }

  const mine = sealed.keys[memberId];
  if (!mine) return null;

  const secret = dmSharedSecret(
    recipientKeys.privateKey,
    base64UrlDecode(sealed.sender),
    conversationId,
  );

  const contentKey = aesGcm(
    secret,
    base64UrlDecode(mine.iv),
    wrapContext(conversationId, sealed.sender, memberId),
  ).decrypt(base64UrlDecode(mine.key));

  const plain = aesGcm(
    contentKey,
    base64UrlDecode(sealed.iv),
    bodyContext(conversationId, sealed.sender),
  ).decrypt(base64UrlDecode(sealed.body));

  const attachments: Record<string, SealedAttachmentKey> = {};
  for (const [fileId, entry] of Object.entries(sealed.files ?? {})) {
    const meta = aesGcm(
      contentKey,
      base64UrlDecode(entry.iv),
      fileKeyContext(conversationId, sealed.sender, fileId),
    ).decrypt(base64UrlDecode(entry.meta));

    attachments[fileId] = JSON.parse(
      new TextDecoder().decode(meta),
    ) as SealedAttachmentKey;
  }

  return { text: new TextDecoder().decode(plain), attachments };
}
