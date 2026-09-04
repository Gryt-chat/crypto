import { gcm } from "@noble/ciphers/aes.js";

import { base64Url, base64UrlDecode } from "./base64";

/**
 * A file the server stores and cannot read (GRYT-729 left this out).
 *
 * Each file gets its own random key. The bytes are encrypted under it before
 * they leave the device, and the key — with the real name, type and size —
 * travels inside the sealed message. A key per file rather than the message's
 * content key because the lifetimes differ: an upload happens while somebody is
 * still typing, and can be cancelled, retried or moved to another message.
 *
 * The server still learns that a file exists, how big the ciphertext is, and
 * when. Padding the size is separate work and is not pretended at here.
 *
 * The whole file is encrypted in memory. Uploads are capped at 100 MB by
 * default and the client already holds the bytes. A streaming format is a
 * different envelope and would arrive as a version 2, not as a change here.
 */

const IV_BYTES = 12;
const FILE_KEY_BYTES = 32;

/** Not a secret and not a key — it only has to be unique among a sender's files. */
const BINDING_ID_BYTES = 16;

export const SEALED_ATTACHMENT_TYPE = "gryt-sealed-attachment";

/**
 * What a reader needs to open one file. Every field is hidden from the server.
 * `name` and `mime` are unverified — treat both as text somebody chose.
 */
export interface SealedAttachmentKey {
  /**
   * What the ciphertext is bound to. Generated here, not the server's file id,
   * which does not exist until the upload has already been encrypted and sent.
   * A swap still fails, and nobody has to agree on an id first.
   */
  id: string;
  /** The file's own key, base64url. */
  key: string;
  /** Its nonce, base64url. */
  iv: string;
  /** What it was called on the sender's machine. */
  name?: string;
  /** What the sender's picker said it was. */
  mime?: string;
  /** The plaintext length, so a reader can draw a size before fetching. */
  size?: number;
  width?: number;
  height?: number;
}

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes as Uint8Array<ArrayBuffer>;
}

/**
 * Binds the ciphertext to the sender's own id for it, so swapped uploads
 * decrypt to nothing rather than to the wrong file, which the reader — never
 * having seen the original — would have no way to notice. The conversation goes
 * in for the replay reason `message-keys.ts` gives.
 */
function fileContext(
  conversationId: string,
  id: string,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    `${SEALED_ATTACHMENT_TYPE}/v1/${conversationId}/${id}`,
  ) as Uint8Array<ArrayBuffer>;
}

/**
 * Encrypt a file, ready to upload. Nothing has to be agreed with the server
 * first — see {@link SealedAttachmentKey.id}.
 */
export function sealAttachment({
  bytes,
  conversationId,
  name,
  mime,
  width,
  height,
}: {
  bytes: Uint8Array;
  conversationId: string;
  name?: string;
  mime?: string;
  width?: number;
  height?: number;
}): { ciphertext: Uint8Array<ArrayBuffer>; meta: SealedAttachmentKey } {
  const id = base64Url(randomBytes(BINDING_ID_BYTES));
  const key = randomBytes(FILE_KEY_BYTES);
  const iv = randomBytes(IV_BYTES);

  const ciphertext = gcm(
    key,
    iv,
    fileContext(conversationId, id),
  ).encrypt(bytes as Uint8Array<ArrayBuffer>);

  return {
    ciphertext: ciphertext as Uint8Array<ArrayBuffer>,
    meta: {
      id,
      key: base64Url(key),
      iv: base64Url(iv),
      size: bytes.length,
      ...(name === undefined ? null : { name }),
      ...(mime === undefined ? null : { mime }),
      ...(width === undefined ? null : { width }),
      ...(height === undefined ? null : { height }),
    },
  };
}

/**
 * Turn the downloaded bytes back into the file. Throws when they do not open;
 * unlike a message there is no ordinary reason for that, so a caller should say
 * the file is broken rather than draw an empty one.
 */
export function openAttachment({
  ciphertext,
  conversationId,
  meta,
}: {
  ciphertext: Uint8Array;
  conversationId: string;
  meta: SealedAttachmentKey;
}): Uint8Array<ArrayBuffer> {
  return gcm(
    base64UrlDecode(meta.key),
    base64UrlDecode(meta.iv),
    fileContext(conversationId, meta.id),
  ).decrypt(ciphertext as Uint8Array<ArrayBuffer>) as Uint8Array<ArrayBuffer>;
}
