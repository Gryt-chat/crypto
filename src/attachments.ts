import { gcm } from "@noble/ciphers/aes.js";

import { base64Url, base64UrlDecode } from "./base64";

/**
 * A file the server stores and cannot read (GRYT-729 left this out).
 *
 * The message body has been unreadable to the server since GRYT-718. The files
 * hanging off it were not: an upload went up as itself, the server validated
 * it, made a thumbnail, recorded its name, type and dimensions, and served it
 * back to anybody with the link. So a conversation could be private and its
 * photographs public, which is the failure mode where the words are the part
 * nobody needed.
 *
 * ## The shape
 *
 * Each file gets its own random key. The bytes are encrypted under it before
 * they leave the device, and the key — with the real name, type and size —
 * travels inside the sealed message, encrypted again under that message's
 * content key. So opening a file needs the message, and opening the message
 * needs a wrapped key, which is the property the text already had.
 *
 * A key per file rather than the message's own content key, because the two
 * have different lifetimes: an upload happens while somebody is still typing,
 * and can be cancelled, retried or attached to a different message. Deriving it
 * from a message that does not exist yet would mean re-encrypting the file when
 * the draft changed.
 *
 * ## What the server still learns
 *
 * That a file exists, how big the ciphertext is, and when. Not its name, not
 * its type, not its contents, and not its dimensions. Padding the size is a
 * different piece of work and is not pretended at here.
 *
 * ## One shot, not a stream
 *
 * The whole file is encrypted in memory. Uploads are capped by the server —
 * 100 MB by default — and the client is already holding the bytes to send them,
 * so this adds a copy rather than a new problem. A streaming format would be
 * better for the top of that range and is a different envelope; if it happens,
 * it happens as a version 2 rather than as a change to this one.
 */

const IV_BYTES = 12;
const FILE_KEY_BYTES = 32;

export const SEALED_ATTACHMENT_TYPE = "gryt-sealed-attachment";

/**
 * What a reader needs to open one file, and what a sender knows about it.
 *
 * Every field is hidden from the server. `name` and `mime` are what the picker
 * reported; nothing verifies them, and a client should treat both as text
 * somebody chose — the same care an unencrypted `original_name` has always
 * needed.
 */
export interface SealedAttachmentKey {
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
 * What the ciphertext is bound to.
 *
 * The file id goes in, so the bytes stored under one id cannot be served back
 * under another and still open. A server that swapped two members' uploads
 * would otherwise produce files that decrypt perfectly and are the wrong ones —
 * and since the reader never saw the original, nothing would look wrong.
 *
 * The conversation goes in for the reason `message-keys.ts` gives: the same
 * pair talking in two places must not be able to have a file replayed between
 * them.
 */
function fileContext(
  conversationId: string,
  fileId: string,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    `${SEALED_ATTACHMENT_TYPE}/v1/${conversationId}/${fileId}`,
  ) as Uint8Array<ArrayBuffer>;
}

/**
 * Encrypt a file, ready to upload.
 *
 * The id has to be decided before the bytes are sealed, because it is what they
 * are bound to. Callers generate one rather than taking the server's: an id
 * chosen after the upload would mean either re-encrypting or leaving the bytes
 * unbound, and a server that assigns the id could then assign the same one
 * twice.
 */
export function sealAttachment({
  bytes,
  conversationId,
  fileId,
  name,
  mime,
  width,
  height,
}: {
  bytes: Uint8Array;
  conversationId: string;
  fileId: string;
  name?: string;
  mime?: string;
  width?: number;
  height?: number;
}): { ciphertext: Uint8Array<ArrayBuffer>; meta: SealedAttachmentKey } {
  const key = randomBytes(FILE_KEY_BYTES);
  const iv = randomBytes(IV_BYTES);

  const ciphertext = gcm(
    key,
    iv,
    fileContext(conversationId, fileId),
  ).encrypt(bytes as Uint8Array<ArrayBuffer>);

  return {
    ciphertext: ciphertext as Uint8Array<ArrayBuffer>,
    meta: {
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
 * Turn the downloaded bytes back into the file.
 *
 * Throws when they do not open. There is no ordinary reason for that — unlike a
 * message, where a member who joined later legitimately has no key — so a
 * caller should say the file is broken rather than draw an empty one.
 */
export function openAttachment({
  ciphertext,
  conversationId,
  fileId,
  meta,
}: {
  ciphertext: Uint8Array;
  conversationId: string;
  fileId: string;
  meta: SealedAttachmentKey;
}): Uint8Array<ArrayBuffer> {
  return gcm(
    base64UrlDecode(meta.key),
    base64UrlDecode(meta.iv),
    fileContext(conversationId, fileId),
  ).decrypt(ciphertext as Uint8Array<ArrayBuffer>) as Uint8Array<ArrayBuffer>;
}
