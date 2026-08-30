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

/**
 * Enough that two attachments never collide, and no more.
 *
 * This is not a secret and not a key. It exists so that one file's ciphertext
 * does not open under another's metadata, so all it has to be is unique among
 * the attachments a person sends.
 */
const BINDING_ID_BYTES = 16;

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
  /**
   * What the ciphertext is bound to. Generated here, not supplied.
   *
   * It used to be the file id, and that could not work: the server assigns the
   * id, and it assigns it in the response to the upload — by which point the
   * bytes have already been encrypted and sent. A caller would have had to
   * choose the id and talk the server into using it, which means a
   * client-chosen primary key and a uniqueness problem that is the server's to
   * lose.
   *
   * A random value chosen here does the same job. The point of binding was
   * never the id itself: it is that a server serving one file's bytes under
   * another's name produces something that does not open. Bound to a value the
   * sender picked and wrote into the encrypted metadata, a swap still fails,
   * and nobody has to agree on an id first.
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
 * What the ciphertext is bound to.
 *
 * The sender's own id for this attachment goes in, so bytes stored under one
 * cannot be served back under another and still open. A server that swapped two
 * members' uploads would otherwise produce files that decrypt perfectly and are
 * the wrong ones — and since the reader never saw the original, nothing would
 * look wrong.
 *
 * The conversation goes in for the reason `message-keys.ts` gives: the same
 * pair talking in two places must not be able to have a file replayed between
 * them.
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
 * Encrypt a file, ready to upload.
 *
 * Nothing has to be agreed with the server first. The value the ciphertext is
 * bound to is generated here and returned in `meta`, so a caller can encrypt,
 * upload, take whatever id the server hands back, and file the metadata under
 * it — see {@link SealedAttachmentKey.id}.
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
 * Turn the downloaded bytes back into the file.
 *
 * Throws when they do not open. There is no ordinary reason for that — unlike a
 * message, where a member who joined later legitimately has no key — so a
 * caller should say the file is broken rather than draw an empty one.
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
