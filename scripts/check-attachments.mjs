/* eslint-env node */

/**
 * A file the server stores and cannot read (GRYT-729).
 *
 * The words in a direct message have been unreadable to the server since
 * GRYT-718. The photographs hanging off them were not — an upload went up as
 * itself, was validated, thumbnailed, named and served back to anybody with the
 * link. So a conversation could be private and its pictures public, which is
 * the failure where the text is the part nobody needed.
 *
 * Every case here is one where getting it wrong looks like nothing being wrong.
 * A file that decrypts under the wrong id is the wrong file, drawn without
 * complaint, to somebody who never saw the original. A key that reaches the
 * envelope in the clear is a conversation that reads as encrypted and is not.
 *
 * Against `dist`, because dist is what a client installs.
 */

import assert from "node:assert/strict";

const {
  deriveDmKeyPair,
  openAttachment,
  openMessage,
  sealAttachment,
  sealMessage,
  asIdentityScope,
} = await import("../dist/index.js");

const SCOPE = asIdentityScope("srv:attachments");
const CONVERSATION = "dm_g0123456789abcdef0123456789abcdef";
const OTHER = "dm_gfedcba9876543210fedcba9876543210";

const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);
const alice = { id: "user_alice", keys: deriveDmKeyPair(seed(3), SCOPE) };
const bob = { id: "user_bob", keys: deriveDmKeyPair(seed(7), SCOPE) };
const carol = { id: "user_carol", keys: deriveDmKeyPair(seed(11), SCOPE) };

const asRecipient = (p) => ({ memberId: p.id, publicKey: p.keys.publicKey });
const pair = [alice, bob].map(asRecipient);

/** A file with bytes above 0x7f in it, which is where a lazy encoding breaks. */
const FILE = Uint8Array.from({ length: 5000 }, (_, i) => (i * 31) % 256);

const read = (sealed, person, conversation = CONVERSATION) =>
  openMessage({
    sealed,
    conversationId: conversation,
    memberId: person.id,
    recipientKeys: person.keys,
  });

/* ── the round trip, and the ciphertext is not the file ──────────────────── */

{
  const { ciphertext, meta } = sealAttachment({
    bytes: FILE,
    conversationId: CONVERSATION,
    fileId: "file_1",
    name: "holiday.jpg",
    mime: "image/jpeg",
    width: 4032,
    height: 3024,
  });

  assert.notDeepEqual(
    Array.from(ciphertext.subarray(0, 64)),
    Array.from(FILE.subarray(0, 64)),
    "the bytes went up as themselves",
  );
  assert.equal(ciphertext.length, FILE.length + 16, "GCM appends a 16-byte tag");

  const opened = openAttachment({
    ciphertext,
    conversationId: CONVERSATION,
    fileId: "file_1",
    meta,
  });
  assert.deepEqual(Array.from(opened), Array.from(FILE));

  // The size is the plaintext's, so a reader can draw "2.4 MB" without
  // downloading anything.
  assert.equal(meta.size, FILE.length);
  assert.equal(meta.name, "holiday.jpg");
  assert.equal(meta.mime, "image/jpeg");
  assert.equal(meta.width, 4032);
  assert.equal(meta.height, 3024);
}

/* ── two files never share a key ─────────────────────────────────────────── */

{
  const a = sealAttachment({ bytes: FILE, conversationId: CONVERSATION, fileId: "a" });
  const b = sealAttachment({ bytes: FILE, conversationId: CONVERSATION, fileId: "b" });

  assert.notEqual(a.meta.key, b.meta.key, "a key per file, not one per sender");
  assert.notEqual(a.meta.iv, b.meta.iv);
  // Same bytes, same length, different ciphertext. Identical output would mean
  // a server could tell two people sent the same file.
  assert.notDeepEqual(Array.from(a.ciphertext), Array.from(b.ciphertext));
}

/* ── bytes served back under another id do not open ──────────────────────── */

{
  const { ciphertext, meta } = sealAttachment({
    bytes: FILE,
    conversationId: CONVERSATION,
    fileId: "file_1",
  });

  // The case this exists for: a server that swaps two uploads hands a reader a
  // file that decrypts perfectly and is the wrong one, and the reader never saw
  // the original. Binding the id means it fails instead.
  assert.throws(
    () =>
      openAttachment({
        ciphertext,
        conversationId: CONVERSATION,
        fileId: "file_2",
        meta,
      }),
    "a file opened under a different id",
  );

  assert.throws(
    () =>
      openAttachment({
        ciphertext,
        conversationId: OTHER,
        fileId: "file_1",
        meta,
      }),
    "a file replayed into another conversation",
  );
}

/* ── the key rides inside the sealed message, and nowhere else ───────────── */

{
  const { meta } = sealAttachment({
    bytes: FILE,
    conversationId: CONVERSATION,
    fileId: "file_1",
    name: "receipts.pdf",
  });

  const sealed = await sealMessage({
    plaintext: "here it is",
    conversationId: CONVERSATION,
    senderKeys: alice.keys,
    recipients: pair,
    attachments: { file_1: meta },
  });

  const wire = JSON.stringify(sealed);
  assert.ok(!wire.includes(meta.key), "the file key is in the envelope in the clear");
  assert.ok(!wire.includes("receipts.pdf"), "the file name is in the envelope in the clear");

  const opened = await read(sealed, bob);
  assert.deepEqual(opened.attachments.file_1, meta,
    "the recipient has to get back exactly what the sender put in");
  assert.equal(opened.text, "here it is");
}

/* ── somebody with no wrapped key gets no file key either ────────────────── */

{
  const { meta } = sealAttachment({
    bytes: FILE,
    conversationId: CONVERSATION,
    fileId: "file_1",
  });

  const sealed = await sealMessage({
    plaintext: "not for carol",
    conversationId: CONVERSATION,
    senderKeys: alice.keys,
    recipients: pair,
    attachments: { file_1: meta },
  });

  assert.equal(await read(sealed, carol), null,
    "a late joiner must not get the file key by a different door than the text");
}

/* ── a file entry moved onto another file does not open ──────────────────── */

{
  const first = sealAttachment({ bytes: FILE, conversationId: CONVERSATION, fileId: "file_1" });
  const second = sealAttachment({ bytes: FILE, conversationId: CONVERSATION, fileId: "file_2" });

  const sealed = await sealMessage({
    plaintext: "two files",
    conversationId: CONVERSATION,
    senderKeys: alice.keys,
    recipients: pair,
    attachments: { file_1: first.meta, file_2: second.meta },
  });

  // Swapped by whoever stores the envelope. Without the file id in the wrapping
  // context this would hand back the wrong key, which then fails at the file —
  // reading like corruption rather than like tampering.
  const tampered = {
    ...sealed,
    files: { file_1: sealed.files.file_2, file_2: sealed.files.file_1 },
  };

  await assert.rejects(
    () => read(tampered, bob),
    "a file key moved onto another file was accepted",
  );
}

/* ── a message with no files is the same envelope it always was ──────────── */

{
  const sealed = await sealMessage({
    plaintext: "just words",
    conversationId: CONVERSATION,
    senderKeys: alice.keys,
    recipients: pair,
  });

  // `files` is left off entirely rather than written as `{}`, so every message
  // sealed before attachments existed is byte-identical to one sealed now and
  // `check-crypto-vectors.mjs` keeps meaning what it means.
  assert.equal("files" in sealed, false, "an empty files map changes the envelope");

  const opened = await read(sealed, bob);
  assert.deepEqual(opened.attachments, {},
    "a caller looping over attachments must not have to null-check first");
}

/* ── an empty file, and a one-byte one ───────────────────────────────────── */

{
  for (const size of [0, 1]) {
    const bytes = new Uint8Array(size);
    const { ciphertext, meta } = sealAttachment({
      bytes,
      conversationId: CONVERSATION,
      fileId: "edge",
    });
    assert.deepEqual(
      Array.from(openAttachment({ ciphertext, conversationId: CONVERSATION, fileId: "edge", meta })),
      Array.from(bytes),
      `${size} bytes did not survive the round trip`,
    );
  }
}

console.log(
  "attachments: a file per key, bound to its id and conversation, with the key only inside the sealed message",
);
