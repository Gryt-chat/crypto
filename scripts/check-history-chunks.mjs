/* eslint-env node */

/**
 * The history chunk format (GRYT-1484). The vector is what the phone and the desktop open
 * to check themselves. If it stops opening, the format moved: don't regenerate it.
 */

import assert from "node:assert/strict";

import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { deflateSync, inflateSync } from "fflate";

import {
  base64Url,
  base64UrlDecode,
  generateHistoryKey,
  HISTORY_CHUNK_MAX_RAW_BYTES,
  HISTORY_CHUNK_MAX_RECORDS,
  openHistoryChunk,
  parseHistoryManifest,
  planHistoryChunks,
  sealHistoryChunk,
} from "../dist/index.js";

const utf8 = (s) => new TextEncoder().encode(s);
const KEY = Uint8Array.from({ length: 32 }, (_, i) => (i * 3 + 1) % 251);
const DAY = 24 * 60 * 60 * 1000;
const T = 1790000000000;

const RECORDS = [
  { scope: "srv:vectors", conversationId: "dm_1", messageId: "m1", sentAt: T, message: { text: "hello", reactions: { "👍": ["u2"] } } },
  { scope: "srv:vectors", conversationId: "dm_1", messageId: "m2", sentAt: T + 60000, message: { text: "second", edits: [{ text: "2nd", at: T + 70000 }] } },
  { scope: "srv:vectors", conversationId: "dm_2", messageId: "m3", sentAt: T + 120000, message: { text: "photo", attachments: [{ id: "a1", key: "k" }] } },
];

const ENTRY = {
  id: "pk-T8CEhRUA_X2484Fl93g", scope: "srv:vectors", first: T, last: T + 120000, count: 3, bytes: 224,
  sha256: "cRFT-snm_hFVnqJLIn5cMtj7G6wkq9YtTo-LCiGrdCw",
};
const SEALED = base64UrlDecode(
  "FNsmKcUE9CHSpmP_ng47p9sl8kXAzSD28_KWOFXpbav56rcNU-G5nod6f2_eBjCcw0y09EtuKaG8v61uf4H-qAnJ0tQq7Yw4iJI0VilqCrMKFjnByo5Olqfb861Orhw16AMZg-v4Rmj4FPZE1Op7GB_fHEmVqizElEiIBYaLm4OVN6YdkAxHmxedyElguXMU-AcT1v7-cMWH9RPC-GuIvtlZyA_TVoD62_1KlOwqPmQabSJFZnv4KasYnObtzUwj_mTdtpD7wOpFojoHTLuJeIAGMsVdq8u-sYO8apNW8b8",
);

const record = (scope, sentAt, n) => ({ scope, conversationId: "dm", messageId: `m${n}`, sentAt, message: { text: `t${n}` } });

/* ── the fixed vector opens ─────────────────────────────────────────────── */

{
  assert.deepEqual(openHistoryChunk(KEY, ENTRY, SEALED), RECORDS);
}

/* ── and opens again with the format written out from the doc ───────────── */

{
  // nonce || AES-256-GCM(HKDF(key, salt "gryt-history-chunk-v1", info id), raw DEFLATE of JSON).
  const lp = (b) => Uint8Array.from([b.length >> 8, b.length & 0xff, ...b]);
  const id = base64UrlDecode(ENTRY.id);
  const label = utf8("gryt-history-chunk-v1");
  const aad = Uint8Array.from([...lp(label), ...lp(id), ...lp(utf8("srv:vectors"))]);
  const chunkKey = hkdf(sha256, KEY, label, id, 32);
  const compressed = gcm(chunkKey, SEALED.subarray(0, 12), aad).decrypt(SEALED.subarray(12));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(inflateSync(compressed))), RECORDS);
  assert.equal(base64Url(sha256(SEALED)), ENTRY.sha256);
}

/* ── round trips, and every seal is fresh ───────────────────────────────── */

{
  const key = generateHistoryKey();
  const a = sealHistoryChunk(key, RECORDS);
  const b = sealHistoryChunk(key, RECORDS);
  assert.deepEqual(openHistoryChunk(key, a.entry, a.sealed), RECORDS);
  assert.notEqual(a.entry.id, b.entry.id, "a new id, so a new key, every time");
  assert.notEqual(base64Url(a.sealed.subarray(0, 12)), base64Url(b.sealed.subarray(0, 12)));
  assert.equal(sealHistoryChunk.length, 2, "no id or nonce can be passed in");
  assert.deepEqual(parseHistoryManifest(JSON.parse(JSON.stringify({ v: 1, chunks: [a.entry, b.entry] }))).chunks,
    [a.entry, b.entry], "the manifest survives the trip through the envelope's JSON");
}

/* ── the relay can't swap, change or reorder a chunk ────────────────────── */

{
  const key = generateHistoryKey();
  const one = sealHistoryChunk(key, RECORDS);
  const two = sealHistoryChunk(key, [record("srv:vectors", T, 9)]);

  assert.throws(() => openHistoryChunk(key, one.entry, two.sealed), /isn't the one the manifest lists/);
  for (const position of [0, 11, 12, 40, one.sealed.length - 1]) {
    const bad = Uint8Array.from(one.sealed);
    bad[position] ^= 1;
    assert.throws(() => openHistoryChunk(key, one.entry, bad), /isn't the one/, `flipping byte ${position}`);
  }
  assert.throws(() => openHistoryChunk(generateHistoryKey(), one.entry, one.sealed), /didn't open/, "another key");

  // An entry rewritten to match other bytes still fails the seal: the id and scope are bound in.
  const rehashed = { ...one.entry, id: two.entry.id };
  assert.throws(() => openHistoryChunk(key, rehashed, one.sealed), /didn't open/);
  assert.throws(() => openHistoryChunk(key, { ...one.entry, scope: "srv:other" }, one.sealed), /didn't open/);
  assert.throws(() => openHistoryChunk(key, { ...one.entry, count: 2 }, one.sealed), /doesn't match/);
  assert.throws(() => openHistoryChunk(key, { ...one.entry, last: T }, one.sealed), /doesn't match/);
}

/* ── a chunk holds one scope, one day, 1 to 1,000 records ───────────────── */

{
  const key = generateHistoryKey();
  assert.throws(() => sealHistoryChunk(key, []), /1 to 1000/);
  assert.throws(() => sealHistoryChunk(key, [record("a", T, 1), record("b", T, 2)]), /one scope/);
  assert.throws(() => sealHistoryChunk(key, [record("a", T, 1), record("a", T + DAY, 2)]), /one UTC day/);
  const many = Array.from({ length: 1001 }, (_, i) => record("a", T, i));
  assert.throws(() => sealHistoryChunk(key, many), /1 to 1000/);
  assert.throws(() => sealHistoryChunk(key, [{ ...record("a", T, 1), sentAt: 1.5 }]), /time/);
  assert.throws(() => sealHistoryChunk(new Uint8Array(16), RECORDS), /32 bytes/);
}

/* ── planning: newest day first, then scope, split at 1,000 ─────────────── */

{
  const day1 = Date.UTC(2026, 8, 1, 12);
  const day2 = day1 + DAY;
  const input = [
    record("srv:b", day1, 1), record("srv:a", day1 + 1000, 2), record("srv:a", day2, 3),
    ...Array.from({ length: 1500 }, (_, i) => record("srv:c", day2 + i, 100 + i)),
  ];
  const chunks = planHistoryChunks(input);
  assert.deepEqual(chunks.map((c) => [c[0].scope, c.length]),
    [["srv:a", 1], ["srv:c", HISTORY_CHUNK_MAX_RECORDS], ["srv:c", 500], ["srv:a", 1], ["srv:b", 1]]);
  assert.equal(chunks[1][0].sentAt, day2 + 1499, "newest first inside a day too");
  for (const chunk of chunks) sealHistoryChunk(generateHistoryKey(), chunk);
  assert.equal(planHistoryChunks([record("srv:a", day1, 1), record("srv:a", day2, 2)]).length, 2,
    "midnight UTC ends a chunk even when the scope stays the same");

  const big = "x".repeat(400_000);
  const heavy = Array.from({ length: 12 }, (_, i) => ({ ...record("srv:a", day1 + i, i), message: { text: big } }));
  const split = planHistoryChunks(heavy);
  assert.ok(split.length > 1, "splits on size before the relay's 2 MiB limit");
  for (const chunk of split) {
    assert.ok(utf8(JSON.stringify(chunk)).length <= HISTORY_CHUNK_MAX_RAW_BYTES);
    assert.ok(sealHistoryChunk(generateHistoryKey(), chunk).sealed.length <= 2 * 1024 * 1024);
  }
  assert.throws(() => planHistoryChunks([{ ...record("a", T, 1), message: "x".repeat(HISTORY_CHUNK_MAX_RAW_BYTES) }]),
    /too big/);
}

/* ── a chunk that inflates past the limit is refused, not truncated ─────── */

{
  const key = generateHistoryKey();
  const id = new Uint8Array(16).fill(7);
  const nonce = new Uint8Array(12);
  const lp = (b) => Uint8Array.from([b.length >> 8, b.length & 0xff, ...b]);
  const label = utf8("gryt-history-chunk-v1");
  const bomb = deflateSync(new Uint8Array(HISTORY_CHUNK_MAX_RAW_BYTES + 100).fill(0x20));
  const aad = Uint8Array.from([...lp(label), ...lp(id), ...lp(utf8("a"))]);
  const sealed = Uint8Array.from([...nonce, ...gcm(hkdf(sha256, key, label, id, 32), nonce, aad).encrypt(bomb)]);
  const entry = { id: base64Url(id), scope: "a", first: T, last: T, count: 1, bytes: sealed.length, sha256: base64Url(sha256(sealed)) };
  assert.throws(() => openHistoryChunk(key, entry, sealed), /too big/);
}

/* ── the manifest ───────────────────────────────────────────────────────── */

{
  const bad = (chunks, pattern = /isn't valid/) => assert.throws(() => parseHistoryManifest({ v: 1, chunks }), pattern);
  assert.throws(() => parseHistoryManifest({ v: 2, chunks: [] }), /isn't valid/);
  bad([ENTRY, ENTRY], /twice/);
  bad([{ ...ENTRY, id: ENTRY.id.slice(0, -1) }]);
  bad([{ ...ENTRY, id: ENTRY.id.replace(/-/g, "+") }], /isn't valid/);
  bad([{ ...ENTRY, first: ENTRY.last + 1 }]);
  bad([{ ...ENTRY, count: 0 }]);
  bad([{ ...ENTRY, count: 1001 }]);
  bad([{ ...ENTRY, bytes: 2 * 1024 * 1024 + 1 }]);
  bad([{ ...ENTRY, scope: "" }]);
  assert.deepEqual(parseHistoryManifest({ v: 1, chunks: [{ ...ENTRY, extra: 1 }] }).chunks, [ENTRY]);
}

console.log("history-chunks: the vector opens by the doc's recipe, a swapped or changed chunk is refused, and chunks stay under the relay's limit");
