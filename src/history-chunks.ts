/**
 * The history chunk format (GRYT-1484): pairing sends history in it, and the stage 4 backup
 * will too, with its own key. See docs/pairing-design.md section 5 and mls-design section 5.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { deflateSync, inflateSync } from "fflate";

import { base64Url, base64UrlDecode } from "./base64";

export const HISTORY_KEY_BYTES = 32;
export const HISTORY_CHUNK_MAX_RECORDS = 1000;
/** Sealed, which is the relay's limit on one chunk. */
export const HISTORY_CHUNK_MAX_BYTES = 2 * 1024 * 1024;
/** Before compression. Leaves room for DEFLATE's worst case, so a sealed chunk always fits. */
export const HISTORY_CHUNK_MAX_RAW_BYTES = HISTORY_CHUNK_MAX_BYTES - 64 * 1024;

const LABEL = "gryt-history-chunk-v1";
const ID_BYTES = 16;
const NONCE_BYTES = 12;
const DAY_MS = 24 * 60 * 60 * 1000;

/** One archived message. `message` is the decrypted message as the archive keeps it. */
export interface HistoryRecord {
  scope: string;
  conversationId: string;
  messageId: string;
  /** Milliseconds since the epoch. */
  sentAt: number;
  message: unknown;
}

export interface HistoryChunkEntry {
  /** 16 random bytes, base64url. The chunk's key and associated data both depend on it. */
  id: string;
  scope: string;
  first: number;
  last: number;
  count: number;
  /** The sealed chunk's length and SHA-256 (base64url), so nothing can be swapped in. */
  bytes: number;
  sha256: string;
}

export interface HistoryManifest {
  v: 1;
  chunks: HistoryChunkEntry[];
}

const utf8 = (value: string) => new TextEncoder().encode(value);

function lp(bytes: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([bytes.length >> 8, bytes.length & 0xff]), bytes);
}

function chunkKey(historyKey: Uint8Array, id: Uint8Array): Uint8Array {
  if (historyKey.length !== HISTORY_KEY_BYTES) throw new Error(`A history key is ${HISTORY_KEY_BYTES} bytes.`);
  return hkdf(sha256, historyKey, utf8(LABEL), id, 32);
}

const aadFor = (id: Uint8Array, scope: string) => concatBytes(lp(utf8(LABEL)), lp(id), lp(utf8(scope)));
const dayOf = (sentAt: number) => Math.floor(sentAt / DAY_MS);
const isText = (v: unknown): v is string => typeof v === "string" && v !== "";
const isTime = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/** One spelling per value, so two entries can't name the same chunk differently. */
function isCanonical(text: string, length: number): boolean {
  try {
    const bytes = base64UrlDecode(text);
    return bytes.length === length && base64Url(bytes) === text;
  } catch {
    return false;
  }
}

/** A fresh key for one transfer. The backup passes its own seed-derived key instead. */
export function generateHistoryKey(): Uint8Array {
  return randomBytes(HISTORY_KEY_BYTES);
}

function checkRecord(value: unknown): HistoryRecord {
  const r = value as Partial<HistoryRecord> | null;
  if (!r || typeof r !== "object" || !isText(r.scope) || !isText(r.conversationId) || !isText(r.messageId)) {
    throw new Error("A history record needs a scope, a conversation id and a message id.");
  }
  if (!isTime(r.sentAt) || r.message === undefined) {
    throw new Error("A history record needs a time and a message.");
  }
  return { scope: r.scope, conversationId: r.conversationId, messageId: r.messageId, sentAt: r.sentAt, message: r.message };
}

/**
 * Records into chunks, newest UTC day first across all servers, then by scope. A chunk ends
 * at 1,000 records, a new day, a new scope, or the raw size limit, whichever comes first.
 */
export function planHistoryChunks(records: readonly HistoryRecord[]): HistoryRecord[][] {
  const sorted = records.map(checkRecord).sort((a, b) =>
    dayOf(b.sentAt) - dayOf(a.sentAt) ||
    (a.scope < b.scope ? -1 : a.scope > b.scope ? 1 : 0) ||
    b.sentAt - a.sentAt ||
    (a.messageId < b.messageId ? -1 : a.messageId > b.messageId ? 1 : 0));

  const chunks: HistoryRecord[][] = [];
  let current: HistoryRecord[] = [];
  let size = 2;
  for (const record of sorted) {
    const recordSize = utf8(JSON.stringify(record)).length + 1;
    if (recordSize + 2 > HISTORY_CHUNK_MAX_RAW_BYTES) throw new Error("One history record is too big for a chunk.");
    const head = current[0];
    if (head && (
      current.length === HISTORY_CHUNK_MAX_RECORDS ||
      head.scope !== record.scope ||
      dayOf(head.sentAt) !== dayOf(record.sentAt) ||
      size + recordSize > HISTORY_CHUNK_MAX_RAW_BYTES
    )) {
      chunks.push(current);
      current = [];
      size = 2;
    }
    current.push(record);
    size += recordSize;
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}

/** Compress and seal one chunk under a fresh id and nonce. Nothing about either is passed in. */
export function sealHistoryChunk(
  historyKey: Uint8Array,
  records: readonly HistoryRecord[],
): { entry: HistoryChunkEntry; sealed: Uint8Array } {
  const checked = records.map(checkRecord);
  const [head] = checked;
  if (!head || checked.length > HISTORY_CHUNK_MAX_RECORDS) {
    throw new Error(`A history chunk holds 1 to ${HISTORY_CHUNK_MAX_RECORDS} records.`);
  }
  if (checked.some((r) => r.scope !== head.scope || dayOf(r.sentAt) !== dayOf(head.sentAt))) {
    throw new Error("A history chunk holds one scope and one UTC day.");
  }
  const raw = utf8(JSON.stringify(checked));
  if (raw.length > HISTORY_CHUNK_MAX_RAW_BYTES) throw new Error("That history chunk is too big.");

  const id = randomBytes(ID_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const sealed = concatBytes(
    nonce,
    gcm(chunkKey(historyKey, id), nonce, aadFor(id, head.scope)).encrypt(deflateSync(raw)),
  );
  const times = checked.map((r) => r.sentAt);
  return {
    entry: {
      id: base64Url(id),
      scope: head.scope,
      first: Math.min(...times),
      last: Math.max(...times),
      count: checked.length,
      bytes: sealed.length,
      sha256: base64Url(sha256(sealed)),
    },
    sealed,
  };
}

/**
 * The records back, or a throw. The hash, the seal, the size, the scope, the count and the
 * times all have to match the manifest entry, which travels sealed separately.
 */
export function openHistoryChunk(
  historyKey: Uint8Array,
  entry: HistoryChunkEntry,
  sealed: Uint8Array,
): HistoryRecord[] {
  const checked = parseHistoryChunkEntry(entry);
  if (sealed.length !== checked.bytes || base64Url(sha256(sealed)) !== checked.sha256) {
    throw new Error("That history chunk isn't the one the manifest lists.");
  }
  const id = base64UrlDecode(checked.id);

  let raw: Uint8Array;
  try {
    const compressed = gcm(chunkKey(historyKey, id), sealed.subarray(0, NONCE_BYTES), aadFor(id, checked.scope))
      .decrypt(sealed.subarray(NONCE_BYTES));
    // One byte of room past the limit: filling it means the chunk was too big, not truncated.
    raw = inflateSync(compressed, { out: new Uint8Array(HISTORY_CHUNK_MAX_RAW_BYTES + 1) });
  } catch {
    throw new Error("That history chunk didn't open.");
  }
  if (raw.length > HISTORY_CHUNK_MAX_RAW_BYTES) throw new Error("That history chunk is too big.");

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    throw new Error("That history chunk isn't readable.");
  }
  if (!Array.isArray(parsed)) throw new Error("That history chunk isn't readable.");

  const records = parsed.map(checkRecord);
  const times = records.map((r) => r.sentAt);
  if (
    records.length !== checked.count ||
    records.some((r) => r.scope !== checked.scope) ||
    Math.min(...times) !== checked.first ||
    Math.max(...times) !== checked.last
  ) {
    throw new Error("That history chunk doesn't match its manifest entry.");
  }
  return records;
}

export function parseHistoryChunkEntry(value: unknown): HistoryChunkEntry {
  const e = value as Partial<HistoryChunkEntry> | null;
  const ok =
    !!e && typeof e === "object" &&
    isText(e.id) && isText(e.scope) && isText(e.sha256) &&
    isTime(e.first) && isTime(e.last) && e.first <= e.last &&
    Number.isSafeInteger(e.count) && e.count! >= 1 && e.count! <= HISTORY_CHUNK_MAX_RECORDS &&
    Number.isSafeInteger(e.bytes) && e.bytes! > NONCE_BYTES && e.bytes! <= HISTORY_CHUNK_MAX_BYTES;
  if (!ok || !isCanonical(e.id!, ID_BYTES) || !isCanonical(e.sha256!, 32)) {
    throw new Error("A history manifest entry isn't valid.");
  }
  return { id: e.id!, scope: e.scope!, first: e.first!, last: e.last!, count: e.count!, bytes: e.bytes!, sha256: e.sha256! };
}

/** The manifest from the pairing envelope's `history.manifest`. Ids have to be unique. */
export function parseHistoryManifest(value: unknown): HistoryManifest {
  const m = value as { v?: unknown; chunks?: unknown } | null;
  if (!m || typeof m !== "object" || m.v !== 1 || !Array.isArray(m.chunks)) {
    throw new Error("That history manifest isn't valid.");
  }
  const chunks = m.chunks.map(parseHistoryChunkEntry);
  if (new Set(chunks.map((c) => c.id)).size !== chunks.length) {
    throw new Error("A history manifest lists one chunk twice.");
  }
  return { v: 1, chunks };
}
