/**
 * What A seals to N on Approve (GRYT-1484): the seed, the keys, the account, the servers,
 * the pins and the history key. JSON, sealed with the session's `seal`, never over 256 KiB.
 */

import { base64Url, base64UrlDecode } from "./base64";
import { type HistoryManifest, parseHistoryManifest } from "./history-chunks";
import { type IdentityBackupEntry, isIdentityBackupEntry } from "./identity-backup";
import type { PeerPin } from "./peer-keys";
import { asIdentityScope, type IdentityScope } from "./scope";

export const PAIRING_ENVELOPE_VERSION = 1;
export const PAIRING_ENVELOPE_MAX_BYTES = 256 * 1024;
const KEY_BYTES = 32;

/** Which Keycloak N signs in with, and which account it has to end up as. Absent for a guest. */
export interface PairingAccount {
  issuer: string;
  clientId: string;
  identityUrl: string;
  sub: string;
  username: string;
}

export interface PairingServer {
  host: string;
  name: string;
  /** From A's server pins. N derives its guest key under this, never its own guess. */
  scope: IdentityScope;
  nickname?: string;
  scheme?: "http" | "https";
}

export interface PairingPin extends PeerPin {
  /** Decision 4: once seen on MLS, never sealed to with version 1 again. */
  seenOnMls?: boolean;
}

export interface PairingHistory {
  /** 32 random bytes, made for this transfer. */
  key: Uint8Array;
  /** The snapshot manifest, checked by the chunk format's own parser. */
  manifest: HistoryManifest;
}

export interface PairingEnvelope {
  seed: Uint8Array;
  /** Stored keys the seed can't derive, as `exportLocalIdentities` writes them. */
  keys: IdentityBackupEntry[];
  account?: PairingAccount;
  servers: PairingServer[];
  /** By scope, then member id. */
  pins: Record<string, Record<string, PairingPin>>;
  history?: PairingHistory;
  /** A's device name, for "linked from". */
  from: string;
}

function refuse(field: string): never {
  throw new Error(`The pairing envelope's ${field} isn't valid.`);
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const isText = (v: unknown): v is string => typeof v === "string" && v !== "";
const isTime = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0;

/** `https`, or `http` on this machine only. N signs in wherever this points. */
function isSecureUrl(v: unknown): v is string {
  return typeof v === "string" && /^(https:\/\/[^/\s]+|http:\/\/(localhost|127\.0\.0\.1)(:\d+)?)(\/\S*)?$/i.test(v);
}

function bytesOf(value: unknown, length: number | null, field: string): Uint8Array {
  if (typeof value !== "string") refuse(field);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    refuse(field);
  }
  if (length === null ? bytes.length === 0 : bytes.length !== length) refuse(field);
  return bytes;
}

/** A plain map, with no key that could reach a prototype when somebody copies it later. */
function entriesOf(value: unknown, field: string): [string, unknown][] {
  if (!isObject(value)) refuse(field);
  const entries = Object.entries(value);
  if (entries.some(([key]) => key === "" || key === "__proto__")) refuse(field);
  return entries;
}

function readPin(value: unknown): PairingPin {
  if (!isObject(value)) refuse("pins");
  const { thumbprint, dmPublicKey, personPublicKey, firstSeenAt, lastSeenAt, comparedAt, seenOnMls } = value;
  if (!isText(thumbprint) || !isTime(firstSeenAt) || !isTime(lastSeenAt)) refuse("pins");
  bytesOf(dmPublicKey, KEY_BYTES, "pins");
  if (personPublicKey !== undefined) bytesOf(personPublicKey, null, "pins");
  if (comparedAt !== undefined && !isTime(comparedAt)) refuse("pins");
  if (seenOnMls !== undefined && typeof seenOnMls !== "boolean") refuse("pins");

  const pin: PairingPin = { thumbprint, dmPublicKey: dmPublicKey as string, firstSeenAt, lastSeenAt };
  if (personPublicKey !== undefined) pin.personPublicKey = personPublicKey as string;
  if (comparedAt !== undefined) pin.comparedAt = comparedAt;
  if (seenOnMls !== undefined) pin.seenOnMls = seenOnMls;
  return pin;
}

function readServer(value: unknown): PairingServer {
  if (!isObject(value)) refuse("servers");
  const { host, name, scope, nickname, scheme } = value;
  if (!isText(host) || typeof name !== "string" || !isText(scope)) refuse("servers");
  if (nickname !== undefined && typeof nickname !== "string") refuse("servers");
  if (scheme !== undefined && scheme !== "http" && scheme !== "https") refuse("servers");

  const server: PairingServer = { host, name, scope: asIdentityScope(scope) };
  if (nickname !== undefined) server.nickname = nickname;
  if (scheme !== undefined) server.scheme = scheme;
  return server;
}

function readAccount(value: unknown): PairingAccount {
  if (!isObject(value)) refuse("account");
  const { issuer, clientId, identityUrl, sub, username } = value;
  if (!isSecureUrl(issuer) || !isSecureUrl(identityUrl)) refuse("account");
  if (!isText(clientId) || !isText(sub) || !isText(username)) refuse("account");
  return { issuer, clientId, identityUrl, sub, username };
}

/**
 * The envelope from its bytes, or a throw. Fields it doesn't know are dropped, and what it
 * returns is built fresh, so nothing N didn't check gets written.
 */
export function decodePairingEnvelope(bytes: Uint8Array): PairingEnvelope {
  if (bytes.length > PAIRING_ENVELOPE_MAX_BYTES) refuse("size");
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    refuse("encoding");
  }
  if (!isObject(raw)) refuse("encoding");
  if (typeof raw.v === "number" && raw.v > PAIRING_ENVELOPE_VERSION) {
    throw new Error("This device was linked from a newer version of Gryt. Update this one first.");
  }
  if (raw.v !== PAIRING_ENVELOPE_VERSION) refuse("version");

  const seed = bytesOf(raw.seed, KEY_BYTES, "seed");
  if (seed.every((byte) => byte === seed[0])) refuse("seed");

  if (!Array.isArray(raw.keys) || !raw.keys.every(isIdentityBackupEntry)) refuse("keys");
  const keys = raw.keys.map(({ scope, host, privateJwk, publicJwk }) =>
    host === undefined ? { scope, privateJwk, publicJwk } : { scope, host, privateJwk, publicJwk },
  );

  if (!Array.isArray(raw.servers)) refuse("servers");
  const servers = raw.servers.map(readServer);

  const pins = Object.fromEntries(
    entriesOf(raw.pins, "pins").map(([scope, members]) => [
      scope,
      Object.fromEntries(entriesOf(members, "pins").map(([member, pin]) => [member, readPin(pin)])),
    ]),
  );

  if (typeof raw.from !== "string") refuse("from");
  const envelope: PairingEnvelope = { seed, keys, servers, pins, from: raw.from };

  if (raw.account !== undefined) envelope.account = readAccount(raw.account);
  if (raw.history !== undefined) {
    if (!isObject(raw.history)) refuse("history");
    let manifest: HistoryManifest;
    try {
      manifest = parseHistoryManifest(raw.history.manifest);
    } catch {
      refuse("history");
    }
    envelope.history = { key: bytesOf(raw.history.key, KEY_BYTES, "history"), manifest };
  }
  return envelope;
}

function serialize(envelope: PairingEnvelope): Uint8Array {
  const { seed, keys, account, servers, pins, history, from } = envelope;
  return new TextEncoder().encode(
    JSON.stringify({
      v: PAIRING_ENVELOPE_VERSION,
      seed: base64Url(seed),
      keys,
      account,
      servers,
      pins,
      history: history && { key: base64Url(history.key), manifest: history.manifest },
      from,
    }),
  );
}

/** Written from what the decoder accepts, so it never sends what N would refuse, or extras. */
export function encodePairingEnvelope(envelope: PairingEnvelope): Uint8Array {
  return serialize(decodePairingEnvelope(serialize(envelope)));
}
