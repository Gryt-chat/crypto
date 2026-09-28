/**
 * Linking a device (GRYT-1484): the one-off keys, the commitment, the key schedule, the
 * sealed channel both ways, the emoji, the QR and the short code. See docs/pairing-design.md.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";

import { base64Url } from "./base64";
import { crockfordDecode, crockfordEncode, normalizeCrockford } from "./crockford";
import { PAIRING_EMOJI, type PairingEmoji } from "./pairing-emoji";

export const PAIRING_KEY_BYTES = 32;
export const PAIRING_SESSION_ID_BYTES = 16;

const LABEL = "gryt-pair-v1";
const N_TO_A = 1;
const A_TO_N = 2;
const NONCE_BYTES = 12;
/** The counter sits in the nonce's last four bytes, so it stops rather than wraps. */
const MAX_MESSAGES = 0xffffffff;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function expectLength(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new Error(`A pairing ${what} is ${length} bytes.`);
  }
  return bytes;
}

/** `lp` in the key schedule: a two-byte big-endian length, then the bytes. */
function lp(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error("Too long for a length prefix.");
  return concatBytes(new Uint8Array([bytes.length >> 8, bytes.length & 0xff]), bytes);
}

/** The public half. The secret lives in `secrets` and can be taken out exactly once. */
export interface PairingKey {
  readonly publicKey: Uint8Array;
}

const secrets = new WeakMap<PairingKey, Uint8Array>();

/**
 * A fresh X25519 key for one session. Passing `secret` is for known-answer tests only:
 * both sides reusing a secret with the same session id would reuse every nonce.
 */
export function createPairingKey(secret?: Uint8Array): PairingKey {
  const sk = secret
    ? Uint8Array.from(expectLength(secret, PAIRING_KEY_BYTES, "secret key"))
    : x25519.utils.randomSecretKey();
  const key: PairingKey = Object.freeze({ publicKey: x25519.getPublicKey(sk) });
  secrets.set(key, sk);
  return key;
}

function takeSecret(key: PairingKey): Uint8Array {
  const sk = secrets.get(key);
  if (!sk) throw new Error("That pairing key has been used already. Make a new one for each session.");
  secrets.delete(key);
  return sk;
}

/** What N sends the relay in place of its key: `SHA-256("gryt-pair-v1 commit" || pkN)`. */
export function pairingCommitment(newDevicePublicKey: Uint8Array): Uint8Array {
  expectLength(newDevicePublicKey, PAIRING_KEY_BYTES, "public key");
  return sha256(concatBytes(utf8(`${LABEL} commit`), newDevicePublicKey));
}

export interface PairingSession {
  /** Four emoji both screens show, from the shared secret and the whole transcript. */
  readonly emoji: readonly PairingEmoji[];
  /** `kc`, base64url: the device authorization's `nonce` and the extension's `binding`. */
  readonly keycloakNonce: string;
  /** Seal the next message to the other side. There is no nonce to pass, on purpose. */
  seal(plaintext: Uint8Array): Uint8Array;
  /** Open the other side's next message, in order. One failure closes the session. */
  open(sealed: Uint8Array): Uint8Array;
  /** Wipe the keys. Every later call throws. */
  close(): void;
}

export interface NewDeviceSessionInput {
  sessionId: Uint8Array;
  approverPublicKey: Uint8Array;
}

/** N's side, once the relay has passed on `pkA`. Uses up `key`. */
export function startNewDeviceSession(key: PairingKey, input: NewDeviceSessionInput): PairingSession {
  const sk = takeSecret(key);
  try {
    const pkN = key.publicKey;
    const pkA = expectLength(input.approverPublicKey, PAIRING_KEY_BYTES, "public key");
    return derive(sk, pkA, "n", input.sessionId, pairingCommitment(pkN), pkN, pkA);
  } finally {
    sk.fill(0);
  }
}

export interface ApproverSessionInput {
  sessionId: Uint8Array;
  /** What the relay handed over at the claim, before A sent `pkA`. */
  commitment: Uint8Array;
  /** What N revealed afterwards. */
  newDevicePublicKey: Uint8Array;
  /** `pkN` from the QR, when A scanned one rather than typing the code. */
  scannedPublicKey?: Uint8Array;
}

/** A's side, once N has revealed. Uses up `key`, even when the checks fail. */
export function startApproverSession(key: PairingKey, input: ApproverSessionInput): PairingSession {
  const sk = takeSecret(key);
  try {
    const pkN = expectLength(input.newDevicePublicKey, PAIRING_KEY_BYTES, "public key");
    const commit = expectLength(input.commitment, 32, "commitment");
    if (!equalBytes(pairingCommitment(pkN), commit)) {
      throw new Error("The new device's key doesn't match what it committed to.");
    }
    if (input.scannedPublicKey !== undefined && !equalBytes(input.scannedPublicKey, pkN)) {
      throw new Error("The new device's key doesn't match its QR code.");
    }
    return derive(sk, pkN, "a", input.sessionId, commit, pkN, key.publicKey);
  } finally {
    sk.fill(0);
  }
}

function derive(
  sk: Uint8Array,
  theirPublicKey: Uint8Array,
  side: "n" | "a",
  sessionId: Uint8Array,
  commit: Uint8Array,
  pkN: Uint8Array,
  pkA: Uint8Array,
): PairingSession {
  expectLength(sessionId, PAIRING_SESSION_ID_BYTES, "session id");

  const th = sha256(concatBytes(lp(utf8(LABEL)), lp(sessionId), lp(commit), lp(pkN), lp(pkA)));

  let dh: Uint8Array;
  try {
    dh = x25519.getSharedSecret(sk, theirPublicKey);
  } catch {
    throw new Error("The other device's pairing key isn't usable.");
  }

  const prk = extract(sha256, dh, th);
  dh.fill(0);
  const kNA = expand(sha256, prk, utf8(`${LABEL} n to a`), 32);
  const kAN = expand(sha256, prk, utf8(`${LABEL} a to n`), 32);
  const sas = expand(sha256, prk, utf8(`${LABEL} emoji`), 3);
  const kc = expand(sha256, prk, utf8(`${LABEL} keycloak`), 16);
  prk.fill(0);

  const bits = (sas[0] << 16) | (sas[1] << 8) | sas[2];
  const emoji = Object.freeze([18, 12, 6, 0].map((shift) => PAIRING_EMOJI[(bits >> shift) & 63]));

  const [sendKey, sendDirection, openKey, openDirection] =
    side === "n" ? [kNA, N_TO_A, kAN, A_TO_N] : [kAN, A_TO_N, kNA, N_TO_A];

  let sent = 0;
  let opened = 0;
  let closed = false;

  const nonceFor = (counter: number) => {
    const nonce = new Uint8Array(NONCE_BYTES);
    new DataView(nonce.buffer).setUint32(NONCE_BYTES - 4, counter);
    return nonce;
  };
  const close = () => {
    closed = true;
    sendKey.fill(0);
    openKey.fill(0);
  };
  const usable = (counter: number) => {
    if (closed) throw new Error("This pairing session is closed.");
    if (counter >= MAX_MESSAGES) throw new Error("This pairing session has sent all it can.");
  };

  return {
    emoji,
    keycloakNonce: base64Url(kc),
    seal(plaintext) {
      usable(sent);
      // Counted before sealing, so no failure path can hand the same nonce out twice.
      const nonce = nonceFor(sent++);
      const aad = concatBytes(th, new Uint8Array([sendDirection]), nonce);
      return gcm(sendKey, nonce, aad).encrypt(plaintext);
    },
    open(sealed) {
      usable(opened);
      const nonce = nonceFor(opened);
      const aad = concatBytes(th, new Uint8Array([openDirection]), nonce);
      try {
        const plaintext = gcm(openKey, nonce, aad).decrypt(sealed);
        opened++;
        return plaintext;
      } catch {
        close();
        throw new Error("A pairing message didn't open. It was changed, replayed or from another session.");
      }
    },
    close,
  };
}

// ── The QR ─────────────────────────────────────────────────────────────

// A leading `*` can't start a URI scheme, and `*` apart keeps `gryt:` out of the text
// entirely, so a system camera sees text and not a link to open Gryt with.
const QR_PREFIX = "GRYT";
const QR_SEPARATOR = "*";
const QR_VERSION = 1;

/** The session id as the relay and the QR spell it: 26 characters of Crockford base32. */
export function encodePairingSessionId(sessionId: Uint8Array): string {
  return crockfordEncode(expectLength(sessionId, PAIRING_SESSION_ID_BYTES, "session id"));
}

export function decodePairingSessionId(text: string): Uint8Array | null {
  return crockfordDecode(text, PAIRING_SESSION_ID_BYTES);
}

/**
 * An origin with no path, lower case. `https` anywhere, and `http` only on this machine,
 * so a relay the QR names can't be read in transit.
 */
function relayOrigin(value: string): string | null {
  const origin = value.toLowerCase();
  const port = "(:[0-9]{1,5})?";
  if (new RegExp(`^https://[a-z0-9-]+(\\.[a-z0-9-]+)*${port}$`).test(origin)) return origin;
  if (new RegExp(`^http://(localhost|127\\.0\\.0\\.1)${port}$`).test(origin)) return origin;
  return null;
}

export interface PairingQr {
  sessionId: Uint8Array;
  publicKey: Uint8Array;
  /** Only for a server with its own auth server. The caller checks it against A's own. */
  relayOrigin?: string;
}

export type ParsedPairingQr =
  | ({ ok: true } & PairingQr)
  | { ok: false; reason: "not-pairing" | "newer-version" | "malformed" };

/** `*GRYT*1*<session>*<pkN>[*<relay origin>]`, all upper case so QR's alphanumeric mode fits. */
export function formatPairingQr(qr: PairingQr): string {
  const parts = [
    QR_PREFIX,
    String(QR_VERSION),
    encodePairingSessionId(qr.sessionId),
    crockfordEncode(expectLength(qr.publicKey, PAIRING_KEY_BYTES, "public key")),
  ];
  if (qr.relayOrigin !== undefined) {
    const origin = relayOrigin(qr.relayOrigin);
    if (!origin) throw new Error("A relay origin is https://host, with an optional port.");
    parts.push(origin.toUpperCase());
  }
  return QR_SEPARATOR + parts.join(QR_SEPARATOR);
}

/** Strict: a scanner reads exactly what was drawn, so nothing here is forgiven. */
export function parsePairingQr(text: string): ParsedPairingQr {
  const parts = text.slice(1).split(QR_SEPARATOR);
  if (text[0] !== QR_SEPARATOR || parts.length < 2 || parts[0] !== QR_PREFIX) {
    return { ok: false, reason: "not-pairing" };
  }
  if (!/^[1-9][0-9]{0,5}$/.test(parts[1])) return { ok: false, reason: "malformed" };
  if (Number(parts[1]) > QR_VERSION) return { ok: false, reason: "newer-version" };
  if (parts.length < 4) return { ok: false, reason: "malformed" };

  const sessionId = decodePairingSessionId(parts[2]);
  const publicKey = crockfordDecode(parts[3], PAIRING_KEY_BYTES);
  if (!sessionId || !publicKey) return { ok: false, reason: "malformed" };
  if (parts.length === 4) return { ok: true, sessionId, publicKey };

  const origin = parts.length === 5 ? relayOrigin(parts[4]) : null;
  if (!origin) return { ok: false, reason: "malformed" };
  return { ok: true, sessionId, publicKey, relayOrigin: origin };
}

// ── The short code ─────────────────────────────────────────────────────

/** Eight characters of Crockford base32: 40 bits, and a handle for the relay, not a key. */
export const PAIRING_CODE_LENGTH = 8;
export const PAIRING_CODE_BITS = PAIRING_CODE_LENGTH * 5;
const CODE_BYTES = PAIRING_CODE_BITS / 8;

/** The canonical form, without the dash. The relay makes these; the apps only read them. */
export function generatePairingCode(): string {
  const bytes = new Uint8Array(CODE_BYTES);
  crypto.getRandomValues(bytes);
  return crockfordEncode(bytes);
}

/** `XXXX-XXXX`, for the screen. */
export function formatPairingCode(code: string): string {
  const canonical = parsePairingCode(code);
  if (!canonical) throw new Error("That isn't a pairing code.");
  return `${canonical.slice(0, 4)}-${canonical.slice(4)}`;
}

/** Typed text back to the canonical code, or null. Case, dashes, O, I and L are forgiven. */
export function parsePairingCode(text: string): string | null {
  const clean = normalizeCrockford(text);
  return crockfordDecode(clean, CODE_BYTES) ? clean : null;
}
