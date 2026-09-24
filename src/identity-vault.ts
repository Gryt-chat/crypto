/**
 * The seed, sealed so the account can carry it to a second device (GRYT-783). Version 2
 * adds key slots and Argon2id; version 1 keeps opening exactly as it did (GRYT-1473).
 */
import { gcm } from "@noble/ciphers/aes.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64Url, base64UrlDecode } from "./base64";
import { parseRecoveryKey, RECOVERY_KEY_BYTES } from "./recovery-key";

export const VAULT_TYPE = "gryt-identity-vault";
export const VAULT_VERSION = 2;

/** `m` is in KiB, so this is 64 MiB. RFC 9106's second option with `p` dropped to one. */
export const VAULT_ARGON2ID = { m: 65536, t: 3, p: 1 } as const;

/** What version 1 was sealed at. Read, never written. */
export const VAULT_V1_PBKDF2_ITERATIONS = 600_000;

/* The most a stored bundle may ask a device to spend. Past this it is refused, so the
   account cannot make every sign-in allocate a gigabyte. */
const MAX_ARGON2ID = { m: 262144, t: 10, p: 4 } as const;
const MAX_PBKDF2_ITERATIONS = 10_000_000;

const KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;

/** How the secret was chosen. Presentation only, never mixed into a key. */
export type VaultSecretKind = "phrase" | "password";

/** Argon2id's cost. `m` is in KiB. */
export interface Argon2idParams {
  m: number;
  t: number;
  p: number;
}

/**
 * The slow KDFs, supplied by the platform: WASM on the web, native on a phone. Both return
 * 32 bytes, and `check-identity-vault.mjs` holds the answers they must agree on.
 */
export interface VaultKdfs {
  argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2idParams): Promise<Uint8Array>;
  /** Only for opening version 1. */
  pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array>;
}

/** Pure JS, from `@noble/hashes`. Correct everywhere, and far too slow on a phone. */
export const referenceVaultKdfs: VaultKdfs = {
  argon2id: (password, salt, { m, t, p }) =>
    argon2idAsync(password, salt, { m, t, p, dkLen: KEY_BYTES }),
  pbkdf2Sha256: (password, salt, iterations) =>
    pbkdf2Async(sha256, password, salt, { c: iterations, dkLen: KEY_BYTES }),
};

export interface SealedVaultV1 {
  type: typeof VAULT_TYPE;
  version: 1;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  secretKind: VaultSecretKind;
  salt: string;
  iv: string;
  data: string;
}

export interface PasswordSlot extends Argon2idParams {
  kind: "password";
  kdf: "argon2id";
  salt: string;
  iv: string;
  /** The content key, wrapped. */
  key: string;
}

export interface RecoverySlot {
  kind: "recovery";
  kdf: "hkdf-sha256";
  salt: string;
  iv: string;
  key: string;
}

export type VaultSlot = PasswordSlot | RecoverySlot;

export interface SealedVaultV2 {
  type: typeof VAULT_TYPE;
  version: 2;
  secretKind: VaultSecretKind;
  /* Always empty. Clients before this only recognise a vault that has a `salt`, and offer
     to set a password over one that has none instead of saying they are too old. */
  salt: "";
  /** The seed, under a random content key that each slot wraps. */
  iv: string;
  data: string;
  slots: VaultSlot[];
}

export type SealedVault = SealedVaultV1 | SealedVaultV2;

export interface SealSeedOptions {
  password: string;
  secretKind?: VaultSecretKind;
  /** 32 bytes from `generateRecoveryKey`. Omitted, the vault has no recovery slot. */
  recoveryKey?: Uint8Array;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/** NFC, so one password typed on a Mac and on Android is the same bytes. */
const passwordBytes = (password: string) => utf8(password.normalize("NFC"));

const dataAad = (version: number) => utf8(`${VAULT_TYPE}:v${version}`);
const slotAad = (kind: VaultSlot["kind"]) => utf8(`${VAULT_TYPE}:v2:${kind}`);

function recoveryWrappingKey(recoveryKey: Uint8Array, salt: Uint8Array): Uint8Array {
  return hkdf(sha256, recoveryKey, salt, utf8(`${VAULT_TYPE}:v2:recovery`), KEY_BYTES);
}

const isString = (v: unknown): v is string => typeof v === "string";

function isSlot(value: unknown): value is VaultSlot {
  const s = value as Record<string, unknown> | null;
  if (!s || !isString(s.salt) || !isString(s.iv) || !isString(s.key)) return false;
  if (s.kind === "recovery") return s.kdf === "hkdf-sha256";
  return (
    s.kind === "password" &&
    s.kdf === "argon2id" &&
    Number.isInteger(s.m) &&
    Number.isInteger(s.t) &&
    Number.isInteger(s.p)
  );
}

/**
 * Whether a blob is a vault this code can try. A slot of a kind it does not know is
 * skipped when opening, not refused, so a third kind can arrive without a format change.
 */
export function isSealedVault(value: unknown): value is SealedVault {
  const v = value as { type?: unknown; version?: unknown; salt?: unknown; iv?: unknown; data?: unknown; slots?: unknown } | null;
  if (!v || v.type !== VAULT_TYPE || !isString(v.iv) || !isString(v.data)) return false;
  if (v.version === 1) return isString(v.salt);
  if (v.version === 2) return Array.isArray(v.slots);
  return false;
}

/** Whether a vault should be re-sealed the next time its secret is in hand. */
export function vaultNeedsUpgrade(vault: SealedVault): boolean {
  // Defensive: a caller may be holding a newer vault it could not type.
  if (!isSealedVault(vault)) return false;
  if (vault.version === 1) return true;
  const slot = vault.slots.find((s): s is PasswordSlot => isSlot(s) && s.kind === "password");
  if (!slot) return false;
  return slot.m < VAULT_ARGON2ID.m || slot.t < VAULT_ARGON2ID.t;
}

/** Whether a recovery key opens this vault. */
export function vaultHasRecoverySlot(vault: SealedVault): boolean {
  return isSealedVault(vault) && vault.version === 2 && vault.slots.some((s) => isSlot(s) && s.kind === "recovery");
}

/**
 * Seal a seed as version 2 at {@link VAULT_ARGON2ID}. **No password floor here:** re-sealing
 * an old four-character password has to work, so the floor is the UI's.
 */
export async function sealSeed(
  seed: Uint8Array,
  { password, secretKind = "password", recoveryKey }: SealSeedOptions,
  kdfs: VaultKdfs = referenceVaultKdfs,
): Promise<SealedVaultV2> {
  if (!password) throw new Error("Choose a password before sealing the seed.");
  if (seed.length === 0) throw new Error("There is no seed to seal.");
  if (recoveryKey && recoveryKey.length !== RECOVERY_KEY_BYTES) {
    throw new Error(`A recovery key is ${RECOVERY_KEY_BYTES} bytes.`);
  }

  const contentKey = randomBytes(KEY_BYTES);
  const iv = randomBytes(IV_BYTES);
  const data = gcm(contentKey, iv, dataAad(2)).encrypt(seed);

  const passwordSalt = randomBytes(SALT_BYTES);
  const passwordIv = randomBytes(IV_BYTES);
  const passwordKey = await kdfs.argon2id(passwordBytes(password), passwordSalt, VAULT_ARGON2ID);
  if (passwordKey.length !== KEY_BYTES) throw new Error("Argon2id returned the wrong length.");

  const slots: VaultSlot[] = [
    {
      kind: "password",
      kdf: "argon2id",
      ...VAULT_ARGON2ID,
      salt: base64Url(passwordSalt),
      iv: base64Url(passwordIv),
      key: base64Url(gcm(passwordKey, passwordIv, slotAad("password")).encrypt(contentKey)),
    },
  ];

  if (recoveryKey) {
    const salt = randomBytes(SALT_BYTES);
    const slotIv = randomBytes(IV_BYTES);
    const wrapping = recoveryWrappingKey(recoveryKey, salt);
    slots.push({
      kind: "recovery",
      kdf: "hkdf-sha256",
      salt: base64Url(salt),
      iv: base64Url(slotIv),
      key: base64Url(gcm(wrapping, slotIv, slotAad("recovery")).encrypt(contentKey)),
    });
  }

  return {
    type: VAULT_TYPE,
    version: 2,
    secretKind,
    salt: "",
    iv: base64Url(iv),
    data: base64Url(data),
    slots,
  };
}

const WRONG = "Wrong password, or this sealed identity has been altered.";
const TOO_COSTLY = "This sealed identity asks for more work than Gryt will do to open it.";

/* AES-GCM fails the same way for a wrong key and an altered blob, and the wrong key is
   overwhelmingly the likely one, so the message leads with it. */
function openOrNull(key: Uint8Array, iv: string, aad: Uint8Array, data: string): Uint8Array | null {
  try {
    return gcm(key, base64UrlDecode(iv), aad).decrypt(base64UrlDecode(data));
  } catch {
    return null;
  }
}

async function openV1(vault: SealedVaultV1, secret: string, kdfs: VaultKdfs): Promise<Uint8Array> {
  const iterations = typeof vault.iterations === "number" ? vault.iterations : VAULT_V1_PBKDF2_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error(TOO_COSTLY);
  }
  // Not normalised: version 1 hashed the string exactly as it was typed.
  const key = await kdfs.pbkdf2Sha256(utf8(secret), base64UrlDecode(vault.salt), iterations);
  const seed = openOrNull(key, vault.iv, dataAad(1), vault.data);
  if (!seed) throw new Error(WRONG);
  return seed;
}

async function contentKeyFrom(
  vault: SealedVaultV2,
  secret: string,
  kdfs: VaultKdfs,
): Promise<Uint8Array | null> {
  const slots = vault.slots.filter(isSlot);

  // Tried first when the text parses as a recovery key. A password that happens to look
  // like one still falls through to the password slot.
  const recoveryKey = parseRecoveryKey(secret);
  if (recoveryKey) {
    for (const slot of slots) {
      if (slot.kind !== "recovery") continue;
      const wrapping = recoveryWrappingKey(recoveryKey, base64UrlDecode(slot.salt));
      const key = openOrNull(wrapping, slot.iv, slotAad("recovery"), slot.key);
      if (key) return key;
    }
  }

  for (const slot of slots) {
    if (slot.kind !== "password") continue;
    const { m, t, p } = slot;
    if (m > MAX_ARGON2ID.m || t > MAX_ARGON2ID.t || p > MAX_ARGON2ID.p || t < 1 || p < 1 || m < 8 * p) {
      throw new Error(TOO_COSTLY);
    }
    const wrapping = await kdfs.argon2id(passwordBytes(secret), base64UrlDecode(slot.salt), { m, t, p });
    const key = openOrNull(wrapping, slot.iv, slotAad("password"), slot.key);
    if (key) return key;
  }

  return null;
}

/**
 * Open a vault with its password, or a recovery key typed into the same field. The path
 * comes from `version` and nothing is guessed. Throws on a wrong secret or altered blob.
 */
export async function openSeed(
  vault: unknown,
  secret: string,
  kdfs: VaultKdfs = referenceVaultKdfs,
): Promise<Uint8Array> {
  if (!isSealedVault(vault)) {
    const v = vault as { type?: unknown; version?: unknown } | null;
    const newer = v?.type === VAULT_TYPE && typeof v.version === "number" && v.version > VAULT_VERSION;
    throw new Error(
      newer ? "This sealed identity was written by a newer version of Gryt." : "That is not a sealed Gryt identity.",
    );
  }
  if (!secret) throw new Error(WRONG);

  if (vault.version === 1) return openV1(vault, secret, kdfs);

  const contentKey = await contentKeyFrom(vault, secret, kdfs);
  const seed = contentKey && openOrNull(contentKey, vault.iv, dataAad(2), vault.data);
  if (!seed) throw new Error(WRONG);
  return seed;
}
