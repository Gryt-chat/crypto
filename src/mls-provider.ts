/**
 * The crypto under `ts-mls`, for suite 1 only, on `@noble` with no WebCrypto: Hermes has no
 * `crypto.subtle`. One provider on every platform, so a quirk can't split a group.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { expand as hkdfExpand, extract as hkdfExtract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import type {
  Ciphersuite,
  CiphersuiteImpl,
  CryptoProvider,
  Hpke,
  PrivateKey,
  PublicKey,
} from "ts-mls";

/** Decision 1 in `docs/mls-design.md`. Anything else is refused rather than half-supported. */
export const MLS_CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" as const;

// RFC 9180 identifiers: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0001;
const N_SECRET = 32;
const N_K = 16;
const N_N = 12;
const N_H = 32;

const EMPTY = new Uint8Array(0);

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function i2osp(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = length - 1, n = value; i >= 0; i--, n = Math.floor(n / 256)) out[i] = n & 0xff;
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time for equal lengths; the length of a MAC is not a secret. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const HPKE_V1 = utf8("HPKE-v1");

/** RFC 9180 section 4: LabeledExtract and LabeledExpand under one suite id. */
function labelled(suiteId: Uint8Array) {
  return {
    extract: (salt: Uint8Array, label: string, ikm: Uint8Array) =>
      hkdfExtract(sha256, concat(HPKE_V1, suiteId, utf8(label), ikm), salt),
    expand: (prk: Uint8Array, label: string, info: Uint8Array, length: number) =>
      hkdfExpand(sha256, prk, concat(i2osp(length, 2), HPKE_V1, suiteId, utf8(label), info), length),
  };
}

const kemLabel = labelled(concat(utf8("KEM"), i2osp(KEM_ID, 2)));
const hpkeLabel = labelled(
  concat(utf8("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2)),
);

/** What `ts-mls` calls a key. Its types say `CryptoKey`, and it never looks inside. */
interface RawKey {
  type: "private" | "public";
  pk: Uint8Array;
  sk?: Uint8Array;
}

function privateKey(sk: Uint8Array): PrivateKey {
  const key: RawKey = { type: "private", sk: sk.slice(), pk: x25519.getPublicKey(sk) };
  return key as unknown as PrivateKey;
}

function publicKey(pk: Uint8Array): PublicKey {
  if (pk.length !== 32) throw new Error(`An X25519 public key is 32 bytes, not ${pk.length}.`);
  const key: RawKey = { type: "public", pk: pk.slice() };
  return key as unknown as PublicKey;
}

function raw(key: PrivateKey | PublicKey): RawKey {
  return key as unknown as RawKey;
}

/** x25519 refuses low-order points itself, which is RFC 9180's all-zero check. */
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const prk = kemLabel.extract(EMPTY, "eae_prk", dh);
  return kemLabel.expand(prk, "shared_secret", kemContext, N_SECRET);
}

function encap(pkR: Uint8Array): { enc: Uint8Array; shared: Uint8Array } {
  const skE = x25519.utils.randomSecretKey();
  const enc = x25519.getPublicKey(skE);
  return { enc, shared: extractAndExpand(x25519.getSharedSecret(skE, pkR), concat(enc, pkR)) };
}

function decap(enc: Uint8Array, key: RawKey): Uint8Array {
  if (!key.sk) throw new Error("Decapsulation needs a private key.");
  return extractAndExpand(x25519.getSharedSecret(key.sk, enc), concat(enc, key.pk));
}

/** Base mode only (mode 0, no PSK): MLS never uses the other three. */
function keySchedule(shared: Uint8Array, info: Uint8Array) {
  const context = concat(
    new Uint8Array([0]),
    hpkeLabel.extract(EMPTY, "psk_id_hash", EMPTY),
    hpkeLabel.extract(EMPTY, "info_hash", info),
  );
  const secret = hpkeLabel.extract(shared, "secret", EMPTY);
  return {
    key: hpkeLabel.expand(secret, "key", context, N_K),
    nonce: hpkeLabel.expand(secret, "base_nonce", context, N_N),
    exporter: hpkeLabel.expand(secret, "exp", context, N_H),
  };
}

function keyPair(sk: Uint8Array): { privateKey: PrivateKey; publicKey: PublicKey } {
  const priv = privateKey(sk);
  return { privateKey: priv, publicKey: publicKey(raw(priv).pk) };
}

/** Single-shot HPKE: every seal is a fresh encapsulation, so the sequence number is always 0. */
const hpke: Hpke = {
  async seal(pub, plaintext, info, aad) {
    const { enc, shared } = encap(raw(pub).pk);
    const s = keySchedule(shared, info);
    return { enc, ct: gcm(s.key, s.nonce, aad ?? EMPTY).encrypt(plaintext) };
  },
  async open(priv, kemOutput, ciphertext, info, aad) {
    const s = keySchedule(decap(kemOutput, raw(priv)), info);
    return gcm(s.key, s.nonce, aad ?? EMPTY).decrypt(ciphertext);
  },
  async exportSecret(pub, exporterContext, length, info) {
    const { enc, shared } = encap(raw(pub).pk);
    const exporter = keySchedule(shared, info).exporter;
    return { enc, secret: hpkeLabel.expand(exporter, "sec", exporterContext, length) };
  },
  async importSecret(priv, exporterContext, kemOutput, length, info) {
    const exporter = keySchedule(decap(kemOutput, raw(priv)), info).exporter;
    return hpkeLabel.expand(exporter, "sec", exporterContext, length);
  },
  async importPrivateKey(bytes) {
    return privateKey(bytes);
  },
  async importPublicKey(bytes) {
    return publicKey(bytes);
  },
  // Copies, because `ts-mls` zeroes secrets it has finished with.
  async exportPublicKey(key) {
    return raw(key).pk.slice();
  },
  async exportPrivateKey(key) {
    const sk = raw(key).sk;
    if (!sk) throw new Error("That is a public key.");
    return sk.slice();
  },
  async encryptAead(key, nonce, aad, plaintext) {
    return gcm(key, nonce, aad ?? EMPTY).encrypt(plaintext);
  },
  async decryptAead(key, nonce, aad, ciphertext) {
    return gcm(key, nonce, aad ?? EMPTY).decrypt(ciphertext);
  },
  async deriveKeyPair(ikm) {
    const prk = kemLabel.extract(EMPTY, "dkp_prk", ikm);
    return keyPair(kemLabel.expand(prk, "sk", EMPTY, N_SECRET));
  },
  async generateKeyPair() {
    return keyPair(x25519.utils.randomSecretKey());
  },
  keyLength: N_K,
  nonceLength: N_N,
};

const suite1: Omit<CiphersuiteImpl, "name"> = {
  kdf: {
    extract: async (salt, ikm) => hkdfExtract(sha256, ikm, salt),
    expand: async (prk, info, length) => hkdfExpand(sha256, prk, info, length),
    size: N_H,
  },
  hash: {
    digest: async (data) => sha256(data),
    mac: async (key, data) => hmac(sha256, key, data),
    verifyMac: async (key, mac, data) => equalBytes(mac, hmac(sha256, key, data)),
  },
  signature: {
    sign: async (signKey, message) => ed25519.sign(message, signKey),
    // Strict RFC 8032, as WebCrypto does it; every client has to agree. Bad lengths are a no.
    verify: async (pub, message, signature) => {
      try {
        return ed25519.verify(signature, message, pub, { zip215: false });
      } catch {
        return false;
      }
    },
    keygen: async () => {
      const signKey = ed25519.utils.randomSecretKey();
      return { signKey, publicKey: ed25519.getPublicKey(signKey) };
    },
  },
  hpke,
  rng: { randomBytes: (n) => randomBytes(n) },
};

/** Pass this wherever `ts-mls` takes a `CryptoProvider`. */
export const grytMlsCryptoProvider: CryptoProvider = {
  async getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl> {
    if (cs.name !== MLS_CIPHERSUITE) {
      throw new Error(`Gryt only speaks ${MLS_CIPHERSUITE}, not ${cs.name}.`);
    }
    return { ...suite1, name: cs.name };
  },
};
