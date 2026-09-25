// Measurement only, not for shipping: a ts-mls CryptoProvider with no WebCrypto at all, for
// runtimes without crypto.subtle (Hermes). HPKE base mode per RFC 9180, checked by vectors.mjs.

import { p256 } from "@noble/curves/nist.js"
import { x25519 } from "@noble/curves/ed25519.js"
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { gcm } from "@noble/ciphers/aes.js"
import { chacha20poly1305 } from "@noble/ciphers/chacha.js"
import { makeHashImpl } from "ts-mls/crypto/implementation/noble/makeHashImpl.js"
import { makeNobleSignatureImpl } from "ts-mls/crypto/implementation/default/makeNobleSignatureImpl.js"

const utf8 = (s) => new TextEncoder().encode(s)
const i2osp = (n, len) => {
  const out = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--, n = Math.floor(n / 256)) out[i] = n & 0xff
  return out
}
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0))
  let o = 0
  for (const p of parts) out.set(p, (o += p.length) - p.length)
  return out
}
const random = (n) => crypto.getRandomValues(new Uint8Array(n))

const KEMS = {
  "DHKEM-P256-HKDF-SHA256": {
    id: 0x0010,
    nsecret: 32,
    publicOf: (sk) => p256.getPublicKey(sk, false),
    dh: (sk, pk) => p256.getSharedSecret(sk, pk, true).slice(1),
    generate: () => p256.utils.randomSecretKey(),
    // RFC 9180 7.1.3: rejection sampling on the expanded candidate
    derive(labeledExpand, prk) {
      const order = p256.Point.CURVE().n
      for (let counter = 0; counter < 256; counter++) {
        const bytes = labeledExpand(prk, "candidate", i2osp(counter, 1), 32)
        let sk = 0n
        for (const b of bytes) sk = (sk << 8n) | BigInt(b)
        if (sk !== 0n && sk < order) return bytes
      }
      throw new Error("DeriveKeyPairError")
    },
  },
  "DHKEM-X25519-HKDF-SHA256": {
    id: 0x0020,
    nsecret: 32,
    publicOf: (sk) => x25519.getPublicKey(sk),
    dh: (sk, pk) => x25519.getSharedSecret(sk, pk),
    generate: () => x25519.utils.randomSecretKey(),
    derive: (labeledExpand, prk) => labeledExpand(prk, "sk", new Uint8Array(), 32),
  },
}
const AEADS = {
  AES128GCM: { id: 0x0001, nk: 16, nn: 12, cipher: gcm },
  CHACHA20POLY1305: { id: 0x0003, nk: 32, nn: 12, cipher: chacha20poly1305 },
}

function makeHpke(alg) {
  const kem = KEMS[alg.kem]
  const aead = AEADS[alg.aead]
  if (!kem || !aead || alg.kdf !== "HKDF-SHA256") throw new Error(`pure provider: unsupported ${JSON.stringify(alg)}`)
  const labeled = (suiteId) => ({
    extract: (salt, label, ikm) => hkdfExtract(sha256, concat(utf8("HPKE-v1"), suiteId, utf8(label), ikm), salt),
    expand: (prk, label, info, len) => hkdfExpand(sha256, prk, concat(i2osp(len, 2), utf8("HPKE-v1"), suiteId, utf8(label), info), len),
  })
  const kemL = labeled(concat(utf8("KEM"), i2osp(kem.id, 2)))
  const hpkeL = labeled(concat(utf8("HPKE"), i2osp(kem.id, 2), i2osp(0x0001, 2), i2osp(aead.id, 2)))

  const extractAndExpand = (dh, kemContext) => kemL.expand(kemL.extract(new Uint8Array(), "eae_prk", dh), "shared_secret", kemContext, kem.nsecret)
  const encap = (pkR) => {
    const skE = kem.generate()
    const enc = kem.publicOf(skE)
    return { enc, shared: extractAndExpand(kem.dh(skE, pkR), concat(enc, pkR)) }
  }
  const decap = (enc, key) => extractAndExpand(kem.dh(key.sk, enc), concat(enc, key.pk))
  const schedule = (shared, info) => {
    const ctx = concat(new Uint8Array([0]), hpkeL.extract(new Uint8Array(), "psk_id_hash", new Uint8Array()), hpkeL.extract(new Uint8Array(), "info_hash", info))
    const secret = hpkeL.extract(shared, "secret", new Uint8Array())
    return {
      key: hpkeL.expand(secret, "key", ctx, aead.nk),
      nonce: hpkeL.expand(secret, "base_nonce", ctx, aead.nn),
      exporter: hpkeL.expand(secret, "exp", ctx, 32),
    }
  }
  const priv = (sk) => ({ type: "private", sk, pk: kem.publicOf(sk) })

  return {
    async seal(publicKey, plaintext, info, aad) {
      const { enc, shared } = encap(publicKey.pk)
      const s = schedule(shared, info)
      return { enc, ct: aead.cipher(s.key, s.nonce, aad ?? new Uint8Array()).encrypt(plaintext) }
    },
    async open(privateKey, kemOutput, ciphertext, info, aad) {
      const s = schedule(decap(kemOutput, privateKey), info)
      return aead.cipher(s.key, s.nonce, aad ?? new Uint8Array()).decrypt(ciphertext)
    },
    async exportSecret(publicKey, exporterContext, length, info) {
      const { enc, shared } = encap(publicKey.pk)
      return { enc, secret: hpkeL.expand(schedule(shared, info).exporter, "sec", exporterContext, length) }
    },
    async importSecret(privateKey, exporterContext, kemOutput, length, info) {
      return hpkeL.expand(schedule(decap(kemOutput, privateKey), info).exporter, "sec", exporterContext, length)
    },
    async importPrivateKey(k) {
      return priv(k.slice())
    },
    async importPublicKey(k) {
      return { type: "public", pk: k.slice() }
    },
    async exportPublicKey(k) {
      return k.pk
    },
    async exportPrivateKey(k) {
      return k.sk
    },
    async encryptAead(key, nonce, aad, plaintext) {
      return aead.cipher(key, nonce, aad ?? new Uint8Array()).encrypt(plaintext)
    },
    async decryptAead(key, nonce, aad, ciphertext) {
      return aead.cipher(key, nonce, aad ?? new Uint8Array()).decrypt(ciphertext)
    },
    async deriveKeyPair(ikm) {
      const k = priv(kem.derive(kemL.expand, kemL.extract(new Uint8Array(), "dkp_prk", ikm)))
      return { privateKey: k, publicKey: { type: "public", pk: k.pk } }
    },
    async generateKeyPair() {
      const k = priv(kem.generate())
      return { privateKey: k, publicKey: { type: "public", pk: k.pk } }
    },
    keyLength: aead.nk,
    nonceLength: aead.nn,
  }
}

export const pureCryptoProvider = {
  async getCiphersuiteImpl(cs) {
    return {
      kdf: {
        extract: async (salt, ikm) => hkdfExtract(sha256, ikm, salt),
        expand: async (prk, info, len) => hkdfExpand(sha256, prk, info, len),
        size: 32,
      },
      hash: makeHashImpl(cs.hash),
      signature: await makeNobleSignatureImpl(cs.signature),
      hpke: makeHpke(cs.hpke),
      rng: { randomBytes: random },
      name: cs.name,
    }
  },
}
