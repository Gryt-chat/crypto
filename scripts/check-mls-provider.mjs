/* eslint-env node */

/**
 * The HPKE and signatures under MLS, against RFC 9180, 8032 and 4231 known answers. A wrong
 * byte here is a group nobody can join, so a failing vector means the code is wrong.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Hermes has no `crypto.subtle`. Taking it away here proves nothing below leans on it.
Object.defineProperty(globalThis.crypto, "subtle", { value: undefined });

const {
  MLS_CIPHERSUITE,
  grytMlsCryptoProvider,
} = await import("../dist/index.js");
const {
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processMessage,
  acceptAll,
} = await import("ts-mls");

const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const enc = new TextEncoder();

const cs = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE), grytMlsCryptoProvider);
const { hpke, signature, hash, kdf } = cs;

/* ── RFC 9180 A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM ── */

{
  const v = JSON.parse(readFileSync(new URL("./fixtures/hpke-rfc9180-a11.json", import.meta.url)));

  const r = await hpke.deriveKeyPair(unhex(v.ikmR));
  assert.equal(hex(await hpke.exportPrivateKey(r.privateKey)), v.skRm, "DeriveKeyPair(ikmR) gave the wrong skR");
  assert.equal(hex(await hpke.exportPublicKey(r.publicKey)), v.pkRm, "DeriveKeyPair(ikmR) gave the wrong pkR");

  const e = await hpke.deriveKeyPair(unhex(v.ikmE));
  assert.equal(hex(await hpke.exportPrivateKey(e.privateKey)), v.skEm, "DeriveKeyPair(ikmE) gave the wrong skE");
  assert.equal(hex(await hpke.exportPublicKey(e.publicKey)), v.pkEm, "DeriveKeyPair(ikmE) gave the wrong pkE");
  assert.equal(v.enc, v.pkEm, "the vector's enc is pkE for a DHKEM");

  const skR = await hpke.importPrivateKey(unhex(v.skRm));
  const e0 = v.encryption;
  const pt = await hpke.open(skR, unhex(v.enc), unhex(e0.ct), unhex(v.info), unhex(e0.aad));
  assert.equal(hex(pt), e0.pt, "open() on the RFC ciphertext gave the wrong plaintext");

  for (const x of v.exports) {
    const out = await hpke.importSecret(skR, unhex(x.exporter_context), unhex(v.enc), x.L, unhex(v.info));
    assert.equal(hex(out), x.exported_value, `the exporter gave the wrong ${x.L} bytes`);
  }

  const bad = unhex(e0.ct);
  bad[0] ^= 1;
  await assert.rejects(
    hpke.open(skR, unhex(v.enc), bad, unhex(v.info), unhex(e0.aad)),
    "a tampered HPKE ciphertext opened",
  );
  await assert.rejects(
    hpke.open(skR, unhex(v.enc), unhex(e0.ct), unhex(v.info), new Uint8Array()),
    "an HPKE ciphertext opened with the wrong aad",
  );
}

/* ── seal and exportSecret agree with the halves the vectors pinned ──────── */

{
  const r = await hpke.generateKeyPair();
  const info = enc.encode("info");
  const sealed = await hpke.seal(r.publicKey, enc.encode("round trip"), info, enc.encode("aad"));
  const opened = await hpke.open(r.privateKey, sealed.enc, sealed.ct, info, enc.encode("aad"));
  assert.equal(new TextDecoder().decode(opened), "round trip");

  const sent = await hpke.exportSecret(r.publicKey, enc.encode("ctx"), 32, info);
  const got = await hpke.importSecret(r.privateKey, enc.encode("ctx"), sent.enc, 32, info);
  assert.equal(hex(got), hex(sent.secret), "the two ends of the exporter disagree");

  const again = await hpke.seal(r.publicKey, enc.encode("round trip"), info);
  assert.notEqual(hex(again.enc), hex(sealed.enc), "two seals shared an ephemeral key");
}

/* ── low-order X25519 points are refused, not turned into a zero secret ──── */

{
  const zero = new Uint8Array(32);
  const one = new Uint8Array(32);
  one[0] = 1;
  for (const point of [zero, one]) {
    const pub = await hpke.importPublicKey(point);
    await assert.rejects(hpke.seal(pub, enc.encode("x"), new Uint8Array()), "sealed to a low-order point");
  }
  await assert.rejects(hpke.importPublicKey(new Uint8Array(31)), "took a 31-byte public key");
}

/* ── RFC 8032 7.1 test 1, and the strict reading every client must share ── */

{
  const sk = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const pk = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sig =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
  assert.equal(hex(await signature.sign(sk, new Uint8Array())), sig, "Ed25519 signed the RFC vector differently");
  assert.equal(await signature.verify(pk, new Uint8Array(), unhex(sig)), true);
  assert.equal(await signature.verify(pk, enc.encode("x"), unhex(sig)), false, "a signature verified for other bytes");

  // S + L is the same signature to a lax verifier. Strict RFC 8032 refuses S >= L.
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const s = unhex(sig.slice(64)).reverse();
  const bumped = BigInt("0x" + hex(s)) + L;
  const sBytes = unhex(bumped.toString(16).padStart(64, "0")).reverse();
  const malleable = new Uint8Array([...unhex(sig.slice(0, 64)), ...sBytes]);
  assert.equal(await signature.verify(pk, new Uint8Array(), malleable), false, "a non-canonical S verified");

  // Identity key, identity R, S = 0: ZIP215 takes it for any message, RFC 8032 refuses it.
  const identity = new Uint8Array(32);
  identity[0] = 1;
  const forged = new Uint8Array(64);
  forged[0] = 1;
  assert.equal(await signature.verify(identity, enc.encode("anything"), forged), false, "verification is not strict RFC 8032");
  assert.equal(await signature.verify(pk, new Uint8Array(), new Uint8Array(3)), false, "a short signature threw or verified");
  assert.equal(await signature.verify(pk.slice(1), new Uint8Array(), unhex(sig)), false, "a short key threw or verified");
}

/* ── RFC 4231 test case 2, and the MAC check ───────────────────────────── */

{
  const key = enc.encode("Jefe");
  const data = enc.encode("what do ya want for nothing?");
  const mac = await hash.mac(key, data);
  assert.equal(hex(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  assert.equal(await hash.verifyMac(key, mac, data), true);
  const off = mac.slice();
  off[31] ^= 1;
  assert.equal(await hash.verifyMac(key, off, data), false, "a MAC one bit off verified");
  assert.equal(await hash.verifyMac(key, mac.slice(0, 16), data), false, "a truncated MAC verified");
  assert.equal(kdf.size, 32);
}

/* ── ts-mls pinned exactly, at 1.6.4 or later (GHSA-gwp3-968w-m7gv) ──── */

{
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
  const pinned = pkg.dependencies["ts-mls"];
  assert.match(pinned, /^\d+\.\d+\.\d+$/, "ts-mls has to be pinned exactly, since mixed versions reject each other's commits");
  const [major, minor, patch] = pinned.split(".").map(Number);
  assert.ok(major > 1 || (major === 1 && (minor > 6 || (minor === 6 && patch >= 4))), "ts-mls below 1.6.4 lets a removed member read on");
  const installed = JSON.parse(readFileSync(new URL("../node_modules/ts-mls/package.json", import.meta.url))).version;
  assert.equal(installed, pinned, "the installed ts-mls is not the pinned one");
}

/* ── only suite 1 ──────────────────────────────────────────────────────── */

await assert.rejects(
  getCiphersuiteImpl(getCiphersuiteFromName("MLS_128_DHKEMP256_AES128GCM_SHA256_P256"), grytMlsCryptoProvider),
  /Gryt only speaks/,
);

/* ── and ts-mls runs on it: two members, one message, no WebCrypto ─────── */

{
  const kp = (name) =>
    generateKeyPackage({ credentialType: "basic", identity: enc.encode(name) }, defaultCapabilities(), defaultLifetime, [], cs);
  const [a, b] = await Promise.all([kp("alice"), kp("bob")]);
  let alice = await createGroup(enc.encode("g"), a.publicPackage, a.privatePackage, [], cs);
  const added = await createCommit({ state: alice, cipherSuite: cs }, {
    extraProposals: [{ proposalType: "add", add: { keyPackage: b.publicPackage } }],
    ratchetTreeExtension: true,
  });
  alice = added.newState;
  const welcome = decodeMlsMessage(encodeMlsMessage({ version: "mls10", wireformat: "mls_welcome", welcome: added.welcome }), 0)[0];
  const bob = await joinGroup(welcome.welcome, b.publicPackage, b.privatePackage, emptyPskIndex, cs);
  const sent = await createApplicationMessage(alice, enc.encode("hello from noble"), cs);
  const wire = encodeMlsMessage({ version: "mls10", wireformat: "mls_private_message", privateMessage: sent.privateMessage });
  const got = await processMessage(decodeMlsMessage(wire, 0)[0], bob, emptyPskIndex, acceptAll, cs);
  assert.equal(got.kind, "applicationMessage");
  assert.equal(new TextDecoder().decode(got.message), "hello from noble");
}

console.log("mls-provider: RFC 9180, 8032 and 4231 answers match, and ts-mls runs on it without WebCrypto");
