/* eslint-env node */

/**
 * The person key, its binding, device certificates and the AuthenticationService. A leaf that
 * gets past these is a device in somebody's DMs that they never added.
 */

import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, hkdfSync } from "node:crypto";

import {
  MLS_CIPHERSUITE,
  asIdentityScope,
  base64Url,
  createMlsAuthenticationService,
  derivePersonKeyPair,
  deviceCertificateOf,
  deriveDmKeyPair,
  generateDeviceId,
  generateDeviceSignatureKeyPair,
  grytMlsCryptoProvider,
  readDeviceCertificate,
  signDeviceCertificate,
  signDmKeyBinding,
  signPersonKeyBinding,
  verifyPersonKeyBinding,
} from "../dist/index.js";
import {
  createCommit,
  createGroup,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackageWithKey,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processMessage,
  acceptAll,
} from "ts-mls";

const SCOPE = asIdentityScope("srv:vectors");
const OTHER = asIdentityScope("srv:other");
const seed = (n) => Uint8Array.from({ length: 32 }, (_, i) => (i * n + n) % 251);
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));

/* ── the person key: pinned bytes, and node:crypto agrees with them ─────── */

{
  const pair = derivePersonKeyPair(seed(7), SCOPE);
  // Nothing regenerates this. If it moves, every person key on every server moved with it.
  assert.equal(hex(pair.publicKey), "d8f5cef95460c0edbb61f083a18483c3cdb06635e79c934a2197d9207f323811");

  const ikm = hkdfSync("sha256", seed(7), "gryt-mls-person-v1", "srv:vectors", 32);
  assert.equal(hex(pair.privateKey), hex(new Uint8Array(ikm)), "the person key is not HKDF(seed, label, scope)");
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(ikm)]);
  const jwk = createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" })).export({ format: "jwk" });
  assert.equal(base64Url(pair.publicKey), jwk.x, "node:crypto derives a different Ed25519 public key");

  assert.notEqual(hex(derivePersonKeyPair(seed(7), OTHER).publicKey), hex(pair.publicKey), "two servers got one person key");
  assert.notEqual(hex(pair.privateKey), hex(deriveDmKeyPair(seed(7), SCOPE).privateKey), "the person key shares bytes with the DM key");
  assert.throws(() => derivePersonKeyPair(new Uint8Array(32), SCOPE), /single repeated byte/);
}

/* ── the binding: identity says the person key is theirs, for one server ── */

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) };
}

{
  const alice = await identity();
  const person = derivePersonKeyPair(seed(3), SCOPE);
  const binding = await signPersonKeyBinding({
    personPublicKey: person.publicKey,
    scope: SCOPE,
    identityPrivateKey: alice.privateKey,
    identityPublicJwk: alice.publicJwk,
    now: 1758800000,
  });
  const verified = await verifyPersonKeyBinding(binding, SCOPE);
  assert.equal(hex(verified.personPublicKey), hex(person.publicKey));
  assert.equal(verified.signedAt, 1758800000);
  assert.equal(typeof verified.identityThumbprint, "string");

  await assert.rejects(verifyPersonKeyBinding(binding, OTHER), /different server/, "a binding replayed on another server verified");

  const dmBinding = await signDmKeyBinding({
    dmPublicKey: person.publicKey,
    scope: SCOPE,
    identityPrivateKey: alice.privateKey,
    identityPublicJwk: alice.publicJwk,
  });
  await assert.rejects(verifyPersonKeyBinding(dmBinding, SCOPE), /issued by/, "a DM key binding passed as a person key binding");

  const [h, p, s] = binding.split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url"));
  const swapped = Buffer.from(JSON.stringify({ ...payload, person: base64Url(new Uint8Array(32).fill(9)) })).toString("base64url");
  await assert.rejects(verifyPersonKeyBinding(`${h}.${swapped}.${s}`, SCOPE), /does not check out/, "a swapped person key verified");

  const header = JSON.parse(Buffer.from(h, "base64url"));
  const none = Buffer.from(JSON.stringify({ ...header, alg: "none" })).toString("base64url");
  await assert.rejects(verifyPersonKeyBinding(`${none}.${p}.${s}`, SCOPE), /ES256/);

  const mallory = await identity();
  const resigned = await signPersonKeyBinding({
    personPublicKey: person.publicKey,
    scope: SCOPE,
    identityPrivateKey: mallory.privateKey,
    identityPublicJwk: mallory.publicJwk,
  });
  const other = await verifyPersonKeyBinding(resigned, SCOPE);
  assert.notEqual(other.identityThumbprint, verified.identityThumbprint, "two identities gave one thumbprint, so a pin can't tell them apart");

  // React Native signs through a function; the result has to verify the same way.
  const viaFunction = await signPersonKeyBinding({
    personPublicKey: person.publicKey,
    scope: SCOPE,
    identityPrivateKey: async (bytes) =>
      new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, alice.privateKey, bytes)),
    identityPublicJwk: alice.publicJwk,
  });
  assert.equal((await verifyPersonKeyBinding(viaFunction, SCOPE)).identityThumbprint, verified.identityThumbprint);
}

/* ── device certificates: pinned bytes, and every flipped byte refused ─── */

const KARI = derivePersonKeyPair(seed(7), SCOPE);
const certificate = (over = {}) =>
  signDeviceCertificate({
    personPrivateKey: KARI.privateKey,
    scope: SCOPE,
    leafSignatureKey: new Uint8Array(32).fill(0x11),
    deviceId: base64Url(new Uint8Array(16).fill(0x22)),
    deviceName: "Kari’s phone",
    now: 1758800000,
    ...over,
  });

{
  const bytes = certificate();
  // The credential bytes in every leaf. Nothing regenerates them.
  assert.equal(
    hex(bytes),
    "01000b7372763a766563746f7273d8f5cef95460c0edbb61f083a18483c3cdb06635e79c934a2197d9207f323811" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "22222222222222222222222222222222" +
      "0e4b617269e28099732070686f6e65" +
      "0000000068d52880" +
      "2c73e41991c7f14f610250979c09d5353d70ed35ed0555161354a3c8eb087d83a979e3dd6af565557f7b29f302e6a0727f9ed7158052d6590b514dd75c9d7902",
  );

  const read = readDeviceCertificate(bytes, SCOPE);
  assert.equal(read.deviceName, "Kari’s phone");
  assert.equal(read.deviceId, base64Url(new Uint8Array(16).fill(0x22)));
  assert.equal(read.signedAt, 1758800000);
  assert.equal(hex(read.personPublicKey), hex(KARI.publicKey));

  for (let i = 0; i < bytes.length; i++) {
    const bad = bytes.slice();
    bad[i] ^= 0x01;
    assert.throws(() => readDeviceCertificate(bad, SCOPE), `a certificate with byte ${i} flipped was read`);
  }
  assert.throws(() => readDeviceCertificate(bytes, OTHER), /different server/);
  assert.throws(() => readDeviceCertificate(new Uint8Array([...bytes, 0]), SCOPE), /after the signature/);
  assert.throws(() => readDeviceCertificate(bytes.slice(0, -1), SCOPE), /cut short/);
  assert.throws(() => certificate({ deviceName: "x".repeat(65) }), /device name/);
  assert.throws(() => certificate({ deviceName: "" }), /device name/);
  assert.throws(() => certificate({ deviceId: "short" }), /device id/);
  assert.equal(readDeviceCertificate(certificate({ deviceId: generateDeviceId() }), SCOPE).scope, SCOPE);
}

/* ── the AuthenticationService on its own ─────────────────────────────── */

{
  const leaf = generateDeviceSignatureKeyPair();
  const bytes = certificate({ leafSignatureKey: leaf.publicKey });
  const credential = { credentialType: "basic", identity: bytes };
  let asked = 0;
  const trusting = createMlsAuthenticationService({ scope: SCOPE, trustPersonKey: () => (asked++, true) });

  assert.equal(await trusting.validateCredential(credential, leaf.publicKey), true);
  assert.equal(await trusting.validateCredential(credential, leaf.publicKey), true);
  assert.equal(asked, 2, "the trust decision was cached along with the signature check");
  assert.equal(await trusting.validateCredential(credential, generateDeviceSignatureKeyPair().publicKey), false, "a certificate for another leaf key passed");
  assert.equal(await trusting.validateCredential({ credentialType: "x509", certificates: [bytes] }, leaf.publicKey), false);
  assert.equal(await trusting.validateCredential({ credentialType: "basic", identity: new TextEncoder().encode("alice") }, leaf.publicKey), false);

  const otherServer = createMlsAuthenticationService({ scope: OTHER, trustPersonKey: () => true });
  assert.equal(await otherServer.validateCredential(credential, leaf.publicKey), false, "a certificate for another server passed");

  const refusing = createMlsAuthenticationService({ scope: SCOPE, trustPersonKey: async () => false });
  assert.equal(await refusing.validateCredential(credential, leaf.publicKey), false);
  const throwing = createMlsAuthenticationService({ scope: SCOPE, trustPersonKey: () => { throw new Error("no pin store"); } });
  assert.equal(await throwing.validateCredential(credential, leaf.publicKey), false, "a trust callback that threw let the leaf in");
  const truthy = createMlsAuthenticationService({ scope: SCOPE, trustPersonKey: () => "yes" });
  assert.equal(await truthy.validateCredential(credential, leaf.publicKey), false, "a truthy non-boolean counted as trust");

  const copy = deviceCertificateOf(credential, SCOPE);
  copy.personPublicKey.fill(0);
  assert.equal(hex(deviceCertificateOf(credential, SCOPE).personPublicKey), hex(KARI.publicKey), "writing to a returned certificate changed the cache");
}

/* ── and ts-mls calls it: an untrusted person is refused on add and on join ── */

{
  const cs = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE), grytMlsCryptoProvider);
  const people = { kari: derivePersonKeyPair(seed(11), SCOPE), ola: derivePersonKeyPair(seed(13), SCOPE), eve: derivePersonKeyPair(seed(17), SCOPE) };
  const device = async (who, name) => {
    const leaf = generateDeviceSignatureKeyPair();
    const identityBytes = signDeviceCertificate({
      personPrivateKey: people[who].privateKey,
      scope: SCOPE,
      leafSignatureKey: leaf.publicKey,
      deviceId: generateDeviceId(),
      deviceName: name,
    });
    return generateKeyPackageWithKey({ credentialType: "basic", identity: identityBytes }, defaultCapabilities(), defaultLifetime, [], leaf, cs);
  };
  const trusted = new Set([hex(people.kari.publicKey), hex(people.ola.publicKey)]);
  const clientConfig = (trust) => ({
    keyRetentionConfig: { retainKeysForGenerations: 10, retainKeysForEpochs: 4, maximumForwardRatchetSteps: 200 },
    lifetimeConfig: { maximumTotalLifetime: 2628000n, validateLifetimeOnReceive: false },
    keyPackageEqualityConfig: {
      compareKeyPackages: (a, b) => hex(a.leafNode.signaturePublicKey) === hex(b.leafNode.signaturePublicKey),
      compareKeyPackageToLeafNode: (a, b) => hex(a.leafNode.signaturePublicKey) === hex(b.signaturePublicKey),
    },
    paddingConfig: { kind: "padUntilLength", padUntilLength: 256 },
    authService: createMlsAuthenticationService({ scope: SCOPE, trustPersonKey: (c) => trust.has(hex(c.personPublicKey)) }),
  });
  const add = (kp) => ({ proposalType: "add", add: { keyPackage: kp.publicPackage } });
  const unwire = (m) => decodeMlsMessage(encodeMlsMessage(m), 0)[0];

  const [kariLaptop, olaPhone, evePhone] = await Promise.all([device("kari", "laptop"), device("ola", "phone"), device("eve", "phone")]);
  let kari = await createGroup(new TextEncoder().encode("dm"), kariLaptop.publicPackage, kariLaptop.privatePackage, [], cs, clientConfig(trusted));

  await assert.rejects(
    createCommit({ state: kari, cipherSuite: cs }, { extraProposals: [add(evePhone)], ratchetTreeExtension: true }),
    /Could not validate credential/,
    "Kari's client committed an Add for somebody it doesn't trust",
  );

  const added = await createCommit({ state: kari, cipherSuite: cs }, { extraProposals: [add(olaPhone)], ratchetTreeExtension: true });
  kari = added.newState;
  const welcome = unwire({ version: "mls10", wireformat: "mls_welcome", welcome: added.welcome }).welcome;
  const ola = await joinGroup(welcome, olaPhone.publicPackage, olaPhone.privatePackage, emptyPskIndex, cs, undefined, undefined, clientConfig(trusted));
  assert.ok(ola, "Ola couldn't join a group of people he trusts");

  // A client that doesn't trust Kari refuses the Welcome whose tree has her in it.
  const onlyOla = new Set([hex(people.ola.publicKey)]);
  await assert.rejects(
    joinGroup(welcome, olaPhone.publicPackage, olaPhone.privatePackage, emptyPskIndex, cs, undefined, undefined, clientConfig(onlyOla)),
    /Could not validate credential/,
    "joined a group whose tree has an untrusted leaf in it",
  );

  // Kari's client is lenient here; Ola's still refuses the commit that adds Eve.
  const lenient = { ...kari, clientConfig: clientConfig(new Set([...trusted, hex(people.eve.publicKey)])) };
  const sneaky = await createCommit({ state: lenient, cipherSuite: cs }, { extraProposals: [add(evePhone)], ratchetTreeExtension: true });
  const wire = unwire(sneaky.commit);
  await assert.rejects(processMessage(wire, ola, emptyPskIndex, acceptAll, cs), /Could not validate credential/, "Ola accepted a commit adding somebody he doesn't trust");
}

console.log("mls-credentials: the person key and certificate bytes hold, bindings and certificates refuse tampering, and ts-mls asks before any leaf gets in");
