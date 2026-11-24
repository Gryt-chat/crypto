/**
 * The DM line a sender seals to a recipient's phone (GRYT-2275). The vector is fixed so the
 * iPhone extension's Swift can check against the same bytes. Against `dist`.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const { base64Url, base64UrlDecode, generateDeviceSignatureKeyPair, generateDmPreviewKeyPair, openDmPreview, sealDmPreview, signDmPreviewKey, verifyDmPreviewKey } =
  await import("../dist/index.js");
const { x25519 } = await import("@noble/curves/ed25519.js");

const vector = JSON.parse(readFileSync(new URL("./fixtures/dm-preview.json", import.meta.url), "utf8"));
const recipientPrivate = base64UrlDecode(vector.recipientPrivateKey);
const recipientPublic = x25519.getPublicKey(recipientPrivate);
assert.equal(base64Url(recipientPublic), vector.recipientPublicKey);

// The same randomness gives the same bytes, so the fixture pins the format.
const fixed = [base64UrlDecode(vector.ephemeralPrivateKey), base64UrlDecode(vector.nonce)];
const sealed = sealDmPreview(recipientPublic, vector.deviceId, vector.preview, () => fixed.shift() ?? new Uint8Array());
assert.equal(sealed, vector.blob, "the format moved: the iPhone extension can't open this");
assert.deepEqual(openDmPreview(recipientPrivate, vector.deviceId, vector.blob), vector.preview);

assert.equal(openDmPreview(recipientPrivate, "another-device", vector.blob), null, "bound to the device it was sealed for");
assert.equal(openDmPreview(generateDmPreviewKeyPair().privateKey, vector.deviceId, vector.blob), null, "another phone's key");
const flipped = base64UrlDecode(vector.blob);
flipped[60] ^= 1;
assert.equal(openDmPreview(recipientPrivate, vector.deviceId, base64Url(flipped)), null, "a changed byte");
assert.equal(openDmPreview(recipientPrivate, vector.deviceId, "AA"), null);

const mine = generateDmPreviewKeyPair();
const round = sealDmPreview(mine.publicKey, "d1", { t: "Pingy", b: "æøå 👋" });
assert.deepEqual(openDmPreview(mine.privateKey, "d1", round), { t: "Pingy", b: "æøå 👋" });
assert.notEqual(sealDmPreview(mine.publicKey, "d1", { t: "a", b: "b" }), sealDmPreview(mine.publicKey, "d1", { t: "a", b: "b" }), "fresh each time");

const device = generateDeviceSignatureKeyPair();
const sig = signDmPreviewKey(device.signKey, "d1", mine.publicKey);
assert.ok(verifyDmPreviewKey(device.publicKey, "d1", mine.publicKey, sig));
assert.ok(!verifyDmPreviewKey(device.publicKey, "d2", mine.publicKey, sig), "signed for one device");
assert.ok(!verifyDmPreviewKey(device.publicKey, "d1", generateDmPreviewKeyPair().publicKey, sig), "a swapped key");
assert.ok(!verifyDmPreviewKey(generateDeviceSignatureKeyPair().publicKey, "d1", mine.publicKey, sig), "another device's signature");
assert.ok(!verifyDmPreviewKey(device.publicKey, "d1", mine.publicKey, "junk"));

console.log("dm-preview: ok");
