/** Sealed device names (GRYT plan step 5). The vector is what both apps open: don't regenerate it. */

import assert from "node:assert/strict";

import { DEVICE_NAME_MAX_BYTES, openDeviceName, sealDeviceName } from "../dist/index.js";

const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const other = Uint8Array.from({ length: 32 }, (_, i) => 32 - i);
const nonce = Uint8Array.from({ length: 12 }, (_, i) => i);

const sealed = sealDeviceName(seed, "  Windows PC  ", nonce);
assert.equal(openDeviceName(seed, sealed), "Windows PC");
assert.equal(openDeviceName(other, sealed), null, "another seed can't read it");
assert.ok(!sealed.includes("Windows"), "the name isn't visible in the sealed form");
assert.notEqual(sealDeviceName(seed, "Mac"), sealDeviceName(seed, "Mac"), "a fresh nonce each time");

const bytes = Buffer.from(sealed, "base64url");
bytes[bytes.length - 1] ^= 1;
assert.equal(openDeviceName(seed, bytes.toString("base64url")), null, "a changed blob doesn't open");
assert.equal(openDeviceName(seed, "not base64 at all !!"), null);

const long = sealDeviceName(seed, "ø".repeat(100));
assert.equal(new TextEncoder().encode(openDeviceName(seed, long) ?? "").length, DEVICE_NAME_MAX_BYTES);
assert.ok(long.length <= 123);

assert.equal(sealed, "AAECAwQFBgcICQoLvfh2Jmu-ALU0OE4xYdil-2nHaV7ZnHGVgv4", "the format moved");
console.log("device-name: ok");
