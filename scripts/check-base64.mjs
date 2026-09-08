/* eslint-env node */

/**
 * base64url that does not go through the host (GRYT-732). It has to encode every byte the
 * way `btoa` does, or every message already sent becomes unreadable on one platform.
 */

import assert from "node:assert/strict";

const { base64Url, base64UrlDecode } = await import("../dist/base64.js");

/** What the modules did before this file existed. */
const viaBtoa = (bytes) => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/* ── every byte value, at every offset in the three-byte group ──────────── */

{
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.equal(base64Url(all), viaBtoa(all), "all 256 byte values");

  // Rotating the array walks each value through all three positions in a group,
  // which is where the shifting differs.
  for (let shift = 1; shift < 3; shift++) {
    const rotated = Uint8Array.from(all, (_, i) => all[(i + shift) % 256]);
    assert.equal(base64Url(rotated), viaBtoa(rotated), `rotated by ${shift}`);
  }
}

/* ── every length, so the two padding cases are covered ─────────────────── */

{
  const source = Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) % 256);
  for (let n = 0; n <= source.length; n++) {
    const slice = source.subarray(0, n);
    assert.equal(base64Url(slice), viaBtoa(slice), `${n} bytes`);
    assert.deepEqual(
      Array.from(base64UrlDecode(base64Url(slice))),
      Array.from(slice),
      `${n} bytes did not survive the round trip`,
    );
  }

  assert.equal(base64Url(new Uint8Array(0)), "", "empty encodes to empty");
  assert.equal(base64UrlDecode("").length, 0);
}

/* ── the decoder takes what both callers used to pass it ────────────────── */

{
  const bytes = Uint8Array.from([251, 255, 190, 0, 127, 128]);
  const standard = Buffer.from(bytes).toString("base64");

  for (const [shape, value] of [
    ["base64url, unpadded", base64Url(bytes)],
    ["base64url, padded", `${base64Url(bytes)}==`],
    ["standard +/ with padding", standard],
    ["standard +/ without", standard.replace(/=+$/, "")],
  ]) {
    assert.deepEqual(
      Array.from(base64UrlDecode(value)),
      Array.from(bytes),
      `${shape} did not decode`,
    );
  }

  assert.throws(() => base64UrlDecode("not base64!"), /Not base64url/);
}

/* ── no host base64 is reachable from the built package ─────────────────── */

{
  // The point of the file is that it does not call these. A reintroduced `btoa` would pass
  // every assertion above on Node and fail on a phone.
  const { readdirSync, readFileSync } = await import("node:fs");
  const dir = new URL("../dist/", import.meta.url);

  for (const file of readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    const source = readFileSync(new URL(file, dir), "utf8");
    for (const banned of ["btoa(", "atob("]) {
      assert.ok(
        !source.includes(banned),
        `dist/${file} calls ${banned} — that works in a browser and not on Hermes`,
      );
    }
  }
}

console.log(
  "base64: identical to btoa for all 256 byte values and every length, decodes both spellings, and dist calls neither",
);
