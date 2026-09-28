/* eslint-env node */

/**
 * The pairing envelope and the identity backup it carries (GRYT-1484). N writes what this
 * returns, so everything it lets through ends up in somebody's key store.
 */

import assert from "node:assert/strict";

import {
  base64Url,
  decodePairingEnvelope,
  encodePairingEnvelope,
  PAIRING_ENVELOPE_MAX_BYTES,
  parseIdentityBackup,
} from "../dist/index.js";

const hex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => new TextEncoder().encode(s);
const seq = (n, m) => Uint8Array.from({ length: n }, (_, i) => (i * m + m) % 251);

const JWK = { kty: "EC", crv: "P-256", x: "eHg", y: "eXk" };
const PIN = {
  thumbprint: "tp",
  dmPublicKey: base64Url(seq(32, 3)),
  personPublicKey: base64Url(seq(32, 7)),
  firstSeenAt: 1,
  lastSeenAt: 2,
  comparedAt: 3,
  seenOnMls: true,
};

const FULL = {
  seed: seq(32, 11),
  keys: [{ scope: "old.example", host: "old.example", privateJwk: { ...JWK, d: "ZGQ" }, publicJwk: JWK }],
  account: {
    issuer: "https://auth.gryt.chat/realms/gryt",
    clientId: "gryt-web",
    identityUrl: "https://id.gryt.chat",
    sub: "0b5e",
    username: "sivert",
  },
  servers: [
    { host: "chat.example", name: "Example", scope: "srv:abc", nickname: "S", scheme: "https" },
    { host: "other.example", name: "", scope: "other.example" },
  ],
  pins: { "srv:abc": { user_1: PIN, user_2: { thumbprint: "t2", dmPublicKey: PIN.dmPublicKey, firstSeenAt: 5, lastSeenAt: 6 } } },
  history: { key: seq(32, 19), manifest: { chunks: [{ id: "c1" }] } },
  from: "Sivert's iPhone",
};

const GUEST = { seed: seq(32, 11), keys: [], servers: [], pins: {}, from: "" };

const roundTrip = (e) => decodePairingEnvelope(encodePairingEnvelope(e));
const raw = (overrides) => {
  const base = JSON.parse(new TextDecoder().decode(encodePairingEnvelope(FULL)));
  return utf8(JSON.stringify({ ...base, ...overrides }));
};

/* ── round trips ────────────────────────────────────────────────────────── */

{
  const back = roundTrip(FULL);
  assert.equal(hex(back.seed), hex(FULL.seed));
  assert.equal(hex(back.history.key), hex(FULL.history.key));
  assert.deepEqual({ ...back, seed: 0, history: 0 }, { ...FULL, seed: 0, history: 0 });
  assert.deepEqual(back.history.manifest, FULL.history.manifest);

  const guest = roundTrip(GUEST);
  assert.equal(guest.account, undefined, "a guest has no account, and skips Keycloak");
  assert.equal(guest.history, undefined);

  const local = { ...FULL.account, issuer: "http://localhost:8080/realms/gryt", identityUrl: "http://127.0.0.1:3000" };
  assert.deepEqual(roundTrip({ ...FULL, account: local }).account, local, "plain http only on this machine");

  const [key] = JSON.parse(new TextDecoder().decode(encodePairingEnvelope(FULL))).keys;
  assert.deepEqual(Object.keys(key), ["scope", "host", "privateJwk", "publicJwk"]);
}

/* ── extras are dropped, not carried ────────────────────────────────────── */

{
  const back = decodePairingEnvelope(raw({ tokens: "keycloak", servers: [{ ...FULL.servers[0], token: "x" }] }));
  assert.equal(back.tokens, undefined, "an unknown field never reaches storage");
  assert.equal(back.servers[0].token, undefined);

  const withExtra = encodePairingEnvelope({ ...FULL, mlsState: "never", servers: [{ ...FULL.servers[0], token: "t" }] });
  assert.ok(!new TextDecoder().decode(withExtra).includes("never"), "MLS state never leaves the device");
  assert.ok(!new TextDecoder().decode(withExtra).includes('"token"'), "nor does a server's access token");
}

/* ── refusals ───────────────────────────────────────────────────────────── */

{
  const refused = (overrides, pattern = /isn't valid/) =>
    assert.throws(() => decodePairingEnvelope(raw(overrides)), pattern, JSON.stringify(overrides).slice(0, 80));

  refused({ v: 2 }, /newer version/);
  refused({ v: "1" });
  refused({ seed: undefined });
  refused({ seed: base64Url(new Uint8Array(32).fill(7)) });
  refused({ seed: base64Url(seq(16, 1)) });
  refused({ keys: [{ scope: "x", publicJwk: JWK, privateJwk: JWK }] }, /keys/);
  refused({ account: { ...FULL.account, issuer: "http://auth.evil.example/realms/gryt" } }, /account/);
  refused({ account: { ...FULL.account, sub: "" } }, /account/);
  refused({ servers: [{ host: "h", name: "n" }] }, /servers/);
  refused({ servers: [{ ...FULL.servers[0], scheme: "ftp" }] }, /servers/);
  refused({ pins: { "srv:abc": { u: { ...PIN, dmPublicKey: base64Url(seq(31, 1)) } } } }, /pins/);
  refused({ pins: { "srv:abc": { u: { ...PIN, seenOnMls: "yes" } } } }, /pins/);
  refused({ pins: { "srv:abc": [] } }, /pins/);
  refused({ history: { key: base64Url(seq(32, 1)) } }, /history/);
  refused({ from: undefined }, /from/);

  const proto = new TextDecoder().decode(raw({})).replace('"pins":{"srv:abc"', '"pins":{"__proto__"');
  assert.ok(proto.includes('"pins":{"__proto__"'));
  assert.throws(() => decodePairingEnvelope(utf8(proto)), /pins/);

  assert.throws(() => decodePairingEnvelope(utf8("{")), /encoding/);
  assert.throws(() => decodePairingEnvelope(new Uint8Array([0xff, 0xfe])), /encoding/);
  assert.throws(() => decodePairingEnvelope(new Uint8Array(PAIRING_ENVELOPE_MAX_BYTES + 1)), /size/);
  assert.throws(() => encodePairingEnvelope({ ...GUEST, from: "x".repeat(PAIRING_ENVELOPE_MAX_BYTES) }), /size/,
    "A finds out before sealing, not N after");
  assert.ok(encodePairingEnvelope({ ...GUEST, from: "x".repeat(PAIRING_ENVELOPE_MAX_BYTES - 200) }));
}

/* ── the identity backup file, both versions ────────────────────────────── */

{
  const v2 = { type: "gryt-local-identity-backup", version: 2, exportedAt: "t", seed: "c2Vl", identities: FULL.keys };
  assert.deepEqual(parseIdentityBackup(JSON.stringify(v2)), { seed: "c2Vl", identities: FULL.keys });

  const v1 = { type: "gryt-local-identity-backup", version: 1, exportedAt: "t",
    identities: [{ host: "old.example", privateJwk: JWK, publicJwk: JWK }] };
  assert.deepEqual(parseIdentityBackup(JSON.stringify(v1)), {
    identities: [{ scope: "old.example", host: "old.example", privateJwk: JWK, publicJwk: JWK }],
  }, "version 1's host is version 2's scope");

  assert.throws(() => parseIdentityBackup("not json"), /isn't a Gryt identity backup/);
  assert.throws(() => parseIdentityBackup(JSON.stringify({ ...v2, version: 3 })), /isn't a Gryt identity backup/);
}

console.log("pairing-envelope: round trips, drops what it does not know, and refuses a bad seed, account, server or pin");
