/* eslint-env node */

/**
 * Pairing (GRYT-1484), against docs/pairing-design.md section 2. The vectors are what the
 * phone and the desktop check themselves against. If one fails, the protocol moved.
 */

import assert from "node:assert/strict";

import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  base64Url,
  CROCKFORD_ALPHABET,
  createPairingKey,
  formatPairingCode,
  formatPairingQr,
  generatePairingCode,
  PAIRING_CODE_BITS,
  PAIRING_EMOJI,
  pairingCommitment,
  parsePairingCode,
  parsePairingQr,
  startApproverSession,
  startNewDeviceSession,
} from "../dist/index.js";

const hex = (b) => Buffer.from(b).toString("hex");
const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => new TextDecoder().decode(b);
const seq = (n, m) => Uint8Array.from({ length: n }, (_, i) => (i * m + m) % 251);

const SK_N = seq(32, 5);
const SK_A = seq(32, 9);
const SESSION = seq(16, 13);

/** Both sides of one honest session, the way the relay's order produces them. */
function pair({ skN, skA, sessionId = SESSION } = {}) {
  const n = createPairingKey(skN);
  const a = createPairingKey(skA);
  const commitment = pairingCommitment(n.publicKey);
  const nSide = startNewDeviceSession(n, { sessionId, approverPublicKey: a.publicKey });
  const aSide = startApproverSession(a, { sessionId, commitment, newDevicePublicKey: n.publicKey });
  return { n: nSide, a: aSide, pkN: n.publicKey, pkA: a.publicKey };
}

/* ── fixed vectors ──────────────────────────────────────────────────────── */

{
  const { n, a, pkN, pkA } = pair({ skN: SK_N, skA: SK_A });
  assert.equal(hex(pkN), "6b75e1a2690207d9410cbe40166336432c2255b4b17f4da7255874b6d84db05d");
  assert.equal(hex(pkA), "4efdeaed8e92d10d097ddcf4e1dda48938a85b6b24a335add35aade9936b4453");
  assert.equal(hex(pairingCommitment(pkN)), "8d68a4415627c40d3ea10fce54d46e948101abf4aea41964cb510b3b0d413d7c");
  assert.deepEqual(n.emoji.map((e) => e.name), ["Pencil", "Gift", "Trophy", "Pencil"]);
  assert.equal(n.keycloakNonce, "KI57__cbYYfaLLAyO2wSPQ");

  const hello = utf8("hello from the new device");
  assert.equal(base64Url(n.seal(hello)), "CzsmVyxEEV8Uti2LChXvqUiECrGazp05wqWmCamjcAS7U7S3-zshBns");
  assert.equal(base64Url(n.seal(hello)), "F_BMMz3H2mJDsWEcVok-XqmXnZvBkr5rpKTnJww09uDWH7DCry4TWQA",
    "the second message is under counter 1, so the same text seals differently");
  assert.equal(base64Url(a.seal(utf8("hello from the approving device"))),
    "RIgV5E6BrDc_Cg6N5IKq8agCn6DGTOHIP86jm5fN-NB8Iy-vCvHN93tg0RcPuis");

  assert.equal(formatPairingQr({ sessionId: SESSION, publicKey: pkN }),
    "*GRYT*1*1MD2ED219SDPGXC2HYEAKDP3T0*DDTY38K9083XJG8CQS01CRSP8CP24NDMP5ZMV9S5B1TBDP2DP1EG");

  // Matrix's sas-emoji.json, in its order. Pinned whole, variation selectors included.
  assert.equal(PAIRING_EMOJI.length, 64);
  assert.equal(new Set(PAIRING_EMOJI.map((e) => e.name)).size, 64);
  assert.equal(PAIRING_EMOJI[21].emoji, "☁️");
  assert.equal(hex(sha256(utf8(JSON.stringify(PAIRING_EMOJI)))),
    "3e140c5c95ff34f7611a0bec57a02da28d15bd5c66dd579067f399e6f789fa17");
}

/* ── the key schedule, written out from the doc rather than imported ────── */

{
  const pkN = x25519.getPublicKey(SK_N);
  const pkA = x25519.getPublicKey(SK_A);
  const lp = (b) => Uint8Array.from([b.length >> 8, b.length & 0xff, ...b]);
  const commit = sha256(Uint8Array.from([...utf8("gryt-pair-v1 commit"), ...pkN]));
  const th = sha256(Uint8Array.from([
    ...lp(utf8("gryt-pair-v1")), ...lp(SESSION), ...lp(commit), ...lp(pkN), ...lp(pkA),
  ]));
  const prk = extract(sha256, x25519.getSharedSecret(SK_N, pkA), th);
  const kNA = expand(sha256, prk, utf8("gryt-pair-v1 n to a"), 32);
  const sas = expand(sha256, prk, utf8("gryt-pair-v1 emoji"), 3);
  const kc = expand(sha256, prk, utf8("gryt-pair-v1 keycloak"), 16);

  const { n, a } = pair({ skN: SK_N, skA: SK_A });
  const bits = (sas[0] << 16) | (sas[1] << 8) | sas[2];
  assert.deepEqual(n.emoji, [18, 12, 6, 0].map((s) => PAIRING_EMOJI[(bits >> s) & 63]),
    "four emoji, six bits each, first emoji from the top bits");
  assert.deepEqual(a.emoji, n.emoji);
  assert.equal(n.keycloakNonce, base64Url(kc));

  // Nonce: a 12-byte big-endian counter. AAD: th, one direction byte (1 is N to A), the nonce.
  const nonce = new Uint8Array(12);
  nonce[11] = 1;
  n.seal(utf8("first"));
  const expected = gcm(kNA, nonce, Uint8Array.from([...th, 1, ...nonce])).encrypt(utf8("second"));
  assert.equal(hex(n.seal(utf8("second"))), hex(expected));
}

/* ── round trips, both ways and in order ────────────────────────────────── */

{
  const { n, a } = pair();
  for (let i = 0; i < 5; i++) {
    assert.equal(text(a.open(n.seal(utf8(`to a ${i}`)))), `to a ${i}`);
    assert.equal(text(n.open(a.seal(utf8(`to n ${i}`)))), `to n ${i}`);
  }
  assert.throws(() => n.open(n.seal(utf8("echo"))), /didn't open/,
    "a side can't open its own message: each direction has its own key");
}

/* ── a relay that swaps keys gets two sets of emoji ─────────────────────── */

{
  // It has to commit to its fake N key before A's key exists, and pick its fake A key blind.
  const n = createPairingKey();
  const a = createPairingKey();
  const fakeN = createPairingKey();
  const fakeA = createPairingKey();

  const onN = startNewDeviceSession(n, { sessionId: SESSION, approverPublicKey: fakeA.publicKey });
  const onA = startApproverSession(a, {
    sessionId: SESSION,
    commitment: pairingCommitment(fakeN.publicKey),
    newDevicePublicKey: fakeN.publicKey,
  });
  assert.notDeepEqual(onN.emoji, onA.emoji, "a relay in the middle has to show up in the emoji");
  assert.throws(() => onA.open(onN.seal(utf8("seed"))), /didn't open/);
}

{
  // Swapping only pkA, which the QR path can't stop, changes the emoji too.
  const n1 = createPairingKey(SK_N);
  const n2 = createPairingKey(SK_N);
  const real = startNewDeviceSession(n1, { sessionId: SESSION, approverPublicKey: createPairingKey(SK_A).publicKey });
  const swapped = startNewDeviceSession(n2, { sessionId: SESSION, approverPublicKey: createPairingKey().publicKey });
  assert.notDeepEqual(real.emoji, swapped.emoji);
}

/* ── a commitment that doesn't match is refused ─────────────────────────── */

{
  const n = createPairingKey();
  const other = createPairingKey();
  const a = createPairingKey();
  assert.throws(() => startApproverSession(a, {
    sessionId: SESSION,
    commitment: pairingCommitment(n.publicKey),
    newDevicePublicKey: other.publicKey,
  }), /committed to/);
  assert.throws(() => startApproverSession(a, {
    sessionId: SESSION, commitment: pairingCommitment(n.publicKey), newDevicePublicKey: n.publicKey,
  }), /used already/, "a refused attempt still uses up the key");

  const b = createPairingKey();
  assert.throws(() => startApproverSession(b, {
    sessionId: SESSION,
    commitment: pairingCommitment(n.publicKey),
    newDevicePublicKey: n.publicKey,
    scannedPublicKey: other.publicKey,
  }), /QR code/, "the revealed key has to be the one A read off N's screen");

  assert.throws(() => startNewDeviceSession(createPairingKey(), {
    sessionId: SESSION, approverPublicKey: new Uint8Array(32),
  }), /isn't usable/, "a low-order key gives an all-zero secret");
}

/* ── nonce reuse is impossible by construction ──────────────────────────── */

{
  const n = createPairingKey();
  const a = createPairingKey();
  startNewDeviceSession(n, { sessionId: SESSION, approverPublicKey: a.publicKey });
  assert.throws(() => startNewDeviceSession(n, { sessionId: SESSION, approverPublicKey: a.publicKey }),
    /used already/, "a second session from one key would restart the counter under the same keys");

  const { n: side } = pair();
  assert.equal(side.seal.length, 1, "seal takes the plaintext and nothing else");
  assert.notEqual(hex(side.seal(utf8("same"))), hex(side.seal(utf8("same"))));
  assert.deepEqual(Object.keys(createPairingKey()), ["publicKey"], "the secret isn't reachable");
  side.close();
  assert.throws(() => side.seal(utf8("after")), /closed/);
}

/* ── tampered, replayed and reordered messages are refused ──────────────── */

{
  const clean = utf8("the envelope");
  for (const position of [0, 5, 11, 12, 27]) {
    const { n, a } = pair();
    const sealed = n.seal(clean);
    sealed[position] ^= 1;
    assert.throws(() => a.open(sealed), /didn't open/, `flipping byte ${position}`);
    assert.throws(() => a.open(n.seal(clean)), /closed/, "one failure ends the session");
  }

  const { n, a } = pair();
  n.seal(utf8("one"));
  const second = n.seal(utf8("two"));
  assert.throws(() => a.open(second), /didn't open/, "reordered");

  const replay = pair();
  const once = replay.n.seal(utf8("one"));
  replay.a.open(once);
  assert.throws(() => replay.a.open(once), /didn't open/, "replayed");
}

/* ── a wrong session is refused ─────────────────────────────────────────── */

{
  const n = createPairingKey(SK_N);
  const a = createPairingKey(SK_A);
  const onN = startNewDeviceSession(n, { sessionId: SESSION, approverPublicKey: a.publicKey });
  const onA = startApproverSession(a, {
    sessionId: seq(16, 17),
    commitment: pairingCommitment(n.publicKey),
    newDevicePublicKey: n.publicKey,
  });
  assert.throws(() => onA.open(onN.seal(utf8("seed"))), /didn't open/);

  const one = pair({ skN: SK_N, skA: SK_A });
  const two = pair({ skN: SK_N, skA: SK_A, sessionId: seq(16, 17) });
  assert.throws(() => two.a.open(one.n.seal(utf8("seed"))), /didn't open/,
    "the same two keys in another session is still another session");
}

/* ── the short code: its alphabet and the brute-force numbers in the doc ── */

{
  assert.equal(PAIRING_CODE_BITS, 8 * Math.log2(CROCKFORD_ALPHABET.length), "eight characters at five bits each");
  assert.equal(PAIRING_CODE_BITS, 40);
  for (let i = 0; i < 2000; i++) {
    const code = generatePairingCode();
    assert.match(code, /^[0-9A-HJKMNP-TV-Z]{8}$/, "Crockford's alphabet: no I, L, O or U");
    assert.equal(parsePairingCode(code), code);
  }
  assert.equal(formatPairingCode("7KQMX4TD"), "7KQM-X4TD");
  assert.equal(parsePairingCode(" 7kqm-x4td "), "7KQMX4TD", "typed in lower case, with the dash");
  assert.equal(parsePairingCode("oIl0-0000"), "01100000", "O reads as 0, I and L as 1");
  assert.equal(parsePairingCode("7KQM-X4TU"), null, "U isn't in the alphabet");
  assert.equal(parsePairingCode("7KQM-X4T"), null);
  assert.equal(CROCKFORD_ALPHABET, "0123456789ABCDEFGHJKMNPQRSTVWXYZ", "the recovery key's alphabet");

  // 20 failures per ten minutes, then an hour's block: 20 guesses per 70 minutes per address.
  const live = 1000;
  const perAddressHour = 20 / (70 / 60);
  const botnetHour = 10_000 * perAddressHour;
  const hoursPerHit = (bits) => 2 ** bits / live / botnetHour;
  assert.ok(Math.abs(2 ** PAIRING_CODE_BITS / live / 1e9 - 1) < 0.1, "one hit per billion guesses");
  assert.equal(Math.round(perAddressHour), 17, "about 17 guesses an hour");
  assert.equal(Math.round(botnetHour / 10_000) * 10_000, 170_000);
  assert.equal(Math.round(hoursPerHit(PAIRING_CODE_BITS) / (24 * 30.4)), 9, "every nine months or so");
  assert.equal(Math.round(hoursPerHit(30)), 6, "six characters would be every six hours");
}

/* ── the QR ─────────────────────────────────────────────────────────────── */

{
  const key = createPairingKey().publicKey;
  const qr = formatPairingQr({ sessionId: SESSION, publicKey: key });
  assert.equal(qr.length, 87);
  assert.match(qr, /^[0-9A-Z $%*+\-./:]+$/, "QR's alphanumeric mode, so it stays a version 4 code");
  const back = parsePairingQr(qr);
  assert.ok(back.ok);
  assert.equal(hex(back.sessionId), hex(SESSION));
  assert.equal(hex(back.publicKey), hex(key));
  assert.equal(back.relayOrigin, undefined);

  const own = formatPairingQr({ sessionId: SESSION, publicKey: key, relayOrigin: "https://ID.Example.org:8443" });
  assert.match(own, /^[0-9A-Z $%*+\-./:]+$/);
  assert.equal(parsePairingQr(own).relayOrigin, "https://id.example.org:8443");
  assert.throws(() => formatPairingQr({ sessionId: SESSION, publicKey: key, relayOrigin: "http://relay.example" }));
  const dev = formatPairingQr({ sessionId: SESSION, publicKey: key, relayOrigin: "http://localhost:3004" });
  assert.equal(parsePairingQr(dev).relayOrigin, "http://localhost:3004");

  const reason = (s) => parsePairingQr(s).reason;
  assert.equal(reason("https://gryt.chat"), "not-pairing");
  assert.equal(reason(qr.replace("*GRYT*1*", "*GRYT*2*")), "newer-version", "an old app refuses rather than guesses");
  assert.equal(reason(qr.toLowerCase()), "not-pairing");
  assert.equal(reason(qr.replace("*GRYT*1*", "*GRYT*1*x")), "malformed");
  assert.equal(reason(qr.slice(0, -1) + "H"), "malformed", "padding bits have to be zero");
  assert.equal(reason(`${qr}*HTTP://EVIL.EXAMPLE`), "malformed", "a relay the QR names has to be https");
  assert.equal(reason(`${qr}*HTTPS://EVIL.EXAMPLE/PATH`), "malformed");
  assert.equal(reason(`${own}*HTTPS://EVIL.EXAMPLE`), "malformed", "one relay, not a list");
  assert.equal(reason(qr.slice(1)), "not-pairing");
  assert.equal(reason(` ${qr}`), "not-pairing", "a scanner that trims would read something else");
  assert.equal(reason(qr.replaceAll("*", ":")), "not-pairing", "the 0.8.0 shape is gone, not tolerated");
}

/* ── the QR isn't a link (GRYT-1577) ────────────────────────────────────── */

// Camera apps match the text against these before offering to open it. `gryt:` is a scheme
// Gryt registers, and schemes ignore case, so a `GRYT:` start was a link into the app.
{
  const key = createPairingKey().publicKey;
  const plain = formatPairingQr({ sessionId: SESSION, publicKey: key });
  const own = formatPairingQr({ sessionId: SESSION, publicKey: key, relayOrigin: "https://id.example.org" });
  const dev = formatPairingQr({ sessionId: SESSION, publicKey: key, relayOrigin: "http://localhost:3004" });

  for (const qr of [plain, own, dev]) {
    // RFC 3986 section 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), then ":".
    assert.doesNotMatch(qr, /^[A-Za-z][A-Za-z0-9+\-.]*:/, "a URI scheme at the start");
    // ZXing's URIResultParser, the one most Android scanner apps run.
    assert.doesNotMatch(qr, /^[a-zA-Z][a-zA-Z0-9+\-.]+:/, "ZXing's URL-with-scheme check");
    assert.doesNotMatch(qr, /^([a-zA-Z0-9-]+\.){1,6}[a-zA-Z]{2,}(:\d{1,5})?(\/|\?|$)/, "ZXing's bare-domain check");
    assert.doesNotMatch(qr, /^(URL|URI|WIFI|MECARD|MATMSG|SMSTO|BIZCARD|BEGIN):/i, "a typed payload");
    assert.doesNotMatch(qr, /@/, "an email address");
    assert.equal(qr, qr.trim(), "no whitespace for a scanner to trim off");
    assert.match(qr, /^[0-9A-Z $%*+\-./:]+$/, "still QR's alphanumeric mode");
  }
  // Nowhere in the text, not only at the start, since data detectors search the whole string.
  assert.doesNotMatch(plain, /GRYT:/i);
  assert.doesNotMatch(plain, /:/, "without a relay there's no colon at all");
  assert.doesNotMatch(own.slice(0, own.lastIndexOf("*")), /:/, "the relay origin is the only part with one");
}

console.log("pairing: the vectors hold, a swapped key moves the emoji, and a changed, replayed or cross-session message is refused");
