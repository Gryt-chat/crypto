/* eslint-env node */

/**
 * The sealed seed on the account (GRYT-1473). Every bundle already on Keycloak has to keep
 * opening, so the vectors here are literals: if one fails the format moved, not the vector.
 */

import assert from "node:assert/strict";

import { argon2id } from "@noble/hashes/argon2.js";

import {
  formatRecoveryKey,
  generateRecoveryKey,
  generateVaultPassword,
  isSealedVault,
  MIN_VAULT_PASSWORD,
  openSeed,
  parseRecoveryKey,
  referenceVaultKdfs,
  sealSeed,
  VAULT_ARGON2ID,
  VAULT_PASSWORD_WORDS,
  VAULT_TYPE,
  vaultHasRecoverySlot,
  vaultNeedsUpgrade,
} from "../dist/index.js";
import { wordlist } from "@scure/bip39/wordlists/english.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const utf8 = (text) => new TextEncoder().encode(text);
const text = (bytes) => new TextDecoder().decode(bytes);

const WORDS =
  "abandon amount liar amount expire adjust cage candy arch gather drum bullet " +
  "absurd math era live bid rhythm alien crouch range attend journey unaware";

/* ── Argon2id gives the published answers ───────────────────────────────── */

{
  // RFC 9106 section 5.3. Needs the secret and associated data, which only noble takes.
  const tag = argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
    t: 3, m: 32, p: 4, dkLen: 32, key: new Uint8Array(8).fill(3), personalization: new Uint8Array(12).fill(4),
  });
  assert.equal(hex(tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", "RFC 9106 Argon2id");

  // phc-winner-argon2's test.c, and the adapter interface every platform implements.
  const phc = await referenceVaultKdfs.argon2id(utf8("password"), utf8("somesalt"), { t: 2, m: 65536, p: 1 });
  assert.equal(hex(phc), "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7", "reference Argon2id test vector");

  // The vault's own parameters. hash-wasm gave the same bytes when this was written, and
  // the client's check holds the same literal against its WASM build.
  const ours = await referenceVaultKdfs.argon2id(
    utf8("vector password"), Uint8Array.from({ length: 16 }, (_, i) => i), VAULT_ARGON2ID,
  );
  assert.equal(hex(ours), "24a8ca3ac31cdb6d9ed4072aeb77d85fcb5b716e3132477dbdf8680ef3060a6d", "Argon2id at the vault's parameters");
}

assert.deepEqual({ ...VAULT_ARGON2ID }, { m: 65536, t: 3, p: 1 }, "the vault's cost is decision 4, not a tuning knob");

/* ── version 1 bundles, sealed by the client on main before this change ──── */

// Each from client identity-vault.ts at b215c594, PBKDF2 at 600,000 through WebCrypto.
const V1 = [
  {
    secret: "hunter2x",
    words: WORDS,
    vault: {"type":"gryt-identity-vault","version":1,"kdf":"PBKDF2-SHA256","iterations":600000,"secretKind":"password","salt":"ya-E99aPOrPB9cVWHRAN0A","iv":"LpB5rtziarP9gIDY","data":"H-1uwG7cQpsTN4M1SX7HZnL8iuXix7CDLdSo5Mq2pdRdIl0elisAc6SEIkXCwQveDe6bi05vufkt18jDz61oW3CedQ9oIaYBa2qGb3UMa5523pxrXRNMoWPduZyL8Z6o7zLkIkTagj6UIZJ6_XCw8CQJRsp5flXRP2MRwa1u-nIsyrjysMWdoiwug6aVSh7B1RbaG3wXFNxT-dLT7WIIlfjSO2Fx"},
  },
  {
    secret: "Blåbær-syltetøy é",
    words: WORDS,
    vault: {"type":"gryt-identity-vault","version":1,"kdf":"PBKDF2-SHA256","iterations":600000,"secretKind":"password","salt":"Qc3KFgl1XZ57LtL4_kYNmg","iv":"sXLH576wBZ8fb72I","data":"InvK5-fPma8O8yG__AGPLge9JRo3W0ov74WKPHmuvMEYUWsNGlhdEXiJrww0aDC4EZGHANg1nrvFI8T2MuS-_q21978-iNw5zDlmrs_UgcYFTcMlQYIBP-bsqg7Tjb33xMMJmuwkFpbqFErJQduy9f1HWcyf2ByOkz72S8go8m4tnoj6a-m-jx7yn_-TyeRoOpzDDMOgUQHzQh06zNqBw-Nl1CvJ"},
  },
  {
    // Four characters, which the old floor allowed. It still has to open.
    secret: "abcd",
    words: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    vault: {"type":"gryt-identity-vault","version":1,"kdf":"PBKDF2-SHA256","iterations":600000,"secretKind":"password","salt":"pMPNT4sc2QDQnL4G09TK_w","iv":"LnGChomQIrhtFB1i","data":"6Dzs3BaIl65Vv4Dil18kjFQJjl2qPYPf_LlcIaHTBOs39Hv_12lRpYwx_xk6aTe515EMjDUZ8VZ1BIc-zU8dZ-DrcSC0XKcc6qtNakz3GwPgh-81ZTvDOMtpVlzBabJcibU7lx93J3gQemZqi4Q_3Q"},
  },
];

for (const { secret, words, vault } of V1) {
  assert.ok(isSealedVault(vault));
  assert.ok(vaultNeedsUpgrade(vault), "every version 1 bundle is due an upgrade");
  assert.equal(text(await openSeed(vault, secret)), words, "a version 1 bundle on Keycloak no longer opens");
  await assert.rejects(() => openSeed(vault, secret + "x"), /Wrong password/);
}

{
  // Version 1 hashed the password unnormalised. The same text in NFD is different bytes.
  const nfd = V1[1].secret.normalize("NFD");
  assert.notEqual(nfd, V1[1].secret);
  await assert.rejects(() => openSeed(V1[1].vault, nfd), /Wrong password/);
}

/* ── the migration: open a version 1, re-seal, open again ───────────────── */

{
  const { secret, words, vault } = V1[0];
  const seed = await openSeed(vault, secret);
  const upgraded = await sealSeed(seed, { password: secret, secretKind: vault.secretKind });
  assert.equal(upgraded.version, 2);
  assert.ok(!vaultNeedsUpgrade(upgraded));
  assert.equal(text(await openSeed(JSON.parse(JSON.stringify(upgraded)), secret)), words);
  // The version 1 bundle is untouched by any of this and still opens on its own.
  assert.equal(text(await openSeed(vault, secret)), words);
}

/* ── a version 2 bundle, frozen when this format shipped ────────────────── */

const RECOVERY = Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1);
const V2 = {"type":"gryt-identity-vault","version":2,"secretKind":"password","salt":"","iv":"nqcvsvYf8MrRqcKe","data":"koQ68z2tN96rbIckVaDaYznXFZrWZ2_EHncb9sPqFCK-RSo9XHnKZjvKO0OTMQKgEqM8MATlAICv2WyZixcPk0h7mzdfHSkPk_tZitn4OGIWwR4IdyZrGKI-8WmytUXSxqCswnvmuL2Akafxdqlo-ALaouM7p7NdXXunmYpLxw7zgV2oRUJ9js9dotA1MJjkH-Dg74-xWjAf1VDLC51NeX7uZQee","slots":[{"kind":"password","kdf":"argon2id","m":65536,"t":3,"p":1,"salt":"zrinFrrnINf3_98bbE3L2Q","iv":"rHX5v0kTPDiYiz3s","key":"FSAg_cXJPP-hP3UoZ-YFoeAS7MrYLSrGuvqmHAjxUdzuw1OECHoofjTPnZdeFlCk"},{"kind":"recovery","kdf":"hkdf-sha256","salt":"e4GrFtB6ph7lgB9adk-iEg","iv":"Vo9hwBqLal_T7ZAe","key":"6nG42JskyoM0NZs0BtWctkHmJJPKNVqT2Jh9AC5uQVpKDVnHerVTJQfFxzAFtVdk"}]};

assert.equal(formatRecoveryKey(RECOVERY), "0440-Y5GX-4GNK-4EA0-8X75-AQ33-D9RQ-GZW6-HPA9-Q8N9-P2VV-XHEC-TFD0");
assert.equal(text(await openSeed(V2, "legal winner thank year wave sausage")), WORDS, "password slot");
assert.equal(text(await openSeed(V2, formatRecoveryKey(RECOVERY))), WORDS, "recovery slot");
assert.equal(text(await openSeed(V2, " 0440y5gx4gnk4ea08x75aq33d9rqgzw6hpa9q8n9p2vvxhectfd0 ")), WORDS, "recovery key, retyped loosely");
assert.ok(vaultHasRecoverySlot(V2));
assert.ok(!vaultNeedsUpgrade(V2));

/* ── clients from before this still recognise a version 2 bundle ────────── */

{
  // The client's isSealedVault at b215c594. Failing it, an old client says the account
  // has no password and offers to set one over the new bundle.
  const oldIsSealedVault = (v) => !!v && v.type === VAULT_TYPE && typeof v.salt === "string" && typeof v.data === "string";
  assert.ok(oldIsSealedVault(V2), "an old client would treat a version 2 bundle as absent");
}

/* ── round trips, wrong secrets and altered bundles ─────────────────────── */

const SEED = utf8(WORDS);

{
  const plain = await sealSeed(SEED, { password: "twelve chars!" });
  assert.equal(plain.slots.length, 1);
  assert.ok(!vaultHasRecoverySlot(plain));
  assert.equal(text(await openSeed(plain, "twelve chars!")), WORDS);
  await assert.rejects(() => openSeed(plain, formatRecoveryKey(RECOVERY)), /Wrong password/, "no recovery slot, no way in with one");

  for (const wrong of ["", "twelve chars", "Twelve chars!", " twelve chars!"]) {
    await assert.rejects(() => openSeed(plain, wrong), /Wrong password/);
  }

  // NFC: a composed and a decomposed é are the same password from here on.
  const composed = await sealSeed(SEED, { password: "café au lait!" });
  assert.equal(text(await openSeed(composed, "café au lait!")), WORDS);
}

{
  const recovery = generateRecoveryKey();
  const sealed = await sealSeed(SEED, { password: "twelve chars!", recoveryKey: recovery });
  const wrongKey = new Uint8Array(recovery);
  wrongKey[0] ^= 1;
  await assert.rejects(() => openSeed(sealed, formatRecoveryKey(wrongKey)), /Wrong password/);

  // The seed is sealed once, not per slot, and never sits in the blob in the clear.
  const hay = JSON.stringify(sealed);
  assert.ok(!hay.includes(WORDS.split(" ")[0] + " "), "the words must not be in the blob");

  const b64 = (s) => s.replace(/-/g, "+").replace(/_/g, "/");
  const flip = (s) => {
    const bytes = Buffer.from(b64(s), "base64");
    bytes[0] ^= 0xff;
    return bytes.toString("base64url");
  };

  for (const field of ["iv", "data"]) {
    const copy = JSON.parse(hay);
    copy[field] = flip(copy[field]);
    await assert.rejects(() => openSeed(copy, "twelve chars!"), /Wrong password/, `flipping ${field}`);
    await assert.rejects(() => openSeed(copy, formatRecoveryKey(recovery)), /Wrong password/, `flipping ${field}`);
  }
  for (const i of [0, 1]) {
    for (const field of ["salt", "iv", "key"]) {
      const copy = JSON.parse(hay);
      copy.slots[i][field] = flip(copy.slots[i][field]);
      const secret = i === 0 ? "twelve chars!" : formatRecoveryKey(recovery);
      await assert.rejects(() => openSeed(copy, secret), /Wrong password/, `flipping slot ${i} ${field}`);
    }
  }

  // Lowering the cost changes the key, so a server cannot make the next open cheaper.
  const cheaper = JSON.parse(hay);
  cheaper.slots[0].m = 1024;
  await assert.rejects(() => openSeed(cheaper, "twelve chars!"), /Wrong password/);

  // And raising it past the ceiling is refused before any memory is allocated.
  const costly = JSON.parse(hay);
  costly.slots[0].m = 4 * 1024 * 1024;
  await assert.rejects(() => openSeed(costly, "twelve chars!"), /more work than Gryt will do/);

  // A slot kind this version does not know is skipped, not fatal.
  const future = JSON.parse(hay);
  future.slots.unshift({ kind: "passkey", kdf: "prf", salt: "", iv: "", key: "" });
  assert.equal(text(await openSeed(future, "twelve chars!")), WORDS);

  // Relabelling the recovery slot as a password slot does not open it.
  const relabelled = JSON.parse(hay);
  relabelled.slots = [{ ...relabelled.slots[1], kind: "password", kdf: "argon2id", ...VAULT_ARGON2ID }];
  await assert.rejects(() => openSeed(relabelled, formatRecoveryKey(recovery)), /Wrong password/);
}

{
  await assert.rejects(() => openSeed({ ...V2, version: 3 }, "x"), /newer version of Gryt/);
  assert.equal(vaultNeedsUpgrade({ type: VAULT_TYPE, version: 3 }), false, "a newer vault is not ours to re-seal");
  assert.equal(vaultHasRecoverySlot({ type: VAULT_TYPE, version: 3 }), false);
  await assert.rejects(() => openSeed({ hello: "world" }, "x"), /not a sealed Gryt identity/);
  await assert.rejects(() => sealSeed(SEED, { password: "" }), /Choose a password/);
  await assert.rejects(() => sealSeed(SEED, { password: "x", recoveryKey: new Uint8Array(16) }), /32 bytes/);

  // Re-sealing a four-character version 1 password has to work; the floor is the UI's.
  const short = await sealSeed(SEED, { password: "abcd" });
  assert.equal(text(await openSeed(short, "abcd")), WORDS);
}

/* ── the recovery key's text form ───────────────────────────────────────── */

{
  for (let i = 0; i < 50; i++) {
    const key = generateRecoveryKey();
    const shown = formatRecoveryKey(key);
    assert.match(shown, /^([0-9A-HJKMNP-TV-Z]{4}-){12}[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.deepEqual(parseRecoveryKey(shown), key);
    assert.deepEqual(parseRecoveryKey(shown.toLowerCase().replace(/-/g, " ")), key);
  }
  const shown = formatRecoveryKey(RECOVERY);
  assert.deepEqual(parseRecoveryKey(shown.replace(/0/g, "O")), RECOVERY, "O reads as zero");
  assert.equal(parseRecoveryKey(shown.slice(0, -1) + "1"), null, "non-zero padding bits");
  assert.equal(parseRecoveryKey(shown.replace("Y", "U")), null, "U is not in the alphabet");
  assert.equal(parseRecoveryKey("legal winner thank year wave sausage"), null);
  assert.equal(parseRecoveryKey(""), null);
}

/* ── generated passwords ────────────────────────────────────────────────── */

{
  assert.equal(VAULT_PASSWORD_WORDS, 6);
  assert.equal(MIN_VAULT_PASSWORD, 12);
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const password = generateVaultPassword();
    const words = password.split(" ");
    assert.equal(words.length, 6);
    for (const w of words) assert.ok(wordlist.includes(w));
    assert.ok(password.length >= MIN_VAULT_PASSWORD, "a generated password has to clear the typed floor too");
    seen.add(password);
  }
  assert.equal(seen.size, 200);
}

console.log("identity-vault: version 1 bundles open, version 2 seals, and both slots hold");
