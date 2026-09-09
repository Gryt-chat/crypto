// The 24-word backup. What matters is that it is the same encoding both apps already
// shipped: a change that round-trips against itself would strand every backup on paper.
import assert from "node:assert/strict";

const { seedToWords, wordsToSeed, assertUsableSeed, SEED_BYTES, BACKUP_WORDS } =
  await import("../dist/index.js");

assert.equal(SEED_BYTES, 32);
assert.equal(BACKUP_WORDS, 24);

// A seed of 0x00..0x1f, confirmed against the client's own @scure/bip39 before this module
// existed. A literal, so this file cannot drift along with the code it checks.
const VECTORS = [
  {
    seed: Uint8Array.from({ length: 32 }, (_, i) => i),
    words:
      "abandon amount liar amount expire adjust cage candy arch gather drum bullet " +
      "absurd math era live bid rhythm alien crouch range attend journey unaware",
  },
];

for (const v of VECTORS) {
  assert.equal(seedToWords(v.seed), v.words, "the encoding moved — every written phrase is stranded");
  assert.deepEqual(wordsToSeed(v.words), v.seed, "a known phrase no longer restores its seed");
}

// Round trip across a spread of seeds.
for (let s = 0; s < 200; s++) {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = (s * 97 + i * 31 + 7) & 0xff;
  assert.deepEqual(wordsToSeed(seedToWords(seed)), seed);
}

// Whitespace and case are forgiven, because people copy these out of a note app.
const seed = new Uint8Array(32);
for (let i = 0; i < 32; i++) seed[i] = (i * 11 + 3) & 0xff;
const phrase = seedToWords(seed);
assert.deepEqual(wordsToSeed(`  ${phrase.toUpperCase().replace(/ /g, "   ")}  `), seed);

// A swapped word has to fail rather than produce a different identity, which is
// the whole reason the checksum is inside the words.
const parts = phrase.split(" ");
[parts[0], parts[1]] = [parts[1], parts[0]];
assert.throws(() => wordsToSeed(parts.join(" ")), /valid identity backup/);

assert.throws(() => wordsToSeed(parts.slice(0, 23).join(" ")), /23 words/);
assert.throws(() => wordsToSeed("   "), /Enter your identity words/);
assert.throws(() => assertUsableSeed(new Uint8Array(31)), /32 bytes, not 31/);
assert.throws(() => assertUsableSeed(new Uint8Array(32)), /single repeated byte/);

console.log(
  "seed-words: a known phrase still restores its seed, round trips across 200 seeds, forgives case and spacing, and refuses a swapped word",
);
