/* eslint-env node */

/**
 * The RFC 9420 interop vectors, suite 1, on Gryt's provider and the pinned ts-mls. Fetched at a
 * fixed commit into `.mls-vectors/`, the first time only. Run on every ts-mls bump.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

import { grytMlsCryptoProvider } from "../dist/index.js";
import { corruptions, runVectors } from "../docs/mls-library-check/vectors-core.mjs";

// The commit docs/mls-library-check.md ran against. Moving it means re-reading what changed.
const COMMIT = "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a";
const root = new URL("..", import.meta.url).pathname;
const dir = join(root, ".mls-vectors", COMMIT);

if (!existsSync(join(dir, "messages.json"))) {
  const tmp = join(root, ".mls-vectors", `fetching-${process.pid}`);
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  const git = (...args) => execFileSync("git", ["-C", tmp, ...args], { stdio: "pipe" });
  git("init", "-q");
  git("remote", "add", "origin", "https://github.com/mlswg/mls-implementations.git");
  git("fetch", "-q", "--depth", "1", "origin", COMMIT);
  git("checkout", "-q", "FETCH_HEAD");
  rmSync(dir, { recursive: true, force: true });
  renameSync(join(tmp, "test-vectors"), dir);
  rmSync(tmp, { recursive: true, force: true });
}

// The harness under docs/ could find its own ts-mls; it has to be the one this package pins.
{
  const harness = createRequire(new URL("../docs/mls-library-check/vectors-core.mjs", import.meta.url));
  const own = createRequire(import.meta.url);
  assert.equal(harness.resolve("ts-mls"), own.resolve("ts-mls"), "the vectors would run against a ts-mls other than the pinned one");
}

const SUITES = [1];
const load = (file) => JSON.parse(readFileSync(join(dir, file), "utf8"));
const report = await runVectors({ load, provider: grytMlsCryptoProvider, suites: SUITES, now: () => performance.now() });

// Suite 1's share of each file at that commit. Fewer means vectors were skipped, not passed.
const EXPECTED = {
  "tree-math.json": 10,
  "crypto-basics.json": 1,
  "secret-tree.json": 3,
  "message-protection.json": 1,
  "key-schedule.json": 1,
  "psk_secret.json": 11,
  "transcript-hashes.json": 1,
  "welcome.json": 1,
  "tree-operations.json": 5,
  "tree-validation.json": 14,
  "treekem.json": 11,
  "messages.json": 300,
  "deserialization.json": 14,
  "passive-client-welcome.json": 8,
  "passive-client-handling-commit.json": 13,
  "passive-client-random.json": 1,
};

let total = 0;
let checks = 0;
for (const r of report) {
  const detail = r.suites.flatMap((s) => s.failures.map((f) => `vector ${f.vector}: ${f.failed.join("; ")}`));
  assert.equal(r.fail, 0, `${r.file}: ${r.fail} vectors failed\n  ${detail.join("\n  ")}`);
  assert.equal(r.pass, EXPECTED[r.file], `${r.file} ran ${r.pass} vectors, expected ${EXPECTED[r.file]}`);
  total += r.pass;
  checks += r.suites.reduce((a, s) => a + s.checks, 0);
}
assert.equal(report.length, Object.keys(EXPECTED).length, "a vector file wasn't run");

// And the checks can fail: one wrong expected value per file has to fail exactly one vector.
const corrupted = await runVectors({
  load: (file) => {
    const vectors = load(file);
    const i = vectors.findIndex((v) => v.cipher_suite === undefined || SUITES.includes(v.cipher_suite));
    corruptions[file](vectors[i]);
    return vectors;
  },
  provider: grytMlsCryptoProvider,
  suites: SUITES,
  now: () => performance.now(),
});
for (const r of corrupted) assert.equal(r.fail, 1, `a corrupted ${r.file} failed ${r.fail} vectors, not 1`);

console.log(`mls-vectors: all ${total} suite 1 RFC 9420 vectors pass on Gryt's provider (${checks} checks), and a corrupted one fails in each of the ${report.length} files`);
