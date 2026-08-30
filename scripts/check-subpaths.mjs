/* eslint-env node */

/**
 * Every module is reachable on its own, not only through the barrel (GRYT-732).
 *
 * The client imports these by subpath rather than as `export * from
 * "@gryt/crypto"`, because its own `peer-keys` exports the same names as this
 * package's with the store already supplied. Two star exports of one name is
 * ambiguous and TypeScript drops the name instead of complaining, so the client
 * takes seven subpaths and leaves the eighth alone.
 *
 * That makes a file name here part of the published surface. Renaming
 * `dm-keys.ts` compiles, passes every other check, publishes, and breaks the
 * client's barrel on install — which is a long way from the rename.
 *
 * Against `dist`, because the `exports` map points there and a wildcard that
 * resolves in the source tree and not in the tarball is the failure worth
 * catching.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));

assert.deepEqual(
  pkg.exports["./*"],
  { types: "./dist/*.d.ts", default: "./dist/*.js" },
  "the wildcard subpath is what the client's barrel resolves through",
);

/** The seven the client takes by subpath, and `peer-keys`, which it wraps. */
const MODULES = [
  "comparison-code",
  "conversation-encryption",
  "dm-key-binding",
  "dm-keys",
  "member-keys",
  "message-keys",
  "peer-keys",
  "scope",
  "thumbprint",
];

const barrel = await import("../dist/index.js");

for (const name of MODULES) {
  const direct = await import(`../dist/${name}.js`);
  const exported = Object.keys(direct).filter((k) => k !== "default");

  assert.ok(
    exported.length > 0,
    `${name} exports nothing, so importing it by subpath gets a consumer an empty object`,
  );

  for (const key of exported) {
    assert.ok(
      key in barrel,
      `${name} exports ${key} and the barrel does not — one of the two is wrong`,
    );
  }
}

console.log(
  `subpaths: all ${MODULES.length} modules import on their own and agree with the barrel`,
);
