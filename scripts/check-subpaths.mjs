/* eslint-env node */

/**
 * Every module is reachable on its own, not only through the barrel (GRYT-732), so a file
 * name here is published surface. Against `dist`, because the `exports` map points there.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));

assert.deepEqual(
  pkg.exports["./*"],
  { types: "./dist/*.d.ts", default: "./dist/*.js" },
  "the wildcard subpath is what the client's barrel resolves through",
);

// The wildcard swallows this otherwise, resolving `@gryt/crypto/package.json` to
// `dist/package.json.js`. Metro and most bundlers read a manifest that way.
assert.equal(
  pkg.exports["./package.json"],
  "./package.json",
  "the manifest has to stay reachable past the wildcard",
);

/** The seven the client takes by subpath, and `peer-keys`, which it wraps. */
const MODULES = [
  "attachments",
  "base64",
  "comparison-code",
  "conversation-encryption",
  "dm-key-binding",
  "dm-keys",
  "member-keys",
  "message-keys",
  "peer-keys",
  "scope",
  "seed-words",
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
