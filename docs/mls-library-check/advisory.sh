#!/bin/sh
# Runs the vectors and the group properties against ts-mls 1.6.2, the last release before
# GHSA-gwp3-968w-m7gv was fixed. Installs into .advisory/ so the pinned 1.6.4 is untouched.
set -e
cd "$(dirname "$0")"
[ -d vectors ] || sh fetch-vectors.sh
rm -rf .advisory
mkdir -p .advisory
node -e '
const { execSync } = require("child_process")
const peers = JSON.parse(execSync("npm view ts-mls@1.6.2 peerDependencies --json"))
const keep = Object.keys(require("./package.json").dependencies).filter((d) => d in peers)
const deps = Object.fromEntries([["ts-mls", "1.6.2"], ...keep.map((d) => [d, peers[d]])])
require("fs").writeFileSync(".advisory/package.json", JSON.stringify({ private: true, type: "module", dependencies: deps }, null, 2))
'
cp vectors.mjs vectors-core.mjs properties.mjs pure-provider.mjs .advisory/
ln -s ../vectors .advisory/vectors
(cd .advisory && npm install --no-audit --no-fund --loglevel=error)
{
  node .advisory/vectors.mjs --provider=default --json=results/vectors-node-default-1.6.2.json | grep -v '^       suite' || true
  node .advisory/properties.mjs --provider=default || true
} | tee results/advisory-1.6.2.txt
