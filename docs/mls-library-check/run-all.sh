#!/bin/sh
# Everything behind docs/mls-library-check.md, in order, writing results/*.json.
# Chrome and Electron need macOS paths or CHROME/ELECTRON; Hermes needs HERMES_DESTROOT.
set -e
cd "$(dirname "$0")"
[ -d vectors ] || sh fetch-vectors.sh
node self-test.mjs
for p in default pure; do node vectors.mjs --provider=$p --json=results/vectors-node-$p.json; done
for p in default pure; do node properties.mjs --provider=$p | tee results/properties-node-$p.txt; done
node web-run.mjs chrome vectors default --json=results/vectors-chrome-default.json
node web-run.mjs electron vectors default --json=results/vectors-electron-default.json
for p in default pure; do node bench-node.mjs --provider=$p --json=results/bench-node-$p.json; done
for p in default pure; do node web-run.mjs chrome bench $p --json=results/bench-chrome-$p.json; done
node web-run.mjs electron bench default --json=results/bench-electron-default.json
[ -n "$HERMES_DESTROOT" ] && sh hermes.sh || echo "HERMES_DESTROOT not set, skipping Hermes"
sh advisory.sh
