#!/bin/sh
# Builds a small JSI host against the Hermes that React Native ships in its CocoaPod, then runs
# the vectors and the bench in it. HERMES_DESTROOT is ios/Pods/hermes-engine/destroot after pod install.
set -e
cd "$(dirname "$0")"
: "${HERMES_DESTROOT:?set HERMES_DESTROOT to <mobile>/ios/Pods/hermes-engine/destroot}"
FW="$HERMES_DESTROOT/Library/Frameworks/universal/hermesvm.xcframework/macos-arm64_x86_64"
mkdir -p .hermes
clang++ -std=c++20 -O2 -I"$HERMES_DESTROOT/include" -F"$FW" -framework hermesvm -Wl,-rpath,"$FW" hermes-host.cpp -o .hermes/hermes-host
node bundle.mjs vectors-hermes-entry.mjs .hermes/vectors.js --hermes
node bundle.mjs bench-hermes-entry.mjs .hermes/bench.js --hermes
.hermes/hermes-host .hermes/vectors.js | tee .hermes/vectors.txt | grep -v '^RESULT_JSON'
grep '^RESULT_JSON' .hermes/vectors.txt | cut -c13- > results/vectors-hermes-pure.json
.hermes/hermes-host .hermes/bench.js | tee .hermes/bench.txt | grep -v '^RESULT_JSON'
grep '^RESULT_JSON' .hermes/bench.txt | cut -c13- > results/bench-hermes-pure.json
