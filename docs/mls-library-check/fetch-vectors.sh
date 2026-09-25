#!/bin/sh
# Fetches the RFC 9420 interop vectors at the commit this check was run against.
set -e
cd "$(dirname "$0")"
COMMIT=cfd450286d1bfd9cd2519b95c80f9771f94a5b1a
rm -rf .mls-implementations vectors
git clone --quiet https://github.com/mlswg/mls-implementations.git .mls-implementations
git -C .mls-implementations checkout --quiet "$COMMIT"
cp -R .mls-implementations/test-vectors vectors
rm -rf .mls-implementations
echo "vectors at mls-implementations@$COMMIT"
