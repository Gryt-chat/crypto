# @gryt/crypto

Message encryption for [Gryt](https://gryt.chat): key derivation, key bindings,
sealed envelopes, pinning, and the code two people compare out of band.

Used by the desktop client and the mobile app. They run this, not two ports of
it — two implementations of one envelope is a pair of clients that send each
other messages nobody can read, with the sender looking at the text they typed
either way.

## What it is

- **`dm-keys`** — an X25519 keypair per server, from the same seed the identity
  comes from, and the shared secret between two of them.
- **`dm-key-binding`** — a short JWT saying "this message key is mine", signed
  by the identity key that joined the server.
- **`message-keys`** — a random key per message, encrypted once for each member.
- **`peer-keys`** — pin what you saw first, refuse a change.
- **`member-keys`** — the same decision over a whole member list.
- **`conversation-encryption`** — every member has a usable key, or nobody gets
  it sealed.
- **`comparison-code`** — sixty digits two people read to each other.

## What it deliberately isn't

**Platform-specific.** No `crypto.subtle`, which React Native does not have. No
storage — pins go through a `PeerPinStore` the caller supplies. No network, no
React, no config.

Two exceptions, named where they are: `crypto.getRandomValues`, which every
target has, and signing a binding, which takes either a WebCrypto key or a
function, because that is the one place the platforms hold a key differently.

**Forward secret.** A message key comes from the seed and never moves, so a seed
that leaks reads every message ever sent to it. Signal and Matrix ratchet; this
does not. That is GRYT-754 and it is a different protocol rather than a setting.

**A cryptography library.** The primitives are `@noble/curves`,
`@noble/hashes` and `@noble/ciphers`. This is the composition of them.

## Checks

`npm test` runs every `scripts/check-*.mjs` against the built `dist`, which is
what a client installs. `check-crypto-vectors.mjs` holds bytes produced before
the WebCrypto-to-noble conversion and nothing regenerates them — a change that
quietly altered the envelope would leave every message already sent unreadable.

## Licence

AGPL-3.0-only.
