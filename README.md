<div align="center">
  <img src="https://raw.githubusercontent.com/Gryt-chat/client/main/public/logo.svg" width="80" alt="Gryt logo" />
  <h1>@gryt/crypto</h1>
  <p>Message encryption for <a href="https://gryt.chat">Gryt</a>.<br />Key derivation, key bindings, sealed envelopes, pinning, and the code two people compare out of band.</p>
</div>

<br />

```sh
npm install @gryt/crypto
```

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
- **`attachments`** — a key per file, bound so one file’s bytes cannot be served
  as another’s, with the key inside the sealed message.
- **`identity-vault`** — the 24 words, sealed so your account can carry them to
  a new device. Argon2id over the password, and an optional recovery key that
  opens it on its own. Bundles sealed the old way, with PBKDF2, still open.
- **`recovery-key`** — that key as 52 characters you can write down without
  mixing up 0 and O.
- **`mls-person-key`** — an Ed25519 key per server from the 24 words, the same
  on all your devices, and a JWT from your identity key saying it's yours.
- **`mls-device-certificate`** — the person key signing one device's MLS leaf
  key, with a device id and a name. These bytes are the leaf's credential.
- **`mls-authentication`** — the check `ts-mls` runs on every leaf: a
  certificate that verifies, for this server, for this leaf key, from a person
  key the client trusts. The client decides what it trusts.
- **`mls-group`** — MLS groups for DMs: a device, its KeyPackages, create, add,
  remove, update, process, encrypt and decrypt, and the group state as bytes to
  save. Everything that goes over the network is MLS wire bytes.
- **`mls-provider`** — the crypto `ts-mls` runs on: X25519 HPKE, Ed25519 and
  SHA-256 on `@noble`, for MLS suite 1 only. It lives here because Hermes has no
  `crypto.subtle`, and both of the library's own providers need it.
- **`vault-password`** — six random words, and the 12-character floor for a
  password you type yourself.

## Installing it with npm

`ts-mls` is pinned exactly, and it pins its optional `@noble` peers at older
versions than this package uses. npm stops with `ERESOLVE` over that, so an npm
project needs the same override this repository has:

```json
"overrides": {
  "ts-mls": { "@noble/curves": "$@noble/curves", "@noble/ciphers": "$@noble/ciphers" }
}
```

Yarn 1 prints a warning and carries on.

## Importing it

Everything is on the barrel, and every module is also its own subpath:

```ts
import { sealMessage } from "@gryt/crypto";
import { sealMessage } from "@gryt/crypto/message-keys";
```

The subpaths exist because the desktop client re-exports this package through
its own `@/common` barrel alongside a `peer-keys` of its own — the same
functions with `localStorage` already supplied. Two star exports of one name is
ambiguous, and TypeScript drops the name rather than saying so, so it takes the
other modules by subpath and leaves `peer-keys` to its own file.

That makes the file names here part of the published surface.
`scripts/check-subpaths.mjs` is what stops a rename getting out.

## What it deliberately isn't

**Platform-specific.** No `crypto.subtle`, which React Native does not have. No
`btoa` or `atob` either — Hermes has them and they stop agreeing with you about
bytes above `0x7f`, so `base64.ts` does it from the alphabet up. No storage —
pins go through a `PeerPinStore` the caller supplies. No network, no React, no
config.

Three exceptions, named where they are. `crypto.getRandomValues`, which every
target has. Signing a binding, which takes either a WebCrypto key or a
function, because that's where the platforms hold a key differently. And the
vault's Argon2id, which takes a `VaultKdfs` from the app: pure-JS Argon2id takes
26 seconds on an interpreter, so the web uses WASM and a phone uses native code.
The pure-JS one here is the reference, and the answers every implementation has
to give are in `check-identity-vault.mjs`.

**Hiding that a file exists.** An attachment is encrypted and its name, type and
dimensions go inside the message, but the server still sees that a file was
uploaded, how big the ciphertext is, and when. Padding the size is separate work
and is not pretended at.

**Forward secret, yet.** A sealed message's key comes from the seed and never
moves, so a seed that leaks reads every sealed message ever sent to it. That's
GRYT-754. The MLS modules above are the fix, and nothing sends through them
until the clients switch over, which is the rest of stage 1 in
[`docs/mls-design.md`](docs/mls-design.md).
[`docs/message-security.md`](docs/message-security.md) covers where the seed is
stored and how it reaches a second device.

**A cryptography library.** The primitives are `@noble/curves`,
`@noble/hashes` and `@noble/ciphers`. This is the composition of them.

## Checks

`npm test` runs every `scripts/check-*.mjs` against the built `dist`, which is
what a client installs. `check-crypto-vectors.mjs` holds bytes produced before
the WebCrypto-to-noble conversion and nothing regenerates them — a change that
quietly altered the envelope would leave every message already sent unreadable.
`check-identity-vault.mjs` does the same for the sealed seed: three bundles
sealed by the client before Argon2id, and one from the version that added it.
`check-mls-provider.mjs` runs the MLS crypto against the RFC 9180, 8032 and 4231
known answers with `crypto.subtle` taken away, the way Hermes has it.

## Issues

Please report bugs and request features in the
[main Gryt repository](https://github.com/Gryt-chat/gryt/issues).

## Sponsors

What sponsoring pays for, the tiers, and everyone who has sponsored:
[gryt.chat/sponsors](https://gryt.chat/sponsors). To sponsor:
[GitHub Sponsors](https://github.com/sponsors/Gryt-chat).

The list itself lives in the [Gryt README](https://github.com/Gryt-chat/gryt#sponsors),
in one place rather than ten, so it cannot fall out of step across repositories.

## License

[AGPL-3.0](https://github.com/Gryt-chat/gryt/blob/main/LICENSE) — Part of [Gryt](https://github.com/Gryt-chat/gryt)
