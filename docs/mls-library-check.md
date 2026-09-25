# Checking ts-mls

This answers one of the open questions in [message-security.md](message-security.md):

> **`ts-mls` maturity.** Version 1.6.4, updated August 2026, and I haven't read the code or
> checked what it claims against RFC 9420's interop vectors.

Nothing in `@gryt/crypto` changes because of it. The harness lives in
[`mls-library-check/`](mls-library-check/) with its own `package.json`, and `ts-mls` is only
installed there. It isn't a dependency of the package.

Everything here ran on 2026-09-25, against `ts-mls` 1.6.4, on an Apple M5 Pro.

## Verdict

**Use it, with conditions.** It passes every RFC 9420 interop vector in every runtime I
tried, Hermes included. Group operations are fast on desktop, and slow but workable on the
phone. There are eight conditions further down. Three of them change the plan:

1. **It doesn't run on Hermes as shipped.** Both of its built-in crypto providers go
   through `@hpke/core`, which needs `crypto.subtle`, and Hermes doesn't have it. Gryt has to
   supply the provider. The one in this harness is about 150 lines on top of `@noble` and
   passes the vectors, but it's crypto code Gryt would own.
2. **Pin 1.6.4 or later, and don't count on `npm audit`.** A high-severity advisory went out
   on 2026-08-28: removing a member didn't stop them reading. It isn't in the GitHub Advisory
   Database, so `npm audit` reports nothing on 1.6.2.
3. **The interop vectors missed that bug.** I ran them against 1.6.2 and all 785 passed. A
   short property test caught it straight away. Tests like that belong in Gryt's CI
   whichever library ends up underneath.

## The library

| | |
|---|---|
| Version | 1.6.4, published 2026-08-28. 1.6.3 went out the same day, and 1.6.4 only changes the version number. |
| Maintainer | Luka Jacobowitz, alone. 255 of the commits are his. The next most active person has 3, and dependabot has 344. `SECURITY.md` says "maintained by a single volunteer". |
| History | 0.1.0 in June 2025, 1.0.0 in July 2025. Minor releases about monthly until 1.6.1 in January 2026. After that, work moved to 2.0, with 16 release candidates from January to July 2026. 1.x is a maintenance branch that gets security fixes. |
| Activity | 108 stars, 21 forks. Last commit 2026-09-24. 11 open issues, 3 of them from dependabot. |
| Audit | None. The README says so, and suggests an independent review before production use. |
| Licence | MIT, which is fine next to `@gryt/crypto`'s AGPL-3.0. |
| Dependencies | One, `@hpke/core` 1.9.0, pinned exactly. Seven optional peers, also pinned exactly: `@noble/curves` 2.0.1, `@noble/ciphers` 2.1.1, `@hpke/chacha20poly1305`, `@hpke/dhkem-x448`, `@hpke/ml-kem`, `@hpke/hybridkem-x-wing` and `@noble/post-quantum`. |
| Size | 691 KB unpacked. The whole public API plus the pure provider bundles to 138 KB minified, 36 KB gzipped, without `@noble`. With `@noble` it's 236 KB minified and 74 KB gzipped, and the app already ships most of that. |
| Interop | The repository runs the same RFC vector files in its own tests. It also has an `interop/` gRPC client for the `mls-implementations` test harness. |

### Ciphersuites

It has all seven RFC 9420 suites, plus twelve post-quantum ones (ML-KEM, X-Wing and ML-DSA)
from drafts. The RFC vectors only cover suites 1 to 7.

Gryt needs one of these two:

- **Suite 2, `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`.** This one fits if the leaf
  signature key is the existing P-256 identity key, with its `id.gryt.chat` certificate as
  the credential. No new key type.
- **Suite 1, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.** This one fits if each device
  gets its own leaf key, bound to the identity with a P-256 signature the way
  `dm-key-binding.ts` works. Layer 2 already heads that way, since each device becomes its
  own leaf. On Hermes it costs about 40% less than suite 2, per message and per join.

Both pass everything below. I'd lean towards suite 1. It's GRYT-1244's call, though, because
it depends on what a leaf credential is.

### The advisory

[GHSA-gwp3-968w-m7gv](https://github.com/LukaJCB/ts-mls/security/advisories/GHSA-gwp3-968w-m7gv),
high severity, published 2026-08-28. Versions below 1.6.4 are affected, and 1.6.4 has the
fix. The title is "Commit with a single Remove omits the UpdatePath, letting a removed
member decrypt subsequent epochs".

When a commit had exactly one Remove proposal, or exactly one Update, `ts-mls` left the
UpdatePath out. The check said `> 1` where it should have said `> 0`. With no path, the
commit secret fell back to zeroes, so the next epoch could be worked out from the previous
`init_secret` alone. The removed member still had that. Receivers accepted the missing path
because they checked with the same predicate. So kicking one person didn't lock them out.
And a single self-update didn't rotate anything, which weakened post-compromise security
too.

The bug is in every 1.x release I checked, from 1.2.0 (September 2025) to 1.6.2. The fix
landed on the 1.x branch as a private-fork merge, and it's more than the one-character
change. It also changes how the commit secret is derived, and it leaves newly added members
out of the path encryption. The 2.0 release candidates rewrote that predicate in July and
never had this form of the bug.

What this means for Gryt:

- **`npm audit` doesn't see it.** It's a repository advisory that never made it into the
  GitHub Advisory Database. `npm audit` on a tree with 1.6.2 reports zero vulnerabilities,
  and Dependabot would say the same. The only way to hear about the next one is to watch
  the repository's security advisories.
- **Mixed versions break groups.** After the fix, a 1.6.4 receiver rejects the path-less
  commit a 1.6.2 member sends. Desktop, web and phone have to move together, which means
  one pinned version through `@gryt/crypto`.
- **A property test caught what the vectors missed.** More on that below.

### Other open issues on 1.x

- [#720](https://github.com/LukaJCB/ts-mls/issues/720): an Update proposal from the member
  at leaf 0 gets rejected. Fixed on `main` for 2.0, but not on 1.x.
- [#721](https://github.com/LukaJCB/ts-mls/issues/721): `joinGroupExternal` can't carry a
  PSK, and silently derives a zero `psk_secret`. Gryt doesn't need external joins or PSKs
  for anything layer 3 describes.

## RFC 9420 interop vectors

The vectors come from
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations) at commit
`cfd4502`. That's all 16 files in `test-vectors/`. The checks in
[`vectors-core.mjs`](mls-library-check/vectors-core.mjs) are written from the repository's
`test-vectors.md`, not copied from the library's tests. They go through `ts-mls`'s own
functions: decoders, tree math, the key schedule, TreeKEM, joining from a Welcome, and
processing commits as a passive client.

To show the checks can fail, [`self-test.mjs`](mls-library-check/self-test.mjs) flips one
expected value in each file and expects exactly one failing vector per file. It gets that
for all 16.

There are two providers:

- **default** is `ts-mls`'s own, with WebCrypto underneath. It covers suites 1 to 7.
- **pure** is [`pure-provider.mjs`](mls-library-check/pure-provider.mjs): HPKE from RFC 9180
  on `@noble`, with no WebCrypto. It covers suites 1 to 3, the HKDF-SHA256 ones, and it's
  what Hermes needs.

| File | Default: vectors | Pure: vectors |
|---|--:|--:|
| tree-math | 10 | 10 |
| crypto-basics | 7 | 3 |
| secret-tree | 21 | 9 |
| message-protection | 7 | 3 |
| key-schedule | 7 | 3 |
| psk_secret | 77 | 33 |
| transcript-hashes | 7 | 3 |
| welcome | 7 | 3 |
| tree-operations (suite 1 only) | 5 | 5 |
| tree-validation | 98 | 42 |
| treekem | 77 | 33 |
| messages | 300 | 300 |
| deserialization | 14 | 14 |
| passive-client-welcome | 56 | 24 |
| passive-client-handling-commit | 91 | 39 |
| passive-client-random (suite 1 only) | 1 | 1 |
| **Total** | **785 (44,681 checks)** | **525 (32,689 checks)** |

Every vector passed, per file and per suite, in all of these runs:

| Runtime | Provider | Suites | Result |
|---|---|---|---|
| Node 24.16.0 | default | 1–7 | 785 / 785 |
| Node 24.16.0 | pure | 1–3 | 525 / 525 |
| Chrome 153, headless | default | 1–7 | 785 / 785 |
| Electron 40.6.1 (Chrome 144) | default | 1–7 | 785 / 785 |
| Hermes 250829098.0.17 | pure | 1–3 | 525 / 525 |
| Node 24.16.0, **ts-mls 1.6.2** | default | 1–7 | 785 / 785 |

The per-suite breakdown is in [`results/`](mls-library-check/results/).

### What the vectors don't cover

The vectors check what a receiver computes from the inputs it's given. They don't check
what a sender leaves out, or what a receiver should refuse, and the advisory bug was both.
No vector has a single-Remove commit without a path that a client has to reject. A live
interop run against another implementation would probably have caught it, since that
implementation would refuse the commit. The static files can't.

So [`properties.mjs`](mls-library-check/properties.mjs) checks six things Gryt depends on,
through the public API and the wire format:

| Property | 1.6.4 | 1.6.2 |
|---|---|---|
| A removed member can't read the next epoch | pass | **fail**, suites 1 and 2 |
| A new member can't read messages from before the join | pass | pass |
| A replayed message is rejected | pass | pass |
| Two messages from one epoch open out of order | pass | pass |
| A message from the previous epoch opens after a commit | pass | pass |
| A tampered ciphertext is rejected | pass | pass |

On 1.6.4 all six hold, for both suites and both providers. On 1.6.2 the first one fails:
Bob reads a message sent after he was removed. [`advisory.sh`](mls-library-check/advisory.sh)
reproduces it.

## Performance

How it ran:

- Only Alice commits, so the tree's inner nodes stay blank and each path gets encrypted to
  about n leaves. That's the worst case for a tree. In a real group, where members take
  turns committing, it gets closer to log n.
- Every message goes through the wire encoding.
- Group operations are the median of 5 rounds. Encrypt and decrypt are the mean over 100
  messages with a 256-byte payload.
- **add** is Alice adding one member to a group of n: her commit, Bob processing it, and the
  new member joining from the Welcome. **remove** takes that member out again. **update**
  is an empty commit.
- Chrome and Electron use the default provider. Hermes has to use the pure one.
- Hermes is the React Native 0.86 CocoaPod (`hermes-engine` 250829098.0.17), running in a
  small JSI host on the Mac ([`hermes-host.cpp`](mls-library-check/hermes-host.cpp)). The
  bundle goes through `babel-preset-expo`'s Hermes profile like the app's does, and it runs
  interpreted, same as in the app. So it's the same engine on a faster CPU than a phone's.
  A mid-range Android phone would be slower, maybe 2–4x. I didn't measure one.
- Chrome rounds its clock to 0.1 ms, so its sub-millisecond numbers are rough.

All times are in milliseconds.

### Suite 1, X25519 and Ed25519

| Runtime | n | create | add: commit / process / join | remove: commit / process | update: commit / process | encrypt | decrypt |
|---|--:|--:|--:|--:|--:|--:|--:|
| Node 24 | 2 | 1.07 | 1.84 / 1.69 / 2.22 | 2.50 / 1.78 | 2.32 / 1.62 | 0.23 | 0.22 |
| Node 24 | 10 | 0.28 | 3.48 / 2.29 / 5.60 | 5.82 / 3.89 | 5.36 / 5.33 | 0.25 | 0.24 |
| Node 24 | 100 | 0.32 | 25.1 / 20.8 / 107 | 46.5 / 27.7 | 35.2 / 20.0 | 0.21 | 0.22 |
| Chrome 153 | 2 | 0.10 | 0.50 / 0.30 / 0.50 | 0.50 / 0.50 | 0.40 / 0.40 | 0.06 | 0.06 |
| Chrome 153 | 10 | 0.00 | 0.90 / 0.80 / 1.70 | 1.90 / 1.20 | 2.20 / 1.20 | 0.06 | 0.07 |
| Chrome 153 | 100 | 0.10 | 5.70 / 5.30 / 39.8 | 17.7 / 7.10 | 14.4 / 11.2 | 0.07 | 0.07 |
| Electron 40 | 2 | 0.20 | 0.50 / 0.40 / 0.50 | 0.60 / 0.40 | 0.50 / 0.40 | 0.07 | 0.07 |
| Electron 40 | 10 | 0.20 | 1.00 / 0.80 / 1.80 | 2.10 / 1.20 | 2.20 / 1.20 | 0.07 | 0.07 |
| Electron 40 | 100 | 0.10 | 5.60 / 4.80 / 43.2 | 15.6 / 7.40 | 16.4 / 7.40 | 0.07 | 0.10 |
| Hermes | 2 | 1.93 | 62.9 / 51.0 / 83.0 | 59.2 / 59.8 | 60.2 / 59.7 | 4.91 | 15.8 |
| Hermes | 10 | 1.95 | 81.6 / 64.6 / 227 | 269 / 105 | 268 / 107 | 4.89 | 15.7 |
| Hermes | 100 | 1.93 | 262 / 190 / 2565 | 2083 / 310 | 2059 / 308 | 4.91 | 15.9 |

### Suite 2, P-256

| Runtime | n | create | add: commit / process / join | remove: commit / process | update: commit / process | encrypt | decrypt |
|---|--:|--:|--:|--:|--:|--:|--:|
| Node 24 | 2 | 1.80 | 5.43 / 5.88 / 7.75 | 3.89 / 5.75 | 3.48 / 5.08 | 0.62 | 1.82 |
| Node 24 | 10 | 0.44 | 7.23 / 6.86 / 20.8 | 9.37 / 7.23 | 7.97 / 7.74 | 0.31 | 1.44 |
| Node 24 | 100 | 0.41 | 20.0 / 18.0 / 213 | 34.6 / 23.8 | 37.4 / 23.7 | 0.34 | 1.46 |
| Chrome 153 | 2 | 0.60 | 2.00 / 2.10 / 3.00 | 1.60 / 1.80 | 1.20 / 1.90 | 0.15 | 0.56 |
| Chrome 153 | 10 | 0.10 | 2.60 / 2.60 / 8.30 | 3.30 / 2.90 | 3.20 / 3.10 | 0.16 | 0.56 |
| Chrome 153 | 100 | 0.00 | 6.30 / 5.90 / 80.3 | 21.4 / 8.10 | 18.9 / 11.3 | 0.13 | 0.56 |
| Electron 40 | 2 | 0.40 | 3.20 / 4.00 / 5.20 | 1.30 / 2.90 | 1.30 / 2.90 | 0.19 | 1.13 |
| Electron 40 | 10 | 0.20 | 3.50 / 4.30 / 15.0 | 3.40 / 3.70 | 3.20 / 3.80 | 0.21 | 1.10 |
| Electron 40 | 100 | 0.00 | 8.10 / 11.0 / 144 | 22.8 / 9.90 | 23.0 / 9.80 | 0.18 | 1.14 |
| Hermes | 2 | 4.26 | 103 / 87.3 / 149 | 63.1 / 98.2 | 61.4 / 96.6 | 4.91 | 27.7 |
| Hermes | 10 | 2.00 | 121 / 100 / 399 | 385 / 128 | 383 / 129 | 4.61 | 27.1 |
| Hermes | 100 | 2.04 | 278 / 227 / 3887 | 3876 / 325 | 3798 / 328 | 4.61 | 28.8 |

On Hermes a key package takes 23 ms with suite 1 and 14 ms with suite 2. Building a
100-member group in one commit takes 5.8 s with suite 1 and 10.3 s with suite 2.

The Node and Chrome runs with the pure provider are in `results/` as well. In Chrome it
stays within about 2x of WebCrypto, except for full-path commits at 100 members (39 ms
against 18 ms with suite 1).

### What the numbers mean for Gryt

- **Desktop and web are fine at every size here.** The slowest thing is joining a
  100-member group, at 40–210 ms.
- **On the phone, decrypting a message takes 16 ms with suite 1 and 28 ms with suite 2.**
  Most of that is checking the signature in interpreted JavaScript. Catching up on 200
  unread messages in a channel would take 3–6 s on this Mac, and longer on a phone. That
  work needs to happen in batches, away from rendering.
- **Joining or fully recommitting a 100-member group on the phone takes 2–4 s.** A join
  checks every leaf signature in the tree. DMs and small groups stay well under half a
  second. Big private channels on mobile would need a size cap, or a native signature
  module.

## Alternatives

| | ts-mls | OpenMLS | mls-rs | `@wireapp/core-crypto` |
|---|---|---|---|---|
| Language | TypeScript | Rust | Rust | Rust (OpenMLS inside) |
| Hermes | Yes, with a provider Gryt supplies | No WASM on Hermes, so it needs a native module per platform. No official React Native binding. | Same WASM problem. Has `mls-rs-uniffi` for Swift and Kotlin, so a native module is possible. | Already ruled out (50 MB) |
| Web and Electron | Plain JS | WASM. `openmls-wasm` 0.1.0 on npm (1.4 MB) is published by a third party, not the project. | WASM, with a WebCrypto provider | WASM |
| Age and activity | Since April 2025, 108 stars, one maintainer | Since 2020, 1,033 stars, several maintainers, 0.9.0 in August 2026 | Since 2023 (AWS Labs), 254 stars, 0.56.0 | Since 2021, 10.5.3 |
| Advisories | 1 high (2026-08) | 1 high, 3 medium (2025-09 to 2026-08) | None published | Not checked |
| Licence | MIT | MIT | Apache-2.0 or MIT | GPL-3.0 |

OpenMLS and mls-rs are older, and more people have looked at them. But either one means a
Rust toolchain in Gryt's builds, a native module for iOS and Android, and a separate WASM
build for web and Electron. That's two builds of one library, looked after by one person.
`ts-mls` is the only one that's a plain dependency on all three platforms. So the choice in
`message-security.md` stands, with the conditions below attached.

## Conditions

1. **Gryt supplies the crypto provider.** Hermes has no `crypto.subtle`, so neither
   built-in provider works. I tried both in the Hermes host and they fail with "Cannot read
   property 'generateKey' of undefined". The pure provider here passes the vectors on
   Hermes. It's HPKE code, though. It belongs in `@gryt/crypto`, which is published and
   review-required, and it gets reviewed there as crypto. The other route is a WebCrypto
   polyfill from a native module.
2. **Pin exactly, 1.6.4 or later, and pin the peers too.** `ts-mls` pins its optional peers
   exactly, and they change between releases. Its `@noble/curves` 2.0.1 clashes with the
   `^2.3.0` that `@gryt/crypto`, the client and mobile all use. `npm install` stops with
   `ERESOLVE` until the versions agree or there's an override.
3. **Watch the repository's security advisories directly.** `npm audit` and Dependabot miss
   them.
4. **Every client moves together.** One version through `@gryt/crypto`, bumped on desktop,
   web and mobile at the same time. The 1.6.4 fix already makes old and new clients reject
   each other's commits.
5. **Keep property tests in Gryt's CI**, starting with the six above: removal locks people
   out, joining gives no history, replays fail. And run the interop vectors on every version
   bump. `advisory.sh` shows why it takes both.
6. **Plan for 2.0.** 1.x gets fixes, but the work happens on 2.0. That's had 16 release
   candidates and it changes the API. Either start on 2.0 once it's final, or budget for a
   migration and re-run this harness when it happens. The harness imports a few internal
   modules (`ts-mls/crypto/*.js` and so on), so it'll probably need adjusting too.
7. **Measure on a real phone before sizing private channels**, and keep decryption away from
   rendering on mobile.
8. **Nobody has audited it, so review the parts Gryt relies on**: commit validation, joining
   from a Welcome, deleting secret-tree keys, and the provider. One person maintains it. One
   high-severity bug turned up this year, and it had been in releases for about a year.

## What changes in layer 3

- "Pure TypeScript with no WASM, so it runs on Hermes" is only half right. The library runs
  there, but its crypto providers don't. Layer 3 needs a line saying Gryt supplies the
  provider, and that the provider is Gryt's crypto to review.
- Picking a ciphersuite joins GRYT-1244's list. Suite 1 is cheaper on the phone. Suite 2
  reuses the identity key. What a leaf credential is decides it.
- The plan gets a test layer. The property tests and the vectors go in CI next to the MLS
  code, as well as living here.
- The recommendation stays the same: MLS through `ts-mls`, for DMs and private channels
  together.

## Re-running it

```sh
cd docs/mls-library-check
npm ci
npm run fetch-vectors     # mls-implementations at the commit above
npm run self-test         # the checks can fail
npm run vectors           # add -- --provider=pure for the Hermes provider
npm run properties
npm run bench
npm run advisory          # the same vectors and properties against 1.6.2
sh run-all.sh             # everything, writing results/
```

The Chrome and Electron runs go through [`web-run.mjs`](mls-library-check/web-run.mjs). It
starts headless Chrome over CDP, or Electron, and shuts it down afterwards. It expects macOS
paths unless `CHROME` or `ELECTRON` is set. Hermes needs `HERMES_DESTROOT` pointing at
`ios/Pods/hermes-engine/destroot` in a mobile checkout after `pod install`. Then
[`hermes.sh`](mls-library-check/hermes.sh) builds the host and runs the vectors and the
bench.
