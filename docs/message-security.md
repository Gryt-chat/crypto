# Message security in Gryt

A design for Sivert to read and decide on. Nothing in `@gryt/crypto` changes because of
it, and no code ships from it.

It covers three layers that get discussed separately and can't be decided separately:

1. **Where the message key lives** when it isn't in use. GRYT-795.
2. **How it reaches a second device.** GRYT-783 shipped one answer; this revisits it.
3. **What the messaging protocol does with it**, and the missing forward secrecy. GRYT-754.

They interact in one direction that matters. Layer 3 decides how much damage layer 1 can
do. A key that opens five years of history is worth far more to an attacker than a key
that only lets them be you from now on, so how hard the bundle has to be depends on
whether forward secrecy ever lands. Everything below is written against one threat model
rather than three.

## Decisions

These are settled. The reasoning is further down.

1. **The sealed bundle stays on Keycloak, and it stays sealed.** Storing the 24 words in
   plain was considered and rejected. [Why](#plaintext-on-keycloak-considered-and-rejected)
2. **Losing the bundle password means losing the messages.** No server-side recovery, and
   no reset that hands anything back. The app says so at the moment the password is set.
   [What it says](#what-the-app-has-to-say-when-the-password-is-set)
3. **Two recovery routes, neither of which puts anything extra in Gryt's hands.** A device
   that already holds the key can set a new password and re-seal, with no server involved.
   And an optional recovery key, generated and shown once, opens the bundle on its own.
   [How](#the-two-recovery-routes)
4. **Argon2id at `m = 64 MiB, t = 3, p = 1`**, with an enforced minimum on the password.
   `MIN_MESSAGE_PASSWORD = 4` goes. [Numbers](#argon2id-parameters-and-what-a-grind-costs)
5. **Nothing is deleted from Keycloak, and every existing bundle keeps opening.**
   [Migration](#migration-with-nothing-deleted)
6. **Pairing becomes the normal way to add a device**, with the 24 words as the fallback
   for when the other device is gone. [Layer 2](#layer-2-getting-it-to-a-second-device)
7. **Forward secrecy goes to MLS (RFC 9420) via `ts-mls`**, covering DMs and GRYT-1244's
   private channels with one protocol. [Layer 3](#layer-3-the-protocol-and-forward-secrecy-gryt-754)

Until decision 7 lands, the bundle is the highest-value target in the stack, because the
seed inside it reads every direct message ever sent to that person. That's the argument
for doing 4 and 5 now rather than waiting. Once MLS is in, the seed signs and stops
decrypting history, and the Argon2id parameters stop being load-bearing.

## What's deployed today

Verified against `origin/main` on 2026-09-23.

| Where | What |
|---|---|
| `dm-keys.ts` | X25519 keypair per (seed, server scope), through HKDF. Static. Never rolls. |
| `dm-key-binding.ts` | a JWT saying "this DM key is mine", signed by the P-256 identity key that joined the server. No expiry, by design. |
| `message-keys.ts` | a random content key per message, wrapped once per member under the pairwise X25519 secret |
| `peer-keys.ts` | trust on first use, pinned by thumbprint and DM key, no automatic re-pin |
| `comparison-code.ts` | sixty digits two people read to each other |
| `identity-vault.ts` (client) | `sealSeed` / `openSeed`, AES-GCM, key from PBKDF2-SHA256 at 600,000 iterations |
| `message-key.ts` (client) | what gets sealed is the 24-word phrase; adopting it makes the second device the same person |
| `message-vault.ts` (client) | the sealed bundle goes in the Keycloak attribute `grytMessageVault` |
| `bootstrap/gryt-user-profile.json` (auth) | that attribute is `view: [user]`, `edit: [user]`, max 8192 chars, `inputType: hidden` |
| `message-password.ts` (client) | `MIN_MESSAGE_PASSWORD = 4` |

Two properties of the sealed bundle make everything below cheap. It records its own `kdf`
and `iterations`, and `openSeed` reads them out of the bundle rather than assuming, so a
second KDF can be added without stranding anything. And the ciphertext is bound to
`gryt-identity-vault:v1` through AES-GCM associated data, so a bundle can't be relabelled
as something else with the same shape.

Leaving `admin` out of the attribute's `view` permission keeps the bundle off the admin
console. It does nothing about Postgres.

## The threat model

### Who can read what

**Anyone with the Keycloak database, a dump, or the disk.** They get every account's
sealed bundle at once. Each one is AES-GCM over the 24 words, so the ciphertext gives
nothing by itself. What it gives is an offline target: no rate limit, no lockout, nothing
logging the attempt, and one verifiable answer per guess, because AES-GCM's tag says
whether the guess was right.

**Sivert specifically.** He runs the Keycloak, he holds the backups, and he is the person
asking for this. He has said the server shouldn't hold anything that could take over an
account, and then chosen to keep the bundle anyway. Layer 1 below is about making that
choice defensible rather than pretending it isn't a choice.

**A community server operator.** Unaffected by layers 1 and 2. They never see the bundle;
it lives on `auth.gryt.chat`, not on the servers people join. Layer 3 is where they
matter, because they hold the ciphertext.

**Somebody who steals an unlocked device.** Unaffected by anything here. They get the seed
out of local storage, because that's how the device sends messages at all.

### What a weak password costs today

`MIN_MESSAGE_PASSWORD` is 4, and the comment above it says plainly that four is not a
security control. It's right, and here's the size of it.

Measured on an Apple M5 Pro, Node 24, WebCrypto: PBKDF2-SHA256 at 600,000 iterations takes
**45 ms** for one guess. Fine for the person typing their password. For an attacker it's
about 1.2 million SHA-256 compressions per guess, and one consumer GPU does on the order
of 20 billion SHA-256 compressions a second, so roughly **20,000 guesses a second on a
single card**.

| Secret | Candidates | One GPU |
|---|---|---|
| 4 characters, lowercase and digits | 1.7 million | under 2 minutes |
| 4 characters, printable ASCII | 81 million | about an hour |
| human-chosen 8 characters, from a top-ten-million wordlist | 10 million | about 10 minutes |

One card, and the attack runs in parallel across accounts and across cards. Anyone holding
the database today can open a meaningful share of the bundles in an afternoon.

### What the seed opens once it's out

Everything, backwards and forwards. The DM key comes from the seed, never rolls, and
`dm-key-binding.ts` deliberately signs it with no expiry. A recovered seed decrypts every
direct message ever sent to that person on every server they joined, for as long as the
server keeps the ciphertext, plus everything sent afterwards. That's GRYT-754, and it's
what makes the bundle worth attacking at all.

### What forward secrecy would change about all of it

Under a ratcheting protocol the long-term key signs and stops decrypting. Message keys
move forward and old ones are destroyed, so a key recovered in September doesn't open
August. The bundle would still be worth stealing, because whoever opens it can be you from
that moment on. It would stop being worth stealing for the archive.

That's the biggest lever on this page, and it's layer 3 rather than layer 1.

## Layer 1: where the key lives

### Plaintext on Keycloak, considered and rejected

The idea was to store the 24 words unsealed on the account, so that a Keycloak password
reset would bring somebody's messages back with their login. It would have made "I forgot
my password" a solved problem.

It's rejected, and the reasoning should stay written down because it will come up again
the first time somebody loses their messages.

Keycloak's database is dumped every six hours and kept for 31 days, the dumps sit on a NAS
share, and they're about to be copied to an off-site VPS. Plain words in `user_attribute`
would therefore exist in: the live database, up to 124 dumps, the NAS, and soon a machine
outside the house. Anybody with the admin console could read any user's DM key by opening
their account page, and so could anybody who ever got hold of one dump. The seed reads every message that person has
ever received. So that isn't "a password reset can restore messages". It's "everyone with
backup access can read everyone's messages, forever, including the ones sent before they
got access."

The attribute is already declared `view: [user]`, which keeps it off the admin console.
That's a permission in a config file, one line away from not being true, and it does
nothing about the dumps at all.

So the bundle stays sealed and the cost lands where it belongs, in the next section.

### Losing the password means losing the messages

Sivert's words: if you lose your bundle password, you're done, your messages are locked
forever.

This is not a gap to be closed later. It's the same property that makes the claim on the
security page true. A server that can give you your messages back can give them to someone
else, and every mechanism that would let Gryt help is a mechanism that would let Gryt read.

Instead there's a ladder, and every rung on it is something the person holds rather than
something Gryt holds:

| You have | You get |
|---|---|
| the bundle password | your messages, on any device |
| a device that already holds the key | your messages, and you can set a new password from it |
| the recovery key | your messages, on any device |
| the 24 words | your messages; the words **are** the key |
| none of the above | a reset: new seed, new keys, and everything already sent stays sealed |

The reset isn't recovery. It's starting again, and `messageKeySection.tsx` already says so
at the point of resetting, which is the right place for it.

### What the app has to say when the password is set

The moment somebody chooses the password is the only honest place to warn them, because
it's the only moment they can still do something about it. So it shouldn't be a tooltip.

The dialog should say, in about this many words: this password is the only thing that
opens your messages on a new device. Gryt cannot reset it, cannot recover it, and cannot
read your messages without it. If you lose it and you don't have another device signed in
or your recovery key, every message you've already received stays locked, permanently.

And then, in the same dialog rather than a later one:

- the generated password, or the strength floor if they're typing their own
- **a recovery key, generated and shown once**, with a copy button and a "save this" that
  has to be acknowledged
- a plain note that a password manager is a good place for both

Setting up the bundle without a recovery key should be possible and should take an extra
click, not be the default path.

### The two recovery routes

Neither gives Gryt anything it doesn't already have.

**A device that already holds the key can re-seal.** The device has the seed in local
storage, because that's how it sends messages. So "I forgot my bundle password" on a
person with a working laptop is not a recovery problem: Settings asks for a new password,
seals the seed under it, and writes the new bundle over the old one. The old password is
never needed and the server is never involved beyond storing the result. This should be
the first thing offered in Settings when somebody says they've forgotten it, ahead of the
existing reset.

**An optional recovery key.** 32 random bytes from `crypto.getRandomValues`, rendered as
words or base32, shown once at setup, kept by the person. It opens the bundle on its own.
Because it's 256 bits of real entropy, its slot needs no slow KDF at all, just HKDF, so
adding it costs nothing in unlock time.

Both need the bundle to have more than one way in, and that's a format change.

### Bundle format: key slots

Today `sealSeed` encrypts the seed directly under the key derived from the secret, so
there's exactly one way in and changing the password re-encrypts the seed.

Change it to the arrangement LUKS uses, and Apple's FileVault, and 1Password's account
key. A random 32-byte content key encrypts the seed once. Each slot holds that content key,
wrapped under something the person knows or keeps:

- `password` — Argon2id over the password
- `recovery` — HKDF over the 256-bit recovery key, no grind needed
- room for a third later without another format change

Adding, replacing or removing a slot rewrites one small field and never touches the
sealed seed. Changing the password doesn't invalidate the recovery key and the other way
round. The associated data stays a domain separator and picks up the version, exactly as
it does now.

This is a `VAULT_VERSION` bump, which `openSeed` refuses on purpose. So version 1 bundles
have to keep being read by the version-1 path rather than the new one, which is covered in
[migration](#migration-with-nothing-deleted).

### What each route means with one device versus several

**One device.** The recovery key is the only route that survives the device dying, short
of the 24 words. This is the case to push it for, and it's the case where "set it up
later" turns into never. Offer it at setup, not in a settings page nobody opens.

**Several devices.** Re-sealing from a device that holds the key covers almost everything.
The recovery key is still worth having for the day every device goes at once, which is a
house fire or a stolen bag rather than a lost password.

Either way the 24 words sit underneath both, and they're already generated for every
identity, whether or not anybody wrote them down.

### Argon2id parameters, and what a grind costs

**Argon2id, `m = 64 MiB, t = 3, p = 1`.** That's RFC 9106's second recommended option with
the parallelism dropped to one. You get no useful threads out of a JS implementation or
the React Native bridge, so there's nothing for a higher `p` to use.

Argon2's resistance to a GPU comes from `m`, not `t`. Each guess needs 64 MiB of working
memory read and written in a data-dependent order, so a card with 24 GB fits around 370
concurrent instances and each is bounded by memory bandwidth rather than arithmetic. Three
passes over 64 MiB is roughly 384 MiB of traffic per guess; at around 1 TB/s that's a
ceiling near 2,600 guesses a second and realistically closer to **1,000**. Against
PBKDF2's 20,000, a factor of twenty.

A factor of twenty is not what makes this safe. The secret is:

| Secret | Entropy | One GPU at 1,000/s | 10,000 GPUs |
|---|---|---|---|
| 4 characters, printable ASCII | ~26 bits | 19 hours | 7 seconds |
| 12 characters, human-chosen | ~35 bits realistic | 1.1 years | an hour |
| 4 BIP39 words | 44 bits | 557 years | 20 days |
| 5 BIP39 words | 55 bits | 1.1 million years | 114 years |
| **6 BIP39 words** | **66 bits** | **2.3 billion years** | **233,000 years** |
| the recovery key, 256 bits | 256 bits | out of reach | out of reach |

Six words costs one more word than five and buys three orders of magnitude of headroom
against somebody who is not one person with one laptop.

### Enforcing a minimum, without shipping a dictionary

Measuring the strength of a typed password needs a dictionary, and `@zxcvbn-ts/core` plus
`@zxcvbn-ts/language-common` is 2.7 MB unpacked for an estimate that stays an estimate.
So the enforcement is structural rather than analytical:

- **The default is six generated words** from the BIP39 list, via
  `crypto.getRandomValues`. One click, nothing to invent, entropy known exactly.
- **A typed password is still allowed**, behind a floor: at least 12 characters, and
  refused if it appears in a bundled list of the 10,000 most common passwords (about
  75 KB, not 2.7 MB). The dialog shows what that password costs an attacker at the
  parameters above, using the table, so the floor is a number rather than a green bar.
- `MIN_MESSAGE_PASSWORD` goes from 4 to 12 and `describePasswordProblem` grows the
  blocklist check.

The floor is a floor. A twelve-character human password is around 35 bits and the table
says what that's worth. The generated six words are the recommendation and the typed
password is the accommodation, and the UI should read that way round.

### Which library, per platform

This changed twice since GRYT-795 was written.

`@noble/hashes` has shipped `@noble/hashes/argon2.js` since v1.4, and `@gryt/crypto`
already depends on `@noble/hashes ^2.3.0`. So Argon2id needs no new dependency, and the
objection recorded in `passphrase-crypto.ts`, that the alternative is another package on
the path to somebody's identity, no longer applies.

Then noble's own README says to use scrypt instead, because Argon2 can't be fast in JS
without a fast `Uint64Array`. Measured, one guess, Apple M5 Pro, Node 24:

| Implementation | With JIT | Interpreter only (`--jitless`) |
|---|---|---|
| PBKDF2-SHA256 600k, WebCrypto (today) | 45 ms | n/a |
| Argon2id `m=19MiB t=2`, `@noble/hashes` | 96 ms | 5,211 ms |
| Argon2id `m=64MiB t=3`, `@noble/hashes` | 446 ms | 26,173 ms |
| Argon2id `m=64MiB t=3`, `hash-wasm` | 109 ms | n/a |
| scrypt `N=2^16 r=8 p=1` (64 MiB), `@noble/hashes` | 102 ms | 9,754 ms |

The jitless column decides it. Hermes runs AOT bytecode through an interpreter with no
JIT, so a phone is closer to that column than to the first one, and 26 seconds to unlock
is not something anybody would ship. Pure-JS Argon2id is out on mobile.

So: one algorithm, two implementations.

- **Web and Electron: `hash-wasm` 4.12.0.** 1.8 MB unpacked, and the Argon2 WASM module
  loads on demand rather than at startup. **109 ms** measured at the recommended
  parameters.
- **React Native: `react-native-argon2` 4.0.0.** A 30 KB JS wrapper over the platform's
  native Argon2. Hermes has no WebAssembly, so `hash-wasm` isn't available there.
- **`@noble/hashes/argon2.js` stays as the reference**, for test vectors and as a
  fallback, not as the production path.

**What unlocking costs on a phone.** Native Argon2 at these parameters lands in the same
class as the WASM number. Expect something like a fifth of a second on a current phone and
under a second on an old one, for something that happens once when a device is added. The
part to watch on a low-memory Android device is the 64 MiB allocation, not the time.
This is the number to measure first, because if `@noble/hashes` turns out to be two seconds
on a real phone rather than twenty-six, one implementation everywhere beats two.

Two implementations of a key derivation is what `passphrase-crypto.ts` exists to prevent,
and the reason it's acceptable here is that Argon2id is deterministic with published test
vectors. The condition is a check script carrying RFC 9106's known-answer vectors, running
in each client's CI, so the two can't drift without something going red. Without that
script this recommendation is worse than PBKDF2.

`argon2-browser` 1.18.0 is 132 KB and was last published in April 2022, so it isn't a
candidate.

### Migration, with nothing deleted

Nothing is removed from Keycloak. Every existing bundle keeps opening, forever, with no
action from anybody.

Most of that falls out of the format. `openSeed` reads `kdf` and `iterations` from the
bundle instead of assuming them, so a PBKDF2 bundle written in 2026 still opens after
Argon2id ships. The key-slot change does need `VAULT_VERSION` 2, and `openSeed` refuses a
version it doesn't know, so the rule is: **keep the version-1 path and choose on the
version field.** Version 1 opens the old way, single secret, whatever KDF the bundle
names. Version 2 opens a slot. Neither path guesses.

Upgrading somebody's bundle needs their secret, and the server doesn't have it. So the
upgrade happens at the moments the secret is already in hand:

1. **Setting, changing or re-sealing the bundle.** Writes version 2, Argon2id, six
   generated words, plus a recovery slot if they took one. New accounts never see PBKDF2.
2. **Adopting on a new device.** They've just typed their secret to open the bundle.
   Re-seal as version 2 with the same secret and write it back. If that secret was a
   four-character password this raises the grind twentyfold and no further, which is worth
   doing and isn't the fix.
3. **A prompt in Settings for anybody still on version 1**, saying their message password
   is weaker than it should be and offering the six words and a recovery key. The old
   bundle stays in place until the new one is written, so a failure halfway leaves them
   exactly where they were.

**Somebody who never signs in again** keeps their version-1 PBKDF2 bundle untouched, and
it keeps working whenever they come back, however long that is. No expiry, no sweep, no
cleanup job, nothing deleted.

**What migration cannot undo.** Every bundle currently in Keycloak is also in the 31-day
dump window, on the NAS, and in the Postgres WAL. Re-sealing under Argon2id protects the
bundle from here on and does nothing about copies already taken. The only complete answer
is rotating the seed, which loses the old conversations, so it shouldn't be pushed on
everybody. Saying it once in the release note lets anyone who used a genuinely bad password
make that call themselves.

## Layer 2: getting it to a second device

### Pairing, which the UI leads with

The new device generates an ephemeral X25519 keypair and a random 16-byte rendezvous id.
The old device learns the public key and the rendezvous id out of band. Both derive a
shared secret with X25519, run it through HKDF with the rendezvous id as `info`, and the
old device seals the 24 words under AES-GCM with the result. The ciphertext goes to a relay
keyed by the rendezvous id; the new device fetches it once and the relay drops it.
Five-minute expiry, one fetch, then gone.

Signal calls this provisioning and links its desktop app this way. Matrix's SAS
verification is the same handshake with a code-compare where Signal has the QR.

**How the devices authenticate each other.** Two paths, depending on whether there's a
camera:

- *QR.* One device renders the ephemeral public key and the rendezvous id as a QR code and
  the other reads it. The public key arrives over a channel the server isn't on, so
  there's nothing to check afterwards. This is the phone's path.
- *Six digits.* Desktop to desktop, where neither has a usable camera. Both sides do the
  ECDH over the relay, then both display a short number derived from the two public keys,
  and the person confirms the screens match before either side sends anything. A relay that
  substituted its own key produces two different numbers.

Six digits is enough because the attacker gets one online attempt against an expiring
rendezvous rather than offline guesses. `comparison-code.ts` chose sixty digits for two
people on a phone call comparing keys they'll then pin, and sixty digits read off two
screens on the same desk would get skipped.

**Where the relay lives.** `packages/auth/identity` is the natural home. It already
validates Keycloak tokens and knows the `sub`, so it can refuse a rendezvous where the two
sides aren't the same account. That stops a stranger wandering into somebody's pairing. It
stops nothing Sivert could do, and isn't meant to: the QR or the six digits is what stops
him.

**Why the identity certificate isn't enough on its own.** Both devices already hold a
certificate from `id.gryt.chat` binding their P-256 key to the same `sub`, so they could
verify each other with no QR at all. That trusts the CA not to mint a certificate for a
device that isn't yours, and the CA is Sivert. The certificate works as a cheap pre-check
before the person is asked to do anything. As the authentication it hands the account back
to him.

**Cost to the person.** Both devices working, at the same time, in the same place if
they're using the QR. Nothing to type and nothing to remember.

### What the UI leads with

**Add a device → pair.** The QR or the six digits is the first and default option, because
it asks the least and both devices are in front of the person at exactly that moment.

**"I don't have the other device" → the bundle**, six words or the recovery key.

**"I don't have either" → the 24 words**, then the reset if those are gone too.

The bundle stops being the front door and becomes the first fallback. That's a change in
emphasis rather than mechanism, and it's what stops most people ever needing to type a
secret, which is worth more than any parameter on this page.

## Layer 3: the protocol, and forward secrecy (GRYT-754)

### What's missing

There's no ratchet. The DM key comes from the seed, never rolls, and the binding that
publishes it carries no expiry. Every message gets its own content key, which stops a
member added later reading history, and all of those content keys are wrapped under one
static pairwise secret. Recover the seed and you recover all of them.

### The three options

**Stay as-is.** Everything above still holds: the bundle is the highest-value target in
the stack and stays that way. Defensible while there's one person maintaining this, and
the docs are honest about it today, which is the important part.

**Olm.** `@matrix-org/olm` 3.2.15, 651 KB, WASM, no dependencies, the Double Ratchet with
Megolm for groups, proven in Element. Two problems, both already named in GRYT-754. It
needs somewhere to publish prekeys, and **Hermes has no WebAssembly**, so the phone can't
run it at all. The prekey problem is smaller than it looks, because `dm-key-binding.ts` is
already a signed public key published through an untrusted server and one-time prekeys are
the same idea with more of them. The WASM problem is fatal while mobile is in scope.

**MLS (RFC 9420), via `ts-mls`.** 1.6.4, 691 KB unpacked, one dependency (`@hpke/core`),
pure TypeScript with no WASM, so it runs on Hermes once Gryt supplies the crypto provider
([the library check](mls-library-check.md) has why). MLS assumes an untrusted Delivery
Service that orders commits and can't read them, which is what a Gryt community server
already is. It gives forward secrecy and post-compromise security, and a member added to a
group gets no history, which is the behaviour Gryt already has.

### The recommendation

**MLS, for DMs and private channels together.** Three reasons, in order:

1. It's the only one of the three that runs on web, Electron and React Native without
   WebAssembly.
2. A DM is a two-member group, so one protocol covers GRYT-754 and GRYT-1244 instead of
   Olm for pairs plus Megolm for groups.
3. The Delivery Service role is a job the community server can do without being trusted,
   which is the property the rest of Gryt is built around.

What stays either way, as GRYT-754 already says: the scoping, the key bindings, the
trust-on-first-use pinning and the comparison code are Gryt's and aren't what MLS
provides. MLS replaces the envelope, not the wrapper around it.

This is still a design pass of its own rather than a library swap. Per-conversation,
per-device state, a key package directory, epochs, and a story for a message that arrives
out of order or twice are all new moving parts on three platforms.

### What it would do to layers 1 and 2

Both get easier.

Under MLS the seed signs key packages and stops decrypting history, so a leaked bundle
costs impersonation from that moment rather than the archive. The Argon2id parameters stop
being what stands between a database dump and five years of somebody's messages.

And a second device becomes its own MLS leaf with its own keys, the way Signal and Matrix
do multi-device, instead of a copy of the same seed. Pairing then carries an authorisation
to join the groups rather than the seed itself, and the bundle's job narrows to identity
continuity. That's a smaller secret to protect, which is the direction all of this should
be moving.

It also softens decision 2, eventually. Losing the password would cost you the ability to
prove you're the same person, rather than every message you've ever received.

## What GRYT-1244 inherits

GRYT-1244 is the design task for opt-in end-to-end encryption in private channels and
group DMs, using MLS. It isn't designed here. What this page constrains:

- **The library choice is shared.** If DMs go to MLS, channels use the same
  implementation. Two MLS stacks in one client would be worse than either.
- **Hermes with no WebAssembly is the binding constraint** on that choice, for as long as
  the phone is in scope. It rules out `@wireapp/core-crypto` (50 MB, Rust and WASM) as well
  as Olm.
- **The identity layer is already decided.** MLS credentials are the existing P-256
  identity key and its `id.gryt.chat` certificate; `dm-key-binding.ts` is the pattern a key
  package directory follows.
- **The server is the Delivery Service**, untrusted, exactly as it is for message delivery
  now.
- **Multiple devices per account is layer 2's problem, not MLS's.** Whether a person is one
  leaf whose seed is copied between devices, or several leaves, is decided by what pairing
  transfers. Decide it here rather than twice.
- **Key loss has an answer already**, and it's decision 2. A channel encrypted under MLS
  inherits the same rule: nobody can give you back what you can't open. GRYT-1244 asks how
  to handle key loss and shouldn't invent a second answer.
- **Out-of-band verification already exists.** `comparison-code.ts` and the pinning in
  `peer-keys.ts` are Gryt's, they're what the security page documents, and they should
  carry over rather than being replaced by whatever the library offers.

## Open questions

- **The GPU numbers are reasoned, not measured.** The 45 ms and the whole KDF table are
  real measurements on one machine. The 20,000 guesses a second for PBKDF2 and the 1,000
  for Argon2id come from published SHA-256 throughput and memory bandwidth figures, not
  from a rig I ran. The orders of magnitude are right and the exact figures may be off by a
  small factor.
- **The jitless column is a proxy, not a phone.** I couldn't run Hermes. Interpreter-only
  V8 is the closest thing I could measure, and the real number could go either way. Measure
  `@noble/hashes` argon2id on a real device before committing to two implementations.
- **The 64 MiB allocation on a low-memory Android device.** The time is fine with a native
  module; whether a four-year-old phone hands over 64 MiB while the app is foregrounded is
  a different question and I haven't checked it.
- **Whether the recovery key should be offered at setup or required.** Required would mean
  fewer people locked out and one more thing to get through before sending a message.
  Offered means most people will skip it. I've said offered, with an extra click to decline,
  and I'm not confident that's the right side of the line.
- **`ts-mls` maturity.** Checked in [mls-library-check.md](mls-library-check.md). It passes
  every RFC 9420 interop vector: 785 in Node, Chrome and Electron, and the 525 for suites 1
  to 3 on Hermes. The verdict is to use it, with conditions. Gryt has to supply the crypto
  provider on Hermes. And a high-severity advisory, fixed in 1.6.4, slipped past the
  vectors, so Gryt needs exact pins and its own property tests.
- **Six digits for the pairing code.** The reasoning is that an attacker gets one online
  attempt against an expiring rendezvous, so offline-guess entropy isn't the right measure.
  I haven't worked through what the relay would have to do wrong for that to stop holding,
  and a code that turns out to be too short would look fine while protecting less than it
  claims.
- **Whether the relay belongs in `packages/auth/identity` or in the server.** Identity is
  the obvious place because it already validates Keycloak tokens, but it's a certificate
  authority and a blob store is a new kind of job for it. `packages/auth/**` is
  review-required and the deployment consequences on `dev.lan` aren't worked through here.
- **`packages/docs/content/docs/about/security.mdx` never mentions the bundle or the
  message password at all.** It's been incomplete since GRYT-783 shipped, and none of the
  three layers above can ship without a pass over that page. Decision 2 in particular is
  the kind of thing people should be able to read before they rely on it.
