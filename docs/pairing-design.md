# Linking a device (GRYT-1484)

A design for Sivert to read and decide on. No code ships from it.

You scan a QR code on the new device with a device that's already signed in, or type the
short code shown under it, and the new device ends up with your keys, your sign-in and
your message history. This is layer 2 of [message-security.md](message-security.md), and
section 5 of [mls-design.md](mls-design.md) ("Pairing") is the part it fills in.

Read against `origin/main` on 2026-09-28: crypto `9f6d127`, auth `b9e634d`, core `b72c2c5`,
server `2dca6ad`, client `336b9d5b`, mobile `e7d7dc7`.

## Already decided

From Sivert, 2026-09-28 and earlier. Not reopened here.

- **The relay is `id.gryt.chat`**, the identity service in `packages/auth`. It forwards
  sealed blobs it can't open, and guests use it without an account.
- **The first version does keys and sign-in.** The seed or a guest's identity, plus an
  account session through the OAuth 2.0 Device Authorization Grant (RFC 8628) on
  Keycloak. One scan and you're in.
- **History is in this version.** The approving device sends its local history in chunks
  through storage next to the relay. Chunks are deleted once fetched, or after an hour.
  The chunk key travels inside the pairing envelope.
- **Fallback:** the new device shows a QR and a short code. The code can be typed on any
  signed-in device.
- **Against QR phishing:** the approving device shows the new device's name, its OS or
  browser, and a rough location. Both screens show the same emoji. Approval runs out after
  about 60 seconds.
- **Pairing hands over the seed**, so every device is a full peer (MLS decision 3).
- **Once pairing ships, no new Keycloak password bundles get written.** Existing ones keep
  opening (MLS decision 5).
- **The server never holds anything that unlocks an account or messages**, not even
  slowly.

## The short version

- The new device makes a one-off X25519 key and asks the relay for a session. It shows a
  QR holding the session id and its public key, plus an 8-character code.
- The approving device scans the QR or types the code, and sends its own one-off public
  key. The new device only reveals its key to the relay after that, having committed to
  it first, so a relay that swaps keys can't steer the emoji.
- Both work out a shared secret with X25519 and HKDF over the whole exchange. Both show
  four emoji from it. The approving device shows the new device's name, platform and
  rough location, and an Approve button that runs out after 60 seconds.
- On Approve, the approving device sends one sealed envelope: the seed, the server list,
  the pins, a history key and the history manifest. For an account it then approves the
  new device's Keycloak `user_code` on Keycloak's own device page.
- The new device keeps nothing until it's signed in and the account it got matches the
  one in the envelope. Guests skip the Keycloak step.
- History goes up as chunks in the backup format from mls-design section 5, newest first,
  sealed under the key from the envelope. The relay deletes each chunk once fetched, and
  everything after an hour.
- The new device publishes KeyPackages on each server. The approving device adds it to
  every group straight away, then sends the messages between its snapshot and those adds.
- Nothing in `packages/server` has to change. `packages/auth` gets the relay and a
  Keycloak client setting that Sivert applies through the admin API.

## 1. What exists today

**Keys.** Both apps hold a 32-byte seed. The desktop keeps it in IndexedDB
(`gryt_identity_keys`), sealed by the OS keychain under Electron and raw in a browser. The
phone keeps it in SecureStore under `gryt.identity.seed`, `WHEN_UNLOCKED_THIS_DEVICE_ONLY`.
A guest's key on each server comes from the seed through HKDF with the server's scope,
`srv:` plus a lineage id from the server pins, falling back to the host. An account's P-256
key is random per device, and `id.gryt.chat` certifies it for 30 days.

**Sign-in.** Both apps use the public client `gryt-web` with PKCE. The web client runs
`keycloak-js` with `check-sso`. Electron does PKCE itself and signs in through the system
browser (`electron-auth.ts`). The phone uses `expo-auth-session` with `offline_access`
and keeps its tokens in SecureStore.

**Servers.** Each device keeps its own list. The desktop's is the `servers` user value
(`host`, `name`, a per-server `token`), the phone's is the AsyncStorage key `servers`
(`host`, `name`, `nickname`, `scheme`). Nothing syncs them.

**History.** Each app has an encrypted local archive: IndexedDB `gryt_archive` on the
desktop, SQLite `gryt-archive.db` on the phone. Records are keyed by scope, conversation
and message id. MLS group state sits in the same database, behind `MlsStateStore` from
`@gryt/core`. Nothing exports it yet, and the backup format in mls-design section 5 isn't
built.

**MLS.** `@gryt/core`'s DM driver adds a new device lazily: when a person's devices change,
the server pushes `mls:devices:changed`, and whoever sends next in each DM commits the
add. There's no "add this device everywhere now". The server already lets you claim your
own devices' KeyPackages (`mls:keypackages:claim`) and caps you at five devices per server.

**The identity service.** Hono on Node, one container (`gryt-identity`) on dev.lan, with a
data volume that holds the CA key. It has no database and keeps no state beyond that key.
Two endpoints: the JWKS, and `POST /api/v1/certificate`.

**Nothing for pairing.** No QR library in either app, no camera scanner on the phone, and
no device-grant setting on `gryt-web`. The closest thing is the desktop's
`device-delegation.ts`, which vouches for a new device from an identity backup file.

## 2. The protocol

Two devices:

- **N**, the new device. It has nothing and shows the QR and code.
- **A**, the approving device. It's signed in, or has a guest identity, and holds the seed.

The relay is R. Everything R carries after the key exchange is sealed.

### Keys and primitives

**X25519, HKDF-SHA256 and AES-256-GCM**, from `@noble/curves`, `@noble/hashes` and
`@noble/ciphers`. `dm-keys.ts` already does X25519 plus HKDF, and `identity-vault.ts` and
the archive already use AES-GCM from the same libraries. No new dependency, and nothing
that needs WebCrypto, which Hermes doesn't have.

Not HPKE, though `mls-provider.ts` has an RFC 9180 implementation. It's base mode only,
and base mode authenticates nobody: anybody who knows N's public key can seal to it,
the relay included. Auth mode isn't there and isn't needed. Both sides already have a
one-off key, the emoji authenticate both, and a plain Diffie-Hellman between them gives
keys in both directions. HPKE's single-shot seal only goes one way, and pairing needs N
to talk back (the hello, the `user_code`, "ready", acks).

Both key pairs are made fresh for each session and dropped when it ends.

### Step by step

1. **N opens a session.** It makes `(skN, pkN)` and sends R only a commitment:
   `commit = SHA-256("gryt-pair-v1 commit" || pkN)`. R answers with a random 16-byte
   session id, an 8-character code, a bearer token for N, and an expiry five minutes out.
2. **N shows the QR and the code.** The QR holds the session id and `pkN` itself. See
   [the QR](#what-the-qr-holds).
3. **A claims the session**, by session id from the QR or by code. It makes
   `(skA, pkA)` and sends `pkA`. R allows one claim per session. It returns A's own bearer
   token, the commitment, and N's rough location. A second claim gets a refusal.
4. **N reveals.** Once it has `pkA`, N sends `pkN`. A checks it against the commitment,
   and against the QR if it scanned one.
5. **Both derive keys.** See [the key schedule](#the-key-schedule). N sends a sealed hello:
   device name, app and platform, and the time its approval window closes.
6. **Both show four emoji.** A shows them with N's name, platform and location, and
   Approve and Deny, counting down 60 seconds. N shows the same emoji and "Approve on your
   other device".
7. **A approves.** On the phone that's behind Face ID or the passcode. A sends the sealed
   envelope ([contents](#the-envelope)). N checks it arrived before its own deadline.
8. **Accounts only: the session.** N starts a device authorization at Keycloak, using the
   issuer from the envelope, and sends the `user_code` to A sealed. A opens Keycloak's
   device page for that code. N polls Keycloak's token endpoint. See
   [the account half](#3-the-account-half).
9. **N commits.** Only now does N write anything: the seed, the keys, the server list, the
   pins. For an account it first checks the `sub` in its new ID token matches the one in
   the envelope, and throws everything away if it doesn't.
10. **N joins its servers and says so.** It connects to each server, makes its MLS device
    and publishes KeyPackages. Then it sends A a sealed "ready" with its device id on each
    server.
11. **A adds N everywhere and sends history.** See [section 5](#5-history). N fetches,
    checks and deletes chunks as they arrive.
12. **Either side closes the session**, and R deletes everything it holds for it.

### The key schedule

```
commit = SHA-256("gryt-pair-v1 commit" || pkN)
th     = SHA-256(lp("gryt-pair-v1") || lp(sessionId) || lp(commit) || lp(pkN) || lp(pkA))
dh     = X25519(skN, pkA) = X25519(skA, pkN)
prk    = HKDF-Extract(salt = th, ikm = dh)
kNA    = HKDF-Expand(prk, "gryt-pair-v1 n to a", 32)
kAN    = HKDF-Expand(prk, "gryt-pair-v1 a to n", 32)
sas    = HKDF-Expand(prk, "gryt-pair-v1 emoji", 3)
```

`lp` is a two-byte length prefix, for the reason `comparison-code.ts` uses JSON: two
different inputs mustn't join into the same bytes.

Each sealed message is AES-256-GCM under the key for its direction. The nonce is a
12-byte counter that starts at zero for each direction, and the associated data is `th`,
the direction and the counter. A replayed, reordered or cross-session message fails to
open. The counter never repeats under a key, since the keys are new for every session.

### How the emoji bind both keys

The 24 bits of `sas` pick four emoji from a list of 64, six bits each. The list is the one
Matrix uses for SAS verification. It was chosen so the emoji are easy to tell apart across
platforms' emoji fonts, and each one has a name, which both apps show underneath for
screen readers and for anyone who can't see the difference between two dogs.

The emoji come from `dh` and `th`, so they depend on both public keys. A relay that swaps
either key ends up with a different `dh` on each side, and the two screens show different
emoji.

The order in steps 1 to 4 is what stops the relay from grinding a match. Without it, a
relay in the middle could pick its own keys after seeing both real ones, and search about
16 million candidates offline for a pair whose emoji collide. That takes seconds. With the
commitment:

- Toward A, the relay has to present a commitment before A sends `pkA`. So it's fixed its
  fake N key before it knows anything that decides A's emoji.
- Toward N, the relay has to hand over a fake A key before N reveals `pkN`. So it doesn't
  know N's key when it picks, and can't work out N's emoji.

Either way it gets one guess per session, a 1 in 16.7 million chance, and each guess needs
somebody to be linking a device at the time. Bluetooth's numeric comparison and Matrix's
SAS both use this commit-then-reveal order.

In the QR path the relay can't swap `pkN` at all, since A reads it off N's screen. It
could still swap `pkA` toward N and seal its own envelope to N. That can't take anything,
because the seed only ever goes from A to N, but it could sign N in as somebody else. The
emoji stop that too.

### What the QR holds

```
GRYT:1:<session id, 26 chars>:<pkN, 52 chars>
```

Crockford base32 in upper case, so the whole string fits QR's alphanumeric mode: about 85
characters, which is a version 4 code and scans easily off a laptop screen. A server using
its own auth server adds `:<relay origin>` at the end, and that part is checked against the
auth server A is configured with. A never talks to a relay it was only told about by a QR.

It isn't a URL. A `gryt://` link would let the phone's own camera open the approval screen
from any QR anywhere, which is the easiest version of the phishing this is meant to make
hard. Only the scanner inside Gryt reads it. The system camera shows it as text. That's a
trade against convenience, so it's question 3.

The version number means an old app refuses a code from a newer protocol rather than
guessing.

### The short code

Eight characters of Crockford base32, shown as `XXXX-XXXX`, 40 bits. Typing accepts lower
case and reads `O` as `0` and `I` or `L` as `1`, the way `recovery-key.ts` already does.

The code is only a handle for finding the session on R. It carries no key. Guessing one
gets you at most a claim on somebody else's session, and what that claim gets you is:

- the new device's commitment, which is useless on its own
- a chance to seal your own envelope to that device and sign it in as you, which the
  emoji catch, since the owner's own device never reached the emoji screen
- in any case, their device shows "somebody else got there first", which makes the attack
  visible

So brute force buys disruption at most. To keep even that impractical:

- 40 bits against at most 1,000 live sessions is one hit per billion guesses.
- R counts failed code lookups per IP: 20 in ten minutes, then an hour's block.
- Codes die on first claim, and after five minutes unclaimed.

With the block, one address gets about 17 guesses an hour. A botnet of 10,000 addresses
makes about 170,000 an hour, and at 1,000 live sessions that's one stray hit every nine
months or so. Gryt has nowhere near 1,000 people linking devices at once.

Six characters would be 30 bits, and the same botnet would hit a session every six hours.
Eight costs two keystrokes.

### The envelope

One sealed message, A to N, JSON before sealing:

| Field | What | Why |
|---|---|---|
| `v` | 1 | Refuse what you don't understand |
| `seed` | The 32-byte seed | The person key, the guest keys, the DM keys and the backup key all come from it |
| `keys` | Stored keys that don't come from the seed | What `exportLocalIdentities` already carries, for identities made before the seed existed |
| `account` | `issuer`, `clientId`, `identityUrl`, `sub`, `username`. Absent for a guest | Which Keycloak N signs in with, and which account it has to end up as |
| `servers` | Per server: `host`, `name`, `scope`, `nickname`, `scheme` | The scope is the lineage id from the server pins. Without it N derives a different guest key |
| `pins` | The peer pins for each scope: thumbprint, DM key, person key, `comparedAt`, and whether they've been seen on MLS | Without them N would trust whatever keys a server hands it on first sight, and a server could downgrade N to v1 sealing |
| `history` | The history key (32 random bytes), and the snapshot manifest | [Section 5](#5-history) |
| `from` | A's device name | So N can say "linked from Sivert's iPhone" |

The seed and extra keys are the `gryt-local-identity-backup` v2 format the desktop already
exports, moved into `@gryt/crypto` so the phone reads exactly the same thing.

Not in it:

- **Per-server access tokens.** N gets its own by joining. Each server's handshake is a
  signature from the identity key, so the same seed gives the same guest, and a signed-in
  account gets its own certificate.
- **MLS state.** N makes its own leaf. MLS state never leaves the device it was made on.
- **Keycloak tokens.** N gets its own through the device grant, so A's session and N's are
  separate, and signing out of one leaves the other alone.
- **The password bundle.** Decision 5 stops new ones being written.

A size cap of 256 KiB on the envelope covers a few hundred servers' pins.

### The relay's API

On `id.gryt.chat`, under `/api/v1/pairing`. No Keycloak token on any of it, so guests use
it the same way. Each side authenticates with the bearer token R gave it at step 1 or 3,
so somebody who photographs the QR can't read or post as either side.

| Method and path | Who | What |
|---|---|---|
| `POST /sessions` | N | Body `{commit}`. Returns `{id, code, token, expiresAt}` |
| `POST /sessions/claim` | A | Body `{id}` or `{code}`, plus `{pkA}`. Returns `{id, token, commit, location, yourLocation}`. One claim per session |
| `POST /sessions/:id/messages` | Either | Appends a message for the other side: `{type: "reveal", pkN}` once from N, otherwise `{type: "sealed", body}` |
| `GET /sessions/:id/messages?after=n&wait=25` | Either | The other side's messages after `n`. Long-polls up to 25 seconds, under Cloudflare's 100-second limit |
| `PUT /sessions/:id/chunks/:n` | A | One history chunk. Only after the reveal |
| `GET /sessions/:id/chunks/:n` | N | Fetch one |
| `DELETE /sessions/:id/chunks/:n` | N | Done with it. R also deletes a chunk after its second fetch |
| `DELETE /sessions/:id` | Either | Cancel or finish. R deletes the session and every chunk, and the other side's next poll says `closed` |

Long polling rather than a WebSocket, because it needs nothing new in Hono and goes
through the tunnel and every proxy unchanged.

**Lifetimes.**

| State | Lasts | Then |
|---|---|---|
| Open, not claimed | 5 minutes | Gone. N makes a new session, with a new QR and code |
| Claimed, waiting for A's first sealed message | 2 minutes | Gone. The apps enforce the 60 seconds themselves, this is R's backstop |
| After that | 1 hour from the claim, at most | Gone, chunks and all |

**Sizes.** A message up to 64 KiB, the envelope up to 256 KiB, at most 64 messages a
session. A chunk up to 2 MiB. At most 256 MiB of chunks per session.

**Rate limits, per IP.** Ten new sessions per ten minutes. Twenty failed code lookups per
ten minutes, then an hour's block. 1 GiB of chunk uploads a day. The IP comes from
`CF-Connecting-IP`, trusted only on requests that came through the tunnel.

**The disk.** The chunks go on the `gryt-identity-data` volume, which is on the same disk
as the Keycloak Postgres. A full disk takes the auth database down, so R refuses uploads
once all its chunks together reach 2 GiB, or once free space on the volume falls under
5 GiB, whichever comes first. All four limits are environment variables. Where the chunks
live is question 4.

**What R stores.** In memory: the sessions (ids, codes, commitments, public keys, sealed
messages, states, times) and the rate-limit counters by IP, for as long as their window. On
disk: chunk files, under `data/pairing/<session>/<n>`, and nothing that says whose they are.
A restart loses the sessions, so it also empties `data/pairing/`. Anyone halfway through
starts again.

**What R logs.** Counts and durations: sessions opened, claimed, closed and expired, chunk
bytes stored, refusals by reason. No IPs, codes, session ids, user agents or locations.

**What R sees anyway.** Both devices' IPs, when they pair, and how much history went across,
which says roughly how many messages somebody has. For an account, Keycloak sees a device
grant at the same moment, so whoever runs both can tie a session to an account by time.
That's Sivert, and the security page says so.

**Location.** Cloudflare adds `CF-IPCountry` to every request, and city and region headers
once "Add visitor location headers" is turned on under Managed Transforms. R turns them
into "Oslo, Norway" for both sides, and doesn't keep them. It needs `id.gryt.chat` to go
through Cloudflare the way `auth.gryt.chat` does. With the transform off, it's country
only.

### Timeouts, cancelling and a second scan

- **Nobody scans.** The session runs out after five minutes, and N quietly makes a new one
  with a fresh QR and code.
- **A doesn't approve within 60 seconds.** Both apps close it. N goes back to a fresh QR.
  An envelope that arrives after N's deadline is thrown away unopened.
- **Deny, or Cancel on either side.** `DELETE /sessions/:id`. The other screen says
  "Cancelled on the other device".
- **A second scan.** R refuses the second claim. That device shows "Somebody else already
  scanned this code. If that wasn't you, cancel on the new device." N has already swapped
  the QR for the emoji at the first claim, so the window for a second scan is short.
- **The emoji don't match.** The person taps "They don't match" on either side, which
  cancels, and the app says the connection may have been tampered with and to try again.
- **Keycloak fails or times out.** N hasn't written anything yet, so it discards the
  envelope and starts over.
- **History is interrupted.** Keys and sign-in are already done, so N works normally.
  Chunks stay on R for up to the hour. If the app on either side is closed, it carries on
  when reopened within the hour. After that, N shows how far it got, and linking again
  from the same device sends the rest. N merges by message id, so repeats don't duplicate.

## 3. The account half

### How RFC 8628 fits

In RFC 8628 a device with no browser, a TV say, asks for a `device_code` and a
`user_code`, shows the `user_code`, and polls. The person goes to a web page on another
device, signs in, types the code and approves. Then the polling device gets its tokens.

Here N is the TV and A is the other device, already signed in.

1. After A approves, N calls `POST {issuer}/protocol/openid-connect/auth/device` with
   `client_id=gryt-web` and `scope=openid profile email offline_access`, the scope the
   phone already asks for.
2. N sends the `user_code` to A, sealed. The `device_code` never leaves N.
3. A opens `{issuer}/device?user_code=...` in the browser it signs in with. A builds that
   URL from its own configured issuer, never from anything N sent, so a hostile N can't
   point A at a phishing page.
4. N polls `POST {issuer}/protocol/openid-connect/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code` every five seconds until the
   tokens arrive, or the code runs out.
5. N checks the ID token's `sub` against `account.sub` from the envelope. If they differ,
   N throws everything away and says why. That catches a browser signed in to a different
   account than the app.

After that N is an ordinary signed-in device. It stores its tokens where it normally would,
makes its own P-256 key and gets its own certificate from `id.gryt.chat`.

### Can Keycloak do it on its own?

The grant, yes. Keycloak has had RFC 8628 since version 13, and the stack runs 26.5.3. It
issues the codes, runs the device page and answers the polling.

The approval, only in a browser. Keycloak approves a `user_code` on its device page,
against the Keycloak session cookie in that browser. There's no API that takes an access
token and approves a code, and the identity service can't approve one for anybody, because
it has no Keycloak session to approve with.

So there are two ways to do step 3:

- **Keycloak's own page.** A opens it in the browser it signs in with: the page itself on
  the web, the system browser from Electron, and `expo-web-browser` on the phone, which
  shares Safari's or Chrome's cookies unless it was asked for an ephemeral session. With a
  live cookie the page shows Keycloak's grant screen and one Yes. With no cookie, it asks
  for the password first. The realm ends a browser session after 7 days idle and 30 days
  at most, so anybody who signed in more than a month ago types their password. From
  Keycloak's source, the device flow always shows the grant screen, whatever the client's
  consent setting. That needs checking on the dev stack.
- **A Keycloak extension.** A small Java provider in `packages/auth` adding an endpoint
  that takes A's access token and a `user_code` and approves it. Approval then stays in the
  app. But it's Java code built against Keycloak's internal classes, which change between
  versions, on the service every Gryt account depends on.

Question 1 asks which. The recommendation is Keycloak's page for the first version, and
counting how often people hit the password prompt.

### The Keycloak client changes

On `gryt-web`, through the admin API, applied by Sivert. Not in `gryt-realm.json`: a realm
import deletes every account, and the realm file is what took the stack down in
GRYT-136.

| Client attribute | Value | Why |
|---|---|---|
| `oauth2.device.authorization.grant.enabled` | `"true"` | Turns the grant on |
| `oauth2.device.code.lifespan` | `"300"` | Five minutes, matching a session, instead of the realm's default ten |
| `oauth2.device.polling.interval` | `"5"` | The RFC's default, written down |

Nothing else changes: the client stays public, with PKCE and the same redirects.

A script, `bootstrap/enable_device_grant.py`, does the read-modify-write the same way
`update_keycloak_client.py` does, prints the client before and after, and is safe to run
twice. It runs with `--no-deps` and the admin credentials passed at run time, the way the
other one-shots do, since `admin` is normally disabled.

Before trusting the attribute names, set the toggle once in the admin console on the dev
stack, read the client back, and copy what Keycloak wrote. The names above are from
Keycloak's source, not from a running 26.5.

Whether to put the grant on `gryt-web` or on a client of its own is question 2.

### What this opens up

Turning on the device grant for a client lets anybody start a device flow for it. That's
the "device code phishing" pattern: somebody gets a code for their own device, sends it to
you with a story, and if you're signed in to Keycloak and type it at
`auth.gryt.chat/realms/gryt/device`, their device gets your Gryt session.

That session gets them a certificate for their key, so they can join servers as your
account. It doesn't get them your messages. Without the seed they have no person key, and your
contacts refuse their MLS device. And decision 5 means no new password bundle to grind.

Gryt's apps never ask anybody to go to that page and type a code. The security page
should say so plainly.

## 4. Guests

A guest's identity on each server is a key worked out from the seed and that server's
scope. So a guest "signed in" on N means N has the seed and the list of servers with their
scopes, and each server's handshake then succeeds with the same key and sees the same
guest.

So a guest skips step 8 entirely. Nothing about a guest touches Keycloak, and the relay
never knows whether the person was a guest.

N has to get the scope right. It's `srv:` plus the server's lineage id where one is pinned,
and the host where not. If N worked it out for itself before it had the server pins, it
could pick the host and derive a different key. So `servers[].scope` in the envelope is
authoritative, and N writes the server pins before deriving anything.

N doesn't get A's device delegations (`device-delegation.ts`). It holds the seed itself,
so it doesn't need anybody to vouch for it.

## 5. History

### The format

The backup format from mls-design section 5, as it stands:

- Messages go into chunks of up to 1,000, or one day, whichever fills first. A chunk
  holds one server scope.
- Each chunk is compressed with `fflate` and sealed with AES-256-GCM, under
  `HKDF(historyKey, chunkId)`. The associated data is the format's label, the chunk id
  and the scope.
- A manifest lists the chunks in order, with each one's id, scope, first and last time,
  message count, byte size and SHA-256.

The only change for pairing is that `historyKey` is 32 random bytes made for this transfer and sent
in the envelope, instead of the seed-derived backup key. Stage 4 passes the backup key in
the same place, so the code is written once.

The manifest goes inside the sealed channel, never on the relay. So the relay can't drop,
swap, reorder or replay a chunk without the hash or the seal failing.

A record in a chunk is what the archive stores: scope, conversation id, message id, when
it was sent, and the decrypted message, with its reactions, edits and attachment keys. No
MLS state, ever, the same rule as the backup.

**Order.** Newest day first, across all servers. N shows recent conversations within
seconds, and if the history is bigger than the cap it's the oldest that's left behind.

### The snapshot, the adds and the tail

For each MLS group A is in, three positions in the server's group log matter:

- `snap`: A's cursor when it takes the snapshot, at approval.
- `add`: the commit that adds N's device to the group.
- after `add`, N reads the group itself.

The snapshot covers everything up to `snap`. The **tail** is what A decrypted between `snap`
and `add`, which N can't read, since it wasn't in the group yet.

1. At approval, A notes `snap` for every group and starts uploading the snapshot.
2. N publishes KeyPackages on each server and sends "ready" with its device id for each.
3. A claims those KeyPackages (`mls:keypackages:claim` already allows your own devices)
   and commits an Add in every group it shares on that server, most recently active
   first. It only adds the device ids N named, so a device somebody else slipped in
   doesn't ride along.
4. If somebody else's client commits the add first, which the lazy "whoever sends next"
   rule can do, A uses that commit as `add` instead of adding again.
5. Once a group has its `add`, A sends that group's tail as more chunks and a sealed tail
   manifest.
6. Messages sent in the old epoch just before the add can land in the log after it. N
   can't open those. A keeps decrypting them for as long as MLS keeps the old epoch's keys,
   then sends them in a last tail. N swaps them in for its "couldn't decrypt" placeholders,
   matched by message id.

This needs one new thing in `@gryt/core`: a way to add one of your own devices to every
group now, instead of waiting for the next send. That's `addOwnDevice(deviceId)` on the
driver, plus a hook that reports each group's `add` position.

**Cost on the phone.** MLS stage 1 only has DMs, and at two people an add is well under
300 ms on Hermes. A hundred DMs is up to 30 seconds of commits, in the background. The
progress on both screens counts conversations.

**The five-device cap.** If N would be a sixth device on a server, the server refuses its
KeyPackages. A checks its own device count with `mls:devices` before showing Approve and
says so on the approval screen, so nobody finds out halfway through.

### Size

From mls-design, estimated and not measured: about 15 MB compressed per 100,000
messages. The 256 MiB cap per session is about 1.7 million messages. Past that, the oldest
stay behind and N says how far back it has.

## 6. Threat model

**A malicious relay.** It can't read anything past the handshake: the envelope, the hello,
the `user_code` and the history are all sealed under keys from a Diffie-Hellman it isn't
part of. It can try to sit in the middle, and the commitment and the emoji give it a 1 in
16.7 million chance per session. It can drop, delay or refuse, which is a denial of
service and looks like one. It can't swap or replay chunks, because the manifest travels
sealed and carries their hashes. It sees IPs, times and sizes.

**Somebody who sees the QR or the code over your shoulder.** They learn a session id and a
public key. They can't get the seed, which only goes sealed to a key they don't have. They
can race you to claim the session, and then your own device says somebody else got there
first. If they win and approve with their own account or seed, N would sign in as them,
but the emoji on N won't match anything on your device, and N checks the account `sub`.
The bearer tokens stop them posting as either side.

**Phishing.** Somebody gets you to scan a QR from their device: "scan to sign in", "scan to
verify your account". Discord's QR sign-in has been abused exactly like this. What stands in
the way:

- The QR only works in Gryt's own scanner, behind Settings, so a stranger's QR can't open
  the approval screen from the phone's camera.
- The approval screen says, before anything else, that this gives the device everything:
  your messages, your keys and your account. And that Gryt never asks you to scan a code
  from somebody else's device or a website.
- The device's name and platform, which the attacker chooses, and its location, which the
  relay works out from its IP. A careless attacker gives themselves away with a different
  country. A careful one uses a VPN.
- 60 seconds, so it has to be a live, relayed attack, not a QR in an email.
- Afterwards, every other device you have shows "New device linked" with its name, and
  removing it is one tap.

The emoji don't help here, since the attacker's page can show whatever emoji their device
shows. Somebody who's talked into approving a device they don't control gives it
everything, as with Signal and WhatsApp linking.

**A stolen unlocked phone.** The thief already has everything on it: the seed is in local
storage, the history is in the archive. Pairing would let them copy it to a device of their
own quickly, so on the phone Approve asks for Face ID, Touch ID or the passcode first,
through `expo-local-authentication`. On a Mac the desktop app uses Touch ID where there is
one. Elsewhere on the desktop there's no prompt, because there's nothing consistent to ask
for. A thief who has your passcode wins, as they would anyway. Your other devices see the
new one appear.

**Replay.** Every session has fresh keys on both sides, and every key depends on both. A
message or envelope from an old session doesn't open in a new one. Within a session the
counter in the nonce stops one being played twice. Session ids and codes are single-use.
Keycloak's `device_code` is single-use and runs out after five minutes. Chunks are bound to
their id and scope and listed by hash.

**A hostile new device.** In a phishing attempt N is the attacker. N gets nothing until A
approves, and what it sends A is a name, a platform string and a `user_code`. A never opens
a URL from N, and never runs anything N sends.

## 7. What each app shows

Both apps get the same screens, worded the same way. The desktop puts them in Settings,
under Account & security, as a Devices block in `securitySettings.tsx` next to Passkeys.
The phone puts a "Devices" row in the Account group in `YouScreen.tsx`, next to "Your
twenty-four words", opening a new `/devices` route the way `/identity` works.

### The new device

**Signed out, first run.** Next to "Sign in with Gryt" (desktop: `accountSettings.tsx`; the
phone: the Account group), a second button: "Link from another device".

**Link this device.**
> Scan this with Gryt on a device where you're signed in: Settings, Devices, Link a device.
> Or type this code there: **7KQM-X4TD**

The QR sits above, and a new one replaces it every five minutes without comment.

**Check the emoji.**
> Approve on your other device if it shows the same four.
> 🐶 🔑 🚀 🌵
> Dog, Key, Rocket, Cactus

"They don't match" and Cancel underneath.

**Signing in** (accounts only).
> Confirm in the browser on your other device.

**Copying your messages.**
> 12,400 of 48,000 messages. You can use Gryt while this finishes.

This moves to a progress row under Devices if they leave the screen.

### The approving device

**Devices.** This device, then your other devices on each server, from `mls:devices`, each
with a Remove button. Then "Link a device".

**Link a device.** On the phone, the camera, with "Type a code instead" under it. On the
desktop, the code field, since most desktops have no camera to point at a phone.

**Approve.**
> Link this device?
> **MacBook Air**, Gryt desktop on macOS
> Near Oslo, Norway. You're near Oslo, Norway.
> 🐶 🔑 🚀 🌵
> This device gets your messages, your keys and your account. Only approve a device that's
> in front of you, and only if it shows the same emoji. Gryt never asks you to scan a code
> from somebody else's device or a website.

Approve, with the seconds left in it, and Deny. If it'd be a sixth device on a server, a
line saying which server and "remove one first".

**Confirm in your browser** (accounts only). The app opens Keycloak's device page and says
"Tap Yes in the browser, then come back here."

**Sending your messages.**
> Adding MacBook Air to your conversations: 40 of 112.
> Sending messages: 12,400 of 48,000.

### Your other devices

A notice when N's first KeyPackage appears on a server they share: "New device linked:
MacBook Air. Not you? Remove it", opening Devices.

## 8. Build plan

No stacked PRs. Each one branches from `main` after whatever it needs has merged. Sizes are
rough line counts, tests included. Review-required means Sivert reads the whole diff before
it merges.

### crypto (all review-required, published to npm)

1. **Pairing primitives.** The commitment, transcript, key schedule, sealing both ways with
   counters, the emoji list with names, the QR payload, the short code (reusing
   `recovery-key.ts`'s alphabet), and the envelope's shape and parser. The identity backup
   format moves in from the desktop. Known-answer tests, and a test that a swapped key
   changes the emoji. ~600.
2. **The history chunk format.** Chunk, seal, open and the manifest, with `fflate` and
   known-answer tests. The key is a parameter, so stage 4 reuses it. ~450. Independent of
   1, so both branch from `main` and can be open together.

Then a minor release: 0.8.0.

### auth (all review-required)

3. **The rendezvous.** Sessions, claims, codes, messages, long polling, bearer tokens,
   lifetimes, rate limits, logging and the sweeper, in the identity service. In memory
   only. ~500.
4. **Chunk storage.** The upload, fetch and delete endpoints, the caps and the free-disk
   floor, the restart wipe, and the environment variables in compose and the README.
   ~350. After 3.
5. **The device-grant script**, `bootstrap/enable_device_grant.py`, and a README section
   on running it. ~120. Independent of 3 and 4. Sivert applies it.

Plus two things only Sivert can do: deploying the identity service, and turning on
Cloudflare's visitor location headers for `id.gryt.chat`.

### server

Nothing. Claiming your own KeyPackages, committing adds, `mls:devices` and the
`mls:devices:changed` push are already there.

### core (normal review)

6. **The pairing client.** The relay client and both sides' state machines, with the
   timeouts and cancelling from section 2. Platform-free, with the storage writes behind
   an interface each app implements. ~600. After the crypto release.
7. **Adding your own device now.** `addOwnDevice(deviceId)` on the DM driver, and the
   hook that reports each group's `add` position. ~300. Independent of 6.
8. **The history transfer.** Walking the archive newest first through an interface the
   apps implement, chunking, uploading and resuming, the tail, and merging on N. ~500.
   After 6 and 7.

Then a core release, pinned exactly in both apps.

### client

9. **The new device.** "Link from another device", the QR and code, the emoji, the device
   grant polling, writing the seed, keys, servers and pins, and importing history.
   ~900. **Review-required** for the parts in `common/src/auth/**`: writing the seed, and
   storing the tokens from the device grant.
10. **The approving device.** Devices in Account & security, code entry, the approval
    screen, opening Keycloak's device page, and the progress. ~700. **Review-required**
    for reading the seed out of `common/src/auth/**`. Independent of 9.
11. **No more password bundles** (decision 5). `messageKeySection.tsx` stops offering to
    set one, and existing bundles keep opening. ~100. After 9 and 10 have shipped.

### mobile (normal review)

12. **The new device**, the same as 9, with the QR drawn through `react-native-svg`. ~800.
13. **The approving device**, the same as 10, plus `expo-camera` for scanning and
    `expo-local-authentication` for approving. ~800. Independent of 12.
14. **No more password bundles**, if the phone writes them. ~50.

The phone's identity code isn't on the review-required list, though it holds the same
seed as `common/src/auth/**` does on the desktop. Whether it should be is for the list in
`.claude/CLAUDE.md` and `guide/ai.mdx`, together.

### docs (normal review)

15. **A guide page, "Link a device"**, and the security page: what pairing hands over, what
    the relay sees, that Gryt never asks you to type a code on Keycloak's device page, and
    that the password bundle is on its way out. ~200. Merges before the apps release.

### Order

- Crypto 1 and 2, then the crypto release.
- Auth 3, then 4, with 5 alongside. Deploy, apply the Keycloak setting, and turn on the
  location headers before any app ships pairing.
- Core 6 and 7, then 8, then the core release.
- Client 9 and 10 and mobile 12 and 13, together. Docs 15 first.
- Client 11 and mobile 14 once pairing is out.

## 9. Open questions for Sivert

1. **How does the approving device approve the account session?**
   - a. Keycloak's own device page, in the browser it signs in with. No new server code.
     One extra Yes, and a password prompt for anybody whose browser session is over a
     month old
   - b. A Keycloak extension in `packages/auth` that approves a code in the app. No browser,
     but Java against Keycloak's internals, on the service every account depends on

   Recommend **a** for the first version, and counting how often the password prompt shows
   up before deciding whether **b** is worth it.

2. **Which Keycloak client gets the device grant?**
   - a. `gryt-web`, so a linked device is exactly like one that signed in normally
   - b. A new public client, say `gryt-link`, with the grant and nothing else. It can be
     switched off without touching sign-in, but its tokens refresh under a different
     client id forever, and it needs the same scopes and mappers as `gryt-web`

   Recommend **a**. The phishing risk is the same either way, and **b** is a second client
   to keep in step.

3. **Can the phone's own camera open a pairing QR?**
   - a. No. Only Gryt's scanner, inside Settings, reads it
   - b. Yes, through a `gryt://pair` link, so any camera app opens the approval screen

   Recommend **a**. **b** saves two taps and makes "scan this to sign in" phishing work from
   any QR code anywhere.

4. **Where do history chunks live while they're in transit?**
   - a. On the identity service's volume, capped at 256 MiB per pairing and 2 GiB in total,
     and refused under 5 GiB free
   - b. Somewhere off the auth disk, like MinIO or a separate volume on another disk

   Recommend **a** with those caps, since chunks live an hour at most. The caps are there
   because that disk also holds the Keycloak database. If the caps feel too tight for
   somebody with years of history, **b** is where to go, not higher caps on that disk.
