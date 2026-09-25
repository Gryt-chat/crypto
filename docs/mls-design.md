# MLS in Gryt

A design for Sivert to read and decide on. No code ships from it.

It covers GRYT-1244 (opt-in end-to-end encryption for private channels and group DMs) and
GRYT-754 (DMs have no forward secrecy) together, because they're one protocol now. It picks
up where [message-security.md](message-security.md) stops, at "What GRYT-1244 inherits", and
it builds on [the ts-mls check](mls-library-check.md).

Read against `origin/main` on 2026-09-25: crypto `65436ea`, client `4e6a972`, server
`ff062e1`, mobile `f482a09`, docs `669cb03`.

## Already decided

These came from Sivert and aren't reopened here.

- **MLS (RFC 9420) with forward secrecy**, for DMs, group DMs and private channels, through
  `ts-mls` pinned at 1.6.4 or later.
- **History on a new device comes from another of your devices**, through pairing
  (GRYT-1484: the new device shows a QR, the phone approves, and the keys and history go
  across sealed to the new device).
- **An opt-in encrypted history backup that the 24 words unlock**, like Signal's and
  WhatsApp's. It's off by default, so by default the 24 words alone no longer read your
  history.
- **Public channels stay unencrypted** (2026-09-15, in GRYT-1244's description).
- **The server never holds anything that unlocks an account or messages**, not even
  something slow to crack.

## The short version

- Every device is its own MLS leaf. What makes several leaves one person is a **person key**
  per server, worked out from the 24 words, which signs a certificate for each device.
  Peers pin the person key the way they pin the DM key today. `id.gryt.chat` isn't
  involved, so guests work the same way accounts do.
- The community server is the Delivery Service. It keeps KeyPackages and Welcomes, puts
  commits in order (the first one for an epoch wins, the rest retry), and fans out. It sees
  who's in which group and when things happen. It never sees content.
- A DM is a group of the two people's devices. A group DM is a group of up to ten people's
  devices. A private channel is a group of everyone who can read it, and the server proposes
  the adds and removes that its permissions imply. In DMs and group DMs the server can't add
  anybody.
- **Suite 1** (X25519, Ed25519, AES-128-GCM). It's about 40% cheaper on the phone, and under
  this design the P-256 identity key never needs to be a leaf key.
- Old keys get deleted, so **the client becomes the archive**. Each device keeps the
  messages it has decrypted in a local store. Pairing copies that store to a new device, and
  the backup is an encrypted copy of it.
- Sealed DMs from before the switch keep opening with today's DM key. New messages go on
  MLS once everyone in the conversation has a device that can. Until then the conversation
  stays on today's sealing, and it never drops back once a peer has been seen on MLS.
- Four stages: DMs, group DMs, private channels, backup. Stage 1 is the biggest by far,
  because it brings in the local message store and the whole MLS stack.

## 1. Identity and credentials

### What exists today

- **Accounts** sign in with a P-256 key that each device generates for itself. `id.gryt.chat`
  certifies it for 30 days, with the Keycloak `sub` in it, and the `sub` is the same on
  every server.
- **Local identities (guests)** have a P-256 key per server, worked out from the 24 words, so
  two servers see two unrelated people.
- **DMs** use an X25519 key per server, also from the 24 words (`dm-keys.ts`). A JWT signed by
  the identity key the member joined with says "this DM key is mine" (`dm-key-binding.ts`),
  and peers pin the pair on first sight (`peer-keys.ts`). The sixty-digit comparison code
  covers what the pin can't.

The DM key is the same on every device you have, because every device holds the seed. That's
what lets a second device read your DMs. It's also the whole of GRYT-754: one static key
opens everything.

### What a credential is

Three layers, from the long-lived one down:

1. **The identity you joined with.** Unchanged: the account key with its certificate, or
   the local key.
2. **A person key per server.** Ed25519, worked out from the seed with HKDF under a new label
   (something like `gryt-mls-person-v1`) with the server scope as `info`, the same way
   `dm-keys.ts` does it. The identity from layer 1 signs a binding for it, following
   `dm-key-binding.ts`. It's the same on all your devices, and it never goes into an MLS
   tree.
3. **A device leaf key.** Ed25519, random, made on the device, and it never leaves. The
   person key signs a small **device certificate**: the scope, the person key, the leaf's
   signature key, a random device id, a device name, and when it was signed.

The MLS credential is a `basic` credential whose identity bytes are that device certificate.
`ts-mls` has an `AuthenticationService` hook, and that's where a client checks it. The
certificate has to be signed by the person key, the person key has to be bound by that
member's identity, and the person key has to match the pin. A leaf that fails any of those
is refused, whether it arrives in a KeyPackage, a Welcome's tree or a commit.

The server checks the same things when a KeyPackage is uploaded, so an honest server doesn't
hand out junk. Clients never rely on that.

**Why not the account certificate as the credential.** `id.gryt.chat` would then decide
which devices are you, and it's Sivert's CA. It could mint a certificate for a device that
isn't yours, and that device would get added to your DMs. Guests have no certificate at all.
And the certificate runs out every 30 days, so every leaf would need renewing on a timer. The
person key puts that decision on your own devices, which is where pairing puts it anyway.

**Why not the per-server identity key directly.** For a guest it's already seed-derived and
could work. For an account it's a random key per device, so two devices would look like two
unrelated people. A separate person key treats both kinds of identity the same.

**Why not leaf keys from the seed.** Every device would get the same leaf. There'd be no way
to remove one device, and a stolen seed would read new messages without a new leaf showing
up anywhere. Post-compromise security needs leaf secrets that can't be worked out again.

### Pinning and the comparison code

The pin grows a third field. Today it's the identity thumbprint and the DM public key, and it
becomes those plus the person key. A person key whose binding is signed by the identity
already pinned for that member is accepted and recorded. A person key that changes later is
refused, the same way a changed DM key is refused now.

The comparison code moves to cover person keys. `peer-keys.ts` drops `comparedAt` whenever
either half of a pin moves, and adding a person key counts as a move, so people who compared
before would have to compare again. That's the strict reading of the current rule. Stage 1
could soften it: if the binding is signed by the exact identity key the two of them
compared, carrying `comparedAt` across claims nothing new.

### Your own devices

- **Adding one.** The new device gets the seed (by pairing, or by typing the 24 words),
  works out the person key, makes a leaf key, signs its own device certificate and uploads
  KeyPackages to each server it's on. Any member of a group who's online then adds it (see
  [the Delivery Service](#2-the-server-as-delivery-service)). Your other device goes first,
  because during pairing it's the one standing right there.
- **Removing one.** Settings lists your devices on each server, from the device certificates
  in your groups. Removing one publishes a revocation signed by the person key, and every
  client that sees it commits a Remove for that leaf in any group it shares with you. That's
  how a lost phone gets removed from your laptop.
- **A cap.** Five devices per person per server, enforced by the server when KeyPackages are
  uploaded and by clients when adding. It keeps group sizes predictable. Five is a guess.

### Guests

A local identity has a seed, so it gets a person key, device certificates and MLS groups
the same as an account. That's the main reason the design stays away from `id.gryt.chat`.

A guest who moves to an account (GRYT-1249, `mergeGuest.ts`) keeps their person key if the
same seed is behind both. If it isn't, peers see a changed person key, which is what a
changed DM key looks like today. Stage 1 should check which case actually happens.

## 2. The server as Delivery Service

RFC 9420 splits the service side in two. The Authentication Service decides which keys
belong to whom, and in Gryt that's the person key and the pins, on the clients. The Delivery
Service moves messages and orders commits, and that's the community server. It isn't trusted
with content, which is how Gryt already treats it for sealed DMs.

### What it stores

| What | Kept | Notes |
|---|---|---|
| KeyPackages | Per device, 20 at a time plus one last-resort | Handed out once each, then deleted. The last-resort one gets reused when the rest run out, which RFC 9420 allows. A device tops them up when it connects |
| Welcomes | Per receiving device | Deleted once fetched, or after 30 days |
| The group log | Per group, in order | Commits, proposals and application messages, each with a sequence number. Every device keeps a cursor |
| Group records | Per group | The Gryt conversation or channel it belongs to, the current epoch, the members' device ids |
| Revocations | Per person | Signed by the person key, so other clients can remove the leaf |

These are new tables under `packages/server/src/db/**`, which is review-required.

### Putting commits in order

Two members committing at the same moment is normal in a busy channel, and MLS needs exactly
one commit per epoch. The server decides:

- A commit names the epoch it was built on. If that's the group's current epoch, the server
  accepts it, bumps the epoch and fans it out. Anything else is refused with the current
  epoch.
- The loser fetches what it missed, processes it, and rebuilds its commit if it still needs
  to, for example if the person it was removing is still there.
- Application messages aren't ordered this way. They carry their epoch, and receivers keep
  the previous epoch's keys for a short while, so a message sent just before a commit still
  opens after it. The library check's property tests already cover that case.

Commits and proposals go as MLS `PublicMessage` (`ts-mls` has `wireAsPublicMessage`).
Application messages go as `PrivateMessage`. The server needs to see a commit's adds and
removes to check them against the conversation's membership, and it knows the membership
anyway. The only other thing a `PublicMessage` commit shows is the tree's public keys, which
the server already has from the KeyPackages.

### What it sees

- Which devices are in which group, which is the same as who's in which conversation. It
  knows that today.
- When each commit happens, and what kind it is.
- When each message is sent, by which connection, and how big it is. MLS pads private
  messages. `ts-mls` has a padding setting, and padding to 256-byte steps hides most of the
  length for a little bandwidth.
- How many devices each person has on that server, from the KeyPackages.

It doesn't see message text, attachment keys, reactions or edits, since those all travel
inside `PrivateMessage`.

### Forks, and a device that falls behind

With the server choosing one commit per epoch, two members shouldn't end up in different
states unless something's wrong on a device. Three things can go wrong:

- **The device crashed between processing a commit and saving its state.** It's one epoch
  behind with a cursor past the commit. So the new MLS state and the cursor get saved in one
  write, and the cursor never moves on its own.
- **The state was restored from an old copy.** A Time Machine or iCloud backup of the app's
  storage would bring back old secrets. MLS's `reuse_guard` stops the worst of it (nonce
  reuse), but the device is out of sync. So MLS state is kept out of OS backups, and the
  history backup in section 5 holds plaintext and never MLS state.
- **A bug.** It'll happen.

In each case the device can't open what's arriving. It tells the server, drops its state for
that group, uploads a fresh KeyPackage and asks to be removed and added again. Whichever
member is online commits the Remove and the Add. Messages sent in between are lost for that
device, unless another of your devices sends them across the way pairing does. The UI says
"some messages couldn't be decrypted on this device" instead of drawing nothing.

A whole group that forks, where several members disagree about the epoch, is what `ReInit`
is for, and `ts-mls` has it. It should be rare enough to handle by hand in stage 1.

### How long the server keeps ciphertext

Once every device has fetched a message and deleted its key, nobody can open the copy on the
server. It still costs disk. The server keeps the group log for 30 days, so a device that's
been off for a few weeks can catch up, and drops it after that. A device away longer gets a
gap, the same as after a fork. Some operators may want it shorter, so it's question 7.

## 3. How Gryt maps onto groups

### DMs

One MLS group per DM conversation. The leaves are every device of both people.

DM conversation ids come from the sorted pair (`directConversationId` in
`conversations.ts`), so both sides can try to create the group at once. The server takes the
first group registered for a conversation and tells the other client to throw its own away
and wait for the Welcome.

Creating one means fetching a KeyPackage for each of the other person's devices and each of
your other devices, creating the group and committing the adds, which sends the Welcomes. On
a phone that's about 60 ms for the commit and 80 ms to join, from the n=2 row of the Hermes
table.

When a device appears for either person, whoever sends next adds it first. When a device is
revoked, whoever sees the revocation removes it. There's no external sender in a DM group,
so the server can't propose anything.

### Group DMs

The same, with more people. `MAX_CONVERSATION_MEMBERS` is 10, so a group DM is at most fifty
leaves at five devices each, and more like twenty in practice.

- **Adding someone** needs `create_groups`, as now. The member adding them commits an Add for
  each of the new person's devices, and the server checks the permission when it accepts the
  commit.
- **Leaving.** In MLS you can't commit your own removal. You send a Remove proposal for your
  own leaves and the next member online commits it. The server stops delivering to you as
  soon as you leave, which covers the gap.
- **Removing someone else** isn't possible today (`dm.ts` only has leaving), and this doesn't
  add it.
- **Somebody leaves the server or gets banned from it.** They can't connect, so nothing
  reaches them, and other members' clients commit the Remove when the server says they're
  gone. A server can always cause a removal. In a DM or a group DM it can never cause an add.

One thing changes for people. Today leaving a group deletes the membership row, and history
stops being readable (`leaveConversation`). Under MLS the leaver keeps what their devices
already decrypted, because it's in their local store. They could always have screenshotted
it, but a UI that used to make history vanish shouldn't suggest it still does.

### Private channels

**What "private" means.** Gryt has no private channel as such. It has channels whose scope
rules decide who has `read_messages` (`channelPermissions.ts`). So an encrypted channel is
one where the default role can't read and somebody with `manage_channels` has turned
encryption on. The group is whatever `channelReaders()` returns, which is everybody who may
read the channel. The owner is always in it, because `mayInChannel` always says yes to the owner.

**The server proposes and a member commits.** Membership here follows the server's
permissions, and it changes when an admin edits a role or a scope. Nobody in the
channel does anything to cause it. So the server is listed in the group as an **external sender**
(RFC 9420's `external_senders` extension, `proposeExternal` in `ts-mls`). When the readers
change, the server sends Add and Remove proposals, and the next member online commits them.

The external sender's key has to match the suite. With suite 1 the server needs an Ed25519
key for this, signed by its existing P-256 identity key (`serverIdentity.ts`) so clients can
check it against the server pin. That code sits in `packages/server/src/auth/**`.

**What that means for trust.** In a private channel the server decides who's in it, because
it decides who can read it. Encryption doesn't change that. What it does change:

- Somebody with the database, the disk or a backup gets ciphertext.
- An operator who wants to read has to add somebody, and it shows. Every add appears in the
  channel ("Kari joined the encrypted channel") and in the member list, with that person's
  pinned keys.
- An operator can't add a device to somebody who's already in, because only that person's
  key can sign a device certificate.

That's weaker than a DM. It's still better than today, where channel messages sit in the
database in plain text. The toggle should say so in about that many words.

**What changes membership.**

| Event | Group change | Who commits |
|---|---|---|
| A role that can read is given to somebody | Add each of their devices | A member, after the server proposes |
| That role is taken away, or a scope rule stops them reading | Remove their leaves | Same |
| Kick or ban from the server | Remove their leaves | Same. The server stops delivering right away |
| Timeout or mute | Nothing. They can still read | - |
| They add or revoke a device | Add or Remove that leaf | Any member, or their own device |
| Somebody makes the channel readable by the default role | Refused while encryption is on | - |

A member who wants to send while a proposal is waiting commits it first. So nobody sends into
an epoch that still includes somebody who's been removed. The server has also stopped
delivering to them, so there are two things in the way.

**Re-keying cost.** From the library check, suite 1, milliseconds, 100 leaves, in the worst
case where one member does all the committing:

| Operation | Chrome | Electron | Hermes on the Mac |
|---|--:|--:|--:|
| Add one: commit / others process / new member joins | 5.7 / 5.3 / 39.8 | 5.6 / 4.8 / 43.2 | 262 / 190 / 2,565 |
| Remove one: commit / others process | 17.7 / 7.1 | 15.6 / 7.4 | 2,083 / 310 |
| Update: commit / others process | 14.4 / 11.2 | 16.4 / 7.4 | 2,059 / 308 |
| Decrypt one message | 0.07 | 0.10 | 15.9 |
| Build a 100-member group in one commit | - | - | 5,800 |

Desktop is fine at every size measured. On a phone, processing somebody else's commit takes
about a third of a second, and that's the common case. Committing a removal or joining a big
group takes 2 to 2.6 seconds on the Mac's CPU, and the library check guesses two to four
times that on a mid-range Android phone. Nobody has measured one yet.

So stage 3 has three rules:

- **Desktop commits first.** When the server proposes something, it asks an online desktop
  or web member first, and only asks a phone if nobody has committed after 30 seconds.
  Anyone can still commit. The server only suggests who goes first.
- **Turning encryption on for an existing channel happens on a desktop.** Building the group
  at 100 takes 5.8 seconds even on the Mac's Hermes.
- **A size cap, counted in devices.** The tree has one leaf per device, and the measurements
  stop at 100 leaves. At two devices each, that's about 50 people. Real groups should do
  better (when members take turns committing, the tree fills in and a commit costs closer to
  log n), but that hasn't been measured either. Where the cap goes is question 10.

Each device also updates its own leaf once a week, when it next sends, for post-compromise
security. At 100 leaves that's about 100 commits a week for each phone to process, around 30
seconds of work spread over the week.

**Turning it on.** Somebody with `manage_channels` does it, on a channel that's already
private. It's one-way, the way Matrix does it. If it could be switched off, a server could
switch it off. Messages from before stay in plain text on the server, readable by anybody who
can read the channel, and the channel shows where encryption started.

## 4. Ciphersuite

**Suite 1, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.**

The library check said this depends on what a leaf credential is. Here a leaf is a fresh
per-device key certified by the person key, so the P-256 identity key never has to be a leaf
key, and suite 2's one advantage goes away. P-256 still turns up twice, at the edges. The
identity key signs the person-key binding, and the server's identity key signs its
external-sender key. Each is checked once and cached.

What suite 1 saves on Hermes, from the library check:

| | Suite 1 | Suite 2 |
|---|--:|--:|
| Decrypt one message | 15.9 ms | 28.8 ms |
| Join a 100-leaf group | 2,565 ms | 3,887 ms |
| Commit a removal at 100 | 2,083 ms | 3,876 ms |
| Build a 100-member group | 5.8 s | 10.3 s |
| Make a KeyPackage | 23 ms | 14 ms |

KeyPackages are the only row suite 2 wins, and they get made in the background a few at a
time.

The tables leave out one cost. A join checks every leaf's signature, and Gryt's
`AuthenticationService` adds a device-certificate check per leaf on top, which could roughly
double the join time. So verified certificates get cached by hash, and each one is checked
once per device, ever.

## 5. History

### The client becomes the archive

Forward secrecy means the client has to keep its own history. Today a client scrolls up, the
server sends old envelopes, and the static DM key opens them. Under MLS a message's key is
deleted once it's been used. Scroll up next week and the server can send the ciphertext, but
nothing can open it.

So each device keeps what it decrypted, in a local store:

- **Electron:** IndexedDB, with the store's key sealed by the OS keychain, the way the seed is
  sealed today (`writeSeed` with `sealSecret`).
- **Web:** IndexedDB. The browser can throw it away and there's no keychain, so the web
  client says plainly that history lives in this browser, and points at pairing and the
  backup.
- **Phone:** SQLite, with the key in the Keychain or Keystore.

The web client needs one more thing. Tabs share one IndexedDB, and two tabs processing the
same group at once would corrupt it. One tab holds a Web Lock and does the MLS work, and the
others read the store.

Search, scrollback, notification text and quoting all read from the local store now. It's
most of stage 1's client work.

### Pairing (GRYT-1484)

In GRYT-1484 the new device shows a QR, the phone approves, and a relay forwards a sealed
blob. For MLS the blob carries:

- the seed, as GRYT-1484 plans, so the new device can work out the person key and sign its
  own device certificate
- the local store for each server, in the same format as the backup below, sealed to a
  one-off key that goes inside the pairing envelope

With the seed, the new device uploads KeyPackages, and the phone adds it to every group
straight away. The gap between the snapshot and the adds is a few seconds, and the phone
sends that tail across too.

History is bigger than anything the relay was sized for, about 15 MB for 100,000 messages
(see [Size](#size)). So the relay carries the key and a list of chunks, and the chunks go up
to the same place, deleted once fetched or after an hour. Where the relay lives is already
an open question on GRYT-1484. This makes it a question about storage as well.

### The encrypted backup

Off by default, and turned on per server in Settings.

**What's in it.** The local store's plaintext: messages, who sent them, when, reactions,
edits, and the attachment keys and metadata. The attachment bytes aren't in it. They're
already on the server, encrypted, and the keys in the backup open them for as long as the
server keeps them. No MLS state goes in, ever. A backup of MLS secrets would put back the
very thing forward secrecy takes away.

**The key.** HKDF over the seed, under its own label (`gryt-history-backup-v1`), with the
server scope as `info`. The 24 words open it and nothing else does. There's no password
anywhere in the chain, so there's nothing to grind. Somebody with the server's disk gets a
blob behind 256 bits.

**The format.**

- Messages go into chunks of up to 1,000, or one day, whichever fills first.
- Each chunk is compressed (`fflate` is a small pure-JS option that runs on Hermes) and
  sealed with AES-256-GCM, under a key from HKDF over the backup key and a random chunk id.
- A manifest lists the chunks in order, with each chunk's hash and a counter that only goes
  up. It's sealed the same way and replaced on every write.
- A device remembers the highest counter it has written, so if the server hands back an
  older manifest, that device notices. A brand-new device restoring from the words can't
  notice, and the design doesn't claim it can.

**Where it's stored.** On the community server, as an opaque blob per member, served only to
that member once they've signed in. It works for guests and accounts alike, needs no new
central service, doesn't link your servers together, and sits on the same server as the
conversations it backs up. If that server shuts down, the conversations are gone too. The
other places it could go are in question 6.

**Keeping it current.** One device writes at a time, holding a lease the server keeps per
member. That device appends a chunk when one fills and rewrites the manifest. If the lease
holder hasn't written for a day, another device takes over. Compaction (merging small
chunks, applying deletes) runs now and then on whichever device holds the lease.

**What the 24 words unlock.**

| You have | You get |
|---|---|
| The 24 words, backup off | Your identity and person key on each server, so new messages reach you. No history |
| The 24 words, backup on | The above, plus each server's backup once you sign in there |
| Another device of yours | Everything that device has, through pairing |
| The server's disk, no words | Blobs it can't open |

#### Size

A stored message is roughly 300 bytes before compression: a 100-character text plus ids,
times, reactions and attachment keys. Compression roughly halves text like that.

| Messages | Raw | Compressed, roughly |
|--:|--:|--:|
| 10,000 | 3 MB | 1.5 MB |
| 100,000 | 30 MB | 15 MB |
| 1,000,000 | 300 MB | 150 MB |

These are estimates, and nothing here was measured. The server needs a per-member cap that operators can
set, since the disk is theirs.

### The password bundle and the backup don't mix

message-security.md decided the sealed bundle stays on Keycloak. It holds the 24 words under
a password, and the backup key comes from the 24 words. So once the backup exists, anybody
who guesses the bundle password opens every backup too, and an Argon2id grind against the
bundle becomes a grind against history.

That runs into the rule that the server holds nothing that unlocks messages, even slowly.
Under MLS the bundle on its own only costs impersonation from that moment on, which is why
message-security.md accepted it. With the backup on, it costs history as well. This needs a
decision from Sivert, and it's question 5.

### What a new member of a private channel sees

MLS gives a new member nothing from before they joined, and the library check tests exactly
that. For stage 3 the channel shows "messages before you joined aren't available on this
device", and that's all.

Sharing history on purpose could come later. A member's client would seal the last N days
from its own store to the new member, the way pairing does. It'd need a channel setting, and
the channel would have to show who shared what.

## 6. Migration from sealed DMs

**Old messages keep opening.** Envelopes of type `gryt-sealed-message`, version 1, stay on the
server, and `openForConversation` keeps reading them with the DM key from the seed. That code
stays, read-only, for good. So the 24 words still read every DM sent before the switch, for
as long as the server keeps it. Only new messages get forward secrecy.

**New messages go on MLS when everyone can.** A device shows it can do MLS by uploading
KeyPackages, and a server shows it by advertising it at connect. Per conversation:

- Every member has at least one MLS device, and the server supports it. The conversation goes
  on MLS and stays there.
- Somebody has no MLS device at all. The conversation stays on version 1 sealing, which is
  what it has today, so nothing gets worse. The composer says who's holding it up, the way
  `decideSealing` already names people with no key.
- Somebody has an MLS device and an old one, say an updated phone and a laptop that isn't.
  The conversation goes on MLS, and the old laptop shows "sent to your newer devices, update
  Gryt to read it here" in place of the message.

**No going back.** Once a client has seen a peer on MLS, it records that in the pin and never
seals to them with version 1 again. Otherwise a server could hide somebody's KeyPackages and
push the conversation back to the old scheme. The pin already stops the same trick for DM
keys.

**The cut-over.** Stage 1 ships with both paths. Two minor releases later, or 60 days,
whichever is longer, clients stop sending version 1. After that a conversation with somebody
who never updated can't be sent to, and the composer says why. Reading version 1 never
stops.

MLS also signs every message with the sender's leaf. A version 1 envelope isn't
authenticated as coming from its sender, and the comment at the top of `message-keys.ts`
says so.

## 7. The phone

**Speed.** DMs and group DMs are small. At 10 leaves every suite 1 operation is under 300 ms
on the Mac's Hermes, and adds and joins are under 250 ms. Channels are where the phone gets
slow, and section 3's rules keep phones out of the expensive commits.

**Catching up.** Decrypting takes 16 ms a message with suite 1, mostly the signature check in
interpreted JS. 200 unread messages is about 3 seconds on the Mac, so maybe 6 to 12 on a
phone. That runs in batches, off the render path, newest conversation first, and the UI
shows the unread count before the text arrives.

**Background limits.** iOS gives an app about 30 seconds when a background fetch wakes it,
and Android's headless JS tasks are similar. That's enough to catch up a DM and not a big
channel. Nothing processes MLS in the background until push exists.

**Push.** Gryt has no push service today, and the phone only notifies from an open
connection. When push comes, the payload can't hold the text. There are two ways to do it:

- A push that only says "new message on this server". The app wakes, fetches, decrypts and
  shows a local notification. It's simple, and nothing about the content goes to Apple or
  Google.
- The ciphertext in the push, decrypted in the iOS Notification Service Extension. That's a
  separate process with a 24 MB memory limit and no React Native runtime, and it would need
  the MLS state too, shared with the app and locked against it. Signal works this way, and
  it's a lot of native code.

The first is the recommendation for when push lands.

**A native signature module.** If a real phone turns out slower than the library check
guessed, the cheapest speed-up is Ed25519 verification in native code, since that's most of
the decrypt and join cost. It'd mean a provider that's part JS and part native, and a second
set of vectors in the phone's CI.

## 8. What breaks or changes

The server can't read an encrypted conversation, so anything that relied on it reading moves
to the client or stops.

| Feature | In sealed DMs today | Under MLS, and in encrypted channels |
|---|---|---|
| **Search** | No server search | Client-side, over the local store |
| **Link previews** | Needs checking whether sealed DMs unfurl through the server | Off by default. Fetching through `linkPreview.ts` tells the server every URL. A preview made by the sender on desktop or phone could go inside the message later |
| **Notifications** | Decrypted locally | Same. The server can't parse mentions, so `mentions.ts` doesn't work there. Clients find their own mentions after decrypting, and drop an `@everyone` from somebody whose role doesn't allow it |
| **Unread and mention counts** | Unread counted by the server | The server counts messages. Mentions are counted on the client |
| **Bots** | Can't read sealed DMs | Can't read. A bot could one day be a visible member with its own leaf. Not in stage 3 |
| **Webhooks** | - | Refused into an encrypted channel. A webhook would post plain text into a channel that says it's encrypted |
| **Reports** | Reference a message by id, and a moderator reads the channel | The reporter's client sends its decrypted copy with the report, labelled as the reporter's copy. See below |
| **Deleting a message** | The server deletes the envelope | The server deletes the ciphertext, and a signed delete goes to the group. Honest clients delete their local copy |
| **Spam filter** | Metadata only (`DirectSend`) | Encrypted channels get the same metadata-only scoring. The text and mention checks in `ChannelSend` can't run |
| **Profanity filter, export** | Already gone for DMs | Gone for encrypted channels too |
| **Voice** | Not encrypted end to end | Unchanged. MLS's exporter could key SFrame for calls later, as its own design |

**Reports.** A forwarded copy proves nothing on its own, because a reporter could type
anything. MLS can do better. Every application message is signed by the sender's leaf, so a
reporter could hand over that one message's key and nonce. Whoever checks it could then open
the exact ciphertext the server stored and check the signature against the sender's device
certificate. Revealing one message's key reveals only that message. It also needs the group
context for that epoch, which the reporter would supply, and how a moderator can trust that
part is real work. Stage 3 ships the forwarded copy, clearly labelled.

**Deniability.** Signal's messages are deniable and MLS messages aren't. Each one is signed by
the sender's device, so a member who wants to prove to somebody else what you said can do it.
The verifiable report above relies on that. It deserves a sentence on the security page.

## 9. Staged build

Each stage ships on its own. Line counts are rough guesses, tests included.

**Release order, every stage:** `@gryt/crypto` to npm first (a minor bump), then the server,
then the desktop client, web client and phone together, all pinning the same `@gryt/crypto`
and the same `ts-mls` exactly. The library check's condition 4 is why they move together,
since 1.6.4 and older clients already reject each other's commits. The server goes before
the clients because the desktop app embeds a server, and a client won't use MLS on a server
that doesn't advertise it. `about/security.mdx` changes in the same stage.

### Stage 1: DMs

This one closes GRYT-754.

| Repo | What | Size | Review-required |
|---|---|--:|---|
| crypto | `ts-mls` pinned, with a peer override for `@noble/curves`. The Hermes crypto provider. Person key, bindings, device certificates, `AuthenticationService`. A group engine: create, add, remove, process, encrypt, decrypt, state encoding. The six property tests and the RFC vectors in CI | ~2,000 | **All of it.** Published to npm, and the provider is HPKE code Gryt owns |
| server | KeyPackage directory, Welcome mailbox, group log with cursors, commit ordering, capability flag, 30-day retention | ~1,000 | **`src/db/**`**, for the new tables |
| client | Local message store, MLS state store with the tab lock, replacing `useConversationSealing`, the version 1 fallback, the device list in Settings, "couldn't decrypt" states | ~1,800 | **`common/src/auth/**`**, for the person key from the seed and the store key |
| mobile | The same on Hermes, SQLite store, batched decryption | ~1,500 | - |
| docs | `about/security.mdx`: forward secrecy, devices, the archive on the device | ~150 | - |

Adding a device without typing the 24 words needs GRYT-1484, which has review-required parts
of its own (`packages/auth/**`, if the relay goes there). Stage 1 can ship first with the 24
words as the only way to add a device, and pairing carries history once it lands.

### Stage 2: group DMs

| Repo | What | Size | Review-required |
|---|---|--:|---|
| crypto | Leaving by proposal, removing a revoked device, property tests for both | ~300 | **All of it** |
| server | Checking adds against `create_groups`, removals when somebody leaves the server | ~250 | **`src/db/**`** |
| client and mobile | Adding, leaving, and the "you keep what you already read" wording | ~400 each | - |

### Stage 3: private channels

| Repo | What | Size | Review-required |
|---|---|--:|---|
| crypto | External-sender checks, the server's Ed25519 key binding, property tests (a server Remove really removes, an unlisted external sender is refused) | ~500 | **All of it** |
| server | The external-sender key next to `serverIdentity.ts`. Working out reader changes from `channelReaders()` on every role, scope, kick and ban. The committer hint. The size cap. Refusing webhooks and public scopes | ~1,500 | **`src/auth/**`** for the key, and **`src/db/**`** |
| client and mobile | The toggle and what it says, client-side mentions, previews off, report forwarding, "before you joined" | ~1,200 client, ~900 mobile | - |
| docs | Encrypted channels on the security page and the host configuration page | ~200 | - |

Measure a real phone before this one, per the library check's condition 7.

### Stage 4: encrypted backup

| Repo | What | Size | Review-required |
|---|---|--:|---|
| crypto | Backup key, chunk format, manifest, `fflate`, known-answer tests | ~500 | **All of it** |
| server | Blob storage per member, the lease, the cap | ~400 | **`src/db/**`**, and **`src/storage/**`** if the blobs go in object storage |
| client and mobile | The setting, writing, compacting and restoring | ~700 each | **`common/src/auth/**`**, for the key from the seed |

If the backup lives somewhere other than the community server (question 6), the server row
moves to that repo, and `packages/auth/**` is review-required too.

## 10. Open questions for Sivert

Each one can be asked on its own.

1. **Which ciphersuite?**
   - a. Suite 1: X25519, Ed25519, AES-128-GCM
   - b. Suite 2: P-256 throughout, so the identity key could be a leaf key

   Recommend **a**. Leaves are per-device keys in this design, so suite 2's advantage doesn't
   apply, and suite 1 is about 40% cheaper on the phone: 15.9 ms against 28.8 ms per message,
   and 2.6 s against 3.9 s to join 100 leaves.

2. **What vouches for a device?**
   - a. The `id.gryt.chat` certificate, per device
   - b. A person key per server, from the 24 words, that signs each device
   - c. Nothing. Everybody who talks to you pins each of your devices separately

   Recommend **b**. With **a** the CA can add a device to somebody's DMs, and guests have no
   certificate. With **c** every new laptop shows up to all your contacts as a changed key.

3. **What does pairing hand the new device?**
   - a. The seed, as GRYT-1484 plans, so every device is a full peer
   - b. Only a device certificate signed by the old device, plus history. It's a linked
     device that can't add others or open the backup
   - c. The seed to desktop and phone, and a certificate only to the web client

   Recommend **a**, because it's what GRYT-1484 is building and it keeps devices equal.
   **c** is worth a thought, since the web client is the weaker one.

4. **What happens when somebody in a conversation can't do MLS yet?**
   - a. Refuse to send until they update
   - b. Stay on today's sealing until everyone has an MLS device, never go back after that,
     and stop sending the old way two releases or 60 days after stage 1
   - c. Send MLS anyway, and old clients show "update to read"

   Recommend **b**. Nothing gets worse for anybody during the switch, and the pin stops a
   server forcing a downgrade.

5. **What happens to the password bundle on Keycloak once pairing and the backup exist?**
   - a. Keep it as it is. The bundle password then protects the backup as well
   - b. Stop writing new bundles once pairing ships. Existing ones keep opening, nothing is
     deleted, and people can remove their own
   - c. Keep it, but the backup can't be turned on while a bundle exists
   - d. Keep it, and give the backup its own random key in place of the 24 words

   Recommend **b**. With the backup on, the bundle is a grindable path to history, and the
   server isn't supposed to hold one of those. **d** goes against "the 24 words unlock it".

6. **Where does the encrypted backup live?**
   - a. On each community server, one blob per member
   - b. A new blob store on the account service, accounts only
   - c. A file the person keeps: a folder, iCloud Drive or Google Drive
   - d. a, plus c as an export

   Recommend **a**. It works for guests, needs no central service, doesn't link servers,
   and sits next to the conversations it backs up.

7. **How long does a server keep MLS ciphertext?**
   - a. Forever, like channel messages
   - b. 30 days, then it's dropped
   - c. Until every device has fetched it

   Recommend **b**. After that nobody can read it anyway, and 30 days covers a device that's
   been off for a while. An operator could shorten it.

8. **What does a new member of a private channel see from before they joined?**
   - a. Nothing
   - b. A channel setting to share the last N days, sent by a member's client
   - c. History shared automatically by whoever's online

   Recommend **a** for stage 3, and **b** later if people ask.

9. **Who can turn encryption on for a channel, and can it be turned off?**
   - a. `manage_channels`, one-way
   - b. `manage_channels`, reversible
   - c. The owner only, one-way

   Recommend **a**. If encryption could be switched off, a server could switch it off.

10. **How big can an encrypted channel get?**
    - a. 100 devices, about 50 people, until a real phone is measured
    - b. 250 devices, about 100 people
    - c. No cap, with desktops doing the commits

    Recommend **a**. The measurements stop at 100 leaves, and a phone joining at that size
    already takes about 2.6 s on the Mac's CPU.

11. **How do reports work in encrypted conversations?**
    - a. No reporting
    - b. The reporter's client sends its decrypted copy, labelled as unverified
    - c. Verifiable reports, by revealing that one message's key

    Recommend **b** for stage 3, and **c** as its own piece of work afterwards.

12. **What do push notifications carry, once there's push?**
    - a. Only "new message", and the app decrypts after waking
    - b. The ciphertext, decrypted in the notification extension
    - c. Nothing for encrypted conversations

    Recommend **a**. **b** is a lot of native code and a second process touching MLS state.

13. **Link previews in encrypted conversations?**
    - a. Off
    - b. Through the server as today, which tells it every URL
    - c. Made by the sender on desktop and phone, and sent inside the message

    Recommend **a** now and **c** later. The web client can't fetch most pages itself
    because of CORS, so under **c** web senders still get no previews.

## Decisions (Sivert, 2026-09-25)

1. **Ciphersuite:** suite 1 (X25519, Ed25519, AES-128-GCM).
2. **Vouching for a device:** a per-server person key from the 24 words signs each of your devices.
3. **Pairing:** hands the new device the seed, so every device is a full peer.
4. **Someone who can't do MLS yet:** send MLS anyway, and older apps show "update to read". (This differs from the recommendation, which was to stay on today's sealing until everyone could. The trade-off accepted: someone on an old app can't read new messages until they update.)
5. **The password bundle on Keycloak:** once pairing ships, stop writing new ones. Existing bundles keep opening, nothing is deleted, and people can remove their own.
6. **The history backup:** one encrypted blob per member on each community server.
7. **Retention:** a server keeps MLS ciphertext for 30 days, and its host can shorten that.
8. **New members of a private channel:** history is shared with them automatically by a member who's online. (This differs from the recommendation, which was nothing at first. Stage 3 has to design what "automatically" shares, how far back, and what a member's app does when asked, since the sender's app is the one that decrypts and re-shares.)
9. **Turning encryption on for a channel:** Manage channels can do it, and it can't be turned off.
10. **Channel size:** capped at 100 devices (about 50 people) until a real phone is measured.
11. **Reports:** the reporter's app sends its decrypted copy, marked unverified. Verifiable reports come later as their own piece of work.
12. **Push:** only "new message", and the app decrypts after it wakes.
13. **Link previews:** off in encrypted conversations for now. Later they'll be made by the sender's app and sent inside the message.
