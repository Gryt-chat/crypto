/**
 * Message encryption for Gryt.
 *
 * Everything the desktop client and the mobile app both need to derive message
 * keys, say a key is theirs, seal a message to a conversation, decide whether a
 * peer's key is the one seen before, and let two people check that out of band.
 *
 * ## One implementation, on purpose
 *
 * This started as seven files in the client and a plan to port them. Two ports
 * of one envelope is a pair of clients that send each other messages nobody can
 * read, with the sender looking at the text they typed either way — and no
 * amount of test vectors between two implementations is as good as not having
 * two. GRYT-733 made the code platform-free so this could exist.
 *
 * ## Nothing here touches a platform
 *
 * No `crypto.subtle`, which React Native does not have. No storage: pins go
 * through a {@link PeerPinStore} the caller supplies, because the desktop has
 * `localStorage` and a phone has something asynchronous. No network, no React,
 * no config.
 *
 * The two exceptions are named where they are: `crypto.getRandomValues`, which
 * every target has, and signing a key binding, which takes either a WebCrypto
 * key or a function because that is the one place the platforms genuinely hold
 * a key differently.
 *
 * ## What it does not do
 *
 * Forward secrecy. A DM key is derived from the seed and never moves, so a seed
 * that leaks reads every message ever sent to it. Signal and Matrix ratchet;
 * this does not. That is GRYT-754, and it is a different protocol rather than a
 * setting.
 */

export * from "./comparison-code";
export * from "./conversation-encryption";
export * from "./dm-key-binding";
export * from "./dm-keys";
export * from "./member-keys";
export * from "./message-keys";
export * from "./peer-keys";
export * from "./scope";
export * from "./thumbprint";
