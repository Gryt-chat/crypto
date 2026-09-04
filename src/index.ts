/**
 * Message encryption for Gryt, shared by the desktop client and the mobile app.
 *
 * One implementation on purpose: two ports of one envelope is a pair of clients
 * that send each other messages nobody can read, and no set of test vectors
 * between two implementations is as good as not having two.
 *
 * Nothing here touches a platform — no `crypto.subtle`, no storage, no network,
 * no React. The exceptions are named where they are: `crypto.getRandomValues`,
 * and signing a key binding, which takes a WebCrypto key or a function.
 *
 * **No forward secrecy.** A DM key is derived from the seed and never moves, so
 * a leaked seed reads every message ever sent to it. That is GRYT-754, and it
 * is a different protocol rather than a setting.
 */

export * from "./attachments";
// Exported so both apps can drop their own copies, one of which is the `btoa`
// version this replaces.
export * from "./base64";
export * from "./comparison-code";
export * from "./conversation-encryption";
export * from "./dm-key-binding";
export * from "./dm-keys";
export * from "./member-keys";
export * from "./message-keys";
export * from "./peer-keys";
export * from "./scope";
export * from "./seed-words";
export * from "./thumbprint";
