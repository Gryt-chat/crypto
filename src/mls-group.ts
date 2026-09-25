/**
 * The group engine for stage 1: KeyPackages, create, add, remove, update, process, encrypt,
 * decrypt, and state as bytes. Everything that crosses the network is MLS wire bytes.
 */

import {
  type CiphersuiteImpl,
  type ClientConfig,
  type ClientState,
  type IncomingMessageCallback,
  type KeyPackage,
  type MLSMessage,
  type PrivateKeyPackage,
  type Proposal,
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeGroupState,
  decodeMlsMessage,
  defaultCapabilities,
  defaultKeyPackageEqualityConfig,
  defaultLifetime,
  defaultLifetimeConfig,
  emptyPskIndex,
  encodeGroupState,
  encodeMlsMessage,
  generateKeyPackageWithKey,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processMessage,
  zeroOutUint8Array,
} from "ts-mls";
import { makeKeyPackageRef, verifyKeyPackage } from "ts-mls/keyPackage.js";

import { base64Url } from "./base64";
import { type TrustPersonKey, createMlsAuthenticationService, deviceCertificateOf } from "./mls-authentication";
import {
  type DeviceCertificate,
  generateDeviceId,
  generateDeviceSignatureKeyPair,
  signDeviceCertificate,
} from "./mls-device-certificate";
import { derivePersonKeyPair } from "./mls-person-key";
import { MLS_CIPHERSUITE, grytMlsCryptoProvider } from "./mls-provider";
import type { IdentityScope } from "./scope";

export type MlsGroupState = ClientState;

/** What every call that can meet a new leaf needs: the server, and who the client trusts on it. */
export interface MlsTrust {
  scope: IdentityScope;
  trustPersonKey: TrustPersonKey;
}

/** This device on one server: its leaf signature key and the certificate for it. */
export interface MlsDevice {
  signKey: Uint8Array;
  publicKey: Uint8Array;
  certificate: Uint8Array;
}

/** A new device on one server: a random leaf key, certified by the person key from the seed. */
export function createMlsDevice({
  seed,
  scope,
  deviceName,
  deviceId = generateDeviceId(),
}: {
  seed: Uint8Array;
  scope: IdentityScope;
  deviceName: string;
  deviceId?: string;
}): MlsDevice & { deviceId: string } {
  const person = derivePersonKeyPair(seed, scope);
  const leaf = generateDeviceSignatureKeyPair();
  const certificate = signDeviceCertificate({
    personPrivateKey: person.privateKey,
    scope,
    leafSignatureKey: leaf.publicKey,
    deviceId,
    deviceName,
  });
  person.privateKey.fill(0);
  return { signKey: leaf.signKey, publicKey: leaf.publicKey, certificate, deviceId };
}

let suite: Promise<CiphersuiteImpl> | undefined;
export function mlsCiphersuite(): Promise<CiphersuiteImpl> {
  suite ??= getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE), grytMlsCryptoProvider);
  return suite;
}

/** Keeps the previous epoch's keys for a while (design, section 2), and pads short messages. */
function clientConfig(trust: MlsTrust): ClientConfig {
  return {
    keyRetentionConfig: { retainKeysForGenerations: 10, retainKeysForEpochs: 4, maximumForwardRatchetSteps: 200 },
    lifetimeConfig: defaultLifetimeConfig,
    keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
    paddingConfig: { kind: "padUntilLength", padUntilLength: 256 },
    authService: createMlsAuthenticationService(trust),
  };
}

/**
 * DMs take adds, removes and updates from members, and nothing else: no external senders, no
 * extension changes, no ReInit. That's what keeps the server from ever adding anybody.
 */
const dmPolicy: IncomingMessageCallback = (incoming) => {
  const allowed = (p: { proposal: Proposal; senderLeafIndex: number | undefined }) =>
    p.senderLeafIndex !== undefined && ["add", "remove", "update"].includes(String(p.proposal.proposalType));
  if (incoming.kind === "proposal") return allowed(incoming.proposal) ? "accept" : "reject";
  return incoming.senderLeafIndex !== undefined && incoming.proposals.every(allowed) ? "accept" : "reject";
};

function wire(message: MLSMessage): Uint8Array {
  return encodeMlsMessage(message);
}

function unwire(bytes: Uint8Array): MLSMessage {
  let decoded: ReturnType<typeof decodeMlsMessage>;
  try {
    decoded = decodeMlsMessage(bytes, 0);
  } catch {
    decoded = undefined;
  }
  if (!decoded || decoded[1] !== bytes.length) throw new Error("That isn't one whole MLS message.");
  return decoded[0];
}

function keyPackageOf(bytes: Uint8Array): KeyPackage {
  const m = unwire(bytes);
  if (m.wireformat !== "mls_key_package") throw new Error("That isn't a KeyPackage.");
  return m.keyPackage;
}

const capabilities = () => ({ ...defaultCapabilities(), ciphersuites: [MLS_CIPHERSUITE] });

/** One KeyPackage for this device. Upload `keyPackage`; keep `privatePackage` until it's used. */
export async function generateMlsKeyPackage(
  device: MlsDevice,
): Promise<{ keyPackage: Uint8Array; privatePackage: Uint8Array; ref: string }> {
  const cs = await mlsCiphersuite();
  const { publicPackage, privatePackage } = await generateKeyPackageWithKey(
    { credentialType: "basic", identity: device.certificate },
    capabilities(),
    defaultLifetime,
    [],
    { signKey: device.signKey, publicKey: device.publicKey },
    cs,
  );
  const keys = [privatePackage.initPrivateKey, privatePackage.hpkePrivateKey, privatePackage.signaturePrivateKey];
  if (keys.some((k) => k.length !== 32)) throw new Error("A suite 1 private key is 32 bytes.");
  return {
    keyPackage: wire({ version: "mls10", wireformat: "mls_key_package", keyPackage: publicPackage }),
    privatePackage: new Uint8Array([1, ...keys[0], ...keys[1], ...keys[2]]),
    ref: base64Url(await makeKeyPackageRef(publicPackage, cs.hash)),
  };
}

function readPrivatePackage(bytes: Uint8Array): PrivateKeyPackage {
  if (bytes.length !== 97 || bytes[0] !== 1) throw new Error("That isn't a private KeyPackage this version wrote.");
  return {
    initPrivateKey: bytes.slice(1, 33),
    hpkePrivateKey: bytes.slice(33, 65),
    signaturePrivateKey: bytes.slice(65, 97),
  };
}

/**
 * What the server checks on upload, and a client before adding: suite 1, signed by its leaf,
 * and carrying a certificate for this server. Whose person key it is stays the client's call.
 */
export async function readMlsKeyPackage(
  bytes: Uint8Array,
  scope: IdentityScope,
): Promise<{ certificate: DeviceCertificate; ref: string }> {
  const cs = await mlsCiphersuite();
  const kp = keyPackageOf(bytes);
  if (kp.cipherSuite !== MLS_CIPHERSUITE) throw new Error("That KeyPackage isn't suite 1.");
  if (!(await verifyKeyPackage(kp, cs.signature))) throw new Error("That KeyPackage's signature does not check out.");
  const certificate = deviceCertificateOf(kp.leafNode.credential, scope);
  if (!certificate) throw new Error("That KeyPackage has no device certificate for this server.");
  if (base64Url(certificate.leafSignatureKey) !== base64Url(kp.leafNode.signaturePublicKey)) {
    throw new Error("That KeyPackage's certificate is for a different leaf key.");
  }
  return { certificate, ref: base64Url(await makeKeyPackageRef(kp, cs.hash)) };
}

/** A new group with only this device in it. `groupId` is random unless given. */
export async function createMlsGroup(
  device: MlsDevice,
  trust: MlsTrust,
  groupId: Uint8Array = crypto.getRandomValues(new Uint8Array(16)),
): Promise<MlsGroupState> {
  const cs = await mlsCiphersuite();
  const own = await generateMlsKeyPackage(device);
  return createGroup(groupId, keyPackageOf(own.keyPackage), readPrivatePackage(own.privatePackage), [], cs, clientConfig(trust));
}

/** The KeyPackage refs a Welcome is for, so the client can find which private package opens it. */
export function mlsWelcomeRefs(welcome: Uint8Array): string[] {
  const m = unwire(welcome);
  if (m.wireformat !== "mls_welcome") throw new Error("That isn't a Welcome.");
  return m.welcome.secrets.map((s) => base64Url(s.newMember));
}

export async function joinMlsGroup(
  welcome: Uint8Array,
  keyPackage: Uint8Array,
  privatePackage: Uint8Array,
  trust: MlsTrust,
): Promise<MlsGroupState> {
  const m = unwire(welcome);
  if (m.wireformat !== "mls_welcome") throw new Error("That isn't a Welcome.");
  const kp = keyPackageOf(keyPackage);
  return joinGroup(m.welcome, kp, readPrivatePackage(privatePackage), emptyPskIndex, await mlsCiphersuite(), undefined, undefined, clientConfig(trust));
}

/**
 * A commit is sent in the clear as a PublicMessage (design, section 2). Keep the old state until
 * the server accepts it, then call `forgetMlsSecrets(consumed)`.
 */
export interface MlsCommit {
  state: MlsGroupState;
  commit: Uint8Array;
  welcome?: Uint8Array;
  consumed: Uint8Array[];
}

async function commit(state: MlsGroupState, proposals: Proposal[]): Promise<MlsCommit> {
  const r = await createCommit(
    { state, cipherSuite: await mlsCiphersuite() },
    { extraProposals: proposals, ratchetTreeExtension: true, wireAsPublicMessage: true },
  );
  return {
    state: r.newState,
    commit: wire(r.commit),
    welcome: r.welcome && wire({ version: "mls10", wireformat: "mls_welcome", welcome: r.welcome }),
    consumed: r.consumed,
  };
}

/** Adds devices, and returns the Welcome for them. */
export async function addMlsMembers(state: MlsGroupState, keyPackages: Uint8Array[]): Promise<MlsCommit> {
  if (keyPackages.length === 0) throw new Error("Nobody to add.");
  return commit(state, keyPackages.map((kp) => ({ proposalType: "add", add: { keyPackage: keyPackageOf(kp) } })));
}

/** Removes every leaf whose certificate carries one of these device ids. */
export async function removeMlsMembers(state: MlsGroupState, deviceIds: string[], scope: IdentityScope): Promise<MlsCommit> {
  const leaves = mlsGroupMembers(state, scope).filter((m) => deviceIds.includes(m.certificate.deviceId));
  if (leaves.length === 0) throw new Error("None of those devices are in this group.");
  return commit(state, leaves.map((m) => ({ proposalType: "remove", remove: { removed: m.leafIndex } })));
}

/** An empty commit, which gives this leaf fresh keys. The design has one a week. */
export async function updateMlsLeaf(state: MlsGroupState): Promise<MlsCommit> {
  return commit(state, []);
}

/** Zero what the last step used up. After this the state it came from is dead. */
export function forgetMlsSecrets(consumed: Uint8Array[]): void {
  for (const secret of consumed) zeroOutUint8Array(secret);
}

/** Pads to a 256-byte step, so the server sees only roughly how long a message is. */
export async function encryptMlsMessage(
  state: MlsGroupState,
  plaintext: Uint8Array,
): Promise<{ state: MlsGroupState; message: Uint8Array }> {
  // The length prefix grows at 64 and 16,384 bytes, so it counts towards the step.
  const n = plaintext.length;
  const padding = (256 - ((n + (n < 64 ? 1 : n < 16384 ? 2 : 4)) % 256)) % 256;
  const padded = { ...state, clientConfig: { ...state.clientConfig, paddingConfig: { kind: "alwaysPad" as const, paddingLength: padding } } };
  const r = await createApplicationMessage(padded, plaintext, await mlsCiphersuite());
  forgetMlsSecrets(r.consumed);
  return {
    state: { ...r.newState, clientConfig: state.clientConfig },
    message: wire({ version: "mls10", wireformat: "mls_private_message", privateMessage: r.privateMessage }),
  };
}

export type MlsProcessed =
  | { kind: "application"; state: MlsGroupState; plaintext: Uint8Array }
  | { kind: "handshake"; state: MlsGroupState; removed: boolean };

/** A commit, a proposal or a message. Throws on anything it can't or won't accept. */
export async function processMlsMessage(state: MlsGroupState, bytes: Uint8Array): Promise<MlsProcessed> {
  const m = unwire(bytes);
  if (m.wireformat !== "mls_private_message" && m.wireformat !== "mls_public_message") {
    throw new Error("That isn't a group message.");
  }
  const groupId = m.wireformat === "mls_private_message" ? m.privateMessage.groupId : m.publicMessage.content.groupId;
  if (base64Url(groupId) !== base64Url(state.groupContext.groupId)) throw new Error("That message is for another group.");

  const r = await processMessage(m, state, emptyPskIndex, dmPolicy, await mlsCiphersuite());
  forgetMlsSecrets(r.consumed);
  if (r.kind === "applicationMessage") return { kind: "application", state: r.newState, plaintext: r.message };
  if (r.actionTaken !== "accept") throw new Error("That commit or proposal isn't allowed in a DM.");
  return { kind: "handshake", state: r.newState, removed: r.newState.groupActiveState.kind === "removedFromGroup" };
}

/** `processMlsMessage` for when only a message will do. */
export async function decryptMlsMessage(
  state: MlsGroupState,
  bytes: Uint8Array,
): Promise<{ state: MlsGroupState; plaintext: Uint8Array }> {
  const m = unwire(bytes);
  if (m.wireformat !== "mls_private_message" || m.privateMessage.contentType !== "application") {
    throw new Error("That isn't an application message.");
  }
  const r = await processMlsMessage(state, bytes);
  if (r.kind !== "application") throw new Error("That isn't an application message.");
  return r;
}

/** Who's in the group, one entry per device, with the certificate each leaf carries. */
export function mlsGroupMembers(
  state: MlsGroupState,
  scope: IdentityScope,
): { leafIndex: number; certificate: DeviceCertificate }[] {
  const out: { leafIndex: number; certificate: DeviceCertificate }[] = [];
  state.ratchetTree.forEach((node, index) => {
    if (index % 2 !== 0 || node?.nodeType !== "leaf") return;
    const certificate = deviceCertificateOf(node.leaf.credential, scope);
    if (!certificate) throw new Error("A leaf in this group has no certificate, which the checks should have refused.");
    out.push({ leafIndex: index / 2, certificate });
  });
  return out;
}

export function mlsGroupInfo(state: MlsGroupState): { groupId: string; epoch: bigint } {
  return { groupId: base64Url(state.groupContext.groupId), epoch: state.groupContext.epoch };
}

/** What the server orders by, read without any keys. */
export function inspectMlsMessage(bytes: Uint8Array): {
  wireformat: MLSMessage["wireformat"];
  groupId?: string;
  epoch?: bigint;
  contentType?: "application" | "proposal" | "commit";
} {
  const m = unwire(bytes);
  if (m.wireformat === "mls_private_message") {
    const p = m.privateMessage;
    return { wireformat: m.wireformat, groupId: base64Url(p.groupId), epoch: p.epoch, contentType: p.contentType };
  }
  if (m.wireformat === "mls_public_message") {
    const c = m.publicMessage.content;
    return { wireformat: m.wireformat, groupId: base64Url(c.groupId), epoch: c.epoch, contentType: c.contentType };
  }
  return { wireformat: m.wireformat };
}

const STATE_FORMAT = 1;

/** Save this after every step, in the same write as the cursor (design, section 2). */
export function encodeMlsGroupState(state: MlsGroupState): Uint8Array {
  const body = encodeGroupState(state);
  const out = new Uint8Array(body.length + 1);
  out[0] = STATE_FORMAT;
  out.set(body, 1);
  return out;
}

export function decodeMlsGroupState(bytes: Uint8Array, trust: MlsTrust): MlsGroupState {
  if (bytes[0] !== STATE_FORMAT) throw new Error("That group state is a format this version can't read.");
  const body = bytes.subarray(1);
  let decoded: ReturnType<typeof decodeGroupState>;
  try {
    decoded = decodeGroupState(body, 0);
  } catch {
    decoded = undefined;
  }
  if (!decoded || decoded[1] !== body.length) throw new Error("That group state is damaged.");
  return { ...decoded[0], clientConfig: clientConfig(trust) };
}
