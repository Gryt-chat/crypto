/**
 * The `gryt-local-identity-backup` file the desktop exports, moved here so the phone reads
 * the same thing. The pairing envelope carries its seed and entries (GRYT-1484).
 */

export interface IdentityBackupEntry {
  /** A server lineage since GRYT-257, an address before it. Restored under the same name. */
  scope: string;
  /** Last address it was used at. Display only. */
  host?: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

export interface IdentityBackup {
  type: "gryt-local-identity-backup";
  version: 2;
  exportedAt: string;
  /** The seed, base64url. Absent in files written before it existed. */
  seed?: string;
  identities: IdentityBackupEntry[];
}

/** Version 1, where `host` held what version 2 calls `scope`. Read, never written. */
interface IdentityBackupV1 {
  type: "gryt-local-identity-backup";
  version: 1;
  exportedAt: string;
  identities: { host: string; privateJwk: JsonWebKey; publicJwk: JsonWebKey }[];
}

export interface ParsedIdentityBackup {
  /** Base64url, when the file carries one. */
  seed?: string;
  identities: IdentityBackupEntry[];
}

function isJwk(value: unknown, needsPrivate: boolean): value is JsonWebKey {
  if (!value || typeof value !== "object") return false;
  const jwk = value as Record<string, unknown>;
  const fields = needsPrivate ? ["kty", "crv", "x", "y", "d"] : ["kty", "crv", "x", "y"];
  return fields.every((field) => typeof jwk[field] === "string" && jwk[field] !== "");
}

/** One entry with a scope and both halves of an EC key. The pairing envelope checks these. */
export function isIdentityBackupEntry(value: unknown): value is IdentityBackupEntry {
  if (!value || typeof value !== "object") return false;
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.scope === "string" &&
    entry.scope !== "" &&
    (entry.host === undefined || typeof entry.host === "string") &&
    isJwk(entry.privateJwk, true) &&
    isJwk(entry.publicJwk, false)
  );
}

/**
 * Both versions as one shape, or a throw. The desktop skipped a broken entry on import
 * rather than refusing the file, and this keeps that.
 */
export function parseIdentityBackup(raw: string): ParsedIdentityBackup {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("That file isn't a Gryt identity backup.");
  }
  const b = parsed as Partial<IdentityBackup | IdentityBackupV1> | null;
  if (
    !b ||
    typeof b !== "object" ||
    b.type !== "gryt-local-identity-backup" ||
    (b.version !== 1 && b.version !== 2) ||
    !Array.isArray(b.identities)
  ) {
    throw new Error("That file isn't a Gryt identity backup.");
  }

  if (b.version === 2) {
    const backup = b as IdentityBackup;
    return { seed: typeof backup.seed === "string" ? backup.seed : undefined, identities: backup.identities };
  }
  return {
    identities: (b as IdentityBackupV1).identities.map((e) => ({
      scope: e.host,
      host: e.host,
      privateJwk: e.privateJwk,
      publicJwk: e.publicJwk,
    })),
  };
}
