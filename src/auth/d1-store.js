const DEFAULT_CHALLENGE_TTL_SECONDS = 5 * 60;
const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

function assertD1(db) {
  if (!db || typeof db.prepare !== "function") {
    throw new TypeError("A Cloudflare D1 database binding is required");
  }
}

function assertPurpose(purpose) {
  if (purpose !== "registration" && purpose !== "authentication" && purpose !== "credential_add") {
    throw new TypeError("Unsupported WebAuthn challenge purpose");
  }
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

function assertUnixSeconds(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative integer Unix timestamp in seconds`);
  }
}

function assertPositiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
}

export async function createChallenge(
  db,
  { purpose, now = Math.floor(Date.now() / 1000), ttlSeconds = DEFAULT_CHALLENGE_TTL_SECONDS }
) {
  assertD1(db);
  assertPurpose(purpose);
  assertUnixSeconds(now, "now");
  assertPositiveInteger(ttlSeconds, "ttlSeconds");
  if (ttlSeconds > DEFAULT_CHALLENGE_TTL_SECONDS) {
    throw new RangeError("WebAuthn challenge lifetime cannot exceed five minutes");
  }

  const challenge = randomToken();
  const challengeHash = await sha256Base64Url(challenge);
  const expiresAt = now + ttlSeconds;

  await db.prepare(
    "INSERT INTO auth_challenges (challenge_hash, challenge, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(challengeHash, challenge, purpose, now, expiresAt).run();

  return { challenge, expiresAt };
}

/**
 * Atomically claims and deletes a valid challenge. A second concurrent or
 * replayed call receives null because the row no longer exists.
 */
export async function consumeChallenge(db, { challenge, purpose, now = Math.floor(Date.now() / 1000) }) {
  assertD1(db);
  assertPurpose(purpose);
  assertUnixSeconds(now, "now");
  if (typeof challenge !== "string" || challenge.length < 20 || challenge.length > 256) {
    return null;
  }

  const challengeHash = await sha256Base64Url(challenge);
  const row = await db.prepare(
    "DELETE FROM auth_challenges WHERE challenge_hash = ? AND purpose = ? AND expires_at > ? RETURNING challenge"
  ).bind(challengeHash, purpose, now).first();

  return row?.challenge === challenge ? row.challenge : null;
}

export async function storeCredential(
  db,
  { id, publicKey, counter = 0, transports = [], deviceType = null, backedUp = false, now = Math.floor(Date.now() / 1000) }
) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof id !== "string" || id.length < 1 || id.length > 1024) {
    throw new TypeError("Credential ID is invalid");
  }
  if (!(publicKey instanceof Uint8Array) || publicKey.length < 1) {
    throw new TypeError("Credential public key must be a non-empty Uint8Array");
  }
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new TypeError("Credential counter must be a non-negative integer");
  }
  if (!Array.isArray(transports) || transports.some((item) => typeof item !== "string")) {
    throw new TypeError("Credential transports must be an array of strings");
  }

  await db.prepare(
    "INSERT INTO owner_credentials (credential_id, public_key, sign_count, transports_json, device_type, backed_up, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    id,
    publicKey,
    counter,
    JSON.stringify(transports),
    deviceType,
    backedUp ? 1 : 0,
    now
  ).run();
}

export async function findActiveCredential(db, credentialId) {
  assertD1(db);
  if (typeof credentialId !== "string" || credentialId.length < 1) return null;

  const row = await db.prepare(
    "SELECT credential_id, public_key, sign_count, transports_json, device_type, backed_up, created_at, last_used_at FROM owner_credentials WHERE credential_id = ? AND revoked_at IS NULL LIMIT 1"
  ).bind(credentialId).first();

  if (!row) return null;
  const publicKey = row.public_key instanceof Uint8Array
    ? row.public_key
    : row.public_key instanceof ArrayBuffer
      ? new Uint8Array(row.public_key)
      : new Uint8Array(row.public_key);

  let transports = [];
  try {
    const parsed = JSON.parse(row.transports_json || "[]");
    if (Array.isArray(parsed) && parsed.every((item) => typeof item === "string")) transports = parsed;
  } catch {
    transports = [];
  }

  return {
    id: row.credential_id,
    publicKey,
    counter: row.sign_count,
    transports,
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at
  };
}

/** Compare-and-set prevents two concurrent successful assertions from racing the counter. */
export async function updateCredentialCounter(
  db,
  { credentialId, expectedCounter, newCounter, now = Math.floor(Date.now() / 1000) }
) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof credentialId !== "string" || credentialId.length < 1) return false;
  if (![expectedCounter, newCounter].every((value) => Number.isSafeInteger(value) && value >= 0)) {
    throw new TypeError("Credential counters must be non-negative integers");
  }
  if (newCounter < expectedCounter) return false;

  const result = await db.prepare(
    "UPDATE owner_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ? AND sign_count = ? AND revoked_at IS NULL"
  ).bind(newCounter, now, credentialId, expectedCounter).run();

  return result.meta?.changes === 1;
}

export async function revokeCredential(db, { credentialId, now = Math.floor(Date.now() / 1000) }) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  const result = await db.prepare(
    "UPDATE owner_credentials SET revoked_at = ? WHERE credential_id = ? AND revoked_at IS NULL AND (SELECT COUNT(*) FROM owner_credentials WHERE owner_id = 1 AND revoked_at IS NULL) > 1"
  ).bind(now, credentialId).run();
  return result.meta?.changes === 1;
}

export async function createSession(
  db,
  { now = Math.floor(Date.now() / 1000), ttlSeconds = DEFAULT_SESSION_TTL_SECONDS }
) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  assertPositiveInteger(ttlSeconds, "ttlSeconds");
  if (ttlSeconds > MAX_SESSION_TTL_SECONDS) {
    throw new RangeError("Session lifetime cannot exceed seven days");
  }

  const sessionToken = randomToken();
  const csrfToken = randomToken();
  const sessionHash = await sha256Base64Url(sessionToken);
  const csrfHash = await sha256Base64Url(csrfToken);
  const expiresAt = now + ttlSeconds;

  await db.prepare(
    "INSERT INTO auth_sessions (session_hash, csrf_token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)"
  ).bind(sessionHash, csrfHash, now, expiresAt).run();

  return { sessionToken, csrfToken, expiresAt };
}

export async function findActiveSession(db, { sessionToken, now = Math.floor(Date.now() / 1000) }) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof sessionToken !== "string" || sessionToken.length < 40 || sessionToken.length > 256) {
    return null;
  }

  const sessionHash = await sha256Base64Url(sessionToken);
  const row = await db.prepare(
    "SELECT created_at, expires_at, last_seen_at FROM auth_sessions WHERE session_hash = ? AND expires_at > ? AND revoked_at IS NULL LIMIT 1"
  ).bind(sessionHash, now).first();

  return row ? {
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at
  } : null;
}

export async function verifySessionCsrf(
  db,
  { sessionToken, csrfToken, now = Math.floor(Date.now() / 1000) }
) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (
    typeof sessionToken !== "string" || sessionToken.length < 40 ||
    typeof csrfToken !== "string" || csrfToken.length < 40
  ) return false;

  const sessionHash = await sha256Base64Url(sessionToken);
  const row = await db.prepare(
    "SELECT csrf_token_hash FROM auth_sessions WHERE session_hash = ? AND expires_at > ? AND revoked_at IS NULL LIMIT 1"
  ).bind(sessionHash, now).first();
  if (!row || typeof row.csrf_token_hash !== "string") return false;

  const suppliedHash = await sha256Base64Url(csrfToken);
  if (suppliedHash.length !== row.csrf_token_hash.length) return false;
  let difference = 0;
  for (let index = 0; index < suppliedHash.length; index += 1) {
    difference |= suppliedHash.charCodeAt(index) ^ row.csrf_token_hash.charCodeAt(index);
  }
  return difference === 0;
}

export async function revokeSession(db, { sessionToken, now = Math.floor(Date.now() / 1000) }) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof sessionToken !== "string" || sessionToken.length < 40 || sessionToken.length > 256) {
    return false;
  }

  const sessionHash = await sha256Base64Url(sessionToken);
  const result = await db.prepare(
    "UPDATE auth_sessions SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL"
  ).bind(now, sessionHash).run();

  return result.meta?.changes === 1;
}

export async function findOwner(db) {
  assertD1(db);
  return db.prepare(
    "SELECT id, created_at, enrollment_closed_at FROM jarvis_owner WHERE id = 1 LIMIT 1"
  ).first();
}

export async function listActiveCredentials(db) {
  assertD1(db);
  const result = await db.prepare(
    "SELECT credential_id, public_key, sign_count, transports_json, device_type, backed_up, created_at, last_used_at FROM owner_credentials WHERE owner_id = 1 AND revoked_at IS NULL ORDER BY created_at ASC"
  ).all();
  return (result.results || []).map((row) => ({
    id: row.credential_id,
    publicKey: row.public_key instanceof Uint8Array
      ? row.public_key
      : row.public_key instanceof ArrayBuffer
        ? new Uint8Array(row.public_key)
        : new Uint8Array(row.public_key),
    counter: row.sign_count,
    transports: (() => {
      try {
        const parsed = JSON.parse(row.transports_json || "[]");
        return Array.isArray(parsed) && parsed.every((item) => typeof item === "string") ? parsed : [];
      } catch {
        return [];
      }
    })(),
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at
  }));
}

/**
 * Creates the singleton owner and first credential atomically.
 * D1 batch executes the statements transactionally; a competing bootstrap
 * attempt cannot create a second owner.
 */
export async function createOwnerWithCredential(db, {
  id, publicKey, counter = 0, transports = [], deviceType = null,
  backedUp = false, now = Math.floor(Date.now() / 1000)
}) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof id !== "string" || id.length < 1 || id.length > 1024) {
    throw new TypeError("Credential ID is invalid");
  }
  if (!(publicKey instanceof Uint8Array) || publicKey.length < 1) {
    throw new TypeError("Credential public key must be a non-empty Uint8Array");
  }
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new TypeError("Credential counter must be a non-negative integer");
  }
  if (!Array.isArray(transports) || transports.some((item) => typeof item !== "string")) {
    throw new TypeError("Credential transports must be an array of strings");
  }

  const statements = [
    db.prepare(
      "INSERT INTO jarvis_owner (id, created_at, enrollment_closed_at) VALUES (1, ?, ?)"
    ).bind(now, now),
    db.prepare(
      "INSERT INTO owner_credentials (credential_id, owner_id, public_key, sign_count, transports_json, device_type, backed_up, created_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?)"
    ).bind(id, publicKey, counter, JSON.stringify(transports), deviceType, backedUp ? 1 : 0, now)
  ];
  await db.batch(statements);
}
