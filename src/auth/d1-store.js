const DEFAULT_CHALLENGE_TTL_SECONDS = 5 * 60;
const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const SESSION_IDLE_TIMEOUT_SECONDS = 30 * 60;
const SESSION_TOUCH_INTERVAL_SECONDS = 60;

function assertD1(db) {
  if (!db || typeof db.prepare !== "function") {
    throw new TypeError("A Cloudflare D1 database binding is required");
  }
}

function assertPurpose(purpose) {
  if (purpose !== "registration" && purpose !== "authentication" && purpose !== "credential_add" && purpose !== "recovery") {
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
  { purpose, recoveryCodeHash = null, now = Math.floor(Date.now() / 1000), ttlSeconds = DEFAULT_CHALLENGE_TTL_SECONDS }
) {
  assertD1(db);
  assertPurpose(purpose);
  assertUnixSeconds(now, "now");
  if (purpose === "recovery" && (typeof recoveryCodeHash !== "string" || recoveryCodeHash.length < 32)) {
    throw new TypeError("A valid recovery code hash is required for recovery challenges");
  }
  if (purpose !== "recovery" && recoveryCodeHash !== null) {
    throw new TypeError("Recovery code hashes are only valid for recovery challenges");
  }
  assertPositiveInteger(ttlSeconds, "ttlSeconds");
  if (ttlSeconds > DEFAULT_CHALLENGE_TTL_SECONDS) {
    throw new RangeError("WebAuthn challenge lifetime cannot exceed five minutes");
  }

  // Opportunistically prune expired one-time challenges before issuing another.
  await db.prepare("DELETE FROM auth_challenges WHERE expires_at <= ?").bind(now).run();

  const challenge = randomToken();
  const challengeHash = await sha256Base64Url(challenge);
  const expiresAt = now + ttlSeconds;

  await db.prepare(
    "INSERT INTO auth_challenges (challenge_hash, challenge, purpose, recovery_code_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(challengeHash, challenge, purpose, recoveryCodeHash, now, expiresAt).run();

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


export async function findActiveRecoveryCode(db, recoveryCode) {
  assertD1(db);
  if (typeof recoveryCode !== "string" || recoveryCode.length < 40 || recoveryCode.length > 128) return null;
  const codeHash = await sha256Base64Url(recoveryCode);
  const row = await db.prepare(
    "SELECT code_hash FROM owner_recovery_codes WHERE code_hash = ? AND used_at IS NULL LIMIT 1"
  ).bind(codeHash).first();
  return row ? codeHash : null;
}

export async function consumeRecoveryChallenge(db, { challenge, now = Math.floor(Date.now() / 1000) }) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof challenge !== "string" || challenge.length < 20 || challenge.length > 256) return null;
  const challengeHash = await sha256Base64Url(challenge);
  const row = await db.prepare(
    "DELETE FROM auth_challenges WHERE challenge_hash = ? AND purpose = 'recovery' AND expires_at > ? RETURNING challenge, challenge_hash, recovery_code_hash"
  ).bind(challengeHash, now).first();
  if (!row || row.challenge !== challenge || typeof row.recovery_code_hash !== "string") return null;
  return {
    challenge: row.challenge,
    challengeHash: row.challenge_hash,
    recoveryCodeHash: row.recovery_code_hash
  };
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

  // Remove expired/revoked session rows when issuing a new session.
  await db.prepare("DELETE FROM auth_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL").bind(now).run();

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
    "SELECT created_at, expires_at, last_seen_at FROM auth_sessions WHERE session_hash = ? AND expires_at > ? AND revoked_at IS NULL AND COALESCE(last_seen_at, created_at) > ? LIMIT 1"
  ).bind(sessionHash, now, now - SESSION_IDLE_TIMEOUT_SECONDS).first();

  if (!row) return null;
  const previousActivity = row.last_seen_at ?? row.created_at;
  let lastSeenAt = previousActivity;
  if (now - previousActivity >= SESSION_TOUCH_INTERVAL_SECONDS) {
    await db.prepare(
      "UPDATE auth_sessions SET last_seen_at = ? WHERE session_hash = ? AND expires_at > ? AND revoked_at IS NULL"
    ).bind(now, sessionHash, now).run();
    lastSeenAt = now;
  }

  return {
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastSeenAt
  };
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
    "SELECT csrf_token_hash FROM auth_sessions WHERE session_hash = ? AND expires_at > ? AND revoked_at IS NULL AND COALESCE(last_seen_at, created_at) > ? LIMIT 1"
  ).bind(sessionHash, now, now - SESSION_IDLE_TIMEOUT_SECONDS).first();
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

  const recoveryCodes = Array.from({ length: 10 }, () => randomToken());
  const recoveryHashes = await Promise.all(recoveryCodes.map(sha256Base64Url));
  const statements = [
    db.prepare(
      "INSERT INTO jarvis_owner (id, created_at, enrollment_closed_at) VALUES (1, ?, ?)"
    ).bind(now, now),
    db.prepare(
      "INSERT INTO owner_credentials (credential_id, owner_id, public_key, sign_count, transports_json, device_type, backed_up, created_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?)"
    ).bind(id, publicKey, counter, JSON.stringify(transports), deviceType, backedUp ? 1 : 0, now),
    ...recoveryHashes.map((hash) => db.prepare(
      "INSERT INTO owner_recovery_codes (code_hash, created_at) VALUES (?, ?)"
    ).bind(hash, now))
  ];
  await db.batch(statements);
  return { recoveryCodes };
}

/**
 * Atomically consumes one recovery code, enrolls a replacement passkey,
 * invalidates all previous recovery codes, and revokes every active session.
 * The challenge hash is the unique claim marker, preventing concurrent reuse.
 */
export async function completeOwnerRecovery(db, {
  recoveryCodeHash,
  id,
  publicKey,
  counter = 0,
  transports = [],
  deviceType = null,
  backedUp = false,
  now = Math.floor(Date.now() / 1000)
}) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof recoveryCodeHash !== "string" || recoveryCodeHash.length < 32) {
    throw new TypeError("Recovery claim is invalid");
  }
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

  const recoveryCodes = Array.from({ length: 10 }, () => randomToken());
  const recoveryHashes = await Promise.all(recoveryCodes.map(sha256Base64Url));
  const claimHash = await sha256Base64Url(randomToken());
  const claimExists = "EXISTS (SELECT 1 FROM owner_recovery_codes WHERE code_hash = ? AND used_claim_hash = ?)";
  const statements = [
    db.prepare(
      "UPDATE owner_recovery_codes SET used_at = ?, used_claim_hash = ? WHERE code_hash = ? AND used_at IS NULL"
    ).bind(now, claimHash, recoveryCodeHash),
    db.prepare(
      `UPDATE owner_credentials SET revoked_at = ? WHERE revoked_at IS NULL AND ${claimExists}`
    ).bind(now, recoveryCodeHash, claimHash),
    db.prepare(
      `INSERT INTO owner_credentials (credential_id, owner_id, public_key, sign_count, transports_json, device_type, backed_up, created_at) SELECT ?, 1, ?, ?, ?, ?, ?, ? WHERE ${claimExists}`
    ).bind(id, publicKey, counter, JSON.stringify(transports), deviceType, backedUp ? 1 : 0, now, recoveryCodeHash, claimHash),
    db.prepare(
      `DELETE FROM owner_recovery_codes WHERE used_at IS NULL AND ${claimExists}`
    ).bind(recoveryCodeHash, claimHash),
    ...recoveryHashes.map((hash) => db.prepare(
      `INSERT INTO owner_recovery_codes (code_hash, created_at) SELECT ?, ? WHERE ${claimExists}`
    ).bind(hash, now, recoveryCodeHash, claimHash)),
    db.prepare(
      `UPDATE auth_sessions SET revoked_at = ? WHERE revoked_at IS NULL AND ${claimExists}`
    ).bind(now, recoveryCodeHash, claimHash)
  ];

  const results = await db.batch(statements);
  if ((results[0]?.meta?.changes || 0) !== 1 || (results[2]?.meta?.changes || 0) !== 1) {
    throw new Error("Recovery code is invalid or has already been used");
  }
  return { recoveryCodes };
}


export async function revokeAllSessions(db, { now = Math.floor(Date.now() / 1000) }) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  const result = await db.prepare(
    "UPDATE auth_sessions SET revoked_at = ? WHERE revoked_at IS NULL"
  ).bind(now).run();
  return result.meta?.changes || 0;
}


/**
 * Atomically increments a fixed-window request bucket.
 * The caller supplies an HMAC-derived opaque key; raw IPs never enter D1.
 */
export async function consumeRateLimit(
  db,
  { bucketHash, windowStart, windowSeconds, limit, now = Math.floor(Date.now() / 1000) }
) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  if (typeof bucketHash !== "string" || !/^[A-Za-z0-9_-]{40,}$/.test(bucketHash)) {
    throw new TypeError("Rate-limit bucket hash is invalid");
  }
  assertUnixSeconds(windowStart, "windowStart");
  assertPositiveInteger(windowSeconds, "windowSeconds");
  assertPositiveInteger(limit, "limit");
  if (windowStart > now || now >= windowStart + windowSeconds) {
    throw new RangeError("Rate-limit window does not contain now");
  }

  const expiresAt = windowStart + windowSeconds;
  const row = await db.prepare(
    "INSERT INTO auth_rate_limits (bucket_hash, window_start, request_count, expires_at) VALUES (?, ?, 1, ?) " +
    "ON CONFLICT(bucket_hash, window_start) DO UPDATE SET request_count = request_count + 1 " +
    "RETURNING request_count"
  ).bind(bucketHash, windowStart, expiresAt).first();

  // Opportunistic retention once per minute to avoid an extra D1 write per request.
  if (now % 60 === 0) {
    await db.prepare("DELETE FROM auth_rate_limits WHERE expires_at <= ?").bind(now).run();
  }
  const count = Number(row?.request_count);
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new Error("Rate-limit counter could not be read");
  }
  return { allowed: count <= limit, count, remaining: Math.max(0, limit - count), resetAt: expiresAt };
}


const MEMORY_CATEGORIES = new Set(["preference", "fact", "project", "routine", "temporary"]);
const MEMORY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function assertMemoryRecordInput({ id, category, ciphertext, nonce, keyVersion, schemaVersion = 1, now, expiresAt }) {
  if (typeof id !== "string" || !MEMORY_ID_PATTERN.test(id)) throw new TypeError("Memory ID is invalid");
  if (!MEMORY_CATEGORIES.has(category)) throw new TypeError("Memory category is invalid");
  const toBytes = (value, label) => {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new TypeError("Encrypted memory " + label + " must be bytes");
  };
  const encrypted = toBytes(ciphertext, "ciphertext");
  const iv = toBytes(nonce, "nonce");
  if (encrypted.byteLength < 16 || iv.byteLength !== 12) throw new TypeError("Encrypted memory payload is invalid");
  assertPositiveInteger(keyVersion, "keyVersion");
  if (schemaVersion !== 1) throw new TypeError("Memory schema version is unsupported");
  assertUnixSeconds(now, "now");
  if (expiresAt !== null && expiresAt !== undefined) {
    assertUnixSeconds(expiresAt, "expiresAt");
    if (expiresAt <= now) throw new RangeError("Memory expiry must be in the future");
  }
  return { ciphertext: encrypted, nonce: iv, expiresAt: expiresAt ?? null };
}

export async function insertMemoryRecord(db, {
  id, category, ciphertext, nonce, keyVersion, schemaVersion = 1,
  now = Math.floor(Date.now() / 1000), expiresAt = null
}) {
  assertD1(db);
  const input = assertMemoryRecordInput({ id, category, ciphertext, nonce, keyVersion, schemaVersion, now, expiresAt });
  await db.prepare(
    "INSERT INTO owner_memories (id, owner_id, category, ciphertext, nonce, key_version, schema_version, created_at, updated_at, expires_at) " +
    "VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(id, category, input.ciphertext, input.nonce, keyVersion, schemaVersion, now, now, input.expiresAt).run();
  return { id, category, createdAt: now, updatedAt: now, expiresAt: input.expiresAt, keyVersion };
}

export async function listMemoryRecords(db, {
  now = Math.floor(Date.now() / 1000), limit = 100
} = {}) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  assertPositiveInteger(limit, "limit");
  if (limit > 100) throw new RangeError("Memory list limit cannot exceed 100");
  const result = await db.prepare(
    "SELECT id, category, key_version, created_at, updated_at, expires_at " +
    "FROM owner_memories WHERE owner_id = 1 AND (expires_at IS NULL OR expires_at > ?) " +
    "ORDER BY updated_at DESC LIMIT ?"
  ).bind(now, limit).all();
  return (result.results || []).map((row) => ({
    id: row.id,
    category: row.category,
    keyVersion: row.key_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at ?? null
  }));
}

export async function findMemoryRecord(db, id, {
  now = Math.floor(Date.now() / 1000)
} = {}) {
  assertD1(db);
  if (typeof id !== "string" || !MEMORY_ID_PATTERN.test(id)) throw new TypeError("Memory ID is invalid");
  assertUnixSeconds(now, "now");
  const row = await db.prepare(
    "SELECT id, owner_id, category, ciphertext, nonce, key_version, schema_version, created_at, updated_at, expires_at " +
    "FROM owner_memories WHERE id = ? AND owner_id = 1 AND (expires_at IS NULL OR expires_at > ?)"
  ).bind(id, now).first();
  if (!row) return null;
  return {
    id: row.id,
    ownerId: row.owner_id,
    category: row.category,
    ciphertext: row.ciphertext,
    nonce: row.nonce,
    keyVersion: row.key_version,
    schemaVersion: row.schema_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at ?? null
  };
}

export async function updateMemoryRecord(db, {
  id, category, ciphertext, nonce, keyVersion, schemaVersion = 1,
  now = Math.floor(Date.now() / 1000), expiresAt = null
}) {
  assertD1(db);
  const input = assertMemoryRecordInput({ id, category, ciphertext, nonce, keyVersion, schemaVersion, now, expiresAt });
  const result = await db.prepare(
    "UPDATE owner_memories SET category = ?, ciphertext = ?, nonce = ?, key_version = ?, schema_version = ?, updated_at = ?, expires_at = ? " +
    "WHERE id = ? AND owner_id = 1"
  ).bind(category, input.ciphertext, input.nonce, keyVersion, schemaVersion, now, input.expiresAt, id).run();
  return (result.meta?.changes || 0) === 1;
}

export async function deleteMemoryRecord(db, id) {
  assertD1(db);
  if (typeof id !== "string" || !MEMORY_ID_PATTERN.test(id)) throw new TypeError("Memory ID is invalid");
  const result = await db.prepare(
    "DELETE FROM owner_memories WHERE id = ? AND owner_id = 1"
  ).bind(id).run();
  return (result.meta?.changes || 0) === 1;
}

export async function pruneExpiredMemoryRecords(db, {
  now = Math.floor(Date.now() / 1000)
} = {}) {
  assertD1(db);
  assertUnixSeconds(now, "now");
  const result = await db.prepare(
    "DELETE FROM owner_memories WHERE owner_id = 1 AND expires_at IS NOT NULL AND expires_at <= ?"
  ).bind(now).run();
  return result.meta?.changes || 0;
}


export async function deleteAllMemoryRecords(db) {
  assertD1(db);
  const result = await db.prepare(
    "DELETE FROM owner_memories WHERE owner_id = 1"
  ).run();
  return result.meta?.changes || 0;
}
