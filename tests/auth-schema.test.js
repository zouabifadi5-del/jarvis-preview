import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import assert from "node:assert/strict";

const migrationPath = fileURLToPath(new URL("../migrations/0001_owner_auth.sql", import.meta.url));
const migration = readFileSync(migrationPath, "utf8");
const rateLimitMigration = readFileSync(
  fileURLToPath(new URL("../migrations/0002_auth_rate_limits.sql", import.meta.url)),
  "utf8"
);
const memoryMigration = readFileSync(
  fileURLToPath(new URL("../migrations/0003_encrypted_owner_memories.sql", import.meta.url)),
  "utf8"
);
const memoryAuditMigration = readFileSync(
  fileURLToPath(new URL("../migrations/0004_memory_audit.sql", import.meta.url)),
  "utf8"
);

function createDatabase() {
  const db = new DatabaseSync(":memory:");
  // D1 enforces foreign keys by default; mirror that behavior in local SQLite.
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(migration);
  db.exec(rateLimitMigration);
  db.exec(memoryMigration);
  db.exec(memoryAuditMigration);
  return db;
}

test("D1 auth migration creates only the intended auth tables", () => {
  const db = createDatabase();
  try {
    const names = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).all().map((row) => row.name);
    assert.deepEqual(names, [
      "auth_challenges",
      "auth_rate_limits",
      "auth_sessions",
      "jarvis_owner",
      "owner_credentials",
      "owner_memory_audit",
      "owner_memories",
      "owner_memory_settings",
      "owner_recovery_codes"
    ]);
  } finally {
    db.close();
  }
});

test("owner table enforces a single owner row", () => {
  const db = createDatabase();
  try {
    db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);
    assert.throws(() => {
      db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(2, ?)").run(2);
    });
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM jarvis_owner").get().n, 1);
  } finally {
    db.close();
  }
});

test("credential records require an owner and public key; duplicate IDs are rejected", () => {
  const db = createDatabase();
  try {
    db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);
    const insert = db.prepare(
      "INSERT INTO owner_credentials(credential_id, public_key, created_at) VALUES(?, ?, ?)"
    );
    insert.run("synthetic-credential", Buffer.from("synthetic-public-key"), 2);
    assert.throws(() => {
      insert.run("synthetic-credential", Buffer.from("another-key"), 3);
    });
    assert.throws(() => {
      db.prepare(
        "INSERT INTO owner_credentials(credential_id, owner_id, public_key, created_at) VALUES(?, 2, ?, ?)"
      ).run("orphan-credential", Buffer.from("key"), 3);
    });
  } finally {
    db.close();
  }
});

test("challenge purpose and expiry constraints reject invalid records", () => {
  const db = createDatabase();
  try {
    const insert = db.prepare(
      "INSERT INTO auth_challenges(challenge_hash, challenge, purpose, created_at, expires_at) VALUES(?, ?, ?, ?, ?)"
    );
    assert.throws(() => insert.run("bad-purpose", "challenge", "delete-account", 10, 20));
    assert.throws(() => insert.run("bad-expiry", "challenge", "authentication", 20, 20));
    insert.run("valid", "synthetic-challenge", "authentication", 10, 310);
    insert.run("credential-add", "synthetic-add-challenge", "credential_add", 10, 310);
  } finally {
    db.close();
  }
});

test("challenge can be consumed exactly once and expired challenges cannot be consumed", () => {
  const db = createDatabase();
  try {
    const insert = db.prepare(
      "INSERT INTO auth_challenges(challenge_hash, challenge, purpose, created_at, expires_at) VALUES(?, ?, ?, ?, ?)"
    );
    insert.run("one-use", "synthetic-challenge", "authentication", 10, 310);
    insert.run("expired", "expired-challenge", "authentication", 10, 20);

    const consume = db.prepare(
      "DELETE FROM auth_challenges WHERE challenge_hash = ? AND purpose = ? AND expires_at > ? RETURNING challenge"
    );
    assert.equal(consume.get("one-use", "authentication", 100).challenge, "synthetic-challenge");
    assert.equal(consume.get("one-use", "authentication", 100), undefined);
    assert.equal(consume.get("expired", "authentication", 100), undefined);
  } finally {
    db.close();
  }
});

test("session table stores only opaque token hashes and supports revocation", () => {
  const db = createDatabase();
  try {
    const columns = db.prepare("PRAGMA table_info(auth_sessions)").all().map((row) => row.name);
    assert.deepEqual(columns, [
      "session_hash",
      "csrf_token_hash",
      "created_at",
      "expires_at",
      "last_seen_at",
      "revoked_at"
    ]);
    db.prepare(
      "INSERT INTO auth_sessions(session_hash, csrf_token_hash, created_at, expires_at) VALUES(?, ?, ?, ?)"
    ).run("sha256-session-hash", "sha256-csrf-hash", 10, 3600);
    db.prepare("UPDATE auth_sessions SET revoked_at = ? WHERE session_hash = ?").run(20, "sha256-session-hash");
    assert.equal(
      db.prepare("SELECT revoked_at FROM auth_sessions WHERE session_hash = ?").get("sha256-session-hash").revoked_at,
      20
    );
  } finally {
    db.close();
  }
});

test("recovery-code table stores hashes and supports one-time challenge claims", () => {
  const db = createDatabase();
  try {
    const columns = db.prepare("PRAGMA table_info(owner_recovery_codes)").all().map((row) => row.name);
    assert.deepEqual(columns, ["code_hash", "created_at", "used_at", "used_claim_hash"]);
    const challengeColumns = db.prepare("PRAGMA table_info(auth_challenges)").all().map((row) => row.name);
    assert.ok(challengeColumns.includes("recovery_code_hash"));
    assert.throws(() => db.prepare(
      "INSERT INTO auth_challenges (challenge_hash, challenge, purpose, created_at, expires_at) VALUES (?, ?, 'recovery', ?, ?)"
    ).run("bad-recovery-hash", "challenge", 1, 2));
    assert.throws(() => db.prepare(
      "INSERT INTO auth_challenges (challenge_hash, challenge, purpose, recovery_code_hash, created_at, expires_at) VALUES (?, ?, 'registration', ?, ?, ?)"
    ).run("bad-registration-hash", "challenge", "unexpected-code-hash", 1, 2));
    db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);
    db.prepare("INSERT INTO owner_recovery_codes(code_hash, created_at) VALUES(?, ?)").run("opaque-sha256-recovery-hash", 2);
    db.prepare("UPDATE owner_recovery_codes SET used_at = ?, used_claim_hash = ? WHERE code_hash = ? AND used_at IS NULL")
      .run(3, "unique-challenge-hash", "opaque-sha256-recovery-hash");
    assert.equal(
      db.prepare("SELECT used_claim_hash FROM owner_recovery_codes WHERE code_hash = ?").get("opaque-sha256-recovery-hash").used_claim_hash,
      "unique-challenge-hash"
    );
  } finally {
    db.close();
  }
});


test("rate-limit migration stores opaque bucket hashes and bounded counters only", () => {
  const db = createDatabase();
  try {
    const columns = db.prepare("PRAGMA table_info(auth_rate_limits)").all().map((row) => row.name);
    assert.deepEqual(columns, ["bucket_hash", "window_start", "request_count", "expires_at"]);
    assert.throws(() => db.prepare(
      "INSERT INTO auth_rate_limits(bucket_hash, window_start, request_count, expires_at) VALUES(?, ?, ?, ?)"
    ).run("opaque-bucket", 100, 0, 200));
    db.prepare(
      "INSERT INTO auth_rate_limits(bucket_hash, window_start, request_count, expires_at) VALUES(?, ?, ?, ?)"
    ).run("opaque-bucket", 100, 1, 200);
    assert.equal(db.prepare("SELECT request_count FROM auth_rate_limits WHERE bucket_hash = ?").get("opaque-bucket").request_count, 1);
  } finally {
    db.close();
  }
});

test("memory schema stores encrypted payloads only and enforces nonce/category/owner constraints", () => {
  const db = createDatabase();
  try {
    const columns = db.prepare("PRAGMA table_info(owner_memories)").all().map((row) => row.name);
    assert.deepEqual(columns, [
      "id", "owner_id", "category", "ciphertext", "nonce", "key_version",
      "schema_version", "created_at", "updated_at", "expires_at"
    ]);
    assert.equal(columns.some((name) => ["content", "title", "summary", "tags", "plaintext"].includes(name)), false);
    db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);
    const insert = db.prepare(
      "INSERT INTO owner_memories(id, owner_id, category, ciphertext, nonce, key_version, schema_version, created_at, updated_at, expires_at) VALUES(?, 1, ?, ?, ?, 1, 1, ?, ?, NULL)"
    );
    insert.run("123e4567-e89b-42d3-a456-426614174000", "fact", Buffer.alloc(16), Buffer.alloc(12), 10, 10);
    assert.throws(() => insert.run("123e4567-e89b-42d3-a456-426614174001", "secret", Buffer.alloc(16), Buffer.alloc(12), 10, 10));
    assert.throws(() => insert.run("123e4567-e89b-42d3-a456-426614174002", "fact", Buffer.alloc(16), Buffer.alloc(11), 10, 10));
    assert.throws(() => db.prepare(
      "INSERT INTO owner_memories(id, owner_id, category, ciphertext, nonce, key_version, schema_version, created_at, updated_at) VALUES(?, 2, 'fact', ?, ?, 1, 1, 10, 10)"
    ).run("123e4567-e89b-42d3-a456-426614174003", Buffer.alloc(16), Buffer.alloc(12)));
  } finally {
    db.close();
  }
});

test("memory settings default off and accept only explicit boolean state", () => {
  const db = createDatabase();
  try {
    db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);
    const columns = db.prepare("PRAGMA table_info(owner_memory_settings)").all().map((row) => row.name);
    assert.deepEqual(columns, ["owner_id", "enabled", "updated_at"]);
    db.prepare("INSERT INTO owner_memory_settings(owner_id, updated_at) VALUES(1, ?)").run(10);
    assert.equal(db.prepare("SELECT enabled FROM owner_memory_settings WHERE owner_id = 1").get().enabled, 0);
    assert.throws(() => db.prepare(
      "INSERT INTO owner_memory_settings(owner_id, enabled, updated_at) VALUES(2, 1, 10)"
    ).run());
  } finally {
    db.close();
  }
});


test("memory audit triggers record content-free lifecycle events and retain only 200", () => {
  const db = createDatabase();
  try {
    db.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);
    const auditColumns = db.prepare("PRAGMA table_info(owner_memory_audit)").all().map((row) => row.name);
    assert.deepEqual(auditColumns, ["id", "owner_id", "event_type", "occurred_at"]);
    assert.equal(auditColumns.some((name) => ["content", "ciphertext", "record_id", "category", "session_id", "ip_address"].includes(name)), false);

    db.prepare("INSERT INTO owner_memory_settings(owner_id, enabled, updated_at) VALUES(1, 1, 20)").run();
    db.prepare(
      "INSERT INTO owner_memories(id, owner_id, category, ciphertext, nonce, key_version, schema_version, created_at, updated_at, expires_at) VALUES(?, 1, 'fact', ?, ?, 1, 1, 30, 30, NULL)"
    ).run("123e4567-e89b-42d3-a456-426614174000", Buffer.alloc(16), Buffer.alloc(12));
    db.prepare("UPDATE owner_memories SET updated_at = 40 WHERE id = ?").run("123e4567-e89b-42d3-a456-426614174000");
    db.prepare("DELETE FROM owner_memories WHERE id = ?").run("123e4567-e89b-42d3-a456-426614174000");
    db.prepare("UPDATE owner_memory_settings SET enabled = 0, updated_at = 50 WHERE owner_id = 1").run();

    const events = db.prepare(
      "SELECT event_type, occurred_at FROM owner_memory_audit ORDER BY id"
    ).all();
    assert.deepEqual(events.map((row) => row.event_type), ["enabled", "created", "updated", "deleted", "disabled"]);
    assert.equal(events[0].occurred_at, 20);
    assert.equal(events[1].occurred_at, 30);
    assert.equal(events[2].occurred_at, 40);
    assert.equal(events[4].occurred_at, 50);

    // Repeated updates create metadata-only events; the trigger prunes old rows.
    const id = "123e4567-e89b-42d3-a456-426614174001";
    db.prepare(
      "INSERT INTO owner_memories(id, owner_id, category, ciphertext, nonce, key_version, schema_version, created_at, updated_at, expires_at) VALUES(?, 1, 'fact', ?, ?, 1, 1, 60, 60, NULL)"
    ).run(id, Buffer.alloc(16), Buffer.alloc(12));
    for (let timestamp = 61; timestamp <= 270; timestamp += 1) {
      db.prepare("UPDATE owner_memories SET updated_at = ? WHERE id = ?").run(timestamp, id);
    }
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM owner_memory_audit WHERE owner_id = 1").get().count, 200);
  } finally {
    db.close();
  }
});
