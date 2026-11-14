import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import assert from "node:assert/strict";

const migrationPath = fileURLToPath(new URL("../migrations/0001_owner_auth.sql", import.meta.url));
const migration = readFileSync(migrationPath, "utf8");

function createDatabase() {
  const db = new DatabaseSync(":memory:");
  // D1 enforces foreign keys by default; mirror that behavior in local SQLite.
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(migration);
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
      "auth_sessions",
      "jarvis_owner",
      "owner_credentials"
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
