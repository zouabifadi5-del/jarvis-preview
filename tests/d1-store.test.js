import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  createChallenge,
  consumeChallenge,
  consumeRateLimit,
  storeCredential,
  findActiveCredential,
  updateCredentialCounter,
  revokeCredential,
  createSession,
  findActiveSession,
  verifySessionCsrf,
  revokeSession,
  findOwner,
  listActiveCredentials,
  createOwnerWithCredential,
  findActiveRecoveryCode,
  consumeRecoveryChallenge,
  completeOwnerRecovery,
  revokeAllSessions,
  insertMemoryRecord,
  listMemoryRecords,
  findMemoryRecord,
  updateMemoryRecord,
  deleteMemoryRecord,
  deleteAllMemoryRecords,
  pruneExpiredMemoryRecords
} from "../src/auth/d1-store.js";

const migration = readFileSync(
  fileURLToPath(new URL("../migrations/0001_owner_auth.sql", import.meta.url)),
  "utf8"
);
const rateLimitMigration = readFileSync(
  fileURLToPath(new URL("../migrations/0002_auth_rate_limits.sql", import.meta.url)),
  "utf8"
);
const memoryMigration = readFileSync(
  fileURLToPath(new URL("../migrations/0003_encrypted_owner_memories.sql", import.meta.url)),
  "utf8"
);

function makeD1({ seedOwner = true } = {}) {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec(migration);
  sqlite.exec(rateLimitMigration);
  sqlite.exec(memoryMigration);
  if (seedOwner) sqlite.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);

  return {
    sqlite,
    binding: {
      prepare(sql) {
        return {
          async first() {
            return sqlite.prepare(sql).get() ?? null;
          },
          async all() {
            const result = sqlite.prepare(sql).all();
            return { success: true, results: result };
          },
          bind(...values) {
            return {
              async first() {
                return sqlite.prepare(sql).get(...values) ?? null;
              },
              async run() {
                const result = sqlite.prepare(sql).run(...values);
                return {
                  success: true,
                  meta: { changes: Number(result.changes) }
                };
              },
              async all() {
                const result = sqlite.prepare(sql).all(...values);
                return { success: true, results: result };
              }
            };
          }
        };
      },
      async batch(statements) {
        sqlite.exec("BEGIN");
        try {
          const results = [];
          for (const statement of statements) results.push(await statement.run());
          sqlite.exec("COMMIT");
          return results;
        } catch (error) {
          sqlite.exec("ROLLBACK");
          throw error;
        }
      }
    }
  };
}

test("challenge issuance is random, purpose-bound, and single-use", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const issued = await createChallenge(binding, { purpose: "authentication", now: 1000 });
    assert.match(issued.challenge, /^[A-Za-z0-9_-]{40,}$/);
    assert.equal(issued.expiresAt, 1300);
    assert.notEqual(
      (await createChallenge(binding, { purpose: "authentication", now: 1000 })).challenge,
      issued.challenge
    );

    assert.equal(await consumeChallenge(binding, {
      challenge: issued.challenge,
      purpose: "registration",
      now: 1001
    }), null);

    assert.equal(await consumeChallenge(binding, {
      challenge: issued.challenge,
      purpose: "authentication",
      now: 1001
    }), issued.challenge);

    const addCredentialChallenge = await createChallenge(binding, {
      purpose: "credential_add",
      now: 1002
    });
    assert.equal(await consumeChallenge(binding, {
      challenge: addCredentialChallenge.challenge,
      purpose: "credential_add",
      now: 1003
    }), addCredentialChallenge.challenge);

    assert.equal(await consumeChallenge(binding, {
      challenge: issued.challenge,
      purpose: "authentication",
      now: 1001
    }), null);
  } finally {
    sqlite.close();
  }
});

test("expired challenges cannot be consumed and challenge TTL cannot exceed five minutes", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const issued = await createChallenge(binding, { purpose: "registration", now: 1000 });
    assert.equal(await consumeChallenge(binding, {
      challenge: issued.challenge,
      purpose: "registration",
      now: 1300
    }), null);
    await assert.rejects(
      createChallenge(binding, {
        purpose: "authentication",
        now: 1000,
        ttlSeconds: 301
      }),
      RangeError
    );
  } finally {
    sqlite.close();
  }
});

test("credential storage and compare-and-set counter updates work", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const publicKey = new Uint8Array([1, 2, 3, 4]);
    await storeCredential(binding, {
      id: "synthetic-credential",
      publicKey,
      counter: 0,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: false,
      now: 1000
    });

    const stored = await findActiveCredential(binding, "synthetic-credential");
    assert.equal(stored.id, "synthetic-credential");
    assert.deepEqual([...stored.publicKey], [...publicKey]);
    assert.deepEqual(stored.transports, ["internal"]);
    assert.equal(stored.counter, 0);

    assert.equal(await updateCredentialCounter(binding, {
      credentialId: "synthetic-credential",
      expectedCounter: 0,
      newCounter: 1,
      now: 1001
    }), true);

    assert.equal(await updateCredentialCounter(binding, {
      credentialId: "synthetic-credential",
      expectedCounter: 0,
      newCounter: 2,
      now: 1002
    }), false);

    assert.equal((await findActiveCredential(binding, "synthetic-credential")).counter, 1);
  } finally {
    sqlite.close();
  }
});

test("revoked credentials cannot be retrieved or have counters updated", async () => {
  const { sqlite, binding } = makeD1();
  try {
    await storeCredential(binding, {
      id: "revoke-me",
      publicKey: new Uint8Array([9, 8, 7]),
      now: 1000
    });
    await storeCredential(binding, {
      id: "keep-me",
      publicKey: new Uint8Array([6, 5, 4]),
      now: 1000
    });
    assert.equal(await revokeCredential(binding, {
      credentialId: "revoke-me",
      now: 1001
    }), true);
    assert.equal(await findActiveCredential(binding, "revoke-me"), null);
    assert.equal(await updateCredentialCounter(binding, {
      credentialId: "revoke-me",
      expectedCounter: 0,
      newCounter: 1,
      now: 1002
    }), false);
  } finally {
    sqlite.close();
  }
});

test("sessions persist only hashes, validate CSRF, expire, and revoke", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const session = await createSession(binding, { now: 1000 });
    assert.equal(session.expiresAt, 1000 + 8 * 60 * 60);
    assert.equal(await findActiveSession(binding, {
      sessionToken: session.sessionToken,
      now: 1001
    }) !== null, true);
    assert.equal(await verifySessionCsrf(binding, {
      sessionToken: session.sessionToken,
      csrfToken: session.csrfToken,
      now: 1001
    }), true);
    assert.equal(await verifySessionCsrf(binding, {
      sessionToken: session.sessionToken,
      csrfToken: "not-the-csrf-token-at-all",
      now: 1001
    }), false);

    const row = sqlite.prepare("SELECT session_hash, csrf_token_hash FROM auth_sessions").get();
    assert.notEqual(row.session_hash, session.sessionToken);
    assert.notEqual(row.csrf_token_hash, session.csrfToken);

    assert.equal(await findActiveSession(binding, {
      sessionToken: session.sessionToken,
      now: session.expiresAt
    }), null);
    assert.equal(await revokeSession(binding, {
      sessionToken: session.sessionToken,
      now: 1002
    }), true);
    assert.equal(await findActiveSession(binding, {
      sessionToken: session.sessionToken,
      now: 1003
    }), null);
    assert.equal(await revokeSession(binding, {
      sessionToken: session.sessionToken,
      now: 1004
    }), false);
  } finally {
    sqlite.close();
  }
});

test("session lifetime cannot exceed seven days", async () => {
  const { sqlite, binding } = makeD1();
  try {
    await assert.rejects(
      createSession(binding, { now: 1000, ttlSeconds: 7 * 24 * 60 * 60 + 1 }),
      RangeError
    );
  } finally {
    sqlite.close();
  }
});


test("first owner and first passkey are created atomically and enrollment closes", async () => {
  const { sqlite, binding } = makeD1({ seedOwner: false });
  try {
    assert.equal(await findOwner(binding), null);
    const { recoveryCodes } = await createOwnerWithCredential(binding, {
      id: "first-owner-passkey",
      publicKey: new Uint8Array([7, 6, 5, 4]),
      counter: 0,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: true,
      now: 2000
    });
    assert.equal(recoveryCodes.length, 10);
    assert.ok(recoveryCodes.every((code) => /^[A-Za-z0-9_-]{40,}$/.test(code)));
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM owner_recovery_codes").get().count, 10);
    assert.ok(recoveryCodes.every((code) =>
      sqlite.prepare("SELECT COUNT(*) AS count FROM owner_recovery_codes WHERE code_hash = ?").get(code).count === 0
    ));
    const owner = await findOwner(binding);
    assert.equal(owner.id, 1);
    assert.equal(owner.created_at, 2000);
    assert.equal(owner.enrollment_closed_at, 2000);
    const credentials = await listActiveCredentials(binding);
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].id, "first-owner-passkey");
    assert.deepEqual([...credentials[0].publicKey], [7, 6, 5, 4]);
    assert.deepEqual(credentials[0].transports, ["internal"]);
    await assert.rejects(createOwnerWithCredential(binding, {
      id: "second-owner-passkey",
      publicKey: new Uint8Array([1, 1, 1]),
      now: 2001
    }));
    assert.equal((await listActiveCredentials(binding)).length, 1);
  } finally {
    sqlite.close();
  }
});


test("credential storage atomically enforces the ten-passkey owner limit", async () => {
  const { sqlite, binding } = makeD1();
  try {
    for (let index = 0; index < 10; index += 1) {
      assert.equal(await storeCredential(binding, {
        id: "passkey-" + index,
        publicKey: new Uint8Array([index + 1]),
        now: 1000 + index
      }), true);
    }
    assert.equal(await storeCredential(binding, {
      id: "passkey-over-limit",
      publicKey: new Uint8Array([99]),
      now: 1010
    }), false);
    assert.equal(sqlite.prepare(
      "SELECT COUNT(*) AS count FROM owner_credentials WHERE owner_id = 1 AND revoked_at IS NULL"
    ).get().count, 10);
  } finally {
    sqlite.close();
  }
});


test("credential revocation atomically refuses to remove the final active passkey", async () => {
  const { sqlite, binding } = makeD1();
  try {
    await storeCredential(binding, {
      id: "last-passkey",
      publicKey: new Uint8Array([4, 3, 2, 1]),
      now: 1000
    });
    assert.equal(await revokeCredential(binding, {
      credentialId: "last-passkey",
      now: 1001
    }), false);
    assert.notEqual(await findActiveCredential(binding, "last-passkey"), null);
  } finally {
    sqlite.close();
  }
});


test("new challenges and sessions prune expired or revoked rows", async () => {
  const { sqlite, binding } = makeD1();
  try {
    sqlite.prepare(
      "INSERT INTO auth_challenges(challenge_hash, challenge, purpose, created_at, expires_at) VALUES(?, ?, ?, ?, ?)"
    ).run("old-challenge", "old-challenge-value", "authentication", 1, 2);
    const challenge = await createChallenge(binding, { purpose: "authentication", now: 10 });
    assert.ok(challenge.challenge);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM auth_challenges WHERE challenge_hash = ?").get("old-challenge").n, 0);

    sqlite.prepare(
      "INSERT INTO auth_sessions(session_hash, csrf_token_hash, created_at, expires_at) VALUES(?, ?, ?, ?)"
    ).run("expired-session", "expired-csrf", 1, 2);
    sqlite.prepare(
      "INSERT INTO auth_sessions(session_hash, csrf_token_hash, created_at, expires_at, revoked_at) VALUES(?, ?, ?, ?, ?)"
    ).run("revoked-session", "revoked-csrf", 1, 100, 5);
    await createSession(binding, { now: 10 });
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM auth_sessions WHERE session_hash IN ('expired-session', 'revoked-session')").get().n, 0);
  } finally {
    sqlite.close();
  }
});


test("owner-wide session revocation invalidates every active session", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const first = await createSession(binding, { now: 1000 });
    const second = await createSession(binding, { now: 1001 });
    assert.equal(await revokeAllSessions(binding, { now: 1002 }), 2);
    assert.equal(await findActiveSession(binding, { sessionToken: first.sessionToken, now: 1003 }), null);
    assert.equal(await findActiveSession(binding, { sessionToken: second.sessionToken, now: 1003 }), null);
    assert.equal(await revokeAllSessions(binding, { now: 1004 }), 0);
  } finally {
    sqlite.close();
  }
});

test("new challenges prune expired challenge records", async () => {
  const { sqlite, binding } = makeD1();
  try {
    await createChallenge(binding, { purpose: "registration", now: 1000 });
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM auth_challenges").get().count, 1);
    await createChallenge(binding, { purpose: "authentication", now: 1300 });
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM auth_challenges").get().count, 1);
  } finally {
    sqlite.close();
  }
});

test("new sessions prune expired session records", async () => {
  const { sqlite, binding } = makeD1();
  try {
    await createSession(binding, { now: 1000, ttlSeconds: 1 });
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM auth_sessions").get().count, 1);
    await createSession(binding, { now: 1001 });
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM auth_sessions").get().count, 1);
  } finally {
    sqlite.close();
  }
});


test("sessions expire after 30 minutes of inactivity and active access refreshes activity", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const session = await createSession(binding, { now: 1000 });
    const active = await findActiveSession(binding, {
      sessionToken: session.sessionToken,
      now: 1100
    });
    assert.equal(active.lastSeenAt, 1100);
    const refreshed = await findActiveSession(binding, {
      sessionToken: session.sessionToken,
      now: 1100 + 29 * 60
    });
    assert.equal(refreshed.lastSeenAt, 1100 + 29 * 60);
    assert.equal(await findActiveSession(binding, {
      sessionToken: session.sessionToken,
      now: 1100 + 59 * 60
    }), null);
  } finally {
    sqlite.close();
  }
});

test("recovery codes are hashed, single-use, and replace all previous codes atomically", async () => {
  const { sqlite, binding } = makeD1({ seedOwner: false });
  try {
    const initial = await createOwnerWithCredential(binding, {
      id: "recovery-original",
      publicKey: new Uint8Array([1, 3, 5, 7]),
      now: 1000
    });
    const oldCode = initial.recoveryCodes[0];
    const oldUnusedCode = initial.recoveryCodes[1];
    const recoveryCodeHash = await findActiveRecoveryCode(binding, oldCode);
    assert.ok(recoveryCodeHash);
    assert.equal(await findActiveRecoveryCode(binding, "not-a-valid-recovery-code"), null);

    const session = await createSession(binding, { now: 1001 });
    const challenge = await createChallenge(binding, {
      purpose: "recovery",
      recoveryCodeHash,
      now: 1002
    });
    const consumed = await consumeRecoveryChallenge(binding, {
      challenge: challenge.challenge,
      now: 1003
    });
    assert.equal(consumed.challenge, challenge.challenge);
    assert.equal(consumed.recoveryCodeHash, recoveryCodeHash);

    const replacement = await completeOwnerRecovery(binding, {
      recoveryCodeHash,
      id: "recovery-replacement",
      publicKey: new Uint8Array([2, 4, 6, 8]),
      counter: 0,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: true,
      now: 1004
    });
    assert.equal(replacement.recoveryCodes.length, 10);
    assert.ok(await findActiveCredential(binding, "recovery-replacement"));
    assert.equal(await findActiveCredential(binding, "recovery-original"), null, "recovery must revoke the lost passkey");
    assert.equal(await findActiveCredential(binding, "recovery-original"), null);
    assert.equal(await findActiveRecoveryCode(binding, oldCode), null);
    assert.equal(await findActiveRecoveryCode(binding, oldUnusedCode), null);
    assert.equal(await findActiveSession(binding, { sessionToken: session.sessionToken, now: 1005 }), null);
    for (const code of replacement.recoveryCodes) assert.ok(await findActiveRecoveryCode(binding, code));

    await assert.rejects(completeOwnerRecovery(binding, {
      recoveryCodeHash,
      id: "recovery-replay",
      publicKey: new Uint8Array([9, 9, 9]),
      now: 1006
    }), /invalid or has already been used/);
    assert.equal(await findActiveCredential(binding, "recovery-replay"), null);
  } finally {
    sqlite.close();
  }
});

test("recovery challenges are purpose-bound, single-use, and require a code hash", async () => {
  const { sqlite, binding } = makeD1();
  try {
    await assert.rejects(createChallenge(binding, { purpose: "recovery", now: 1000 }), TypeError);
    const issued = await createChallenge(binding, {
      purpose: "recovery",
      recoveryCodeHash: "a".repeat(43),
      now: 1000
    });
    assert.equal(await consumeChallenge(binding, {
      challenge: issued.challenge,
      purpose: "authentication",
      now: 1001
    }), null);
    const consumed = await consumeRecoveryChallenge(binding, {
      challenge: issued.challenge,
      now: 1001
    });
    assert.equal(consumed.challenge, issued.challenge);
    assert.equal(consumed.recoveryCodeHash, "a".repeat(43));
    assert.equal(await consumeRecoveryChallenge(binding, {
      challenge: issued.challenge,
      now: 1002
    }), null);
  } finally {
    sqlite.close();
  }
});


test("rate-limit counters increment atomically within a fixed window and expire", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const bucketHash = "A".repeat(43);
    const first = await consumeRateLimit(binding, {
      bucketHash, windowStart: 900, windowSeconds: 300, limit: 2, now: 901
    });
    assert.deepEqual(first, { allowed: true, count: 1, remaining: 1, resetAt: 1200 });
    const second = await consumeRateLimit(binding, {
      bucketHash, windowStart: 900, windowSeconds: 300, limit: 2, now: 902
    });
    assert.equal(second.allowed, true);
    assert.equal(second.count, 2);
    const third = await consumeRateLimit(binding, {
      bucketHash, windowStart: 900, windowSeconds: 300, limit: 2, now: 903
    });
    assert.equal(third.allowed, false);
    assert.equal(third.count, 3);

    const nextWindow = await consumeRateLimit(binding, {
      bucketHash, windowStart: 1200, windowSeconds: 300, limit: 2, now: 1260
    });
    assert.equal(nextWindow.allowed, true);
    assert.equal(nextWindow.count, 1);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM auth_rate_limits").get().n, 1);
    await assert.rejects(consumeRateLimit(binding, {
      bucketHash: "short", windowStart: 1200, windowSeconds: 300, limit: 2, now: 1260
    }), TypeError);
  } finally {
    sqlite.close();
  }
});


test("encrypted memory storage supports owner-scoped listing, inspection, update, expiry, and deletion", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const id = "123e4567-e89b-42d3-a456-426614174000";
    const ciphertext = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(12).fill(3);
    const created = await insertMemoryRecord(binding, {
      id, category: "fact", ciphertext, nonce, keyVersion: 1, now: 1000
    });
    assert.deepEqual(created, {
      id, category: "fact", createdAt: 1000, updatedAt: 1000, expiresAt: null, keyVersion: 1
    });
    const listed = await listMemoryRecords(binding, { now: 1001 });
    assert.equal(listed.length, 1);
    assert.deepEqual(listed[0], {
      id, category: "fact", keyVersion: 1, createdAt: 1000, updatedAt: 1000, expiresAt: null
    });
    assert.equal("ciphertext" in listed[0], false);
    const found = await findMemoryRecord(binding, id, { now: 1001 });
    assert.deepEqual([...found.ciphertext], [...ciphertext]);
    assert.deepEqual([...found.nonce], [...nonce]);

    const updatedCiphertext = new Uint8Array(32).fill(8);
    const updatedNonce = new Uint8Array(12).fill(4);
    assert.equal(await updateMemoryRecord(binding, {
      id, category: "project", ciphertext: updatedCiphertext, nonce: updatedNonce,
      keyVersion: 1, now: 1002, expiresAt: 2000
    }), true);
    const updated = await findMemoryRecord(binding, id, { now: 1003 });
    assert.equal(updated.category, "project");
    assert.equal(updated.updatedAt, 1002);
    assert.equal(updated.expiresAt, 2000);

    const temporaryId = "123e4567-e89b-42d3-a456-426614174001";
    await insertMemoryRecord(binding, {
      id: temporaryId, category: "temporary", ciphertext, nonce, keyVersion: 1,
      now: 1000, expiresAt: 1005
    });
    assert.equal(await pruneExpiredMemoryRecords(binding, { now: 1005 }), 1);
    assert.equal(await findMemoryRecord(binding, temporaryId, { now: 1005 }), null);
    assert.equal(await deleteMemoryRecord(binding, id), true);
    assert.equal(await deleteMemoryRecord(binding, id), false);
    await insertMemoryRecord(binding, {
      id: temporaryId, category: "fact", ciphertext, nonce, keyVersion: 1, now: 1010
    });
    assert.equal(await deleteAllMemoryRecords(binding), 1);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM owner_memories").get().n, 0);
  } finally {
    sqlite.close();
  }
});

test("encrypted memory storage rejects malformed IDs, categories, payloads, and expiry", async () => {
  const { sqlite, binding } = makeD1();
  try {
    const valid = {
      id: "123e4567-e89b-42d3-a456-426614174000",
      category: "fact",
      ciphertext: new Uint8Array(16),
      nonce: new Uint8Array(12),
      keyVersion: 1,
      now: 1000
    };
    await assert.rejects(insertMemoryRecord(binding, { ...valid, id: "bad-id" }), TypeError);
    await assert.rejects(insertMemoryRecord(binding, { ...valid, category: "credential" }), TypeError);
    await assert.rejects(insertMemoryRecord(binding, { ...valid, nonce: new Uint8Array(11) }), TypeError);
    await assert.rejects(insertMemoryRecord(binding, { ...valid, ciphertext: 16 }), TypeError);
    await assert.rejects(insertMemoryRecord(binding, { ...valid, expiresAt: 999 }), RangeError);
  } finally {
    sqlite.close();
  }
});
