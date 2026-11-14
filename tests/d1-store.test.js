import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  createChallenge,
  consumeChallenge,
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
  createOwnerWithCredential
} from "../src/auth/d1-store.js";

const migration = readFileSync(
  fileURLToPath(new URL("../migrations/0001_owner_auth.sql", import.meta.url)),
  "utf8"
);

function makeD1({ seedOwner = true } = {}) {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec(migration);
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
    await createOwnerWithCredential(binding, {
      id: "first-owner-passkey",
      publicKey: new Uint8Array([7, 6, 5, 4]),
      counter: 0,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: true,
      now: 2000
    });
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
