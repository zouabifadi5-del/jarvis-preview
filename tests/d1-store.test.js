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
  revokeSession
} from "../src/auth/d1-store.js";

const migration = readFileSync(
  fileURLToPath(new URL("../migrations/0001_owner_auth.sql", import.meta.url)),
  "utf8"
);

function makeD1() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec(migration);
  sqlite.prepare("INSERT INTO jarvis_owner(id, created_at) VALUES(1, ?)").run(1);

  return {
    sqlite,
    binding: {
      prepare(sql) {
        return {
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
              }
            };
          }
        };
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
