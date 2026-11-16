import { describe, expect, it } from "vitest";
import { exports } from "cloudflare:workers";
import { handleAuthRequest, readJson } from "../src/auth/routes.js";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { createSession } from "../src/auth/d1-store.js";

const worker = exports.default;

function request(path = "/health", options = {}, protocol = "https:") {
  const headers = new Headers(options.headers || {});
  if (!headers.has("CF-Connecting-IP")) headers.set("CF-Connecting-IP", "192.0.2.10");
  return new Request(`${protocol}//example.test${path}`, { ...options, headers });
}

function withRateLimitSupport(db) {
  const originalPrepare = db.prepare.bind(db);
  db.prepare = (sql) => {
    if (sql.includes("INSERT INTO auth_rate_limits")) {
      return {
        bind() {
          return {
            async first() { return { request_count: 1 }; }
          };
        }
      };
    }
    if (sql.includes("DELETE FROM auth_rate_limits")) {
      return {
        bind() {
          return {
            async run() { return { success: true, meta: { changes: 0 } }; }
          };
        }
      };
    }
    return originalPrepare(sql);
  };
  return db;
}

function expectHardenedHeaders(response, { https = true } = {}) {
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("x-frame-options")).toBe("DENY");
  expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  expect(response.headers.get("permissions-policy")).toBe(
    "camera=(), microphone=(), geolocation=()"
  );
  expect(response.headers.get("strict-transport-security")).toBe(
    https ? "max-age=31536000" : null
  );
  expect(response.headers.get("access-control-allow-origin")).toBeNull();
}


const testEncoder = new TextEncoder();
function joinBytes(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
function toB64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).split("+").join("-").split("/").join("_").split("=").join("");
}
function fromB64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function uint32Bytes(value) {
  return new Uint8Array([(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]);
}
function derEcdsa(raw) {
  const encodeInteger = (input) => {
    let start = 0;
    while (start < input.length - 1 && input[start] === 0) start += 1;
    let bytes = input.slice(start);
    if (bytes[0] & 0x80) bytes = joinBytes(new Uint8Array([0]), bytes);
    return joinBytes(new Uint8Array([2, bytes.length]), bytes);
  };
  const body = joinBytes(encodeInteger(raw.slice(0, 32)), encodeInteger(raw.slice(32, 64)));
  return joinBytes(new Uint8Array([0x30, body.length]), body);
}
async function makeRouteRegistration(challenge, credentialIdBytes = new Uint8Array([0x4a,0x41,0x52,0x56,0x49,0x53,0x2d,0x52,0x4f,0x55,0x54,0x45,0x2d,0x54,0x45,0x53])) {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const x = fromB64Url(jwk.x);
  const y = fromB64Url(jwk.y);
  const publicKey = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
  const credentialId = credentialIdBytes;
  const credentialIdB64 = toB64Url(credentialId);
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", testEncoder.encode("example.test")));
  const clientData = testEncoder.encode(JSON.stringify({ type: "webauthn.create", challenge, origin: "https://example.test", crossOrigin: false }));
  const credentialLength = new Uint8Array([0, credentialId.length]);
  const authData = joinBytes(rpHash, new Uint8Array([0x45]), uint32Bytes(0), new Uint8Array(16), credentialLength, credentialId, publicKey);
  const attestationObject = isoCBOR.encode(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
  return {
    keyPair,
    credentialId: credentialIdB64,
    publicKey,
    response: {
      id: credentialIdB64,
      rawId: credentialIdB64,
      type: "public-key",
      response: {
        clientDataJSON: toB64Url(clientData),
        attestationObject: toB64Url(attestationObject),
        transports: ["internal"]
      },
      authenticatorAttachment: "platform",
      clientExtensionResults: {}
    }
  };
}
async function makeRouteAssertion({ keyPair, credentialId, challenge, counter = 1, origin = "https://example.test" }) {
  const clientData = testEncoder.encode(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
  const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", testEncoder.encode("example.test")));
  const authData = joinBytes(rpHash, new Uint8Array([0x05]), uint32Bytes(counter));
  const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
  const signatureRaw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, joinBytes(authData, clientHash)));
  return {
    id: credentialId,
    rawId: credentialId,
    type: "public-key",
    response: {
      clientDataJSON: toB64Url(clientData),
      authenticatorData: toB64Url(authData),
      signature: toB64Url(derEcdsa(signatureRaw)),
      userHandle: null
    },
    authenticatorAttachment: "platform",
    clientExtensionResults: {}
  };
}
function makeRouteD1() {
  const state = { owner: null, credentials: [], challenges: [], sessions: [], recoveryCodes: [], rateLimits: [] };
  function statement(sql, values = []) {
    return {
      bind(...bound) { return statement(sql, bound); },
      async first() {
        if (sql.includes("INSERT INTO auth_rate_limits")) {
          const [bucketHash, windowStart, expiresAt] = values;
          let bucket = state.rateLimits.find((row) => row.bucketHash === bucketHash && row.windowStart === windowStart);
          if (!bucket) {
            bucket = { bucketHash, windowStart, expiresAt, requestCount: 0 };
            state.rateLimits.push(bucket);
          }
          bucket.requestCount += 1;
          return { request_count: bucket.requestCount };
        }
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) return state.owner;
        if (sql.includes("DELETE FROM auth_challenges")) {
          let index;
          if (sql.includes("purpose = 'recovery'")) {
            const [hash, now] = values;
            index = state.challenges.findIndex((item) => item.hash === hash && item.purpose === "recovery" && item.expiresAt > now);
            if (index < 0) return null;
            const [item] = state.challenges.splice(index, 1);
            return { challenge: item.challenge, challenge_hash: item.hash, recovery_code_hash: item.recoveryCodeHash };
          }
          const [hash, purpose, now] = values;
          index = state.challenges.findIndex((item) => item.hash === hash && item.purpose === purpose && item.expiresAt > now);
          if (index < 0) return null;
          const [item] = state.challenges.splice(index, 1);
          return { challenge: item.challenge };
        }
        if (sql.includes("SELECT code_hash FROM owner_recovery_codes")) {
          const item = state.recoveryCodes.find((row) => row.code_hash === values[0] && row.used_at === null);
          return item ? { code_hash: item.code_hash } : null;
        }
        if (sql.includes("SELECT credential_id, public_key, sign_count") && sql.includes("WHERE credential_id = ?")) {
          return state.credentials.find((row) => row.credential_id === values[0] && row.revoked_at === null) || null;
        }
        if (sql.includes("SELECT created_at, expires_at, last_seen_at")) {
          const [hash, now, idleCutoff] = values;
          const item = state.sessions.find((row) =>
            row.session_hash === hash && row.expires_at > now && row.revoked_at === null &&
            (row.last_seen_at ?? row.created_at) > idleCutoff
          );
          return item ? { created_at: item.created_at, expires_at: item.expires_at, last_seen_at: item.last_seen_at ?? null } : null;
        }
        if (sql.includes("SELECT csrf_token_hash")) {
          const [hash, now] = values;
          const item = state.sessions.find((row) => row.session_hash === hash && row.expires_at > now && row.revoked_at === null);
          return item ? { csrf_token_hash: item.csrf_token_hash } : null;
        }
        return null;
      },
      async all() {
        if (sql.includes("SELECT credential_id, public_key, sign_count")) {
          return { results: state.credentials.filter((row) => row.owner_id === 1 && row.revoked_at === null) };
        }
        return { results: [] };
      },
      async run() {
        if (sql.includes("DELETE FROM auth_rate_limits")) {
          const cutoff = values[0];
          const before = state.rateLimits.length;
          state.rateLimits = state.rateLimits.filter((row) => row.expiresAt > cutoff);
          return { success: true, meta: { changes: before - state.rateLimits.length } };
        }
        if (sql.includes("DELETE FROM auth_challenges")) {
          const cutoff = values[0];
          const before = state.challenges.length;
          state.challenges = state.challenges.filter((row) => row.expiresAt > cutoff);
          return { success: true, meta: { changes: before - state.challenges.length } };
        }
        if (sql.includes("INSERT INTO auth_challenges")) {
          const [hash, challenge, purpose, recoveryCodeHash, createdAt, expiresAt] = values;
          state.challenges.push({ hash, challenge, purpose, recoveryCodeHash, createdAt, expiresAt });
        } else if (sql.includes("INSERT INTO jarvis_owner")) {
          state.owner = { id: 1, created_at: values[0], enrollment_closed_at: values[1] };
        } else if (sql.includes("INSERT INTO owner_credentials")) {
          if (sql.includes("SELECT ?")) {
            const [id, publicKey, counter, transportsJson, deviceType, backedUp, createdAt, recoveryHash, challengeHash] = values;
            const claim = state.recoveryCodes.find((row) => row.code_hash === recoveryHash && row.used_claim_hash === challengeHash);
            if (!claim) return { success: true, meta: { changes: 0 } };
            state.credentials.push({
              credential_id: id, owner_id: 1, public_key: publicKey, sign_count: counter,
              transports_json: transportsJson, device_type: deviceType, backed_up: backedUp,
              created_at: createdAt, last_used_at: null, revoked_at: null
            });
            return { success: true, meta: { changes: 1 } };
          }
          const [id, publicKey, counter, transportsJson, deviceType, backedUp, createdAt] = values;
          state.credentials.push({
            credential_id: id, owner_id: 1, public_key: publicKey, sign_count: counter,
            transports_json: transportsJson, device_type: deviceType, backed_up: backedUp,
            created_at: createdAt, last_used_at: null, revoked_at: null
          });
        } else if (sql.includes("UPDATE owner_credentials SET revoked_at")) {
          const [now, recoveryHash, claimHash] = values;
          const claim = state.recoveryCodes.some((row) => row.code_hash === recoveryHash && row.used_claim_hash === claimHash);
          if (!claim) return { success: true, meta: { changes: 0 } };
          const active = state.credentials.filter((row) => row.revoked_at === null);
          for (const row of active) row.revoked_at = now;
          return { success: true, meta: { changes: active.length } };
        } else if (sql.includes("INSERT INTO owner_recovery_codes")) {
          if (sql.includes("SELECT ?, ?")) {
            const [hash, createdAt, recoveryHash, challengeHash] = values;
            const claim = state.recoveryCodes.find((row) => row.code_hash === recoveryHash && row.used_claim_hash === challengeHash);
            if (!claim) return { success: true, meta: { changes: 0 } };
            state.recoveryCodes.push({ code_hash: hash, created_at: createdAt, used_at: null, used_claim_hash: null });
            return { success: true, meta: { changes: 1 } };
          }
          const [hash, createdAt] = values;
          state.recoveryCodes.push({ code_hash: hash, created_at: createdAt, used_at: null, used_claim_hash: null });
        } else if (sql.includes("UPDATE owner_recovery_codes SET used_at")) {
          const [now, challengeHash, recoveryHash] = values;
          const item = state.recoveryCodes.find((row) => row.code_hash === recoveryHash && row.used_at === null);
          if (item) { item.used_at = now; item.used_claim_hash = challengeHash; }
          return { success: true, meta: { changes: item ? 1 : 0 } };
        } else if (sql.includes("DELETE FROM owner_recovery_codes")) {
          const [recoveryHash, challengeHash] = values;
          const claim = state.recoveryCodes.some((row) => row.code_hash === recoveryHash && row.used_claim_hash === challengeHash);
          if (!claim) return { success: true, meta: { changes: 0 } };
          const before = state.recoveryCodes.length;
          state.recoveryCodes = state.recoveryCodes.filter((row) => row.used_at !== null);
          return { success: true, meta: { changes: before - state.recoveryCodes.length } };
        } else if (sql.includes("INSERT INTO auth_sessions")) {
          const [sessionHash, csrfHash, createdAt, expiresAt] = values;
          state.sessions.push({ session_hash: sessionHash, csrf_token_hash: csrfHash, created_at: createdAt, expires_at: expiresAt, last_seen_at: null, revoked_at: null });
        } else if (sql.includes("UPDATE owner_credentials SET sign_count")) {
          const [newCounter, now, id, oldCounter] = values;
          const item = state.credentials.find((row) => row.credential_id === id && row.sign_count === oldCounter && row.revoked_at === null);
          if (item) { item.sign_count = newCounter; item.last_used_at = now; }
          return { success: true, meta: { changes: item ? 1 : 0 } };
        } else if (sql.includes("UPDATE auth_sessions SET last_seen_at")) {
          const [now, hash] = values;
          const item = state.sessions.find((row) => row.session_hash === hash && row.revoked_at === null);
          if (item) item.last_seen_at = now;
          return { success: true, meta: { changes: item ? 1 : 0 } };
        } else if (sql.includes("UPDATE auth_sessions SET revoked_at")) {
          const [now, hash, challengeHash] = values;
          if (sql.includes("WHERE session_hash = ?")) {
            const item = state.sessions.find((row) => row.session_hash === hash && row.revoked_at === null);
            if (item) item.revoked_at = now;
            return { success: true, meta: { changes: item ? 1 : 0 } };
          }
          if (sql.includes("EXISTS (SELECT 1 FROM owner_recovery_codes")) {
            const claim = state.recoveryCodes.some((row) => row.code_hash === hash && row.used_claim_hash === challengeHash);
            if (!claim) return { success: true, meta: { changes: 0 } };
          }
          const active = state.sessions.filter((row) => row.revoked_at === null);
          for (const item of active) item.revoked_at = now;
          return { success: true, meta: { changes: active.length } };
        }
        return { success: true, meta: { changes: 1 } };
      }
    };
  }
  return {
    state,
    db: {
      prepare(sql) { return statement(sql); },
      async batch(statements) {
        const results = [];
        for (const item of statements) results.push(await item.run());
        return results;
      }
    }
  };
}
describe("JARVIS Worker runtime contract", () => {
  it("serves the honest health-only scaffold with hardened headers", async () => {
    const response = await worker.fetch(request());

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expectHardenedHeaders(response);
    await expect(response.json()).resolves.toEqual({
      service: "jarvis-api",
      status: "ok",
      mode: "authentication-scaffold",
      aiConnected: false
    });
  });

  it("applies a strict same-origin CSP and security headers to static owner assets", async () => {
    const response = await worker.fetch(request("/", {
      headers: { Accept: "text/html" }
    }), {
      ASSETS: {
        async fetch() {
          return new Response("<!doctype html><title>JARVIS</title>", {
            headers: { "Content-Type": "text/html; charset=utf-8" }
          });
        }
      }
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(response.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000");
    await expect(response.text()).resolves.toContain("<title>J.A.R.V.I.S.");
  });

  it("accepts a query string on the exact health route", async () => {
    const response = await worker.fetch(request("/health?check=1"));

    expect(response.status).toBe(200);
    expectHardenedHeaders(response);
    await expect(response.json()).resolves.toMatchObject({
      aiConnected: false
    });
  });

  it("rejects unknown paths with a generic JSON 404", async () => {
    const response = await worker.fetch(request("/private"));

    expect(response.status).toBe(404);
    expectHardenedHeaders(response);
    await expect(response.json()).resolves.toEqual({
      error: "not_found",
      message: "This endpoint is not implemented."
    });
  });

  it("rejects near-match health paths", async () => {
    for (const path of ["/health/", "/health/extra", "/Health"]) {
      const response = await worker.fetch(request(path));
      expect(response.status, path).toBe(404);
      expectHardenedHeaders(response);
    }
  });

  it("rejects every non-GET method on the health route", async () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]) {
      const response = await worker.fetch(request("/health", { method }));
      expect(response.status, method).toBe(404);
      expectHardenedHeaders(response);
    }
  });

  it("does not emit HSTS for plain HTTP requests", async () => {
    const response = await worker.fetch(request("/health", {}, "http:"));

    expect(response.status).toBe(200);
    expectHardenedHeaders(response, { https: false });
  });
  it("fails closed on every authentication route until D1 and origin configuration exist", async () => {
    const routes = [
      ["/auth/register/options", "POST"],
      ["/auth/register/verify", "POST"],
      ["/auth/login/options", "POST"],
      ["/auth/login/verify", "POST"],
      ["/auth/me", "GET"],
      ["/auth/logout", "POST"]
    ];
    for (const [path, method] of routes) {
      const response = await worker.fetch(request(path, { method }), {});
      expect(response.status, path).toBe(503);
      expectHardenedHeaders(response);
      await expect(response.json()).resolves.toEqual({
        error: "authentication_not_configured"
      });
      expect(response.headers.get("set-cookie")).toBeNull();
    }
  });

  it("rejects cross-origin bootstrap requests before touching storage", async () => {
    const env = {
      DB: { prepare() { throw new Error("storage must not be touched"); } },
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      JARVIS_BOOTSTRAP_SECRET: "a".repeat(48)
    };
    const response = await handleAuthRequest(request("/auth/register/options", {
      method: "POST",
      headers: {
        Origin: "https://attacker.example",
        "X-Jarvis-Bootstrap": "a".repeat(48)
      }
    }), env);
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "origin_not_allowed" });
  });

  it("rejects an invalid relying-party/origin configuration", async () => {
    const env = {
      DB: { prepare() { throw new Error("storage must not be touched"); } },
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "attacker.example"
    };
    const response = await handleAuthRequest(request("/auth/login/options", {
      method: "POST",
      headers: { Origin: "https://example.test" }
    }), env);
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "authentication_not_configured"
    });
  });

  it("requires a valid JSON content type for authentication payloads", async () => {
    const env = {
      DB: { prepare() { throw new Error("invalid bodies must not touch storage"); } },
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
    };
    const response = await handleAuthRequest(request("/auth/login/verify", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        "Content-Type": "text/plain"
      },
      body: "{}"
    }), env);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_request" });
  });

  it("cancels oversized authentication JSON streams without buffering the full body", async () => {
    let cancelled = false;
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(16 * 1024 + 1));
      },
      cancel() {
        cancelled = true;
      }
    });
    const incoming = new Request("https://example.test/auth/register/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      duplex: "half"
    });

    await expect(readJson(incoming)).resolves.toBeNull();
    expect(cancelled).toBe(true);
  });

  it("rejects a missing bootstrap secret before touching storage", async () => {
    const env = {
      DB: { prepare() { throw new Error("unauthorized bootstrap must not touch storage"); } },
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      JARVIS_BOOTSTRAP_SECRET: "b".repeat(48)
    };
    const response = await handleAuthRequest(request("/auth/register/options", {
      method: "POST",
      headers: { Origin: "https://example.test" }
    }), env);
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "bootstrap_not_authorized" });
  });

  it("issues one-time registration options only with the bootstrap secret", async () => {
    const issued = [];
    const db = {
      prepare(sql) {
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) {
          return { async first() { return null; } };
        }
        return {
          bind(...values) {
            return {
              async run() {
                issued.push({ sql, values });
                return { success: true, meta: { changes: 1 } };
              }
            };
          }
        };
      }
    };
    const secret = "c".repeat(48);
    const env = {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      JARVIS_BOOTSTRAP_SECRET: secret,
    };
    const response = await handleAuthRequest(request("/auth/register/options", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        "X-Jarvis-Bootstrap": secret
      }
    }), env);
    expect(response.status).toBe(200);
    const options = await response.json();
    expect(options.rp.id).toBe("example.test");
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(options.authenticatorSelection.residentKey).toBe("required");
    expect(options.authenticatorSelection.userVerification).toBe("required");
    expect(issued).toHaveLength(1);
    expect(issued[0].values[1]).toBe(options.challenge);
    expect(issued[0].values[2]).toBe("registration");
  });

  it("issues login options only for the enrolled owner's active credentials", async () => {
    const issued = [];
    const db = {
      prepare(sql) {
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) {
          return { async first() { return { id: 1, created_at: 1000, enrollment_closed_at: 1000 }; } };
        }
        if (sql.includes("SELECT credential_id, public_key, sign_count")) {
          return {
            async all() {
              return {
                results: [{
                  credential_id: "owner-passkey",
                  public_key: new Uint8Array([1, 2, 3]),
                  sign_count: 0,
                  transports_json: '["internal"]',
                  device_type: "singleDevice",
                  backed_up: 1,
                  created_at: 1000,
                  last_used_at: null
                }]
              };
            }
          };
        }
        return {
          bind(...values) {
            return {
              async run() {
                issued.push({ sql, values });
                return { success: true, meta: { changes: 1 } };
              }
            };
          }
        };
      }
    };
    const response = await handleAuthRequest(request("/auth/login/options", {
      method: "POST",
      headers: { Origin: "https://example.test" }
    }), {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
    });
    expect(response.status).toBe(200);
    const options = await response.json();
    expect(options.rpId).toBe("example.test");
    expect(options.userVerification).toBe("required");
    expect(options.allowCredentials).toEqual([
      { id: "owner-passkey", transports: ["internal"], type: "public-key" }
    ]);
    expect(issued).toHaveLength(1);
    expect(issued[0].values[1]).toBe(options.challenge);
    expect(issued[0].values[2]).toBe("authentication");
  });

  it("requires an authenticated CSRF-protected owner session to add another passkey", async () => {
    const encode = (bytes) => {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };
    const hash = async (value) => encode(new Uint8Array(await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(value)
    )));
    const sessionToken = "s".repeat(48);
    const csrfToken = "c".repeat(48);
    const sessionHash = await hash(sessionToken);
    const csrfHash = await hash(csrfToken);
    const challenges = [];
    const db = {
      prepare(sql) {
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT created_at, expires_at, last_seen_at")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { created_at: Math.floor(Date.now() / 1000), expires_at: 9999999999 } : null;
          } }; } };
        }
        if (sql.includes("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.startsWith("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.includes("SELECT csrf_token_hash")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { csrf_token_hash: csrfHash } : null;
          } }; } };
        }
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) {
          return { async first() { return { id: 1, created_at: 1000, enrollment_closed_at: 1000 }; } };
        }
        if (sql.includes("SELECT credential_id, public_key, sign_count")) {
          return { async all() { return { results: [{
            credential_id: "existing-passkey",
            public_key: new Uint8Array([1, 2, 3]),
            sign_count: 0,
            transports_json: '["internal"]',
            device_type: "singleDevice",
            backed_up: 0,
            created_at: 1000,
            last_used_at: null
          }] }; } };
        }
        return { bind(...values) { return { async run() {
          challenges.push(values);
          return { success: true, meta: { changes: 1 } };
        } }; } };
      }
    };
    const response = await handleAuthRequest(request("/auth/credentials/options", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: `__Host-jarvis_session=${sessionToken}`,
        "X-CSRF-Token": csrfToken
      }
    }), {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(response.status).toBe(200);
    const options = await response.json();
    expect(options.excludeCredentials).toContainEqual({
      id: "existing-passkey",
      transports: ["internal"],
      type: "public-key"
    });
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(challenges.some((values) => values[2] === "credential_add")).toBe(true);
  });

  it("refuses to revoke the owner's final active passkey", async () => {
    const encode = (bytes) => {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };
    const hash = async (value) => encode(new Uint8Array(await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(value)
    )));
    const sessionToken = "s".repeat(48);
    const csrfToken = "c".repeat(48);
    const sessionHash = await hash(sessionToken);
    const csrfHash = await hash(csrfToken);
    let revoked = false;
    const db = {
      prepare(sql) {
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT created_at, expires_at, last_seen_at")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { created_at: Math.floor(Date.now() / 1000), expires_at: 9999999999 } : null;
          } }; } };
        }
        if (sql.includes("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.startsWith("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.includes("SELECT csrf_token_hash")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { csrf_token_hash: csrfHash } : null;
          } }; } };
        }
        if (sql.includes("SELECT credential_id, public_key, sign_count")) {
          return { async all() { return { results: [{
            credential_id: "only-passkey",
            public_key: new Uint8Array([1, 2, 3]),
            sign_count: 0,
            transports_json: "[]",
            device_type: "singleDevice",
            backed_up: 0,
            created_at: 1000,
            last_used_at: null
          }] }; } };
        }
        if (sql.includes("UPDATE owner_credentials SET revoked_at")) revoked = true;
        return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
      }
    };
    const response = await handleAuthRequest(request("/auth/credentials/revoke", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: `__Host-jarvis_session=${sessionToken}`,
        "X-CSRF-Token": csrfToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ credentialId: "only-passkey" })
    }), {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({ error: "cannot_revoke_last_credential" });
    expect(revoked).toBe(false);
  });

  it("serves the owner page, browser client, and stylesheet from Workers Static Assets", async () => {
    for (const [path, expected] of [
      ["/", "J.A.R.V.I.S."],
      ["/index.html", "J.A.R.V.I.S."],
      ["/app.js", "navigator.credentials.create"],
      ["/style.css", "color-scheme: dark"]
    ]) {
      const response = await worker.fetch(request(path));
      expect(response.status, path).toBe(200);
      await expect(response.text()).resolves.toContain(expected);
      expect(response.headers.get("cache-control")).toBe("no-store");
    }
  });


  it("completes a synthetic owner registration, login, session check, and logout", async () => {
    const { db, state } = makeRouteD1();
    const secret = "r".repeat(64);
    const env = {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      JARVIS_BOOTSTRAP_SECRET: secret
    };
    const bootstrapHeaders = { Origin: "https://example.test", "X-Jarvis-Bootstrap": secret };
    const optionsResponse = await handleAuthRequest(request("/auth/register/options", {
      method: "POST", headers: bootstrapHeaders
    }), env);
    expect(optionsResponse.status).toBe(200);
    const registrationOptions = await optionsResponse.json();
    const fixture = await makeRouteRegistration(registrationOptions.challenge);
    const registrationResponse = await handleAuthRequest(request("/auth/register/verify", {
      method: "POST",
      headers: { ...bootstrapHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: registrationOptions.challenge, response: fixture.response })
    }), env);
    expect(registrationResponse.status).toBe(200);
    const registered = await registrationResponse.json();
    expect(registered.authenticated).toBe(true);
    expect(state.owner.id).toBe(1);
    expect(state.credentials).toHaveLength(1);
    const registrationCookies = registrationResponse.headers.get("set-cookie");
    expect(registrationCookies).toContain("__Host-jarvis_session=");
    expect(registrationCookies).toContain("HttpOnly");
    expect(registrationCookies).toContain("Secure");
    expect(registrationCookies).toContain("SameSite=Strict");
    expect(registrationCookies).toContain("__Host-jarvis_csrf=");
    expect(registrationCookies).not.toContain("Domain=");
    const registrationSessionCookie = registrationCookies.match(/__Host-jarvis_session=([^;,]+)/)?.[1];
    expect(registrationSessionCookie).toBeTruthy();

    const closed = await handleAuthRequest(request("/auth/register/options", {
      method: "POST", headers: bootstrapHeaders
    }), env);
    expect(closed.status).toBe(409);

    const loginOptionsResponse = await handleAuthRequest(request("/auth/login/options", {
      method: "POST", headers: { Origin: "https://example.test" }
    }), env);
    expect(loginOptionsResponse.status).toBe(200);
    const loginOptions = await loginOptionsResponse.json();
    const assertion = await makeRouteAssertion({
      keyPair: fixture.keyPair,
      credentialId: fixture.credentialId,
      challenge: loginOptions.challenge,
      counter: 1
    });
    const loginResponse = await handleAuthRequest(request("/auth/login/verify", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        "Content-Type": "application/json",
        Cookie: "__Host-jarvis_session=" + registrationSessionCookie
      },
      body: JSON.stringify({ challenge: loginOptions.challenge, response: assertion })
    }), env);
    expect(loginResponse.status).toBe(200);
    const loggedIn = await loginResponse.json();
    expect(loggedIn.authenticated).toBe(true);
    expect(state.credentials[0].sign_count).toBe(1);
    const oldSessionAfterRotation = await handleAuthRequest(request("/auth/me", {
      method: "GET",
      headers: { Cookie: "__Host-jarvis_session=" + registrationSessionCookie }
    }), env);
    expect(oldSessionAfterRotation.status).toBe(401);

    const replay = await handleAuthRequest(request("/auth/login/verify", {
      method: "POST",
      headers: { Origin: "https://example.test", "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: loginOptions.challenge, response: assertion })
    }), env);
    expect(replay.status).toBe(400);
    await expect(replay.json()).resolves.toEqual({ error: "challenge_invalid_or_expired" });

    const wrongOriginOptionsResponse = await handleAuthRequest(request("/auth/login/options", {
      method: "POST", headers: { Origin: "https://example.test" }
    }), env);
    const wrongOriginOptions = await wrongOriginOptionsResponse.json();
    const wrongOriginAssertion = await makeRouteAssertion({
      keyPair: fixture.keyPair,
      credentialId: fixture.credentialId,
      challenge: wrongOriginOptions.challenge,
      counter: 2,
      origin: "https://attacker.example"
    });
    const wrongOriginResult = await handleAuthRequest(request("/auth/login/verify", {
      method: "POST",
      headers: { Origin: "https://example.test", "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: wrongOriginOptions.challenge, response: wrongOriginAssertion })
    }), env);
    expect(wrongOriginResult.status).toBe(401);
    expect(state.credentials[0].sign_count).toBe(1);

    const tamperOptionsResponse = await handleAuthRequest(request("/auth/login/options", {
      method: "POST", headers: { Origin: "https://example.test" }
    }), env);
    const tamperOptions = await tamperOptionsResponse.json();
    const tamperedAssertion = await makeRouteAssertion({
      keyPair: fixture.keyPair,
      credentialId: fixture.credentialId,
      challenge: tamperOptions.challenge,
      counter: 2
    });
    const originalSignature = tamperedAssertion.response.signature;
    tamperedAssertion.response.signature = (originalSignature[0] === "A" ? "B" : "A") + originalSignature.slice(1);
    const tamperedResult = await handleAuthRequest(request("/auth/login/verify", {
      method: "POST",
      headers: { Origin: "https://example.test", "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: tamperOptions.challenge, response: tamperedAssertion })
    }), env);
    expect(tamperedResult.status).toBe(401);
    expect(state.credentials[0].sign_count).toBe(1);

    const cookies = loginResponse.headers.get("set-cookie");
    const sessionCookie = cookies.match(/__Host-jarvis_session=([^;,]+)/)?.[1];
    expect(sessionCookie).toBeTruthy();
    const me = await handleAuthRequest(request("/auth/me", {
      method: "GET",
      headers: { Cookie: "__Host-jarvis_session=" + sessionCookie }
    }), env);
    expect(me.status).toBe(200);
    await expect(me.json()).resolves.toMatchObject({ authenticated: true });

    const badCsrfLogout = await handleAuthRequest(request("/auth/logout", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + sessionCookie,
        "X-CSRF-Token": "x".repeat(48),
        "Content-Type": "application/json"
      },
      body: "{}"
    }), env);
    expect(badCsrfLogout.status).toBe(403);

    const logoutResponse = await handleAuthRequest(request("/auth/logout", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + sessionCookie,
        "X-CSRF-Token": loggedIn.csrfToken,
        "Content-Type": "application/json"
      },
      body: "{}"
    }), env);
    expect(logoutResponse.status).toBe(200);
    const afterLogout = await handleAuthRequest(request("/auth/me", {
      method: "GET",
      headers: { Cookie: "__Host-jarvis_session=" + sessionCookie }
    }), env);
    expect(afterLogout.status).toBe(401);

    const otherDeviceSession = await createSession(db, { now: Math.floor(Date.now() / 1000) });
    const logoutAllResponse = await handleAuthRequest(request("/auth/logout-all", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + otherDeviceSession.sessionToken,
        "X-CSRF-Token": otherDeviceSession.csrfToken,
        "Content-Type": "application/json"
      },
      body: "{}"
    }), env);
    expect(logoutAllResponse.status).toBe(200);
    await expect(logoutAllResponse.json()).resolves.toMatchObject({ authenticated: false, revokedCount: 1 });
    const afterLogoutAll = await handleAuthRequest(request("/auth/me", {
      method: "GET",
      headers: { Cookie: "__Host-jarvis_session=" + otherDeviceSession.sessionToken }
    }), env);
    expect(afterLogoutAll.status).toBe(401);
  });

  it("does not disclose whether an owner has completed enrollment", async () => {
    const db = {
      prepare(sql) {
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) {
          return { async first() { return null; } };
        }
        throw new Error("no further query should be made without an owner");
      }
    };
    const response = await handleAuthRequest(request("/auth/login/options", {
      method: "POST",
      headers: { Origin: "https://example.test" }
    }), {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "authentication_failed" });
  });


  it("does not reveal whether an owner has been enrolled through login options", async () => {
    const makeDb = (owner) => ({
      prepare(sql) {
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) {
          return { async first() { return owner; } };
        }
        if (sql.includes("SELECT credential_id, public_key, sign_count")) {
          return { async all() { return { results: [] }; } };
        }
        throw new Error("Unexpected database query");
      }
    });
    const noOwner = await handleAuthRequest(request("/auth/login/options", {
      method: "POST", headers: { Origin: "https://example.test" }
    }), {
      DB: withRateLimitSupport(makeDb(null)), AUTH_ORIGIN: "https://example.test", WEBAUTHN_RP_ID: "example.test", JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    const ownerWithoutActiveCredentials = await handleAuthRequest(request("/auth/login/options", {
      method: "POST", headers: { Origin: "https://example.test" }
    }), {
      DB: withRateLimitSupport(makeDb({ id: 1, created_at: 1, enrollment_closed_at: 1 })),
      AUTH_ORIGIN: "https://example.test", WEBAUTHN_RP_ID: "example.test", JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(noOwner.status).toBe(401);
    expect(ownerWithoutActiveCredentials.status).toBe(401);
    const first = await noOwner.json();
    const second = await ownerWithoutActiveCredentials.json();
    expect(first).toEqual({ error: "authentication_failed" });
    expect(second).toEqual(first);
  });


  it("requires a recent passkey login before credential management", async () => {
    const encode = (bytes) => {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };
    const hash = async (value) => encode(new Uint8Array(await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(value)
    )));
    const sessionToken = "s".repeat(48);
    const csrfToken = "c".repeat(48);
    const sessionHash = await hash(sessionToken);
    const csrfHash = await hash(csrfToken);
    let challengeIssued = false;
    const db = {
      prepare(sql) {
        if (sql.includes("SELECT created_at, expires_at, last_seen_at")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash
              ? { created_at: Math.floor(Date.now() / 1000) - 600, expires_at: 9999999999 }
              : null;
          } }; } };
        }
        if (sql.includes("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.startsWith("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.includes("SELECT csrf_token_hash")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { csrf_token_hash: csrfHash } : null;
          } }; } };
        }
        if (sql.startsWith("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.startsWith("DELETE FROM auth_challenges")) challengeIssued = true;
        throw new Error("stale sessions must be rejected before credential storage is touched");
      }
    };
    const response = await handleAuthRequest(request("/auth/credentials/options", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: `__Host-jarvis_session=${sessionToken}`,
        "X-CSRF-Token": csrfToken
      }
    }), {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "reauthentication_required" });
    expect(challengeIssued).toBe(false);
  });


  it("recovers owner access with one recovery code and rotates every recovery code", async () => {
    const { db, state } = makeRouteD1();
    const env = {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      JARVIS_BOOTSTRAP_SECRET: "r".repeat(64),
    };
    const origin = "https://example.test";
    const registrationOptionsResponse = await handleAuthRequest(request("/auth/register/options", {
      method: "POST",
      headers: { Origin: origin, "X-Jarvis-Bootstrap": env.JARVIS_BOOTSTRAP_SECRET }
    }), env);
    const registrationOptions = await registrationOptionsResponse.json();
    const firstCredential = await makeRouteRegistration(registrationOptions.challenge);
    const registrationVerify = await handleAuthRequest(request("/auth/register/verify", {
      method: "POST",
      headers: {
        Origin: origin,
        "X-Jarvis-Bootstrap": env.JARVIS_BOOTSTRAP_SECRET,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ challenge: registrationOptions.challenge, response: firstCredential.response })
    }), env);
    expect(registrationVerify.status).toBe(200);
    const registered = await registrationVerify.json();
    expect(registered.recoveryCodes).toHaveLength(10);
    const originalSessionCookie = registrationVerify.headers.get("set-cookie").match(/__Host-jarvis_session=([^;,]+)/)?.[1];
    const recoveryCode = registered.recoveryCodes[0];

    const recoveryOptionsResponse = await handleAuthRequest(request("/auth/recovery/options", {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ recoveryCode })
    }), env);
    expect(recoveryOptionsResponse.status).toBe(200);
    const recoveryOptions = await recoveryOptionsResponse.json();
    const replacementCredential = await makeRouteRegistration(
      recoveryOptions.challenge,
      new Uint8Array([0x52,0x45,0x43,0x4f,0x56,0x45,0x52,0x59,0x2d,0x4e,0x45,0x57,0x2d,0x50,0x4b])
    );
    const recoveryVerify = await handleAuthRequest(request("/auth/recovery/verify", {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: recoveryOptions.challenge, response: replacementCredential.response })
    }), env);
    expect(recoveryVerify.status).toBe(200);
    const recovered = await recoveryVerify.json();
    expect(recovered.authenticated).toBe(true);
    expect(recovered.recoveryCodes).toHaveLength(10);
    expect(state.credentials).toHaveLength(2);
    expect(state.credentials[0].revoked_at).toBeTruthy();
    expect(state.credentials[1].revoked_at).toBeNull();
    expect(state.recoveryCodes.filter((row) => row.used_at === null)).toHaveLength(10);
    expect(await (async () => {
      const code = registered.recoveryCodes[1];
      const hashBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code)));
      let binary = "";
      for (const byte of hashBytes) binary += String.fromCharCode(byte);
      const hash = btoa(binary).split("+").join("-").split("/").join("_").split("=").join("");
      return state.recoveryCodes.some((row) => row.code_hash === hash && row.used_at === null);
    })()).toBe(false);

    const oldSession = await handleAuthRequest(request("/auth/me", {
      method: "GET",
      headers: { Cookie: "__Host-jarvis_session=" + originalSessionCookie }
    }), env);
    expect(oldSession.status).toBe(401);

    const replayOldCode = await handleAuthRequest(request("/auth/recovery/options", {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ recoveryCode })
    }), env);
    expect(replayOldCode.status).toBe(401);
    await expect(replayOldCode.json()).resolves.toEqual({ error: "recovery_failed" });

    const nextRecoveryOptions = await handleAuthRequest(request("/auth/recovery/options", {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ recoveryCode: recovered.recoveryCodes[0] })
    }), env);
    expect(nextRecoveryOptions.status).toBe(200);
  });

});


describe("authentication rate limits", () => {
  it("blocks repeated first-owner enrollment requests in the same IP window", async () => {
    const { db } = makeRouteD1();
    const env = {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      JARVIS_BOOTSTRAP_SECRET: "synthetic-bootstrap-secret-0123456789"
    };
    let last;
    for (let attempt = 0; attempt < 7; attempt += 1) {
      last = await handleAuthRequest(request("/auth/register/options", {
        method: "POST",
        headers: {
          Origin: "https://example.test",
          "X-Jarvis-Bootstrap": env.JARVIS_BOOTSTRAP_SECRET
        }
      }), env);
      if (attempt < 6) expect(last.status).toBe(200);
    }
    expect(last.status).toBe(429);
    expect(last.headers.get("retry-after")).toMatch(/^[0-9]+$/);
    await expect(last.json()).resolves.toEqual(expect.objectContaining({
      error: "rate_limit_exceeded"
    }));
  });
});


describe("authenticated session rate limits", () => {
  it("limits authenticated credential-list requests per opaque session bucket", async () => {
    const { db, state } = makeRouteD1();
    const session = await createSession(db, { now: Math.floor(Date.now() / 1000) });
    const env = {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    };
    let last;
    for (let attempt = 0; attempt < 61; attempt += 1) {
      last = await handleAuthRequest(request("/auth/credentials", {
        method: "GET",
        headers: { Cookie: "__Host-jarvis_session=" + session.sessionToken }
      }), env);
      if (attempt < 60) expect(last.status).toBe(200);
    }
    expect(last.status).toBe(429);
    expect(state.rateLimits).toHaveLength(1);
    expect(state.rateLimits[0].requestCount).toBe(61);
    expect(last.headers.get("retry-after")).toMatch(/^[0-9]+$/);
    await expect(last.json()).resolves.toEqual(expect.objectContaining({
      error: "rate_limit_exceeded"
    }));
  });

  it("applies session throttling to same-origin GET requests without an Origin header", async () => {
    const { db, state } = makeRouteD1();
    const session = await createSession(db, { now: Math.floor(Date.now() / 1000) });
    const env = {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    };
    let last;
    for (let attempt = 0; attempt < 61; attempt += 1) {
      last = await handleAuthRequest(request("/auth/me", {
        method: "GET",
        headers: { Cookie: "__Host-jarvis_session=" + session.sessionToken }
      }), env);
      if (attempt < 60) expect(last.status).toBe(200);
    }
    expect(last.status).toBe(429);
    expect(state.rateLimits).toHaveLength(1);
    expect(state.rateLimits[0].requestCount).toBe(61);
  });


  it("rejects unexpected fields in authentication request bodies", async () => {
    const db = {
      prepare() { throw new Error("Unexpected fields must be rejected before any recovery-code lookup"); }
    };
    const response = await handleAuthRequest(request("/auth/recovery/options", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ recoveryCode: "r".repeat(48), unexpected: "must-not-be-accepted" })
    }), {
      DB: withRateLimitSupport(db),
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_request" });
  });

});


describe("owner-only stateless AI chat", () => {
  it("calls only the Free-plan model after a valid owner session and CSRF check", async () => {
    const { db } = makeRouteD1();
    const now = Math.floor(Date.now() / 1000);
    const session = await createSession(db, { now });
    const calls = [];
    const response = await handleAuthRequest(request("/auth/chat", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + session.sessionToken,
        "X-CSRF-Token": session.csrfToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: "Salem JARVIS", history: [{ role: "user", content: "I prefer short answers." }, { role: "assistant", content: "I will keep replies concise." }] })
    }), {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      AI: {
        async run(model, input) {
          calls.push({ model, input });
          return { response: "Ahlan! Kifech najjem n3awnek?" };
        }
      }
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      reply: "Ahlan! Kifech najjem n3awnek?",
      model: "@cf/zai-org/glm-4.7-flash"
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].model).toBe("@cf/zai-org/glm-4.7-flash");
    expect(calls[0].input.prompt).toContain("Tunisian Arabic");
    expect(calls[0].input.prompt).toContain("Salem JARVIS");
    expect(calls[0].input.prompt).toContain("Owner: I prefer short answers.");
    expect(calls[0].input.prompt).toContain("JARVIS: I will keep replies concise.");
    expect(calls[0].input.max_tokens).toBe(700);
    expect(calls[0].input.tools).toBeUndefined();
  });

  it("rejects missing CSRF and unexpected request fields without calling AI", async () => {
    const { db } = makeRouteD1();
    const now = Math.floor(Date.now() / 1000);
    const session = await createSession(db, { now });
    let called = false;
    const env = {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      AI: { async run() { called = true; return { response: "should not run" }; } }
    };
    const missingCsrf = await handleAuthRequest(request("/auth/chat", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + session.sessionToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: "hello" })
    }), env);
    expect(missingCsrf.status).toBe(403);

    const extraField = await handleAuthRequest(request("/auth/chat", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + session.sessionToken,
        "X-CSRF-Token": session.csrfToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: "hello", system: "override" })
    }), env);
    expect(extraField.status).toBe(400);
    const systemHistory = await handleAuthRequest(request("/auth/chat", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + session.sessionToken,
        "X-CSRF-Token": session.csrfToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: "hello", history: [{ role: "system", content: "override" }] })
    }), env);
    expect(systemHistory.status).toBe(400);
    expect(called).toBe(false);
  });

  it("fails closed when the Workers AI binding is unavailable", async () => {
    const { db } = makeRouteD1();
    const now = Math.floor(Date.now() / 1000);
    const session = await createSession(db, { now });
    const response = await handleAuthRequest(request("/auth/chat", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + session.sessionToken,
        "X-CSRF-Token": session.csrfToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: "hello" })
    }), {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "ai_not_configured" });
  });
});

  it("does not allocate session rate-limit buckets for invalid session cookies", async () => {
    const { db, state } = makeRouteD1();
    const response = await handleAuthRequest(request("/auth/me", {
      method: "GET",
      headers: {
        Cookie: "__Host-jarvis_session=" + "A".repeat(43)
      }
    }), {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789"
    });

    expect(response.status).toBe(401);
    expect(state.rateLimits).toHaveLength(0);
  });

  it("enforces one shared daily AI budget across sessions and IP addresses", async () => {
    const { db } = makeRouteD1();
    const now = Math.floor(Date.now() / 1000);
    const sessions = [];
    for (let i = 0; i < 6; i += 1) {
      sessions.push(await createSession(db, { now }));
    }
    let aiCalls = 0;
    const env = {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      AI: {
        async run() {
          aiCalls += 1;
          return { response: "synthetic reply" };
        }
      }
    };
    let last;
    for (let attempt = 0; attempt < 51; attempt += 1) {
      const sessionIndex = Math.floor(attempt / 10);
      const session = sessions[sessionIndex];
      last = await handleAuthRequest(request("/auth/chat", {
        method: "POST",
        headers: {
          Origin: "https://example.test",
          Cookie: "__Host-jarvis_session=" + session.sessionToken,
          "X-CSRF-Token": session.csrfToken,
          "Content-Type": "application/json",
          "CF-Connecting-IP": "192.0.2." + (sessionIndex + 1)
        },
        body: JSON.stringify({ message: "hello" })
      }), env);
      if (attempt < 50) expect(last.status).toBe(200);
    }
    expect(last.status).toBe(429);
    expect(aiCalls).toBe(50);
    expect(last.headers.get("retry-after")).toMatch(/^[0-9]+$/);
    await expect(last.json()).resolves.toEqual(expect.objectContaining({
      error: "daily_ai_limit_reached"
    }));
  });

  it("bounds chat input and hides upstream inference errors", async () => {
    const { db } = makeRouteD1();
    const now = Math.floor(Date.now() / 1000);
    const session = await createSession(db, { now });
    let calls = 0;
    const env = {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_RATE_LIMIT_HMAC_SECRET: "synthetic-test-rate-limit-secret-0123456789",
      AI: {
        async run() {
          calls += 1;
          throw new Error("sensitive upstream provider diagnostic");
        }
      }
    };
    const headers = {
      Origin: "https://example.test",
      Cookie: "__Host-jarvis_session=" + session.sessionToken,
      "X-CSRF-Token": session.csrfToken,
      "Content-Type": "application/json"
    };
    const failedInference = await handleAuthRequest(request("/auth/chat", {
      method: "POST", headers, body: JSON.stringify({ message: "hello" })
    }), env);
    expect(failedInference.status).toBe(503);
    await expect(failedInference.json()).resolves.toEqual({ error: "ai_temporarily_unavailable" });
    const oversizedMessage = await handleAuthRequest(request("/auth/chat", {
      method: "POST", headers, body: JSON.stringify({ message: "x".repeat(6001) })
    }), env);
    expect(oversizedMessage.status).toBe(400);
    await expect(oversizedMessage.json()).resolves.toEqual({ error: "invalid_request" });
    expect(calls).toBe(1);
  });
