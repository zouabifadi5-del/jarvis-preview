import { describe, expect, it } from "vitest";
import { exports } from "cloudflare:workers";
import { handleAuthRequest } from "../src/auth/routes.js";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { createSession } from "../src/auth/d1-store.js";

const worker = exports.default;

function request(path = "/health", options = {}, protocol = "https:") {
  return new Request(`${protocol}//example.test${path}`, options);
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
async function makeRouteRegistration(challenge) {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const x = fromB64Url(jwk.x);
  const y = fromB64Url(jwk.y);
  const publicKey = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
  const credentialId = new Uint8Array([0x4a,0x41,0x52,0x56,0x49,0x53,0x2d,0x52,0x4f,0x55,0x54,0x45,0x2d,0x54,0x45,0x53]);
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
  const state = { owner: null, credentials: [], challenges: [], sessions: [] };
  function statement(sql, values = []) {
    return {
      bind(...bound) { return statement(sql, bound); },
      async first() {
        if (sql.includes("SELECT id, created_at, enrollment_closed_at")) return state.owner;
        if (sql.includes("DELETE FROM auth_challenges")) {
          const [hash, purpose, now] = values;
          const index = state.challenges.findIndex((item) => item.hash === hash && item.purpose === purpose && item.expiresAt > now);
          if (index < 0) return null;
          const [item] = state.challenges.splice(index, 1);
          return { challenge: item.challenge };
        }
        if (sql.includes("SELECT credential_id, public_key, sign_count") && sql.includes("WHERE credential_id = ?")) {
          const item = state.credentials.find((row) => row.credential_id === values[0] && row.revoked_at === null);
          return item || null;
        }
        if (sql.startsWith("DELETE FROM auth_challenges")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 0 } }; } }; } };
        }
        if (sql.includes("SELECT created_at, expires_at, last_seen_at")) {
          const [hash, now] = values;
          const item = state.sessions.find((row) => row.session_hash === hash && row.expires_at > now && row.revoked_at === null);
          return item ? { created_at: item.created_at, expires_at: item.expires_at, last_seen_at: null } : null;
        }
        if (sql.includes("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
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
        if (sql.includes("INSERT INTO auth_challenges")) {
          const [hash, challenge, purpose, createdAt, expiresAt] = values;
          state.challenges.push({ hash, challenge, purpose, createdAt, expiresAt });
        } else if (sql.includes("INSERT INTO jarvis_owner")) {
          state.owner = { id: 1, created_at: values[0], enrollment_closed_at: values[1] };
        } else if (sql.includes("INSERT INTO owner_credentials")) {
          const [id, publicKey, counter, transportsJson, deviceType, backedUp, createdAt] = values;
          state.credentials.push({
            credential_id: id, owner_id: 1, public_key: publicKey, sign_count: counter,
            transports_json: transportsJson, device_type: deviceType, backed_up: backedUp,
            created_at: createdAt, last_used_at: null, revoked_at: null
          });
        } else if (sql.includes("INSERT INTO auth_sessions")) {
          const [sessionHash, csrfHash, createdAt, expiresAt] = values;
          state.sessions.push({ session_hash: sessionHash, csrf_token_hash: csrfHash, created_at: createdAt, expires_at: expiresAt, revoked_at: null });
        } else if (sql.includes("UPDATE owner_credentials SET sign_count")) {
          const [newCounter, now, id, oldCounter] = values;
          const item = state.credentials.find((row) => row.credential_id === id && row.sign_count === oldCounter && row.revoked_at === null);
          if (item) { item.sign_count = newCounter; item.last_used_at = now; }
          return { success: true, meta: { changes: item ? 1 : 0 } };
        } else if (sql.includes("UPDATE auth_sessions SET revoked_at")) {
          const [now, hash] = values;
          if (sql.includes("WHERE session_hash = ?")) {
            const item = state.sessions.find((row) => row.session_hash === hash && row.revoked_at === null);
            if (item) item.revoked_at = now;
            return { success: true, meta: { changes: item ? 1 : 0 } };
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

  it("rejects a missing bootstrap secret before touching storage", async () => {
    const env = {
      DB: { prepare() { throw new Error("unauthorized bootstrap must not touch storage"); } },
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
      JARVIS_BOOTSTRAP_SECRET: secret
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
    });
    expect(response.status).toBe(200);
    const options = await response.json();
    expect(options.excludeCredentials).toContainEqual({
      id: "existing-passkey",
      transports: ["internal"],
      type: "public-key"
    });
    expect(options.challenge).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(challenges[0][2]).toBe("credential_add");
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test",
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
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
      DB: makeDb(null), AUTH_ORIGIN: "https://example.test", WEBAUTHN_RP_ID: "example.test"
    });
    const ownerWithoutActiveCredentials = await handleAuthRequest(request("/auth/login/options", {
      method: "POST", headers: { Origin: "https://example.test" }
    }), {
      DB: makeDb({ id: 1, created_at: 1, enrollment_closed_at: 1 }),
      AUTH_ORIGIN: "https://example.test", WEBAUTHN_RP_ID: "example.test"
    });
    expect(noOwner.status).toBe(401);
    expect(ownerWithoutActiveCredentials.status).toBe(401);
    const first = await noOwner.json();
    const second = await ownerWithoutActiveCredentials.json();
    expect(first).toEqual({ error: "authentication_failed" });
    expect(second).toEqual(first);
  });


  it("requires a recent passkey session before adding another credential", async () => {
    const encode = (bytes) => {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).split("+").join("-").split("/").join("_").split("=").join("");
    };
    const hash = async (value) => encode(new Uint8Array(await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(value)
    )));
    const sessionToken = "s".repeat(48);
    const csrfToken = "c".repeat(48);
    const sessionHash = await hash(sessionToken);
    const csrfHash = await hash(csrfToken);
    const db = {
      prepare(sql) {
        if (sql.includes("SELECT created_at, expires_at, last_seen_at")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { created_at: 1, expires_at: 9999999999 } : null;
          } }; } };
        }
        if (sql.includes("UPDATE auth_sessions SET last_seen_at")) {
          return { bind() { return { async run() { return { success: true, meta: { changes: 1 } }; } }; } };
        }
        if (sql.includes("SELECT csrf_token_hash")) {
          return { bind(...values) { return { async first() {
            return values[0] === sessionHash ? { csrf_token_hash: csrfHash } : null;
          } }; } };
        }
        throw new Error("Stale session must be rejected before any other database query");
      }
    };
    const response = await handleAuthRequest(request("/auth/credentials/options", {
      method: "POST",
      headers: {
        Origin: "https://example.test",
        Cookie: "__Host-jarvis_session=" + sessionToken,
        "X-CSRF-Token": csrfToken
      }
    }), {
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "reauthentication_required" });
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
      DB: db,
      AUTH_ORIGIN: "https://example.test",
      WEBAUTHN_RP_ID: "example.test"
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "reauthentication_required" });
    expect(challengeIssued).toBe(false);
  });

});
