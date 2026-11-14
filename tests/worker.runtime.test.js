import { describe, expect, it } from "vitest";
import { exports } from "cloudflare:workers";
import { handleAuthRequest } from "../src/auth/routes.js";

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
      { id: "owner-passkey", transports: ["internal"] }
    ]);
    expect(issued).toHaveLength(1);
    expect(issued[0].values[1]).toBe(options.challenge);
    expect(issued[0].values[2]).toBe("authentication");
  });

});
