import { describe, expect, it } from "vitest";
import { exports } from "cloudflare:workers";

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
      mode: "scaffold",
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
});
