import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

function request(path = "/health", options = {}) {
  return new Request(`https://example.test${path}`, options);
}

function assertHardenedHeaders(response) {
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(
    response.headers.get("permissions-policy"),
    "camera=(), microphone=(), geolocation=()"
  );
  assert.equal(
    response.headers.get("strict-transport-security"),
    "max-age=31536000"
  );
  assert.equal(response.headers.get("access-control-allow-origin"), null);
}

test("GET /health returns the honest scaffold status and hardened headers", async () => {
  const response = await worker.fetch(request());

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  assertHardenedHeaders(response);
  assert.deepEqual(await response.json(), {
    service: "jarvis-api",
    status: "ok",
    mode: "scaffold",
    aiConnected: false
  });
});

test("GET /health accepts a query string without changing route matching", async () => {
  const response = await worker.fetch(request("/health?check=1"));

  assert.equal(response.status, 200);
  assert.equal((await response.json()).aiConnected, false);
  assertHardenedHeaders(response);
});

test("unknown paths return a generic JSON 404 with hardened headers", async () => {
  const response = await worker.fetch(request("/not-implemented"));

  assert.equal(response.status, 404);
  assertHardenedHeaders(response);
  assert.deepEqual(await response.json(), {
    error: "not_found",
    message: "This endpoint is not implemented."
  });
});

test("near-match health paths are not treated as the health endpoint", async () => {
  for (const path of ["/health/", "/health/extra", "/Health"]) {
    const response = await worker.fetch(request(path));
    assert.equal(response.status, 404, path);
    assertHardenedHeaders(response);
  }
});

test("only GET can access /health", async () => {
  for (const method of ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]) {
    const response = await worker.fetch(request("/health", { method }));
    assert.equal(response.status, 404, method);
    assertHardenedHeaders(response);
  }
});

test("HTTP requests do not receive an HTTPS-only HSTS header", async () => {
  const response = await worker.fetch(
    new Request("http://example.test/health")
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("strict-transport-security"), null);
  assert.equal(response.headers.get("cache-control"), "no-store");
});
