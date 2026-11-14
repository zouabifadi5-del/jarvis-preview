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


test("same-origin owner access shell is intentionally non-functional and restrictive", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, headers, config] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/_headers", import.meta.url), "utf8"),
    readFile(new URL("../wrangler.toml", import.meta.url), "utf8")
  ]);

  assert.match(html, /J\.A\.R\.V\.I\.S\./);
  assert.match(html, /Access is not enabled yet/);
  assert.match(html, /No sign-in, enrollment, or personal-data access is active/);
  assert.doesNotMatch(html, /<script\b|<form\b/i);
  assert.match(headers, /Content-Security-Policy: default-src 'none'/);
  assert.match(headers, /X-Frame-Options: DENY/);
  assert.match(headers, /Cache-Control: no-store/);
  assert.match(config, /directory = "\.\/public"/);
  assert.match(config, /binding = "ASSETS"/);
});
