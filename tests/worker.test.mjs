import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

test("GET /health returns the honest scaffold status", async () => {
  const response = await worker.fetch(
    new Request("https://example.test/health")
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), {
    service: "jarvis-api",
    status: "ok",
    mode: "scaffold",
    aiConnected: false
  });
});

test("unknown paths return a JSON 404", async () => {
  const response = await worker.fetch(
    new Request("https://example.test/not-implemented")
  );

  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), {
    error: "not_found",
    message: "This endpoint is not implemented."
  });
});

test("non-GET requests cannot call the health endpoint", async () => {
  const response = await worker.fetch(
    new Request("https://example.test/health", { method: "POST" })
  );

  assert.equal(response.status, 404);
});
