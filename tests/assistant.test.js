import test from "node:test";
import assert from "node:assert/strict";
import { handleAssistantRequest } from "../src/assistant.js";

const origin = "https://jarvis.example";
const env = {
  AUTH_ORIGIN: origin,
  DB: { prepare() { throw new Error("Database must not be touched without a session cookie"); } },
  AI: { async run() { throw new Error("AI must not run for unauthenticated requests"); } }
};

test("assistant endpoint fails closed when the AI binding is absent", async () => {
  const request = new Request(origin + "/assistant/chat", {
    method: "POST",
    headers: { Origin: origin, "Content-Type": "application/json" },
    body: JSON.stringify({ messages: [{ role: "user", content: "hello" }] })
  });
  const response = await handleAssistantRequest(request, { ...env, AI: undefined });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "assistant_not_configured");
});

test("assistant endpoint rejects a cross-origin request before inference", async () => {
  const request = new Request(origin + "/assistant/chat", {
    method: "POST",
    headers: { Origin: "https://attacker.example", "Content-Type": "application/json" },
    body: JSON.stringify({ messages: [{ role: "user", content: "hello" }] })
  });
  const response = await handleAssistantRequest(request, env);
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "origin_not_allowed");
});

test("assistant endpoint requires an owner session and CSRF token", async () => {
  const request = new Request(origin + "/assistant/chat", {
    method: "POST",
    headers: { Origin: origin, "Content-Type": "application/json" },
    body: JSON.stringify({ messages: [{ role: "user", content: "hello" }] })
  });
  const response = await handleAssistantRequest(request, env);
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error, "not_authenticated");
});

test("assistant endpoint rejects unsupported methods", async () => {
  const request = new Request(origin + "/assistant/chat", {
    method: "GET",
    headers: { Origin: origin }
  });
  const response = await handleAssistantRequest(request, env);
  assert.equal(response.status, 405);
  assert.equal((await response.json()).error, "method_not_allowed");
});
