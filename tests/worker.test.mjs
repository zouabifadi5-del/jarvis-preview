import test from "node:test";
import assert from "node:assert/strict";

test("same-origin owner access shell loads only its first-party client and uses restrictive headers", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, script, headers, config] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../public/_headers", import.meta.url), "utf8"),
    readFile(new URL("../wrangler.toml", import.meta.url), "utf8")
  ]);

  assert.ok(html.includes("J.A.R.V.I.S."));
  assert.ok(html.includes('src="/app.js"'));
  assert.ok(html.includes("First-time owner setup"));
  assert.ok(html.includes("Continue with passkey"));
  assert.ok(script.includes("/auth/register/options"));
  assert.ok(script.includes("/auth/login/options"));
  assert.ok(script.includes("/auth/credentials/options"));
  assert.ok(script.includes("/auth/logout"));
  assert.ok(!script.includes("localStorage"));
  assert.ok(!script.includes("sessionStorage"));
  assert.ok(!script.includes("https://"));
  assert.ok(headers.includes("Content-Security-Policy: default-src 'none'"));
  assert.ok(headers.includes("script-src 'self'"));
  assert.ok(headers.includes("connect-src 'self'"));
  assert.ok(headers.includes("X-Frame-Options: DENY"));
  assert.ok(headers.includes("Cache-Control: no-store"));
  assert.ok(config.includes('directory = "./public"'));
  assert.ok(config.includes('binding = "ASSETS"'));
});
