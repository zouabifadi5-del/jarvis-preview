import test from "node:test";
import assert from "node:assert/strict";

test("same-origin owner access shell is intentionally non-functional and restrictive", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, headers, config] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/_headers", import.meta.url), "utf8"),
    readFile(new URL("../wrangler.toml", import.meta.url), "utf8")
  ]);

  assert.ok(html.includes("J.A.R.V.I.S."));
  assert.ok(html.includes("Access is not enabled yet"));
  assert.ok(html.includes("No sign-in, enrollment, or personal-data access is active"));
  assert.ok(!html.includes("<script") && !html.includes("<form"));
  assert.ok(headers.includes("Content-Security-Policy: default-src 'none'"));
  assert.ok(headers.includes("X-Frame-Options: DENY"));
  assert.ok(headers.includes("Cache-Control: no-store"));
  assert.ok(config.includes('directory = "./public"'));
  assert.ok(config.includes('binding = "ASSETS"'));
});
