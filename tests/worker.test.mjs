import test from "node:test";
import assert from "node:assert/strict";

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
