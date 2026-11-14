import test from "node:test";
import assert from "node:assert/strict";

test("same-origin owner access shell uses only its bundled passkey client and restrictive headers", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, app, css, headers, config] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../public/style.css", import.meta.url), "utf8"),
    readFile(new URL("../public/_headers", import.meta.url), "utf8"),
    readFile(new URL("../wrangler.toml", import.meta.url), "utf8")
  ]);

  assert.ok(html.includes("J.A.R.V.I.S."));
  assert.ok(html.includes('<script src="/app.js" defer></script>'));
  assert.ok(html.includes('<link rel="stylesheet" href="/style.css">'));
  assert.ok(css.includes("color-scheme: dark"));
  assert.ok(html.includes('id="bootstrap-secret"'));
  assert.ok(html.includes('id="login"'));
  assert.ok(html.includes('id="reauthenticate"'));
  assert.ok(html.includes('id="logout-all"'));
  assert.ok(html.includes('id="recovery-code"'));
  assert.ok(html.includes('id="recovery-panel"'));
  assert.ok(html.includes('id="copy-recovery"'));
  assert.ok(html.includes('id="download-recovery"'));
  const ids = [...html.matchAll(/id="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, "HTML element IDs must be unique");

  assert.ok(app.includes("navigator.credentials.create"));
  assert.ok(app.includes("navigator.credentials.get"));
  assert.ok(app.includes("/auth/register/options"));
  assert.ok(app.includes("/auth/login/verify"));
  assert.ok(app.includes("/auth/credentials/revoke"));
  assert.ok(app.includes("/auth/logout-all"));
  assert.ok(app.includes("/auth/recovery/options"));
  assert.ok(app.includes("/auth/recovery/verify"));
  assert.ok(app.includes("showRecoveryCodes"));
  assert.ok(app.includes("navigator.clipboard"));
  assert.ok(app.includes("jarvis-recovery-codes.txt"));
  assert.ok(!app.includes("localStorage") && !app.includes("sessionStorage"));
  assert.ok(!app.includes("eval("));
  assert.ok(headers.includes("Content-Security-Policy: default-src 'none'"));
  assert.ok(headers.includes("script-src 'self'"));
  assert.ok(headers.includes("script-src-attr 'none'"));
  assert.ok(headers.includes("style-src 'self'"));
  assert.ok(!headers.includes("unsafe-inline"));
  assert.ok(headers.includes("connect-src 'self'"));
  assert.ok(headers.includes("X-Frame-Options: DENY"));
  assert.ok(headers.includes("Cache-Control: no-store"));
  assert.ok(config.includes('directory = "./public"'));
  assert.ok(config.includes('binding = "ASSETS"'));
});
