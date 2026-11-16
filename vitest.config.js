import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.test.toml"
      }
    })
  ],
  test: {
    include: [
      "tests/worker.runtime.test.js",
      "tests/webauthn.runtime.test.js"
    ],
    testTimeout: 10000,
    hookTimeout: 10000
  }
});
