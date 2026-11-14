# J.A.R.V.I.S. — Worker Runtime Compatibility Test

**Status:** The latest verified run #160 passed 37 Workers runtime tests and 19 local SQLite/Node checks, plus browser JavaScript syntax validation and Wrangler dry-run build/config validation (56 test cases total). The auth routes and native browser passkey UI remain a non-production scaffold.  
**Purpose:** Test the Worker scaffold and the server-side WebAuthn library inside the Cloudflare Workers runtime without deploying to Cloudflare.  
**Cost:** Uses the standard GitHub-hosted runner for this public repository; no paid runner, Cloudflare resource, account secret, or billing change.

## Why this test exists

The existing Node.js test suite checks the Worker handler under Node.js. That is useful, but it does not prove that code and dependencies behave in Cloudflare's `workerd` runtime.

Cloudflare recommends its Workers Vitest integration for this purpose. The `@cloudflare/vitest-plugin` runs tests in the Workers runtime locally through Miniflare/workerd and can load the project's Wrangler configuration.

## Candidate versions for this compatibility experiment

- `@simplewebauthn/server@14.1.0`: pinned in `package.json`; synthetic WebAuthn and route option tests pass in the Workers runtime.
- Browser client: native WebAuthn APIs, with no third-party browser package.
- `vitest@4.1.0`: version selected for the test harness.
- `@cloudflare/vitest-plugin@1.8.2`: plugin version selected for this experiment.

The server package is now a declared runtime dependency. CI uses Node.js 24 and installs exact test tooling temporarily. There is still no lockfile or completed dependency-advisory review; passing compatibility tests do not constitute production approval.

## Tests prepared

### Worker contract

- Health response shape and honest `aiConnected: false` state.
- Exact route matching and query-string behavior.
- Generic 404 for unknown routes.
- Rejection of non-GET methods.
- No-store and security response headers.
- No permissive CORS header.
- HSTS only for HTTPS requests.

### SimpleWebAuthn runtime and ceremony tests

- Import and run `generateRegistrationOptions` and `generateAuthenticationOptions` in the Worker runtime.
- Generate a temporary P-256 key pair using WebCrypto.
- Construct a synthetic CBOR/none-attestation registration response and a signed synthetic authentication assertion.
- Verify successful registration and authentication against the expected challenge, origin, and RP ID.
- Assert rejection when registration or authentication uses a wrong challenge, wrong origin, or wrong RP ID.
- Exercise full synthetic route registration/login/session/logout, including challenge replay rejection, wrong-origin assertions, tampered signatures, CSRF failure, and owner-enrollment enumeration protection.
- Reject authentication when user presence or user verification flags are missing.
- Reject an authentication counter rollback.
- Enforce application-level binding between response `id`/`rawId` and the selected stored credential record before calling the library verifier. This is an explicit wrapper because the library expects the caller to select and supply the correct credential.
- Reject malformed CBOR registration attestation data.
- Keep all credential identifiers and keys synthetic and generated during the test; no real owner credential or passkey is created.

The synthetic attestation uses the WebAuthn `none` format and is not evidence of hardware-backed attestation, trusted authenticator provenance, or a real device ceremony. The tests exercise the library's verifier paths with constructed fixtures, not a physical authenticator or Safari/iPhone passkey UI.

### Current CI result

- Local SQLite/Node checks: 15 passed.
- Workers runtime test files: 2 passed.
- Workers runtime test cases: 35 passed, including a synthetic end-to-end first-owner registration, login, session inspection, and logout flow.
- Browser client syntax check: passed with Node.js 24.
- Wrangler `deploy --dry-run`: successful; it validated the Worker and static assets without uploading or deploying.
- Total test cases: 50 passed.
- Verified run #132: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43615565790

### Static shell and Wrangler validation

The isolated branch now contains `public/index.html`, `public/app.js`, and `public/style.css`, with a Workers Static Assets binding in `wrangler.toml`. The first-party browser client uses native WebAuthn APIs for first-owner enrollment, sign-in, additional passkey enrollment, credential listing/revocation, and logout. It does not use third-party scripts, localStorage, or sessionStorage. The Content Security Policy permits only same-origin scripts, styles, and API calls, and blocks inline script attributes. The Worker explicitly routes the root page and static files to Workers Static Assets. The browser client is syntax-checked in CI; Wrangler dry-run and workerd tests validate asset routing. These checks do not replace a real Safari/iPhone ceremony.
## CI safety boundaries

The workflow:
- Runs only on pushes to `jarvis-worker-runtime-tests` and pull requests targeting the listed development branches.
- Uses the standard `ubuntu-latest` runner.
- Has read-only repository permissions.
- Does not receive Cloudflare credentials or other secrets.
- Does not run Wrangler deploy, create a Durable Object, or call Cloudflare account APIs.
- Does not alter the production branch.

The Worker test harness is not a hardened security sandbox. Only trusted project code should be run in it.

## D1 schema validation added alongside this harness

The workflow also runs `tests/auth-schema.test.js` with Node's built-in SQLite module before the Workers runtime tests. This validates the unprovisioned D1 migration's table shape, single-owner constraint, credential foreign key and uniqueness, challenge purpose/expiry constraints, single-use challenge consumption via `DELETE ... RETURNING`, hash-only session storage, challenge issuance/consumption, credential retrieval/revocation/counter compare-and-set, and session expiry/CSRF/revocation. Latest verified workflow run #160 passed all 19 local SQLite/Node checks and all 37 Workers-runtime tests (56 test cases total). It also passed `node --check public/app.js` and Wrangler 4.148.0 `deploy --dry-run`; the dry run validated the Worker and static assets without uploading or deploying. Run: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43615922593 This local SQLite check is not a substitute for a real D1 binding smoke test; that remains gated on the owner's Free-plan confirmation and separate explicit owner approval. The D1 storage helpers are wired into first-owner registration, login, session inspection, logout, and protected additional-credential management routes on the isolated branch. Synthetic tests cover registration/login option generation, origin enforcement, bootstrap-secret checks, content-type enforcement, CSRF-protected additional credential setup, and refusal to revoke the final active credential. The browser client is implemented but remains untested on a real iPhone/browser. Routes fail closed until D1 and exact origin settings are configured. No D1 database, secret, deployment, or real passkey has been created.

## Remaining gates

1. Expand end-to-end route tests for negative registration/login verification, replay, session-cookie flags, CSRF failure, and error handling using a local D1-compatible test adapter.
2. Add multiple-device passkey enrollment and revocation, plus a safe recovery path and login rate limiting.
3. Test the first-party browser passkey client and actual ceremony in Safari on the owner's iPhone; verify iCloud Keychain behavior.
4. Review the pinned dependency and commit a lockfile after advisory review.
5. Only after those gates and separate explicit approval, create an isolated D1 database and perform a real D1 smoke test. No deployment or personal-data storage is authorized by this test.

## References

- Cloudflare Workers testing: https://developers.cloudflare.com/workers/testing/
- Cloudflare Vitest integration: https://developers.cloudflare.com/workers/testing/vitest-integration/
- SimpleWebAuthn server package: https://jsr.io/@simplewebauthn/server
- SimpleWebAuthn helpers: https://jsr.io/@simplewebauthn/server/doc/helpers
- GitHub Actions billing: https://docs.github.com/en/actions/concepts/billing-and-usage
