# J.A.R.V.I.S. — Worker Runtime Compatibility Test

**Status (16 November 2026):** Latest verified run #449 passed 51 Workers-runtime tests and 25 local SQLite/Node checks (76 total), plus production dependency audit, browser JavaScript syntax validation, and Wrangler dry-run validation. The authentication and stateless chat branch remains isolated, undeployed, and not production-ready.  
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

- Local SQLite/Node checks: 25 passed.
- Workers runtime test files: 2 passed.
- Workers runtime test cases: 51 passed, including synthetic end-to-end registration/login/session/logout, recovery, valid-session-only rate-limit bucket allocation, IP and session throttling, daily AI budget enforcement, unexpected-field rejection, bounded chat input, and owner-only chat tests using a mocked AI binding.
- Production dependency audit: passed at moderate severity and above.
- Browser client syntax check: passed with Node.js 24.
- Wrangler `deploy --dry-run`: successful; it validated the Worker and static assets without uploading or deploying.
- Total test cases: 70 passed.
- Verified run #449: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43883804734

### Static shell and Wrangler validation

The isolated branch now contains `public/index.html`, `public/app.js`, and `public/style.css`, with a Workers Static Assets binding in `wrangler.toml`. The first-party browser client uses native WebAuthn APIs for first-owner enrollment, sign-in, additional passkey enrollment, credential listing/revocation, recovery-code display/recovery, individual logout, and sign-out-everywhere. It does not use third-party scripts, localStorage, or sessionStorage. The Content Security Policy permits only same-origin scripts, styles, and API calls, and blocks inline script attributes. The Worker explicitly routes the root page and static files to Workers Static Assets. The browser client is syntax-checked in CI; Wrangler dry-run and workerd tests validate asset routing. These checks do not replace a real Safari/iPhone ceremony.
## CI safety boundaries

The workflow:
- Runs on pushes to `jarvis-worker-runtime-tests` and `jarvis-security-hardening`, and on pull requests targeting the listed development branches.
- Uses the standard `ubuntu-latest` runner.
- Uses `wrangler.test.toml`, which intentionally omits the AI binding so local workerd tests never open a remote Cloudflare AI proxy or consume the account's daily inference allocation. The separate Wrangler dry run validates the deployment config including the AI binding.
- Has read-only repository permissions.
- Does not receive Cloudflare credentials or other secrets.
- Does not run Wrangler deploy, create a Durable Object, or call Cloudflare account APIs.
- Does not alter the production branch.

The Worker test harness is not a hardened security sandbox. Only trusted project code should be run in it.

## D1 schema validation added alongside this harness

The workflow runs `tests/auth-schema.test.js` and `tests/d1-store.test.js` with Node's built-in SQLite module before the Workers runtime tests. It validates the migration table shape, singleton owner constraint, credential foreign keys and uniqueness, one-time recovery-code claims, challenge expiry and single-use consumption, hash-only session storage, counter compare-and-set, idle expiry, CSRF, revocation, and atomic recovery replacement. Latest verified run #449 passed all 25 local SQLite/Node checks and 51 Workers-runtime tests (76 total), as well as the dependency audit, browser syntax check, PWA manifest validation, and Wrangler dry run: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43883804734. The remote D1 database `jarvis-owner-auth` exists; both migrations, six expected tables, and five supporting indexes were verified. A temporary synthetic D1 table passed create/insert/read/delete/drop and cleanup checks; all six application tables remained empty and the foreign-key check had no violations. This D1 smoke test verified storage access, not the authentication routes end to end against the live Worker. Synthetic workerd tests cover registration/login, session rotation, idle timeout, challenge replay, wrong origin, tampered signatures, CSRF rejection, enrollment-state privacy, recent-passkey requirements, all-session revocation, recovery-code replacement, per-IP and per-session throttling, and rejection of unexpected top-level JSON fields. The browser client has not been tested on a physical iPhone. Cloudflare Worker settings list authentication-related secret binding names, but secret values were not read or validated. Authentication code remains undeployed and no real passkey has been registered.

## Remaining gates

1. Exercise the authentication routes against the configured real D1 binding using disposable synthetic credentials and records, then verify cleanup; do not write owner data.
2. Test the first-party browser passkey client and actual ceremony in Safari on the owner's iPhone; verify iCloud Keychain behavior and recovery-code handling.
3. Commit a reproducible lockfile and complete dependency-advisory review.
4. Verify the exact served origin/RP ID and secret-binding configuration without exposing secret values.
5. Complete an independent security review and negative tests. Deployment and owner enrollment remain separate release actions; this test workflow never deploys or stores personal data.

## References

- Cloudflare Workers testing: https://developers.cloudflare.com/workers/testing/
- Cloudflare Vitest integration: https://developers.cloudflare.com/workers/testing/vitest-integration/
- SimpleWebAuthn server package: https://jsr.io/@simplewebauthn/server
- SimpleWebAuthn helpers: https://jsr.io/@simplewebauthn/server/doc/helpers
- GitHub Actions billing: https://docs.github.com/en/actions/concepts/billing-and-usage
