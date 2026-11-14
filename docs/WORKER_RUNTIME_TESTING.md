# J.A.R.V.I.S. — Worker Runtime Compatibility Test

**Status:** The latest synthetic ceremony test run passed 24 of 24 tests across two test files on `jarvis-worker-runtime-tests`. This is a compatibility and verifier test harness, not a production authentication implementation.  
**Purpose:** Test the Worker scaffold and the server-side WebAuthn library inside the Cloudflare Workers runtime without deploying to Cloudflare.  
**Cost:** Uses the standard GitHub-hosted runner for this public repository; no paid runner, Cloudflare resource, account secret, or billing change.

## Why this test exists

The existing Node.js test suite checks the Worker handler under Node.js. That is useful, but it does not prove that code and dependencies behave in Cloudflare's `workerd` runtime.

Cloudflare recommends its Workers Vitest integration for this purpose. The `@cloudflare/vitest-plugin` runs tests in the Workers runtime locally through Miniflare/workerd and can load the project's Wrangler configuration.

## Candidate versions for this compatibility experiment

- `@simplewebauthn/server@14.1.0`: JSR release selected for this test; its official package listing explicitly names Cloudflare Workers as a supported runtime.
- `@simplewebauthn/browser@14.0.0`: browser package candidate; browser behavior still needs separate Safari/iPhone testing.
- `vitest@4.1.0`: version selected for the test harness.
- `@cloudflare/vitest-plugin@1.8.2`: plugin version selected for this experiment.

These are test candidates, not production approvals. The CI job uses Node.js 24 with Node-24-compatible GitHub Actions releases, then installs exact direct package versions temporarily with `--no-save`; no dependencies or lockfile are committed by this experiment. The initial npm `edgesOut` resolver crash was avoided by moving the harness to Node.js 24. A production dependency lockfile is created only after successful compatibility and security review.

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
- Tamper with the synthetic authentication signature and assert verification does not succeed.
- Reject authentication when user presence or user verification flags are missing.
- Reject an authentication counter rollback.
- Enforce application-level binding between response `id`/`rawId` and the selected stored credential record before calling the library verifier. This is an explicit wrapper because the library expects the caller to select and supply the correct credential.
- Reject malformed CBOR registration attestation data.
- Keep all credential identifiers and keys synthetic and generated during the test; no real owner credential or passkey is created.

The synthetic attestation uses the WebAuthn `none` format and is not evidence of hardware-backed attestation, trusted authenticator provenance, or a real device ceremony. The tests exercise the library's verifier paths with constructed fixtures, not a physical authenticator or Safari/iPhone passkey UI.

### Current CI result

- Test files: 2 passed.
- Test cases: 24 passed.
- Worker runtime job: successful.
- The run is associated with commit `ebfad80` on the isolated test branch.

## CI safety boundaries

The workflow:
- Runs only on pushes to `jarvis-worker-runtime-tests` and pull requests targeting the listed development branches.
- Uses the standard `ubuntu-latest` runner.
- Has read-only repository permissions.
- Does not receive Cloudflare credentials or other secrets.
- Does not run Wrangler deploy, create a Durable Object, or call Cloudflare account APIs.
- Does not alter the production branch.

The Worker test harness is not a hardened security sandbox. Only trusted project code should be run in it.

## Remaining gates

1. Add a separate, reviewed server-side authentication design: origin/RP ID allowlists, one-time challenge storage and expiry, credential persistence, replay/counter policy, session issuance, CSRF protections where applicable, rate limits, and recovery procedures.
2. Test additional credential lifecycle cases, including counter semantics for synced passkeys, credential revocation, duplicate registration, and challenge one-time use/expiry.
3. Test the browser package and actual passkey ceremony in Safari on the owner's iPhone; verify iCloud Keychain behavior and recovery paths.
4. Design and review persistence, one-time challenge storage, session issuance, recovery, and rate limiting before any real authentication route or personal-data storage is introduced.
5. Only after those gates, consider a separately approved deployment. No deployment or personal-data storage is authorized by this test.

## References

- Cloudflare Workers testing: https://developers.cloudflare.com/workers/testing/
- Cloudflare Vitest integration: https://developers.cloudflare.com/workers/testing/vitest-integration/
- SimpleWebAuthn server package: https://jsr.io/@simplewebauthn/server
- SimpleWebAuthn helpers: https://jsr.io/@simplewebauthn/server/doc/helpers
- GitHub Actions billing: https://docs.github.com/en/actions/concepts/billing-and-usage
