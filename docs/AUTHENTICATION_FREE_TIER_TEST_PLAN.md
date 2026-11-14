# J.A.R.V.I.S. — Zero-Cost Authentication Test Plan

**Status:** Test plan only — no authentication implementation, storage namespace, migration, or deployment is authorized by this document.
**Target:** One owner, Safari on iPhone 17 Pro Max
**Budget rule:** Free services only. Never enable billing, a paid plan, paid add-ons, or a trial.

## Purpose

Prove the owner-authentication design can work safely in the selected runtime before JARVIS stores credentials or personal data. Tests are staged so that local and isolated checks happen first. Cloud account eligibility is a separate manual verification gate; a verbal assumption is not proof of the account's billing state.

## Stage 0 — Preserve the safe baseline

- Keep the current health-only Worker behavior as the public baseline.
- Do not add login, enrollment, memory, AI, or command routes yet.
- Do not provision a Durable Object, database, bucket, or other cloud resource.
- Do not change Cloudflare billing, plan, production branch, DNS, or deployment settings.
- Confirm work is on `jarvis-foundation`; never modify `jarvis-core`.
- Record the current branch commit and ensure no secrets, credentials, or personal data are present in the public repository.

**Pass condition:** Existing health, unknown-route, and method tests continue to pass; no production behavior changes.

## Stage 1 — Local test harness (no Cloudflare account required)

1. Keep the current zero-dependency Node test command working.
2. Add tests for request method, path, content type, malformed JSON, oversized bodies, and generic error responses before any auth route is introduced.
3. Build WebAuthn tests around deterministic test fixtures and a local Worker runtime; never use a real owner credential or real passkey in automated tests.
4. Test challenge lifecycle: random generation, five-minute expiry, one-time consumption, replay rejection, and concurrency/race behavior.
5. Test origin and RP ID allowlisting with both valid and invalid values.
6. Test credential verification failures: unknown credential, wrong challenge, invalid signature, wrong origin, wrong RP ID, and missing user verification.
7. Test session behavior: opaque random ID, only a hash persisted, expiry, revocation, rotation, logout, and cookie flags.
8. Test CSRF and hostile Origin rejection for every state-changing cookie-authenticated route.
9. Test that logs, error messages, response bodies, and client bundles never contain secrets, session IDs, private keys, or recovery codes.

**Pass condition:** Tests are repeatable locally, fail when a security invariant is intentionally broken, and run without paid services or real credentials.

## Stage 2 — Runtime and dependency compatibility

- Recheck the selected WebAuthn library's latest stable release, licence, security advisories, runtime support, and transitive dependencies immediately before implementation.
- Pin exact package versions and commit the lockfile only after review.
- Run the Worker locally using the intended compatibility date and module settings.
- Verify Web Crypto APIs, cryptographic randomness, binary/base64url handling, and WebAuthn verification work in that exact runtime.
- Check bundle size and CPU/runtime behavior against the documented Free limits; do not assume Node compatibility means Worker compatibility.
- Do not use remote CDN scripts for authentication code.

**Pass condition:** The exact pinned build works in the local Worker runtime and all positive and negative tests pass. No dependency is called production-ready based only on documentation.

## Stage 3 — Cloudflare Free eligibility (read-only account check)

Before provisioning anything, verify in the actual Cloudflare account:

- The account is on the Free plan, not a paid plan or trial.
- Billing/payment settings do not authorize automatic paid usage or an upgrade.
- Workers and the proposed SQLite-backed Durable Object feature are available to this account on Free.
- Current quotas, CPU limits, storage limits, request limits, and over-limit behavior are compatible with the expected single-owner workload.
- No paid add-on or paid resource is required for deployment, storage, logs, analytics, or domain configuration.

Record the date and the relevant plan/feature evidence in the project notes without recording payment details or other sensitive account information.

**Pass condition:** Every item is confirmed from the account and current official documentation. If any item is unclear, stop; do not create the resource and do not enable billing.

## Stage 4 — Isolated cloud smoke test (only after Stage 3 passes)

- First confirm the intended branch, production hostname, and currently deployed code identity.
- Use a separate preview/test environment, not the production owner service.
- Provision only the smallest eligible Free resource after checking its exact limits and deletion behavior.
- Store synthetic test records only; no personal memory, real passkey, or production credential.
- Test create/read/update/delete, transaction rollback, concurrency, expiry cleanup, and behavior at safe request limits.
- Confirm that exceeding a Free quota fails closed and does not trigger paid usage or automatic upgrade.
- Remove the test resource and verify deletion.

**Pass condition:** The isolated test is successful, stays within Free limits, and cleanup is confirmed. If free eligibility or cleanup cannot be proven, stop.

## Stage 5 — Owner-device acceptance (later, after security review)

- Test passkey enrollment and sign-in in Safari on the owner's iPhone over the final HTTPS origin.
- Confirm iOS requires local user verification and that biometric material never leaves the device.
- Test cancellation, wrong origin, expired/replayed challenge, unavailable credential, session expiry, logout, and device loss/revocation.
- Review a safe recovery process before treating passkey login as the sole access path.
- Have the owner explicitly approve enabling one-time enrollment only after all prior stages pass.

**Pass condition:** Every acceptance and negative test passes; enrollment is closed immediately after the single owner credential is registered.

## Stop conditions

Stop immediately if:
- Cloudflare plan or billing state is unknown or paid usage could be triggered.
- A required feature is not available on Free.
- The library fails in the actual Worker runtime or has an unresolved security advisory.
- The production branch, hostname, or deployed code identity is uncertain.
- A test requires real personal data or a real credential before the security gates are complete.
- Any test exposes a secret, session token, credential, or private data.

## Current verified project state

- The Worker currently exposes only a health endpoint and a generic 404 response.
- The existing project has a zero-dependency Node test script and three scaffold tests.
- The WebAuthn packages and Durable Object storage are research candidates only; they are not installed or provisioned.
- Authentication, owner memory, and AI integration are not implemented.
- No deployment or billing change is part of this plan.

## Execution order

`Stage 0 → Stage 1 → Stage 2 → Stage 3 → Stage 4 → Stage 5`

Do not skip a stage. A successful local test does not prove Cloudflare Free eligibility, and a successful health check does not prove authentication or privacy.
