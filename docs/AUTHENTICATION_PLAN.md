# J.A.R.V.I.S. — Authentication Implementation Plan

**Status (16 November 2026):** Initial passkey routes and a native browser passkey UI are implemented on the isolated test branch; both D1 migrations, all six expected application tables, five supporting indexes, and a synthetic D1 read/write/delete/drop smoke test are verified; authentication code remains undeployed and is not production-ready  
**Owner model:** One enrolled owner, no public sign-up  
**Client:** Safari on iPhone 17 Pro Max  
**Budget:** Zero-cost only; no paid plan, billing, trial, or resource may be enabled

## Selected WebAuthn identity and frontend hosting

- **Authentication UI origin (planned):** `https://jarvis-preview-api.zouabifadi5.workers.dev`
- **WebAuthn RP ID (planned):** `jarvis-preview-api.zouabifadi5.workers.dev`
- **Allowed origin:** exact match to the authentication UI origin above
- **API:** same Worker origin; use relative same-origin `/auth/*` requests
- **Cookie scope:** host-only; omit the `Domain` attribute

The owner supplied this Worker URL. To make it a valid WebAuthn identity without buying a domain, the authentication/login page will be served from the same Worker hostname using Cloudflare Workers Static Assets. The existing GitHub Pages preview, if enabled, remains a public demo and will not perform passkey ceremonies. This avoids cross-site cookies/CORS and ensures the browser page's effective domain matches the RP ID.

Cloudflare documents Workers Static Assets as free and unlimited for asset requests, with no additional asset storage charge. Requests that invoke the Worker script remain subject to the Workers Free request limit. A same-origin owner-access interface (`index.html`, `app.js`, `style.css`) and Workers Static Assets configuration have been added to the isolated test branch only. It supports native WebAuthn registration/login, credential management, and session controls, but has not been deployed; the live Worker remains unchanged.

The RP ID and exact origin must be rechecked against the actual served login page before the first real passkey is enrolled. Wrangler's non-deploying build validation has passed for the current static asset configuration, but that does not prove the page is live or validate a real browser ceremony. Never accept origin or RP ID values supplied by a request. Changing the hostname after enrollment generally requires enrolling new passkeys.

References:
- https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
- https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/
- https://developers.cloudflare.com/workers/static-assets/

## 1. Library selection

**Preferred candidate:**
- Server: `@simplewebauthn/server@14.1.0`
- Browser: native WebAuthn APIs (`navigator.credentials.create/get`), no third-party browser package.
- Licence: MIT for the server package.
- The server package's current JSR documentation explicitly lists Cloudflare Workers as a supported runtime.

`@simplewebauthn/server@14.1.0` is pinned in `package.json` and passes the synthetic Worker-runtime compatibility suite. The browser uses native WebAuthn APIs (`navigator.credentials.create/get`) rather than a separate browser library. `@simplewebauthn/server@14.1.0` is the latest npm release as of 14 November 2026. Snyk currently lists zero direct vulnerabilities for this version; the v14.0.2 release fixed two moderate certificate-revocation advisories and v14.1.0 includes subsequent verification hardening. This is not a complete transitive-dependency audit. CI now runs `npm audit --omit=dev --audit-level=moderate`; a committed lockfile, review of transitive results, real D1 test, and real Safari/iPhone ceremony remain outstanding.

References: [npm package](https://www.npmjs.com/package/@simplewebauthn/server), [Snyk package report](https://security.snyk.io/package/npm/%40simplewebauthn%2Fserver), [maintainer changelog](https://github.com/MasterKale/SimpleWebAuthn/blob/master/CHANGELOG.md), [maintainer advisories](https://github.com/MasterKale/SimpleWebAuthn/security/advisories). Do not load a third-party CDN script on authenticated pages.

References:
- https://jsr.io/@simplewebauthn/server
- https://jsr.io/@simplewebauthn/browser
- https://simplewebauthn.dev/docs/packages/server/
- https://simplewebauthn.dev/docs/packages/browser/

## 2. Selected persistence: Cloudflare D1

**Decision: use one Cloudflare D1 database for authentication records. Do not use Durable Objects for this phase.**

D1 is the simpler fit for this relational, low-volume workload: one owner row, passkey credentials, one-time challenges, and revocable sessions. It supports SQL constraints, indexes, prepared statements, and atomic database operations without introducing a custom stateful Durable Object class or routing layer. A Durable Object remains a valid option for future coordinated live-agent state, but that capability is unnecessary for passkey authentication alone.

Cloudflare's current Workers Free D1 limits are 5 million rows read/day, 100,000 rows written/day, 5 GB total account storage, 500 MB per database, and 10 databases per account. D1 has no compute-hour charge. Free-tier query limits fail closed when exceeded until the daily reset; storage exhaustion blocks additional writes and schema changes. The Free plan has 50 D1 read subrequests per Worker invocation. These limits are ample for a single-owner authentication service if queries stay indexed and challenge/session cleanup is bounded.

For comparison, SQLite-backed Durable Objects are also available on Workers Free, but add their own request and duration quotas (currently 100,000 requests/day and 13,000 GB-seconds/day) plus SQL storage quotas. They are designed for stateful coordination; we do not need that complexity for the current auth database.

The owner has confirmed that the Cloudflare account is on the Free plan and has no paid Workers subscription or trial. This is an owner-provided confirmation, not an independent inspection of account billing controls. The isolated owner-auth D1 database has been created; both migration records, six expected application tables, and five supporting indexes were verified. A temporary synthetic table passed create/insert/read/delete/drop checks and was confirmed absent afterward. Never upgrade or enable billing to overcome a quota; stop if any unexpected paid prompt or requirement appears.

References:
- https://developers.cloudflare.com/d1/platform/pricing/
- https://developers.cloudflare.com/d1/platform/limits/
- https://developers.cloudflare.com/durable-objects/platform/pricing/

The schema in [migrations/0001_owner_auth.sql](../migrations/0001_owner_auth.sql) and [migrations/0002_auth_rate_limits.sql](../migrations/0002_auth_rate_limits.sql) has been applied to the existing `jarvis-owner-auth` D1 database and verified. Both migration records, all six expected application tables, and five supporting indexes were confirmed. A temporary synthetic table passed create/insert/read/delete/drop checks and was confirmed absent afterward; no owner account or passkey was created. It stores only:
- a singleton owner marker and passkey credential public keys/metadata;
- short-lived WebAuthn challenges, consumed once with an atomic delete-returning operation;
- hashed opaque session identifiers, hashed CSRF tokens, expiry, and revocation metadata.

Never store passkey private keys, biometric data, plaintext session tokens, prompts, conversation memory, emails, or contacts in this authentication database.

## 3. Authentication flow

### One-time owner enrollment
1. Keep enrollment disabled by default.
2. Enable it only through a controlled server-side bootstrap procedure after HTTPS origin, storage, billing status, and deployment identity are verified.
3. Generate registration options with a cryptographically random challenge, the exact production RP ID and origin, `residentKey: "required"`, and `userVerification: "required"`.
4. Store the challenge with a five-minute expiry and a one-use state.
5. Verify the browser response using SimpleWebAuthn with the expected challenge, exact origin, exact RP ID, and user verification required.
6. Store the credential ID, public key, counter, transports, device type, and backup state. Never store biometric data or a private key.
7. Atomically mark the owner as enrolled and permanently close public enrollment. Do not add a public "register another user" endpoint.

### Owner sign-in
1. `POST /auth/login/options` requires an enrolled owner and supplies only active credentials, with a random five-minute challenge and user verification required.
2. `POST /auth/login/verify` consumes the challenge once and verifies the assertion against the stored public key, exact challenge, origin, RP ID, user-verification flag, and credential ID.
3. The credential counter is updated with compare-and-set semantics.
4. A random opaque session ID and CSRF token are generated; only their hashes are stored in D1.
5. The session is issued in a host-only `Secure; HttpOnly; SameSite=Strict` cookie with `Path=/` and no `Domain`; current lifetime is eight hours. A separate host-only `Secure; SameSite=Strict` CSRF cookie is readable by same-origin JavaScript so it survives page reloads; only its hash is stored server-side.

### Session and logout
- `GET /auth/me` rejects expired or revoked sessions.
- `POST /auth/logout` verifies the CSRF token and exact Origin, revokes the current session, and clears cookies.
- `POST /auth/logout-all` revokes all active sessions after the same Origin/CSRF checks.
- A same-origin browser client performs registration, login, session inspection, additional passkey enrollment, credential listing/revocation, logout, and sign-out-everywhere. The CSRF token is reloaded from a Secure, SameSite, JavaScript-readable cookie; only its hash is stored in D1.
- The intended client and API are same-origin; no wildcard credentialed CORS is configured.
- Never place session IDs in URLs, browser storage, logs, or client JavaScript.

## 4. Implemented route contract (isolated branch only)

All routes are same-origin HTTPS. JSON bodies are content-type checked and capped at 16 KiB:
- `POST /auth/register/options` — creates one-time owner registration options; requires the server-side bootstrap secret.
- `POST /auth/register/verify` — verifies the attestation and atomically creates the singleton owner and first credential; requires the bootstrap secret again.
- `POST /auth/recovery/options` and `POST /auth/recovery/verify` — use one unused 256-bit recovery code to register a replacement passkey. On success, all previous passkeys, active sessions, and unused recovery codes are invalidated; ten new recovery codes are issued once.
- `POST /auth/login/options` — issues a short-lived authentication challenge for active owner credentials.
- `POST /auth/login/verify` — verifies the assertion, compare-and-set updates the counter, and issues a session.
- `GET /auth/me` — returns only whether the owner session is active and its expiry.
- `POST /auth/chat` — accepts one bounded latest message plus up to eight recent user/assistant messages held only in browser page memory, with owner-session and CSRF protection, and calls the Free-plan GLM-4.7-Flash model through `env.AI`; it stores no conversation text and exposes no tools. It is protected by per-session, per-IP, and daily HMAC-keyed request limits.
- `POST /auth/logout` — verifies Origin and CSRF, revokes the current session, and clears cookies.
- `POST /auth/logout-all` — verifies Origin and CSRF, revokes every active session, and clears the current cookies.
- `GET /auth/credentials` — returns limited metadata for active owner passkeys.
- `POST /auth/credentials/options` and `POST /auth/credentials/verify` — add another passkey to the existing owner account, requiring an authenticated session, CSRF token, and a passkey-authenticated session no older than five minutes.
- `POST /auth/credentials/revoke` — revokes a selected credential only when another active credential remains; it also requires recent passkey authentication.

Unknown routes and methods remain rejected. No AI command, memory, or external-account endpoint is implemented in this phase. These routes remain undeployed. The smoke test validated D1 storage operations with synthetic data, not the complete live WebAuthn browser ceremony.

## 5. Required security tests

### Registration and origin
- First owner can enroll only while the server-side bootstrap gate is active.
- Enrollment closes after successful first registration; second owner and repeat enrollment are rejected.
- Wrong origin, wrong RP ID, wrong challenge, expired challenge, replayed challenge, invalid signature, missing user presence, and missing user verification are rejected.
- Malformed, oversized, wrong-content-type, and unexpected top-level fields in registration, login, recovery, and credential-management requests are rejected.

### Login and sessions
- Valid assertion creates a session; unknown credential, bad signature, wrong challenge, wrong origin, expired challenge, and replayed assertion fail.
- Credential counter is handled according to WebAuthn semantics and updated atomically.
- Session cookie has Secure, HttpOnly, SameSite=Strict, Path=/, and no Domain.
- Expired, revoked, malformed, or unknown sessions are rejected.
- Logout revokes the session; the same cookie cannot be reused.
- Session IDs never appear in response bodies, URLs, logs, or browser storage.

### Browser and request protections
- CSRF attempt and hostile Origin are rejected for state-changing routes.
- Cross-origin credentialed requests from unapproved origins are rejected.
- Fixed-window IP rate limits apply to enrollment, login, and recovery attempts; per-session HMAC-keyed limits apply to session inspection, credential listing/addition/revocation, and logout routes. The raw IP and session token are not stored in D1 rate-limit buckets.
- Errors do not reveal whether an owner or credential exists.
- No secret or private credential material appears in the public repository or client bundle.

### iPhone acceptance
- Test the full flow in Safari on the owner's iPhone over the final HTTPS origin.
- Confirm passkey creation and sign-in invoke iOS's native passkey sheet and require user verification.
- Confirm cancellation, unavailable passkeys, device restart, expired sessions, and logout fail safely.
- Test a second physical authenticator and the recovery-code ceremony on the owner's iPhone before relying on the system as the sole access method.

## 6. Current implementation status

Implemented on `jarvis-security-hardening`: first-owner passkey registration, passkey login, session inspection, logout and sign-out-everywhere; multi-device credential listing/addition/revocation with last-credential protection; exact configured origin/RP ID checks; bootstrap secret gate; JSON content-type/body-size validation; five-minute single-use challenges with cleanup; D1-backed owner/credential/session helpers; hashed session and CSRF tokens; host-only Secure/HttpOnly session cookie plus reload-persistent CSRF cookie; CSRF verification; 30-minute idle expiry; session rotation after passkey sign-in; five-minute recent-passkey requirement for credential changes; and fail-closed behavior when D1 or origin settings are absent. A same-origin native WebAuthn UI is included. The synthetic route suite now exercises a successful registration/login/session/logout ceremony and negative paths including replay, wrong origin, tampered signatures, CSRF rejection, and owner-enrollment enumeration.

Latest verified CI run #428 passed 25 local SQLite/Node checks and 51 Workers-runtime tests (76 tests total), plus production dependency audit, browser JavaScript syntax validation, and Wrangler dry-run configuration validation. Run: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43883074168. IP and per-session rate limiting are implemented and covered by synthetic tests; unexpected top-level request fields are rejected on protected JSON routes. Still incomplete: end-to-end Worker routing against the deployed authentication code, safe validation of the configured origin/RP ID and secret presence, committed dependency lockfile review, and iPhone Safari acceptance. Offline recovery codes are implemented and synthetically tested, but need owner-device acceptance testing. The remote D1 database exists and its schema is verified; authentication code remains undeployed and no real passkey has been registered. See [Remote D1 Provisioning Gate](REMOTE_D1_PROVISIONING_GATE.md) for the approval-gated next step.

## 7. Release gates

Do not enable authentication or store personal data until all are true:
1. The production hostname, active branch, and deployed code hash are verified.
2. The actual Cloudflare account plan and billing controls are confirmed zero-cost.
3. D1 database limits and account eligibility are checked in the actual account.
4. The pinned library versions pass Worker runtime tests and dependency review.
5. All negative security tests above pass.
6. One-time bootstrap and recovery have been reviewed; no public enrollment remains.
7. The owner completes end-to-end Safari/iPhone testing.

Until then, the only live service capability must remain the non-sensitive health scaffold.
