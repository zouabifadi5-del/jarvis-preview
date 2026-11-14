# J.A.R.V.I.S. — Authentication Implementation Plan

**Status:** Engineering plan plus a non-functional static shell on the isolated test branch — no authentication code is enabled  
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

Cloudflare documents Workers Static Assets as free and unlimited for asset requests, with no additional asset storage charge. Requests that invoke the Worker script remain subject to the Workers Free request limit. A non-functional static owner-access shell and Workers Static Assets configuration have been added to the isolated test branch only. They have not been deployed; the live Worker remains unchanged.

The RP ID and exact origin must be rechecked against the actual served login page before the first real passkey is enrolled. Wrangler's non-deploying build validation has passed for the current static asset configuration, but that does not prove the page is live or validate a real browser ceremony. Never accept origin or RP ID values supplied by a request. Changing the hostname after enrollment generally requires enrolling new passkeys.

References:
- https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
- https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/
- https://developers.cloudflare.com/workers/static-assets/

## 1. Library selection

**Preferred candidate:**
- Server: `@simplewebauthn/server@14.1.0`
- Browser: `@simplewebauthn/browser@14.0.0`
- Licence: MIT for both packages.
- The server package's current JSR documentation explicitly lists Cloudflare Workers as a supported runtime. The browser package targets modern browsers.

These are candidate versions, not installed dependencies. Pin exact versions and commit a lockfile only after a clean Worker-runtime compatibility test. Review release notes and advisories again at implementation time. Do not load a third-party CDN script on authenticated pages; bundle the browser package with the client.

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

The owner has confirmed that the Cloudflare account is on the Free plan and has no paid Workers subscription or trial. This is an owner-provided confirmation, not an independent inspection of account billing controls. No database has been created. Never upgrade or enable billing to overcome a quota; stop if any unexpected paid prompt or requirement appears.

References:
- https://developers.cloudflare.com/d1/platform/pricing/
- https://developers.cloudflare.com/d1/platform/limits/
- https://developers.cloudflare.com/durable-objects/platform/pricing/

The unprovisioned schema proposal is [migrations/0001_owner_auth.sql](../migrations/0001_owner_auth.sql). It stores only:
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
1. Generate authentication options for the enrolled credential(s), with a new random five-minute challenge and user verification required.
2. Verify the assertion server-side against the stored public key, expected challenge, exact origin, exact RP ID, and current credential counter.
3. Atomically consume the challenge once (a replay must return no row); update the credential counter with a compare-and-set write so concurrent assertions cannot silently overwrite a newer counter.
4. Generate a cryptographically random opaque session ID. Store only its hash and expiry.
5. Set a host-only `Secure; HttpOnly; SameSite=Strict` cookie with `Path=/`; omit `Domain`. Use a short idle timeout and an absolute expiry. Rotate after authentication and privilege changes.

### Session and logout
- A session lookup must reject expired or revoked sessions.
- Logout revokes the stored session and clears the cookie.
- Provide a way to revoke all sessions if the device is lost.
- Protect state-changing cookie-authenticated requests with CSRF tokens and strict Origin checks.
- Restrict CORS to the exact trusted client origin; no wildcard credentialed CORS.
- Never place tokens in URLs, browser storage, logs, or client JavaScript.

## 4. Proposed route contract

All routes are JSON over HTTPS, with strict body-size and schema validation:
- `POST /auth/enroll/options` — available only during controlled bootstrap.
- `POST /auth/enroll/verify` — validates and consumes the one-time enrollment challenge.
- `POST /auth/login/options` — issues a short-lived authentication challenge.
- `POST /auth/login/verify` — verifies the assertion and issues the session cookie.
- `GET /auth/session` — returns only whether the owner session is valid; no secrets.
- `POST /auth/logout` — revokes the current session and clears its cookie.

Unknown routes and methods remain rejected. No AI command endpoint is added in this phase.

## 5. Required security tests

### Registration and origin
- First owner can enroll only while the server-side bootstrap gate is active.
- Enrollment closes after successful first registration; second owner and repeat enrollment are rejected.
- Wrong origin, wrong RP ID, wrong challenge, expired challenge, replayed challenge, invalid signature, missing user presence, and missing user verification are rejected.
- Malformed, oversized, wrong-content-type, and unexpected-field requests are rejected.

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
- Rate limits apply to enrollment and login attempts.
- Errors do not reveal whether an owner or credential exists.
- No secret or private credential material appears in the public repository or client bundle.

### iPhone acceptance
- Test the full flow in Safari on the owner's iPhone over the final HTTPS origin.
- Confirm passkey creation and sign-in invoke iOS's native passkey sheet and require user verification.
- Confirm cancellation, unavailable passkeys, device restart, expired sessions, and logout fail safely.
- Test a second supported authenticator/recovery route before relying on the system as the sole access method.

## 6. Release gates

Do not enable authentication or store personal data until all are true:
1. The production hostname, active branch, and deployed code hash are verified.
2. The actual Cloudflare account plan and billing controls are confirmed zero-cost.
3. D1 database limits and account eligibility are checked in the actual account.
4. The pinned library versions pass Worker runtime tests and dependency review.
5. All negative security tests above pass.
6. One-time bootstrap and recovery have been reviewed; no public enrollment remains.
7. The owner completes end-to-end Safari/iPhone testing.

Until then, the only live service capability must remain the non-sensitive health scaffold.
