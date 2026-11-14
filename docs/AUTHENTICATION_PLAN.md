# J.A.R.V.I.S. — Authentication Implementation Plan

**Status:** Engineering plan only — no authentication code is enabled  
**Owner model:** One enrolled owner, no public sign-up  
**Client:** Safari on iPhone 17 Pro Max  
**Budget:** Zero-cost only; no paid plan, billing, trial, or resource may be enabled

## 1. Selected WebAuthn identity

The owner has selected the existing Cloudflare Worker hostname; no custom domain is owned or required for this development phase.

- **Canonical origin:** `https://jarvis-preview-api.zouabifadi5.workers.dev`
- **WebAuthn RP ID:** `jarvis-preview-api.zouabifadi5.workers.dev` (hostname only; no scheme, path, or trailing slash)
- **Allowed origin:** exact match to the canonical HTTPS origin above
- **Cookie scope:** host-only; omit the `Domain` attribute

Treat this hostname as fixed before the first real passkey is enrolled. A later hostname/RP ID change generally requires owners to enroll new passkeys. Never accept arbitrary origins or RP IDs from request data.

Cloudflare documents `workers.dev` as a free subdomain intended for getting started and personal/hobby projects, and recommends a Workers route or custom domain rather than `workers.dev` for business-critical production workloads. This is therefore the zero-cost development choice, not a claim that the service is production-hardened. Reassess the hostname before storing sensitive personal data or relying on JARVIS for critical operations.

Reference: https://developers.cloudflare.com/workers/configuration/routing/workers-dev/

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

## 2. Persistence candidate

**Candidate: one SQLite-backed Cloudflare Durable Object dedicated to the single owner.**

Cloudflare's current documentation describes Durable Object storage as private to each object, transactional, and strongly consistent. The current Workers Free documentation lists SQLite-backed Durable Objects on Free, with limits including 100,000 Durable Object requests/day, 13,000 GB-seconds/day, 5 million SQL row reads/day, 100,000 SQL row writes/day, and 5 GB total storage. Workers Free itself currently lists 100,000 Worker requests/day and 10 ms CPU per invocation.

This is not proof that the user's account is on the Free plan. The account's actual plan and billing settings must be verified before creating the namespace or deploying a migration. Exceeding Free limits causes operations to fail on Free; do not switch to Paid to resolve that.

References:
- https://developers.cloudflare.com/workers/platform/pricing/
- https://developers.cloudflare.com/durable-objects/platform/limits/
- https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/

The Durable Object would store only:
- one owner record and enrolled passkey public credential(s);
- short-lived, single-use WebAuthn challenges;
- hashed opaque session identifiers with expiry and revocation state;
- minimal security metadata such as credential signature counters and timestamps.

Do not store conversation memory, emails, contacts, or other personal content in this phase.

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
3. Consume the challenge once and update the credential counter in a transaction.
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
3. SQLite Durable Object limits and account eligibility are checked in the actual account.
4. The pinned library versions pass Worker runtime tests and dependency review.
5. All negative security tests above pass.
6. One-time bootstrap and recovery have been reviewed; no public enrollment remains.
7. The owner completes end-to-end Safari/iPhone testing.

Until then, the only live service capability must remain the non-sensitive health scaffold.
