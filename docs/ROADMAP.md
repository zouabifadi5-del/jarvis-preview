# J.A.R.V.I.S. — Delivery Roadmap

## Milestone 0 — Repository foundation
- [x] Keep the public preview separate from the private core repository.
- [x] Create the `jarvis-foundation` development branch.
- [x] Document the architecture and security boundaries.
- [ ] Owner review of the first client implementation (awaiting user review).

## Milestone 1 — Usable client
- [x] Responsive mobile-first command interface.
- [x] Clear preview / service-not-connected status.
- [x] Accessible labeled controls and keyboard submission.
- [x] No simulated AI responses or misleading online claims; test input stays local.

## Milestone 2 — Minimal service
- [x] Select Cloudflare Workers as the provisional backend candidate.
- [x] Connect the public preview repository and configure Cloudflare's production branch as `jarvis-foundation`.
- [ ] Verify the active deployment was built from `jarvis-foundation` and serves the health-only worker scaffold.
- [ ] Verify the live `/health` response and independently confirm zero-cost account/billing status.
- [x] Add zero-dependency tests for health, unknown routes, and rejected methods; expanded suite verified locally with Node.js v22.16.0 (6 passed, 0 failed).
- [x] Add no-store, anti-sniffing, frame, referrer, permissions, and HTTPS-only HSTS response headers to the health-only Worker.
- [ ] Keep credentials on the server only.
- [ ] Add request validation before accepting commands.
- [ ] Add rate limiting and safe error handling.

## Milestone 3 — Owner security and memory (current phase)

**Current position (16 November 2026):** The isolated branch contains the owner passkey/authentication implementation and synthetic Workers-runtime tests. The remote `jarvis-owner-auth` D1 database has both migrations recorded; all six expected application tables and five supporting indexes were verified with read-only SQL. A temporary synthetic table was created, written, read, emptied, and dropped successfully. No owner account or real passkey has been enrolled. The authentication branch remains undeployed. Cloudflare reports the live Worker has authentication-related secret bindings by name, but their values were not read or independently validated.
- [x] Document and implement the initial single-owner passkey, session, privacy, and command-approval foundation (not production-ready or security-audited).
- [x] Pin `@simplewebauthn/server@14.1.0` and verify compatibility in the Cloudflare Workers runtime.
- [x] Document the one-owner enrollment/login/session design and negative-test matrix.
- [x] Add a zero-cost, staged authentication test plan: [Authentication Free-Tier Test Plan](AUTHENTICATION_FREE_TIER_TEST_PLAN.md).
- [x] Expand the local Worker scaffold suite to cover security headers, strict route matching, method rejection, no CORS, and HTTP/HSTS behavior.
- [x] Select D1 (rather than Durable Objects) for the small relational auth store and add the SQL schema migration on the isolated test branch.
- [x] Owner confirmed Cloudflare Free plan and created the `jarvis-owner-auth` D1 database; the isolated branch has the `DB` binding configured.
- [x] Owner confirmed applying `migrations/0001_owner_auth.sql` successfully in the remote D1 console.
- [x] Owner confirmed applying `migrations/0002_auth_rate_limits.sql` successfully in the remote D1 console.
- [x] Verify the remote schema: six expected application tables, five supporting indexes, and both migration records are present.
- [x] Run a temporary synthetic D1 create/insert/read/delete/drop smoke test; verify cleanup and zero remaining rows.
- [x] Document the approval-gated D1 provisioning and first-owner enrollment sequence: [Remote D1 Provisioning Gate](REMOTE_D1_PROVISIONING_GATE.md).
- [x] Add initial passkey registration/login/session/logout handlers and fail-closed behavior on the isolated branch.
- [x] Add synthetic Worker tests for origin checks, bootstrap secret, registration/login options, and content-type enforcement.
- [x] Add a synthetic end-to-end success-path test for owner registration, login, session inspection, and logout.
- [x] Add negative route tests for replayed ceremonies, wrong origin, tampered signatures, CSRF failure, and owner-enrollment enumeration.
- [x] Pin `@simplewebauthn/server@14.1.0` and verify synthetic WebAuthn paths in the Cloudflare Workers runtime.
- [x] Add a CI production-dependency advisory audit (`npm audit --omit=dev --audit-level=moderate`); a committed, reviewed lockfile and full transitive dependency review remain outstanding.
- [x] Pass 25 local SQLite/Node checks and 40 Workers runtime tests (65 total), including HMAC-keyed rate-limit enforcement, plus production dependency audit, browser syntax validation, and a Wrangler non-deploying dry run in CI.
- [x] Add a same-origin native browser passkey UI for first-owner setup, sign-in, session status, add/remove passkeys, recovery-code display/copy/download, and sign-out.
- [ ] Complete owner authentication end to end through the deployed Worker and a physical iPhone passkey; D1 storage operations have been smoke-tested, but the real WebAuthn ceremony is not.
- [x] Add multi-device credential listing/addition/revocation with last-passkey protection, reload-persistent CSRF cookie, sign-out-everywhere, recent-passkey confirmation, session rotation, and idle timeout.
- [x] Add ten one-time hashed recovery codes, replacement-passkey recovery, and atomic invalidation of old credentials, sessions, and recovery codes.
- [x] Implement fixed-window D1 rate-limit counters keyed by HMACs of the Cloudflare client IP and auth action; raw IPs are not stored.
- [x] Add per-session HMAC-keyed throttling for session inspection, credential management, and logout routes; raw session tokens are not stored in rate-limit buckets.
- [x] Pass CI tests for IP and per-session rate-limit enforcement, unexpected-field rejection, and local migration/storage validation; latest CI run #419 passed 25 local SQLite/Node checks and 51 Workers-runtime tests (76 total), including rejection of invalid-session rate-limit bucket allocation: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43882778267. Remote migration records, schema, indexes, and synthetic D1 data-path smoke test are verified.
- [ ] Verify the configured `AUTH_ORIGIN`, `WEBAUTHN_RP_ID`, persistent `JARVIS_RATE_LIMIT_HMAC_SECRET`, and temporary `JARVIS_BOOTSTRAP_SECRET` through safe non-disclosing checks; never read or print secret values.
- [ ] Obtain separate explicit owner approval before deploying the isolated Worker branch.
- [ ] Explicit memory review, correction, export, and deletion.
- [ ] Encrypt sensitive data at rest and in transit.

## Milestone 4 — AI and integrations
- [x] Research the Workers AI Free allocation and shortlist Free-eligible models; document cost, quota, privacy, and test boundaries in [AI Provider Plan](AI_PROVIDER_PLAN.md). No inference request has been made.
- [x] Implement a stateless, passkey-protected chat route and owner-only in-memory chat UI; tests use a mocked AI binding and never invoke real inference.
- [x] Add per-session and per-IP chat throttles plus a 50-request UTC-day owner budget using HMAC-derived D1 buckets.
- [ ] Test model quality in Tunisian Arabic, French, English, and tool-call accuracy with non-sensitive prompts; no live inference in CI.
- [ ] Start with read-only connectors.
- [ ] Require confirmation for messages, sharing, schedule changes, and destructive actions.
- [ ] Require strong confirmation for financial and security actions.

## Non-negotiable constraints
- iPhone-first; no Mac is assumed.
- Zero-cost development; do not enable billing or paid trials.
- Never commit API keys, OAuth secrets, passwords, tokens, or private personal data.
- Do not claim a feature works until it has been tested end to end.
- iOS does not generally allow a third-party web app to continuously listen for a custom wake word in the background. Use supported Shortcuts/Siri entry points instead.
