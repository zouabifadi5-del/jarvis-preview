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

**Current position:** The local authentication implementation and synthetic route tests are complete. The next gated step is creating one remote D1 database for a real binding smoke test; this requires explicit owner approval and does not include deployment.
- [x] Document and implement the initial single-owner passkey, session, privacy, and command-approval foundation (not production-ready or security-audited).
- [x] Pin `@simplewebauthn/server@14.1.0` and verify compatibility in the Cloudflare Workers runtime.
- [x] Document the one-owner enrollment/login/session design and negative-test matrix.
- [x] Add a zero-cost, staged authentication test plan: [Authentication Free-Tier Test Plan](AUTHENTICATION_FREE_TIER_TEST_PLAN.md).
- [x] Expand the local Worker scaffold suite to cover security headers, strict route matching, method rejection, no CORS, and HTTP/HSTS behavior.
- [x] Select D1 (rather than Durable Objects) for the small relational auth store; add an unprovisioned SQL schema migration on the isolated test branch.
- [x] Owner confirmed Cloudflare Free plan and no paid Workers subscription/trial; separate approval is still required before creating D1.
- [x] Document the approval-gated D1 provisioning and first-owner enrollment sequence: [Remote D1 Provisioning Gate](REMOTE_D1_PROVISIONING_GATE.md).
- [x] Add initial passkey registration/login/session/logout handlers and fail-closed behavior on the isolated branch.
- [x] Add synthetic Worker tests for origin checks, bootstrap secret, registration/login options, and content-type enforcement.
- [x] Add a synthetic end-to-end success-path test for owner registration, login, session inspection, and logout.
- [x] Add negative route tests for replayed ceremonies, wrong origin, tampered signatures, CSRF failure, and owner-enrollment enumeration.
- [x] Pin `@simplewebauthn/server@14.1.0` and verify synthetic WebAuthn paths in the Cloudflare Workers runtime.
- [x] Add a CI production-dependency advisory audit (`npm audit --omit=dev --audit-level=moderate`); a committed, reviewed lockfile and full transitive dependency review remain outstanding.
- [x] Pass 23 local SQLite/Node checks, 39 Workers runtime tests, production dependency audit, browser syntax validation, and a Wrangler non-deploying dry run in CI (62 test cases total).
- [x] Add a same-origin native browser passkey UI for first-owner setup, sign-in, session status, add/remove passkeys, recovery-code display/copy/download, and sign-out.
- [ ] Complete owner authentication end to end against a real D1 binding and a physical iPhone passkey; the browser interface is not deployed or device-tested.
- [x] Add multi-device credential listing/addition/revocation with last-passkey protection, reload-persistent CSRF cookie, sign-out-everywhere, recent-passkey confirmation, session rotation, and idle timeout.
- [x] Add ten one-time hashed recovery codes, replacement-passkey recovery, and atomic invalidation of old credentials, sessions, and recovery codes.
- [ ] Add login rate limits and real D1 binding tests.
- [ ] Explicit memory review, correction, export, and deletion.
- [ ] Encrypt sensitive data at rest and in transit.

## Milestone 4 — AI and integrations
- [ ] Verify a no-cost AI path and its limitations before integration.
- [ ] Start with read-only connectors.
- [ ] Require confirmation for messages, sharing, schedule changes, and destructive actions.
- [ ] Require strong confirmation for financial and security actions.

## Non-negotiable constraints
- iPhone-first; no Mac is assumed.
- Zero-cost development; do not enable billing or paid trials.
- Never commit API keys, OAuth secrets, passwords, tokens, or private personal data.
- Do not claim a feature works until it has been tested end to end.
- iOS does not generally allow a third-party web app to continuously listen for a custom wake word in the background. Use supported Shortcuts/Siri entry points instead.
