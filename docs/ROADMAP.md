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
- [x] Add a CI production-dependency advisory audit (`npm audit --omit=dev --audit-level=moderate`); a committed lockfile is now used with `npm ci`; full transitive dependency review remains outstanding.
- [x] Pass 31 local SQLite/Node checks and 55 Workers runtime tests (86 total), including HMAC-keyed rate-limit enforcement, plus production dependency audit, browser syntax validation, and a Wrangler non-deploying dry run in CI.
- [x] Add a same-origin native browser passkey UI for first-owner setup, sign-in, session status, add/remove passkeys, recovery-code display/copy/download, and sign-out.
- [ ] Complete owner authentication end to end through the deployed Worker and a physical iPhone passkey; D1 storage operations have been smoke-tested, but the real WebAuthn ceremony is not.
- [x] Add multi-device credential listing/addition/revocation with last-passkey protection, reload-persistent CSRF cookie, sign-out-everywhere, recent-passkey confirmation, session rotation, and idle timeout.
- [x] Add ten one-time hashed recovery codes, replacement-passkey recovery, and atomic invalidation of old credentials, sessions, and recovery codes.
- [x] Implement fixed-window D1 rate-limit counters keyed by HMACs of the Cloudflare client IP and auth action; raw IPs are not stored.
- [x] Add per-session HMAC-keyed throttling for session inspection, credential management, and logout routes; raw session tokens are not stored in rate-limit buckets.
- [x] Pass CI tests for IP and per-session rate-limit enforcement, unexpected-field rejection, and local migration/storage validation; latest CI run  #609 passed 35 local SQLite/Node checks and 57 Workers-runtime tests (92 total), including invalid-session bucket protection, AES-GCM tamper checks, versioned keyring parsing and lazy re-encryption on edit, encrypted-memory CRUD/export/delete flows, atomic 100-active-memory cap, lazy expiry cleanup on list/save, explicit enable/disable, bounded per-request memory retrieval (five records / 4,000 UTF-8 bytes), rejection when memory is disabled, one-message UI consent, and a synthetic Worker-entrypoint journey covering owner registration, passkey login, authenticated AI chat, anonymous-chat rejection, encrypted memory enable/save/inspect/delete/disable, and logout, including checks that memory is not injected by default, retrieved memory is untrusted context, and chat is rejected after logout before inference (mock AI and synthetic memory key only): https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43905008378. Remote migration records, schema, indexes, and synthetic D1 data-path smoke test are verified.
- [ ] Verify the configured `AUTH_ORIGIN`, `WEBAUTHN_RP_ID`, persistent `JARVIS_RATE_LIMIT_HMAC_SECRET`, and temporary `JARVIS_BOOTSTRAP_SECRET` through safe non-disclosing checks; never read or print secret values.
- [ ] Obtain separate explicit owner approval before deploying the isolated Worker branch.
- [x] Document encrypted, owner-controlled memory lifecycle and release gates in [Private Memory Design](MEMORY_DESIGN.md); persistent memory remains disabled.
- [x] Implement AES-256-GCM encrypted memory storage and owner CRUD/inspect/export/delete API routes with synthetic tests; activation is blocked unless the explicit seven-day D1 retention acceptance flag and server-side key are configured.
- [x] Encrypt memory payloads at rest with AES-256-GCM and protect transport with HTTPS; explicit enable and one-tap disable are implemented. Key rotation, management audit events, bounded chat retrieval, and independent review remain outstanding. Expired records are lazily pruned when the owner lists or saves memories; there is no background scheduled cleanup.
- [x] Build the owner-facing memory review/edit/export/delete interface; memory writes require recent passkey confirmation in both UI and API.
- [x] Add explicit owner-controlled memory enable and one-tap disable controls; persistent memory remains disabled until separate release gates pass.
- [x] Add bounded, per-request opt-in chat retrieval (maximum five recent memories / 4,000 UTF-8 bytes); default chat remains memory-free and retrieved text is untrusted reference data.
- [ ] Independently review the retrieval and key-rotation design; keep real memory disabled until release gates pass.

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
