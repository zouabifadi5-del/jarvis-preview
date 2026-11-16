# J.A.R.V.I.S. — Owner Security Design

**Status (16 November 2026):** Partially implemented on an isolated test branch; not deployed or security-audited. Remote D1 schema and synthetic data-path smoke test are verified, but auth routes have not been exercised end to end against the deployed Worker.  
**Scope:** Future private JARVIS service and its iPhone-first client  
**Constraint:** Zero-cost only. Do not activate a paid service, billing, trial, or resource until its cost and limits have been checked.

## Security objective

Only the one enrolled owner may access private JARVIS data or issue privileged commands. Public visitors may see the preview, but public access must never imply access to owner memory, accounts, credentials, or controls.

## Proposed authentication

- Use a standards-based WebAuthn passkey as the primary owner credential. The current UI uses native `navigator.credentials.create()` and `navigator.credentials.get()` APIs and keeps the bootstrap secret only in the input/request memory; it does not use localStorage or sessionStorage. Initial registration, login, session inspection, individual/global logout, credential management, and one-time recovery-code routes now exist on the isolated branch, with a same-origin native WebAuthn browser UI. Synthetic registration, login, session, and recovery ceremonies pass in the Cloudflare Workers runtime; the real iPhone Safari ceremony and real D1 storage have not been exercised. On an iPhone, iOS may ask the owner to approve a passkey with Face ID or the device passcode. Face ID is the local device-unlock step; the server verifies the signed WebAuthn assertion, not a voice match or a claim that Face ID data was sent to JARVIS.
- Do not create public registration, username/password login, shared hard-coded secrets, or a permanent bearer token in browser JavaScript. Initial owner registration requires a server-side bootstrap secret; it must be generated and configured only after explicit approval and must never be committed.
- Enroll exactly one owner identity through a deliberate, one-time bootstrap procedure after the login page is served from the same HTTPS Worker origin as the API and secure persistent storage is verified. The planned origin is `https://jarvis-preview-api.zouabifadi5.workers.dev` with RP ID `jarvis-preview-api.zouabifadi5.workers.dev`; re-verify the live page origin before enrollment. The GitHub Pages preview is not an authentication origin. Close enrollment immediately after the first credential is registered.
- Bind challenges to the expected origin and relying-party ID; use cryptographically random, short-lived, single-use challenges and verify the challenge, origin, RP ID hash, user-presence and user-verification flags, credential public key, and signature with a maintained WebAuthn implementation.
- Do not write a custom WebAuthn cryptographic verifier. The pinned server dependency is SimpleWebAuthn 14.1.0; it is exercised by the isolated Workers runtime tests and production dependency audit, but has not received a full security review or real-D1 acceptance. The browser uses native WebAuthn APIs. See [Authentication Implementation Plan](AUTHENTICATION_PLAN.md).
- Generate ten high-entropy one-time recovery codes at first-owner enrollment. Store only SHA-256 hashes, show the plaintext codes once, and require the owner to save them offline. Recovery consumes one code and a new passkey ceremony, revokes all old passkeys and sessions, invalidates the remaining old codes, and issues ten replacement codes. Never email or log recovery codes. If all passkeys and all recovery codes are lost, there is no automated recovery path.

## Session and request protection

- After successful passkey verification, issue a cryptographically random opaque session identifier in a host-only `Secure; HttpOnly; SameSite=Strict; Path=/` cookie. Issue a separate host-only `Secure; SameSite=Strict; Path=/` CSRF cookie readable by same-origin JavaScript; store only the CSRF token hash server-side. Never expose session identifiers to JavaScript, URLs, analytics, or logs.
- Store only a hash of each session identifier. Use a 30-minute idle timeout and an 8-hour absolute expiry, rotate the browser session after successful passkey authentication, and provide owner-initiated individual and global logout/revocation.
- Require CSRF protection for state-changing cookie-authenticated requests. Restrict CORS to the exact production client origin; never use wildcard origins with credentials.
- Require HTTPS. Validate method, content type, body size, and request-body fields server-side; reject unexpected top-level fields on registration, login, recovery, and credential-management JSON requests. Reject unknown commands by default.
- Apply fixed-window per-IP rate limits to registration, login, and recovery endpoints. Authenticated session operations use HMAC-derived per-session buckets only after confirming the session is active; arbitrary invalid session cookies cannot allocate persistent buckets; a regression test confirms no bucket is created for a fabricated session cookie. The raw session token is not stored in the rate-limit table. Coverage includes session inspection, credential listing/addition/revocation, logout/sign-out-everywhere, and chat. Chat also has a 30-per-IP-per-minute limit and a 50-request per-owner UTC-day budget, using a stable HMAC bucket shared across sessions. The synthetic Workers-runtime tests cover POST logout throttling, same-origin GET session inspection without an Origin header, and the daily AI cap. Return generic authentication errors that do not reveal whether a credential or account exists.
- Set conservative security headers on the client (including a restrictive Content Security Policy) and avoid third-party scripts, trackers, and remote fonts on authenticated screens.

## Data and memory protection

- Keep the public `jarvis-preview` repository free of personal data, credentials, session material, and real owner memory. Keep `jarvis-core` private.
- Do not persist personal memory or chat transcripts until storage, access controls, backup behavior, deletion behavior, and zero-cost eligibility have been reviewed. The isolated branch now contains AES-256-GCM encrypted memory CRUD/inspect/export/delete API routes with synthetic tests. These routes remain fail-closed unless the owner explicitly accepts the D1 seven-day Time Travel retention window and a server-side encryption key is configured. Memory is not enabled, migration 0003 is not applied to remote D1, and no real owner memory is stored. The iPhone-first UI supports explicit save/list/inspect/edit/export/delete, with recent passkey checks before writes; a one-tap disable control, model retrieval, key-rotation workflow, and management audit trail remain outstanding. Creation, editing, export, and deletion require a recent passkey session; a regression test now verifies that stale sessions cannot create memories. A stateless `POST /auth/chat` route invokes the Workers AI Free-eligible GLM-4.7-Flash model only after owner-session and CSRF checks. It sends a bounded prompt, caps the response, and stores no conversation text. The route has no tools or external action capability; tests stub the AI binding, and no real inference has been performed. A Cloudflare D1 database is provisioned for credentials, challenges, sessions, recovery-code hashes, and rate-limit buckets only; both authentication schema migrations are applied and read-only verified. The encrypted-memory migration is local to the isolated branch and has not been applied remotely. Important: D1 is account-scoped, not branch-scoped. The security branch and deployed Worker settings reference the same database ID, although the currently deployed Worker source remains a health-only scaffold and does not use the authentication routes. Do not treat the branch as a database isolation boundary. The owner has confirmed Free plan and no paid Workers subscription/trial; this remains owner-provided confirmation.
- Minimize stored data. Give the owner controls to inspect, correct, export, and delete memory. Deletion must cover derived indexes and backups according to a documented retention policy.
- Encrypt sensitive records at rest with a key held only in server-side secret storage; never commit encryption keys or place them in client code. HTTPS protects data in transit.
- Do not log prompts, message bodies, memory contents, tokens, recovery codes, or provider secrets. Keep only minimal operational metadata with a defined retention period.

## Command authorization

- Read-only actions may run only within explicitly granted scopes.
- Sending messages, changing appointments, sharing files, or modifying important records requires a clear confirmation describing the exact action and target.
- Payments, purchases, deletion of important data, security changes, and access grants require a separate high-assurance confirmation and must never be triggered by voice recognition alone.
- Treat retrieved documents, web pages, emails, and model outputs as untrusted data, not as authorization or executable instructions.
- Maintain a server-side allowlist of supported actions. Never expose arbitrary shell, SQL, filesystem, or unrestricted URL-fetch capabilities to a model.

## Threats and mitigations

| Threat | Required mitigation |
|---|---|
| Public visitor or automated bot | No public registration; passkey-gated private routes; rate limits |
| Stolen session cookie | HttpOnly/Secure cookie, short expiry, rotation, revocation, CSRF defense |
| Fake or replayed login challenge | Random, short-lived, single-use challenge bound to origin and RP ID |
| Malicious web content or prompt injection | Treat external content as untrusted; server-side action allowlist and explicit approvals |
| Accidental secret publication | Keep secrets out of Git; use server-side secret storage; rotate immediately if exposed |
| Compromised device | Device passcode/Face ID, short sessions, logout/revocation, no unattended high-risk actions |
| Data exposure through logs/backups | Data minimization, no content logging, encryption, retention and deletion policy |

## Deployment gates — all required before private data is enabled

1. Confirm the exact production origin, active branch, deployed code version, and HTTPS behavior.
2. Verify the hosting account remains on a genuinely zero-cost plan; do not enable billing or paid add-ons.
3. Choose storage only after checking its current free limits, data location, access model, retention, and deletion semantics.
4. Select and test a maintained WebAuthn verifier compatible with the runtime.
5. Complete one-owner enrollment, passkey login, session rotation, logout, credential revocation, CSRF, recovery-code replacement, sign-out-everywhere, and owner-only stateless chat tests. IP, per-session, and daily AI rate limits are implemented and synthetically tested. Before production, exercise the code against real D1 using disposable synthetic records, verify secret values and the live origin, test the real Safari/iPhone ceremony, review dependency locking, and complete an independent security review.
6. Complete a security review and negative tests before storing any personal information.

Until every gate is met, the service must remain a non-sensitive scaffold. A successful health check is not proof of authentication, privacy, or production readiness.
