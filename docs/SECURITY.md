# J.A.R.V.I.S. — Owner Security Design

**Status:** Design only; not implemented or security-audited  
**Scope:** Future private JARVIS service and its iPhone-first client  
**Constraint:** Zero-cost only. Do not activate a paid service, billing, trial, or resource until its cost and limits have been checked.

## Security objective

Only the one enrolled owner may access private JARVIS data or issue privileged commands. Public visitors may see the preview, but public access must never imply access to owner memory, accounts, credentials, or controls.

## Proposed authentication

- Use a standards-based WebAuthn passkey as the primary owner credential. On an iPhone, iOS may ask the owner to approve a passkey with Face ID or the device passcode. Face ID is the local device-unlock step; the server verifies the signed WebAuthn assertion, not a voice match or a claim that Face ID data was sent to JARVIS.
- Do not create public registration, username/password login, shared hard-coded secrets, or a permanent bearer token in browser JavaScript.
- Enroll exactly one owner credential through a deliberate, one-time bootstrap procedure after the service has a verified HTTPS origin and secure persistent storage. Close enrollment immediately after the first credential is registered.
- Bind challenges to the expected origin and relying-party ID; use cryptographically random, short-lived, single-use challenges and verify the challenge, origin, RP ID hash, user-presence and user-verification flags, credential public key, and signature with a maintained WebAuthn implementation.
- Do not write a custom WebAuthn cryptographic verifier. The current candidate is SimpleWebAuthn server 14.1.0 with browser 14.0.0; these are research candidates only, not installed or approved for production. See [Authentication Implementation Plan](AUTHENTICATION_PLAN.md). Test exact versions in the chosen Worker runtime before enabling enrollment.
- Provide a small set of one-time recovery codes only if a safe offline recovery process is designed. Store only salted hashes; show the codes once and never send them by email or log them.

## Session and request protection

- After successful passkey verification, issue a cryptographically random opaque session identifier in a `Secure`, `HttpOnly`, appropriately `SameSite` cookie. Never expose session identifiers to JavaScript, URLs, analytics, or logs.
- Store only a hash of each session identifier. Use short idle and absolute expiry, rotate the session after authentication and privilege changes, and provide owner-initiated logout/revocation.
- Require CSRF protection for state-changing cookie-authenticated requests. Restrict CORS to the exact production client origin; never use wildcard origins with credentials.
- Require HTTPS. Validate method, content type, body size, schema, and every field server-side. Reject unknown commands and unknown fields by default.
- Apply per-IP and per-session rate limits to authentication and command routes. Return generic authentication errors that do not reveal whether a credential or account exists.
- Set conservative security headers on the client (including a restrictive Content Security Policy) and avoid third-party scripts, trackers, and remote fonts on authenticated screens.

## Data and memory protection

- Keep the public `jarvis-preview` repository free of personal data, credentials, session material, and real owner memory. Keep `jarvis-core` private.
- Do not persist personal memory until storage, access controls, backup behavior, deletion behavior, and zero-cost eligibility have been reviewed. A SQLite-backed Durable Object is the current storage candidate for credentials, challenges, and sessions only; it is not yet provisioned or account-verified.
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
5. Implement and test one-owner enrollment, passkey login, session rotation, logout, revocation, CSRF, CORS, rate limits, and recovery.
6. Complete a security review and negative tests before storing any personal information.

Until every gate is met, the service must remain a non-sensitive scaffold. A successful health check is not proof of authentication, privacy, or production readiness.
