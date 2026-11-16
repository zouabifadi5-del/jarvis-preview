# J.A.R.V.I.S. — Architecture Foundation

**Project:** Just A Rather Very Intelligent System  
**Primary client:** iPhone 17 Pro Max  
**Budget:** Zero-cost only  
**Current status (16 November 2026):** Security and stateless chat implementation exists on the isolated `jarvis-security-hardening` branch. It is not deployed, no owner passkey has been enrolled, and no real AI inference or personal-data storage has occurred.

## Product principles

1. **Owner-only:** only the single passkey-authenticated owner may access private data or privileged controls.
2. **Least privilege:** integrations receive only the access needed for a specific feature.
3. **Approval before consequential actions:** sending communications, sharing files, changing security settings, purchases, payments, and destructive actions require explicit confirmation.
4. **Privacy by design:** never put credentials, API keys, tokens, personal records, or private operational data in this public repository.
5. **Honest capability states:** distinguish a prototype, a connected integration, and a working AI service. Never show a capability as active until it has been verified.
6. **Zero-cost first:** use open-source components and genuinely free tiers. Do not enable paid services, billing, or trials that can auto-charge.

## Current deployment boundary

- **Public repository:** `jarvis-preview` contains the public preview and non-sensitive documentation.
- **Development branch:** `jarvis-security-hardening` contains owner authentication, the browser interface, and stateless AI chat. It is not merged into `jarvis-foundation` or `main`, and is not deployed.
- **Live Worker:** Cloudflare Worker `jarvis-preview-api` remains a health-only scaffold. A read-only settings check confirms its D1 and AI binding names and authentication secret binding names, but secret values were not read. The deployed Worker does not yet execute the isolated authentication or chat routes.
- **D1:** account-scoped database `jarvis-owner-auth` has both authentication migrations applied. Six application tables and five supporting indexes were verified. A disposable synthetic table passed create/write/read/delete/drop and cleanup checks; the six application tables remain empty and foreign-key checks were clean. D1 is not branch-isolated, so development code must not assume that the database is isolated by Git branch.
- **CI:** latest verified run #433 passed 25 local SQLite/Node checks and 51 Workers-runtime tests (76 total), production dependency audit, browser JavaScript syntax validation, and Wrangler dry-run validation: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43883308442.

## Components

### iPhone client

- A responsive first-party browser interface is served from Workers Static Assets in the isolated branch.
- Native WebAuthn APIs handle owner enrollment, passkey login, credential management, and recovery.
- The owner-only chat panel keeps up to eight recent user/assistant messages in browser page memory only. It clears on reload or sign-out and is not written to D1 or localStorage.
- The next client step is PWA installation support and a documented iOS Shortcuts/Siri entry point. iOS does not generally allow an ordinary website to continuously listen for a custom wake word in the background.

### Identity and authorization

- Single-owner WebAuthn passkeys, one-time enrollment bootstrap, hashed session and CSRF tokens, secure cookies, idle and absolute expiry, session rotation, individual/global logout, credential revocation, and one-time recovery codes are implemented on the isolated branch.
- Authentication operations use per-IP and HMAC-keyed per-session rate limits. Invalid session cookies cannot allocate persistent per-session buckets.
- State-changing routes require same-origin and CSRF checks. Recent passkey authentication is required for credential changes.
- The implementation is synthetic-tested but not independently security-audited or tested in physical iPhone Safari.

### AI service

- The isolated branch declares the native Workers AI binding and implements an owner-session/CSRF-protected `POST /auth/chat` route.
- Current candidate: `@cf/zai-org/glm-4.7-flash`, listed as Workers Free-eligible by Cloudflare. The account-wide free allocation is 10,000 Neurons per UTC day. JARVIS applies a 50-request-per-owner-per-day ceiling plus per-session and per-IP throttles; this is a safety ceiling, not a guarantee of exact Neuron consumption.
- The chat route has bounded input, up to eight recent in-page messages, a bounded output, and no tools, web access, device control, or persistent chat storage.
- Tests mock `env.AI.run()`. No real inference has been performed, and the deployed Worker has not been switched to this code.
- See [Zero-Cost AI Provider Plan](AI_PROVIDER_PLAN.md).

### Persistent memory

- Persistent memory is not implemented or enabled.
- The design requires AES-256-GCM encryption with a server-only key, owner-controlled save/inspect/correct/export/delete, strict lifecycle controls, and no plaintext in D1 or logs.
- The model may suggest memory candidates, but must not save durable memories without explicit owner confirmation.
- See [Private Memory Design](MEMORY_DESIGN.md).

### Integrations and actions

- No personal accounts, calendar, email, files, or external integrations are connected.
- Start with read-only integrations and narrowly scoped permissions.
- Treat retrieved content and model output as untrusted. Use a server-side action allowlist; never expose arbitrary SQL, shell, filesystem, or unrestricted URL-fetch capabilities.
- Sending messages, sharing information, modifying schedules, financial actions, and security changes require explicit confirmation appropriate to the risk.

## Repository and secrets boundaries

- Keep `jarvis-preview` free of credentials, tokens, personal records, and private owner memory.
- Keep the private core repository separate; do not copy secrets into this public repository.
- Store provider and encryption keys only in server-side secret storage. Never put them in browser code, Wrangler configuration, test fixtures, or CI logs.
- Never read or print secret values during routine configuration checks.

## Phased delivery

1. **Foundation:** repository structure, privacy boundaries, permission model, and zero-cost constraints.
2. **Owner security:** finish independent review, verify the live origin and secret configuration without exposing values, and complete real-D1 and iPhone Safari acceptance tests.
3. **Stateless AI:** perform a low-volume live inference test only after the authentication and deployment gates are satisfied and the owner separately approves it.
4. **Memory:** implement encrypted, owner-controlled memory only after the memory design gates are satisfied.
5. **Integrations:** add one read-only integration at a time; require confirmation for writes and consequential actions.
6. **iPhone experience:** PWA installation and supported Shortcuts/Siri activation; no unsupported always-on custom wake-word claims.

## Release gates

- Verify the exact production hostname, active branch, deployed code hash, and HTTPS behavior.
- Confirm the account remains on a genuinely zero-cost plan and do not enable billing or paid add-ons.
- Exercise authentication against real D1 using disposable synthetic records and clean them up.
- Verify origin/RP settings and secret-binding presence without revealing secret values.
- Complete physical iPhone Safari passkey and recovery testing.
- Complete dependency locking/review and an independent security review.
- Keep personal memory disabled until its encryption, backup, export, and deletion gates are met.

Until these gates are satisfied, the live service remains a non-sensitive health scaffold. A successful health response or passing synthetic tests is not proof of production authentication, privacy, or AI readiness.
