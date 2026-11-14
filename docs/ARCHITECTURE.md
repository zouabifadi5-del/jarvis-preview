# J.A.R.V.I.S. — Architecture Foundation

**Project:** Just A Rather Very Intelligent System  
**Status:** Foundation established; isolated authentication implementation in progress  
**Primary client:** iPhone 17 Pro Max  
**Budget constraint:** Zero-cost development only

## Product principles

1. Owner-first: only the authenticated owner can access private data or privileged controls.
2. Least privilege: integrations receive only the access needed for a specific feature.
3. Approval before consequential actions: sending communications, sharing files, changing security settings, purchases, payments, and destructive actions require explicit confirmation.
4. Privacy by design: never put credentials, API keys, tokens, personal records, or private operational data in this public repository.
5. Honest capability states: the interface must distinguish a prototype, a connected integration, and a working AI service. Never show a capability as active until it has been verified.
6. Zero-cost first: use static hosting, open-source components, and genuinely free tiers. Do not enable paid services, billing, or trials that can auto-charge.

## Initial architecture

- **Backend candidate:** Cloudflare Workers is the provisional host for a small stateless API. The owner has confirmed the account is on Cloudflare Free with no paid Workers subscription or trial; no paid services, billing, or trials may be enabled.
- **Deployment status:** The owner connected the public `jarvis-preview` repository to a Cloudflare Workers project named `jarvis-preview-api` and reported setting its production branch to `jarvis-foundation`. GitHub's repository default branch remains `main`; Cloudflare's production-branch setting is separate. A deployment build was reported as complete, but the branch used by the active version has not been independently verified.
- **Service scaffold:** The live Worker remains unchanged and health-only. The isolated `jarvis-worker-runtime-tests` branch now contains initial passkey registration/login/session/logout handlers, but they are not deployed and fail closed without D1 and explicit origin configuration. The worker does not process AI commands or store memory.


- **iPhone client:** responsive web app/PWA, designed for Safari on iPhone. A PWA can provide an app-like home-screen entry point, but iOS does not permit an ordinary website to continuously listen for a custom wake word in the background.
- **Web interface:** the public demo preview may remain on GitHub Pages. A first-party owner-access interface has now been added under `public/` on the isolated runtime-test branch, with native browser passkey flows and Workers Static Assets configured in `wrangler.toml`; it is designed to share the API hostname and has not been deployed or tested on a real device.
- **Application service:** a separate server-side component will eventually handle AI requests and integration calls. It must keep provider credentials server-side; browser code must never contain secret keys.
- **Identity and authorization:** the proposed design is a single-owner WebAuthn passkey, with server-verified assertions and protected sessions. The login page is planned as a Cloudflare Workers Static Asset on the same `workers.dev` origin as the API, so the browser origin and WebAuthn RP ID match without a custom domain; the existing GitHub Pages preview remains public demo-only. The selected persistence design is one Cloudflare D1 database for credential metadata, one-time challenges, and hashed sessions; the SQL migration is unprovisioned; the owner has confirmed the Cloudflare Free plan, but no remote database has been created. The current code has passed 35 synthetic Workers runtime tests and 15 local SQLite/Node checks, browser JavaScript syntax validation, and a Wrangler dry-run build. This is not an end-to-end or production security audit. On iPhone, a passkey may be unlocked locally with Face ID or the device passcode; biometric data is not sent to JARVIS. Voice recognition alone is not sufficient authorization. See [Owner Security Design](SECURITY.md) and [Authentication Implementation Plan](AUTHENTICATION_PLAN.md).
- **Memory:** explicit, inspectable memory with correction and deletion controls. Sensitive records require encryption and stricter access controls.
- **Integrations:** add calendar, email, files, reminders, and other services one at a time using supported OAuth scopes and user-granted permissions.
- **Automation:** use iOS Shortcuts for supported device-side actions. Background execution and wake-word behavior remain subject to iOS restrictions.

## Permission levels

- **Automatic, low risk:** read authorized information, summarize, research, organize, and prepare task lists.
- **Confirm first:** send messages or emails, modify appointments, share information, or make consequential document changes.
- **Explicit, high-assurance approval:** payments, purchases, bookings involving payment, deleting important data, and security/access changes.

## Deployment and repository boundaries

- `jarvis-preview` is public and must contain only non-sensitive demo code and documentation.
- `jarvis-core` remains private and is not modified as part of this public preview work.
- Never commit secrets. Use server-side environment variables or a secrets manager only after a suitable backend host has been selected.
- GitHub Pages serves static files; it is not an application server and cannot safely hold secret API credentials.

## Phased delivery

1. **Foundation:** document architecture, privacy boundaries, permissions, and repository structure.
2. **Client:** create an accessible, responsive preview command interface with honest status indicators.
3. **Service:** deploy the minimal health-only worker scaffold; verify the live endpoint and confirm the account remains on a zero-cost plan before adding functionality.
4. **AI connection:** connect an AI provider only after confirming a no-cost option and its limits. No paid API is assumed.
5. **Identity and memory:** implement owner authentication, protected memory, and data controls.
6. **Integrations:** add one integration at a time, starting with read-only access and explicit approvals for writes.
7. **iPhone experience:** add PWA installation guidance and supported Shortcuts-based activation.

## Current limitations

The isolated branch contains initial passkey registration/login/session/logout code, additional credential management, and a native browser passkey UI, but no live D1 binding or deployment. Recovery, rate limiting, iPhone Safari acceptance, and real D1 integration remain incomplete.


This repository currently hosts a visual prototype. It is not yet an AI assistant, does not authenticate an owner, does not connect to personal accounts, and does not perform real-world actions. Those features must be implemented and tested before being described as operational.
