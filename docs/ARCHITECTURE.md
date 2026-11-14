# J.A.R.V.I.S. — Architecture Foundation

**Project:** Just A Rather Very Intelligent System  
**Status:** Foundation planning  
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

- **Backend candidate:** Cloudflare Workers is the provisional host for a small stateless API. The account's billing status and free-plan eligibility have not yet been independently verified; do not enable paid services, billing, or trials.
- **Deployment status:** The owner connected the public `jarvis-preview` repository to a Cloudflare Workers project named `jarvis-preview-api`, configured its production branch as `jarvis-foundation`, and observed a successful deployment build. GitHub's repository default branch remains `main`; Cloudflare's production-branch setting is separate.
- **Service scaffold:** `src/worker.js` exposes only a non-sensitive `/health` response. The deployment build succeeded, but the live `/health` response has not yet been verified. The worker does not process commands, authenticate users, store memory, or call an AI provider.


- **iPhone client:** responsive web app/PWA, designed for Safari on iPhone. A PWA can provide an app-like home-screen entry point, but iOS does not permit an ordinary website to continuously listen for a custom wake word in the background.
- **Web interface:** static HTML/CSS/JavaScript hosted through GitHub Pages for the public preview. The preview must contain no private user data or secrets.
- **Application service:** a separate server-side component will eventually handle AI requests and integration calls. It must keep provider credentials server-side; browser code must never contain secret keys.
- **Identity and authorization:** authenticate the owner before accessing private features. Face ID can be used through supported iOS authentication flows, but voice recognition alone is not sufficient authorization for sensitive actions.
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

This repository currently hosts a visual prototype. It is not yet an AI assistant, does not authenticate an owner, does not connect to personal accounts, and does not perform real-world actions. Those features must be implemented and tested before being described as operational.
