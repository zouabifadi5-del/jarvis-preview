# JARVIS — iPhone-only implementation

**Active direction:** iPhone-only client. This replaces the previous OpenClaw/desktop-host exploration for the current release.
**Branch:** `jarvis-iphone-only`
**Budget:** Zero cost only. Never enable Workers Paid, AI Gateway prepaid credits, paid APIs, subscriptions, trials, or billing.

## Product shape

JARVIS is a first-party installable web app (PWA) designed for Safari on the owner's iPhone. It is not an OpenClaw Gateway client and does not require a Mac, PC, home server, or continuously running computer.

The PWA provides:
- An owner-only sign-in surface using the existing WebAuthn passkey implementation.
- An authenticated chat interface.
- A server-side Cloudflare Workers AI call so no model key is placed in browser code.
- In-page spoken playback using the browser speech synthesis API where supported.
- An offline cached app shell; AI requests still require an internet connection.
- No persistent conversation history in this first release. The current chat stays in page memory and is discarded when the page is closed/reloaded or the user signs out.

## Free inference

The Worker uses the Cloudflare Workers AI binding and the `@cf/google/gemma-4-26b-a4b-it` model. Cloudflare's pricing documentation lists a free allocation of 10,000 Neurons per day on Workers Free. On Workers Free, once the free allocation is exhausted, inference requests fail until reset; the code has no paid fallback. Never switch the account to Workers Paid or buy AI Gateway credits.

Cloudflare AI is hosted inference, not on-device inference. Prompts sent to JARVIS are processed by Cloudflare to generate replies. Do not send highly sensitive information until the owner has reviewed Cloudflare's current data-handling terms and consciously accepted this trade-off.

References:
- https://developers.cloudflare.com/workers-ai/platform/pricing/
- https://developers.cloudflare.com/workers/wrangler/configuration/#workers-ai
- https://developers.cloudflare.com/workers-ai/get-started/workers-wrangler/

## Security boundaries

- Chat API is same-origin and requires an active D1-backed owner session plus CSRF verification.
- The system prompt is server-controlled; clients cannot supply system or developer roles.
- Request size, number of messages, and message lengths are bounded.
- Conversation content is not written to D1 by this release.
- No API keys or provider secrets are exposed to the iPhone.
- The assistant cannot execute iPhone actions, read contacts, access photos, send messages, or control settings in this release.
- No unauthenticated assistant endpoint is provided.
- The PWA service worker caches only static app-shell assets. It never caches authentication or assistant API requests.

## iOS capability limits

A PWA is the best no-Mac route to a home-screen app, but it is not equivalent to a native Swift app:
- iOS does not permit a normal website/PWA to continuously listen for a custom wake word while backgrounded.
- Siri Shortcuts can be used as an activation route, subject to what the Shortcuts app and current iOS version expose. A shortcut can open JARVIS, but a seamless always-listening custom wake phrase cannot be promised.
- Speech synthesis is available in many iOS Safari contexts, but must be tested on the owner's device.
- The app must be opened at least once online to authenticate and use hosted AI. Cached shell does not mean offline AI.

If always-on custom wake-word activation, fully local AI, or deep device control becomes mandatory, a native iOS app and Apple's supported APIs may be required. Building/signing that app normally requires Xcode on a Mac; this branch deliberately avoids that dependency.

## Deployment and owner actions still required

The GitHub branch is not the deployed Worker. Before the owner can test a real chat:
1. Confirm the Cloudflare account remains on Workers Free.
2. Confirm the D1 database binding and both auth migrations actually exist in the target account; repository notes alone are not proof.
3. Configure the exact `AUTH_ORIGIN`, `WEBAUTHN_RP_ID`, and the required auth secrets using Cloudflare's dashboard, never Git.
4. Enable the Workers AI binding on the same Worker; the Wrangler configuration declares it.
5. Review the final code and explicitly authorize deployment of `jarvis-iphone-only`.
6. Verify `/health`, passkey enrollment/login on iPhone Safari, authenticated chat, free quota behavior, logout, and Home Screen installation.
7. Remove the one-time bootstrap secret immediately after first owner enrollment.

Do not merge this branch into `main` or `jarvis-foundation` as part of the first test deployment. Keep the existing foundation and auth branches intact.

## Current status

Implemented in source on `jarvis-iphone-only`:
- iPhone-first owner-access UI with PWA manifest and service-worker app-shell cache.
- Chat UI and in-memory conversation state.
- Owner-authenticated `POST /assistant/chat` endpoint with same-origin, session, and CSRF checks.
- Server-controlled assistant prompt and bounded chat request validation.
- Cloudflare Workers AI binding configured for the free allocation; no paid fallback.
- Spoken playback button using browser speech synthesis.
- CI workflow expanded to run on this branch and check all new JavaScript files.

Not yet confirmed:
- GitHub Actions result for this new branch.
- Real Cloudflare Worker deployment and AI binding availability.
- Real D1 binding and passkey ceremony on the owner's iPhone.
- Actual inference request against the owner's Cloudflare Free account.
- Safari Home Screen installation and speech playback on the physical iPhone.
- Siri Shortcut handoff and any limitations in the current iOS release.

No claim of a working live assistant is valid until those checks pass.
