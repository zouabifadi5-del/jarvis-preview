# Remote D1 provisioning and deployment gate

**Status:** The owner-auth D1 database has been created on the Cloudflare Free plan, and the isolated branch's Wrangler config contains its `DB` binding. The owner confirmed that migrations `0001_owner_auth.sql` and `0002_auth_rate_limits.sql` were both applied successfully in the remote D1 console. The read-only schema verification output and real D1 smoke tests remain unconfirmed. No Worker secrets or variables have been configured, and no Worker deployment has been performed.

## Provisioned database

- Name: `jarvis-owner-auth`
- Binding: `DB`
- Database ID: `2bee8195-488a-4c73-ba42-d21950e890c4`
- Scope: isolated `jarvis-worker-runtime-tests` branch only; do not add this binding to the live Worker.

## What the authentication database stores

The single D1 database is restricted to:
- The singleton owner marker.
- Passkey credential IDs, public keys, counters, transport metadata, device type, and backup status.
- Short-lived WebAuthn challenges.
- Hashed session and CSRF tokens, expiry, activity, and revocation metadata.
- Hashed one-time recovery codes and their use/replacement metadata; plaintext codes are shown only once during enrollment or recovery.
- HMAC-derived rate-limit bucket identifiers, fixed-window counters, and expiry metadata; raw client IP addresses are not stored.

It must not store conversations, prompts, private memory, email, contact lists, or unrelated personal content.

## Required Worker configuration

The isolated branch configures Workers Static Assets and the D1 binding above.

Required non-secret Worker variables:
- `AUTH_ORIGIN`: the exact HTTPS origin serving the owner page and API.
- `WEBAUTHN_RP_ID`: the hostname only, matching that origin.

Required temporary secret:
- `JARVIS_BOOTSTRAP_SECRET`: a locally generated high-entropy secret of at least 32 characters. Set it through Cloudflare's secret controls; never put its value in Git, a URL, a screenshot, or this repository. Remove it immediately after first-owner enrollment succeeds.
- `JARVIS_RATE_LIMIT_HMAC_SECRET`: a separate, persistent, locally generated high-entropy secret of at least 32 characters. It HMACs the Cloudflare-provided client IP and action group so raw IP addresses are not stored in D1. Keep it configured after enrollment; never reuse the bootstrap secret.

For the currently documented Worker host, the intended values are:
- Origin: `https://jarvis-preview-api.zouabifadi5.workers.dev`
- RP ID: `jarvis-preview-api.zouabifadi5.workers.dev`

These values must be verified against the actual served owner page immediately before first enrollment.

## Remaining approval-gated sequence

1. Confirm the read-only schema query returns the six expected tables and the expiry index; perform real D1 smoke tests for both migrations.
2. Configure `AUTH_ORIGIN`, `WEBAUTHN_RP_ID`, temporary `JARVIS_BOOTSTRAP_SECRET`, and persistent `JARVIS_RATE_LIMIT_HMAC_SECRET` through Cloudflare controls.
3. Obtain separate explicit owner approval before deploying the isolated Worker branch.
4. Verify the served page origin, CSP, cookies, and static assets. Only then perform the first passkey enrollment on the owner's iPhone.
5. Immediately after successful first-owner enrollment, remove the temporary `JARVIS_BOOTSTRAP_SECRET` from the Worker. The database's singleton owner marker permanently closes first-owner enrollment.
6. Run the post-enrollment security checks and document the actual deployment version.

## Safety boundaries

- Keep the Cloudflare account on the Free plan. Do not enable billing, paid features, or a trial.
- D1 Free quotas are finite. Monitor usage; do not automatically upgrade if a quota is reached.
- Deploying or merging is a separate remote action and requires separate explicit approval.
- Do not register a real passkey against an unverified or non-live origin.
- Do not ask the owner to paste the bootstrap secret into chat. The owner should generate and enter it locally through the intended secure setup process.
