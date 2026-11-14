# Remote D1 provisioning and deployment gate

**Status:** Preparation only. No remote D1 database, Worker secret, binding, migration, or deployment has been created.

## What the authentication database stores

The single D1 database is restricted to:
- The singleton owner marker.
- Passkey credential IDs, public keys, counters, transport metadata, device type, and backup status.
- Short-lived WebAuthn challenges.
- Hashed session and CSRF tokens, expiry, activity, and revocation metadata.

It must not store conversations, prompts, private memory, email, contact lists, or unrelated personal content.

## Required Worker configuration

The isolated branch already configures Workers Static Assets. A D1 binding is not yet present. After explicit owner approval to create the remote database, add a binding named `DB` using the actual database ID returned by Cloudflare.

Required non-secret Worker variables:
- `AUTH_ORIGIN`: the exact HTTPS origin serving the owner page and API.
- `WEBAUTHN_RP_ID`: the hostname only, matching that origin.

Required temporary secret:
- `JARVIS_BOOTSTRAP_SECRET`: a locally generated high-entropy secret of at least 32 characters. Set it through Cloudflare's secret controls; never put its value in Git, a URL, a screenshot, or this repository.

For the currently documented Worker host, the intended values are:
- Origin: `https://jarvis-preview-api.zouabifadi5.workers.dev`
- RP ID: `jarvis-preview-api.zouabifadi5.workers.dev`

These values must be verified against the actual served owner page immediately before first enrollment.

## Approved sequence (not yet authorized)

1. Obtain explicit approval from the owner to create exactly one isolated D1 database named `jarvis-owner-auth` on the confirmed Free plan.
2. Create the database and add the returned ID to the isolated branch's Wrangler D1 binding. Do not add a binding to the live Worker yet.
3. Apply `migrations/0001_owner_auth.sql` to that isolated database and run the real D1 smoke tests.
4. Configure `AUTH_ORIGIN`, `WEBAUTHN_RP_ID`, and the temporary `JARVIS_BOOTSTRAP_SECRET` through Cloudflare controls.
5. Obtain separate explicit approval before deploying the isolated Worker branch.
6. Verify the served page origin, CSP, cookies, and static assets. Only then perform the first passkey enrollment on the owner's iPhone.
7. Immediately after successful first-owner enrollment, remove the temporary `JARVIS_BOOTSTRAP_SECRET` from the Worker. The database's singleton owner marker permanently closes first-owner enrollment.
8. Run the post-enrollment security checks and document the actual deployment version.

## Safety boundaries

- The owner has confirmed Cloudflare Free and no paid Workers subscription/trial. Do not enable billing, paid features, or a trial.
- D1 Free quotas are finite. Monitor usage; do not automatically upgrade if a quota is reached.
- Creating a D1 database is a remote account change and requires explicit approval.
- Deploying or merging is a separate remote action and requires separate explicit approval.
- Do not register a real passkey against an unverified or non-live origin.
- Do not ask the owner to paste the bootstrap secret into chat. The owner should generate and enter it locally through the intended secure setup process.
