# Remote D1 provisioning and deployment gate

**Status:** The remote D1 database `jarvis-owner-auth` exists. Both migrations were applied directly and their history was recorded; a read-only query verified all six application tables and five expected indexes. A temporary synthetic table passed create/insert/read/delete/drop testing and was confirmed absent afterward. All six application tables remain empty, and `PRAGMA foreign_key_check` returned no violations. The deployed Worker settings list `DB`, `AI`, `AUTH_ORIGIN`, `WEBAUTHN_RP_ID`, `JARVIS_BOOTSTRAP_SECRET`, and `JARVIS_RATE_LIMIT_HMAC_SECRET` bindings; secret values are not readable through this inspection. The deployed Worker source is still the health-check scaffold and does not execute the isolated authentication routes. No authentication code has been deployed and no owner passkey has been enrolled.

## Provisioned database

- Name: `jarvis-owner-auth`
- Binding: `DB`
- Database ID: `2bee8195-488a-4c73-ba42-d21950e890c4`
- Scope: this is one account-level D1 database, not a branch-specific database. Cloudflare also lists a `DB` binding on the currently deployed Worker settings; the health-only deployed source does not use it. The security branch points to this same database ID. Therefore code-branch isolation does not provide database isolation: any Worker version configured with this binding can access the same records. Owner has now authorized routine project reads, edits, and modifications. The approved synthetic D1 smoke test is complete; no owner data was written. Deployment remains a separate release action.

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

The security branch configures Workers Static Assets and the account-level D1 binding above. The deployed Worker settings also list this same binding, but the deployed source remains a health-only scaffold. Branches and Worker deployments do not create separate D1 databases.

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

1. [x] Read-only verification confirmed all six application tables, five indexes, two migration-history records, empty application tables, and no foreign-key violations.
2. [x] Perform the approved D1 read/write/delete smoke test using a temporary synthetic table only. Verify the target database, read the inserted value back, delete the row, confirm zero rows remain, and drop the table. No owner record was created. All six application tables remain empty. The Worker settings expose the required binding names, but secret values and exact origin configuration still need safe verification.
3. Obtain separate explicit owner approval before deploying the isolated Worker branch.
4. Verify the served page origin, CSP, cookies, and static assets. Only then perform the first passkey enrollment on the owner's iPhone.
5. Immediately after successful first-owner enrollment, remove the temporary `JARVIS_BOOTSTRAP_SECRET` from the Worker. The database's singleton owner marker permanently closes first-owner enrollment.
6. Run the post-enrollment security checks and document the actual deployment version.

## Safety boundaries

- Keep the Cloudflare account on the Free plan. Do not enable billing, paid features, or a trial.
- D1 Free quotas are finite. Monitor usage; do not automatically upgrade if a quota is reached.
- Deploying authentication code or merging it into the production branch remains a separate release action and is not authorized by routine edit permission alone.
- Do not register a real passkey against an unverified or non-live origin.
- Do not ask the owner to paste the bootstrap secret into chat. The owner should generate and enter it locally through the intended secure setup process.
