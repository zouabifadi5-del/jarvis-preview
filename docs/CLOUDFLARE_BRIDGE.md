# Cloudflare automation bridge

This branch contains an isolated, manually triggered GitHub Actions bridge for the
JARVIS Cloudflare account. It does not deploy Worker code.

## Required GitHub repository secrets

Add these under **Settings → Secrets and variables → Actions → New repository secret**:

- `CLOUDFLARE_API_TOKEN`: a scoped Cloudflare API token (never paste it into chat).
- `CLOUDFLARE_ACCOUNT_ID`: the Cloudflare account ID.

Recommended Cloudflare token permissions, scoped to the one account:

- Account / Workers Scripts / Read
- Account / D1 / Read
- Account / D1 / Write (only needed to apply migrations)

Do not use the Global API Key. Do not grant Workers Scripts Edit for this bridge;
Worker deployment is deliberately not implemented here.

## Run

Open **Actions → Cloudflare bridge → Run workflow** and select the
`cloudflare-automation-bridge` branch.

- `inspect`: verifies the token and reads the named Worker and D1 metadata. No writes.
- `list-migrations`: lists the remote D1 migration state. No writes.
- `apply-migrations`: first lists migrations, then applies the migrations present in
  this branch only when the separate `confirm_apply` checkbox is enabled.

The workflow is restricted to this branch, uses GitHub's manual workflow dispatch,
does not print secrets, and does not deploy Worker code.

## Current limitations

This is a GitHub Actions automation bridge, not a direct ChatGPT-to-Cloudflare
connector. ChatGPT can prepare and inspect repository code through the connected
GitHub integration, but cannot read GitHub Actions secrets or start this workflow
through the currently available GitHub connection. A user must add the two secrets
and manually start the workflow. Do not claim Cloudflare access is connected until
an inspection run succeeds.

All operations are subject to Cloudflare and GitHub free-tier limits.
